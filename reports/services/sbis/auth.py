import base64
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ProxyError, SSLError, Timeout

from reports.models import Certificate
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

from .constants import *
from .client import (
    _mask_proxy_url,
    _sbis_request,
    get_good_proxy_for_inn,
    log_http_exchange,
    warmup_good_proxies_for_inn,
)
from .crypto import (
    CERTMGR_BIN,
    CRYPTCP_BIN,
    CRYPTCP_DECR_FLAGS,
    export_cert_der,
    get_fio_from_cert_file,
    get_thumbprint_from_cert,
    run_cmd,
)

def auth_sbis_by_cert(
    cert_path: str,
    thumbprint: str,
    inn: str = "no_inn",
    *,
    proxy_url: str | None = None,
    timeout_sec: int = 30,
    total_budget_sec: int = 45,
) -> str:
    logger.info("[SBIS auth] 1/4 Чтение серта и подготовка запроса")
    with open(cert_path, "rb") as f:
        cert_der = f.read()
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    inn_val = (inn or "").strip() if inn else ""
    if not inn_val or inn_val == "no_inn":
        inn_val = ""
    fio = get_fio_from_cert_file(cert_path)
    fio_val = (fio or "—").strip() or "—"
    cert_params: dict = {
        "ДвоичныеДанные": cert_b64,
        "ИНН": inn_val,
        "ФИО": fio_val,
    }
    logger.info("[SBIS auth] Сертификат.ИНН=%r Сертификат.ФИО=%r", cert_params["ИНН"], (cert_params["ФИО"])[:60])

    req = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": cert_params},
        "id": 1,
    }

    headers = {"Content-Type": "application/json-rpc;charset=utf-8"}
    req_json = json.dumps(req, ensure_ascii=False)

    logger.info("[SBIS auth] 2/4 Отправка HTTP POST в СБИС %s", AUTH_URL)
    resp = _sbis_request(
        "POST",
        AUTH_URL,
        inn=inn,
        headers=headers,
        data=req_json,
        timeout=max(8, int(timeout_sec)),
        proxy_url_override=proxy_url,   # pinned proxy if provided
        total_budget_sec=max(12, int(total_budget_sec)),
    )
    log_http_exchange("AUTH", AUTH_URL, headers, req_json, resp)

    logger.info("[SBIS auth] СБИС ответил: %s", resp.status_code)
    resp.raise_for_status()
    data = resp.json()

    if data.get("error"):
        err = data["error"]
        err_msg = (err.get("message") or err.get("details") or str(err)).lower()
        if (
            "отозван" in err_msg
            or "не является доверенным" in err_msg
            or "выберите другой сертификат" in err_msg
            or "просроченному сертификату" in err_msg
            or "аутентификация по просроченному" in err_msg
        ):
            try:
                tp = (thumbprint or "").strip().lower()
                if inn and inn != "no_inn" and tp:
                    deleted = Certificate.objects.filter(inn=inn, thumbprint=tp).delete()
                    if deleted[0]:
                        logger.warning(
                            "[SBIS auth] Сертификат отозван/просрочен/не доверенный — удалён из БД (inn=%s)",
                            inn,
                        )
            except Exception as e:
                logger.warning("[SBIS auth] Не удалось удалить сертификат из БД: %s", e)
        raise RuntimeError(f"JSON-RPC error при аутентификации: {data['error']}")

    enc_b64 = data.get("result")
    if not enc_b64:
        raise RuntimeError(f"СБИС не вернул result при аутентификации: {data}")

    enc_bin = base64.b64decode(enc_b64)

    logger.info("[SBIS auth] 3/4 Запись .enc, запуск cryptcp -decr (расшифровка)")
    with tempfile.TemporaryDirectory(prefix=f"sbis_auth_dec_{inn}_") as td:
        enc_path = os.path.join(td, "auth.enc")
        dec_path = os.path.join(td, "auth.dec")
        with open(enc_path, "wb") as f:
            f.write(enc_bin)

        run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])

        logger.info("[SBIS auth] 4/4 Чтение session_id из .dec")
        with open(dec_path, "rb") as f:
            session_id = f.read().decode("utf-8").strip()
    return session_id

def sbis_auth_session_for_inn(
    inn: str,
    *,
    prewarm_proxies: bool = True,
    proxy_want: int = 6,
    proxy_warmup_budget_sec: int = 14,
    auth_timeout_sec: int = 14,
    auth_budget_sec: int = 20,
) -> dict:
    """
    1) Берём сертификат из БД по ИНН
    2) Экспортим .cer
    3) Достаём thumbprint
    4) Получаем X-SBISSessionID через СБИС.АутентифицироватьПоСертификату
    """
    inn = (inn or "").strip()
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}

    cert = Certificate.objects.filter(inn=inn, is_active=True).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден активный сертификат для ИНН", "inn": inn}}

    if not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "У сертификата пустой csptest_name", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    try:
        export_cert_der(cert.csptest_name, cert_path)
        thumbprint = get_thumbprint_from_cert(cert_path)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подготовки сертификата: {e}", "inn": inn}}

    candidates: list[str | None] = []
    prewarmed: list[str] = []

    if prewarm_proxies:
        try:
            prewarmed = warmup_good_proxies_for_inn(
                inn,
                want=max(1, int(proxy_want)),
                total_budget_sec=max(6, int(proxy_warmup_budget_sec)),
                per_probe_timeout=4.5,
            )
        except Exception:
            prewarmed = []

    if prewarmed:
        candidates.extend(prewarmed)

    cached_proxy = get_good_proxy_for_inn(inn)
    if cached_proxy and cached_proxy not in candidates:
        candidates.append(cached_proxy)

    # fallback: без pinned proxy, чтобы _sbis_request сам перебрал кандидатов
    candidates.append(None)

    auth_errors: list[str] = []
    for proxy in candidates:
        try:
            session_id = auth_sbis_by_cert(
                cert_path,
                thumbprint,
                inn=inn,
                proxy_url=proxy,
                timeout_sec=max(8, int(auth_timeout_sec)),
                total_budget_sec=max(12, int(auth_budget_sec)),
            )
            return {
                "success": True,
                "result": {
                    "inn": inn,
                    "cert_path": cert_path,
                    "thumbprint": thumbprint,
                    "session_id": session_id,
                    "proxy_used": _mask_proxy_url(proxy) if proxy else None,
                    "prewarmed_count": len(prewarmed),
                },
            }
        except Exception as e:
            auth_errors.append(str(e))
            continue

    return {
        "success": False,
        "error": {
            "message": "Ошибка аутентификации в СБИС: не удалось подобрать живой прокси",
            "inn": inn,
            "attempts": len(candidates),
            "prewarmed_count": len(prewarmed),
            "last_error": auth_errors[-1] if auth_errors else None,
        },
    }
