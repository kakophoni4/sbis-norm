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
from .auth import auth_sbis_by_cert, sbis_auth_session_for_inn
from .client import _sbis_get, _sbis_post, _sbis_request, sbis_rpc
from .crypto import (
    export_cert_der,
    get_thumbprint_from_cert,
    parse_kpp_from_cert_file,
    sbis_decrypt_bytes_with_cert_thumbprint,
    _try_decrypt_bytes_with_cert,
)

def sbis_get_our_org_from_service_info(inn: str, session_id: str, target_inn: str) -> dict | None:
    """
    Достаёт из СБИС.ИнформацияОСлужебныхЭтапах объект нашей организации по ИНН.
    Возвращает объект НашаОрганизация (как в ответе СБИС) или None если не нашли.
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},  # обычно без параметров
        timeout=45,
    )

    if data.get("error"):
        raise RuntimeError(f"СБИС.ИнформацияОСлужебныхЭтапах error: {data['error']}")

    result = data.get("result")
    if not isinstance(result, list):
        # иногда может вернуться не список — лучше сразу увидеть
        raise RuntimeError(f"Unexpected result type: {type(result)}; body={str(result)[:400]}")

    target_inn = (target_inn or "").strip()
    if not target_inn:
        return None

    for item in result:
        org = (item or {}).get("НашаОрганизация") or (item or {}).get("НашаОрганизация".lower()) or None
        # по факту в доке: массив со списком наших организаций — структура может быть как item.НашаОрганизация
        # но встречается и когда item сам = НашаОрганизация. Поэтому подстрахуемся:
        candidate = org if isinstance(org, dict) else (item if isinstance(item, dict) else None)
        if not isinstance(candidate, dict):
            continue

        svul = (candidate.get("СвЮЛ") or {})
        cand_inn = (svul.get("ИНН") or "").strip()
        if cand_inn == target_inn:
            return candidate

    return None

def sbis_list_organizations_from_service_info(
    inn: str,
    session_id: str,
    *,
    timeout: int = 45,
) -> dict:
    """
    СБИС.ИнформацияОСлужебныхЭтапах — разбор всех «наших организаций» из ответа.

    Возвращает dict:
      success: bool
      organizations: [{"inn", "kpp", "name", "raw": dict}, ...]  — по возможности
      error: {...} при ошибке RPC или неожиданной структуре
      raw_result_type: str — для отладки
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
        }

    result = data.get("result")
    raw_type = type(result).__name__

    def _extract_svul_pairs(candidate: dict) -> list[tuple[dict, dict]]:
        """Вернуть пары (родительский объект, СвЮЛ) если есть."""
        out: list[tuple[dict, dict]] = []
        if not isinstance(candidate, dict):
            return out
        svul = candidate.get("СвЮЛ")
        if isinstance(svul, dict):
            out.append((candidate, svul))
        # иногда вложенность иная
        for key in ("НашаОрганизация", "Организация", "ЮЛ"):
            sub = candidate.get(key)
            if isinstance(sub, dict):
                s2 = sub.get("СвЮЛ")
                if isinstance(s2, dict):
                    out.append((sub, s2))
        return out

    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add_from_svul(parent: dict, svul: dict) -> None:
        i = (str(svul.get("ИНН") or "").strip(), str(svul.get("КПП") or "").strip())
        if not i[0] and not i[1]:
            return
        key = (i[0], i[1])
        if key in seen:
            return
        seen.add(key)
        organizations.append(
            {
                "inn": i[0],
                "kpp": i[1],
                "name": (
                    str(svul.get("Название") or svul.get("Наименование") or "").strip()
                ),
                "raw": parent,
            }
        )

    if isinstance(result, list):
        for item in result:
            if not isinstance(item, dict):
                continue
            org = item.get("НашаОрганизация")
            candidates: list[dict] = []
            if isinstance(org, dict):
                candidates.append(org)
            candidates.append(item)
            for cand in candidates:
                for parent, svul in _extract_svul_pairs(cand):
                    _add_from_svul(parent, svul)
    elif isinstance(result, dict):
        # единичный объект или обёртка
        for parent, svul in _extract_svul_pairs(result):
            _add_from_svul(parent, svul)
        for key in ("НашаОрганизация", "Документ", "Организации"):
            sub = result.get(key)
            if isinstance(sub, list):
                for el in sub:
                    if isinstance(el, dict):
                        for parent, svul in _extract_svul_pairs(el):
                            _add_from_svul(parent, svul)
            elif isinstance(sub, dict):
                for parent, svul in _extract_svul_pairs(sub):
                    _add_from_svul(parent, svul)
    else:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": f"Неожиданный тип result: {raw_type}",
                "sample": str(result)[:500] if result is not None else "",
            },
            "raw_result_type": raw_type,
        }

    return {
        "success": True,
        "organizations": organizations,
        "error": None,
        "raw_result_type": raw_type,
    }

def _deep_walk_collect_svul(
    obj: object,
    organizations: list[dict],
    seen: set[tuple[str, str]],
) -> None:
    """Рекурсивно собрать СвЮЛ с ИНН/КПП из произвольного JSON (ответ СБИС)."""
    if isinstance(obj, dict):
        svul = obj.get("СвЮЛ")
        if isinstance(svul, dict):
            inn_v = str(svul.get("ИНН") or "").strip()
            kpp_v = str(svul.get("КПП") or "").strip()
            if inn_v or kpp_v:
                key = (inn_v, kpp_v)
                if key not in seen:
                    seen.add(key)
                    organizations.append(
                        {
                            "inn": inn_v,
                            "kpp": kpp_v,
                            "name": str(
                                svul.get("Название") or svul.get("Наименование") or ""
                            ).strip(),
                            "raw": svul,
                        }
                    )
        for v in obj.values():
            _deep_walk_collect_svul(v, organizations, seen)
    elif isinstance(obj, list):
        for x in obj:
            _deep_walk_collect_svul(x, organizations, seen)

def _filter_service_stages_our_org(
    inn: str,
    kpp: str,
    *,
    org_name: str = "",
    date_from: str,
    date_to: str,
    page_size: int = 50,
) -> dict:
    """Фильтр СБИС.СписокСлужебныхЭтапов (на многих контурах КПП в СвЮЛ обязателен)."""
    kpp = (kpp or "").strip()
    return {
        "Блокировать": "Да",
        "НашаОрганизация": {
            "СвЮЛ": {
                "ИНН": inn,
                "КПП": kpp,
                "Название": (org_name or "").strip(),
                "КодФилиала": "",
            }
        },
        "ТолькоОтчетность": "Да",
        "ТолькоЭДО": "Нет",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }

def sbis_list_organizations_from_service_stages(
    inn: str,
    session_id: str,
    *,
    kpp: str | None = None,
    org_name: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    page_size: int = 50,
    timeout: int = 45,
) -> dict:
    """
    СБИС.СписокСлужебныхЭтапов + рекурсивный разбор СвЮЛ в ответе.

    На контурах СБИС КПП в фильтре часто обязателен («КПП должен быть заполнен»).
    Без kpp HTTP-запрос не выполняется — передайте КПП, возьмите из БД/серта/XML.
    """
    kpp = (kpp or "").strip()
    if not kpp:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": "КПП обязателен для СписокСлужебныхЭтапов на этом контуре СБИС",
                "code": "KPP_REQUIRED",
                "hint": "Передайте kpp=, заполните Organization.kpp, или parse_kpp_from_cert_file()",
            },
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
            "docs_count": None,
        }

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=90)).strftime("%d.%m.%Y")

    filt = _filter_service_stages_our_org(
        inn,
        kpp,
        org_name=org_name,
        date_from=date_from,
        date_to=date_to,
        page_size=page_size,
    )
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.СписокСлужебныхЭтапов",
        params={"Фильтр": filt},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
        }

    result = data.get("result")
    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()
    _deep_walk_collect_svul(result, organizations, seen)

    # как в sbis_list_organizations_from_service_info — без лишнего raw в slim
    slim = []
    for o in organizations:
        slim.append(
            {
                "inn": o["inn"],
                "kpp": o["kpp"],
                "name": o["name"],
            }
        )

    return {
        "success": True,
        "organizations": slim,
        "error": None,
        "raw_result_type": type(result).__name__,
        "source_method": "СписокСлужебныхЭтапов",
        "docs_count": len((result or {}).get("Документ") or [])
        if isinstance(result, dict)
        else None,
    }

def _build_service_stages_filter_minimal(
    inn: str,
    *,
    page_size: int = 20,
    block: bool = True,
    only_reporting: bool = True,
    only_edo: bool = False,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict:
    """
    Минимальный фильтр, чтобы СБИС не ругался и при этом не требовать от нас Billing/SPP.
    Если СБИС у тебя попросит больше реквизитов — расширим позже, но начнём так.
    """
    f = {
        "Блокировать": "Да" if block else "Нет",
        "НашаОрганизация": {"СвЮЛ": {"ИНН": inn}},
        "ТолькоОтчетность": "Да" if only_reporting else "Нет",
        "ТолькоЭДО": "Да" if only_edo else "Нет",
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }
    if date_from:
        f["ДатаС"] = date_from
    if date_to:
        f["ДатаПо"] = date_to
    return {"Фильтр": f}

def sbis_list_service_stages(
    inn: str,
    *,
    kpp: str,
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
    date_from: str | None = None,   # "dd.mm.yyyy"
    date_to: str | None = None,     # "dd.mm.yyyy"
    page_size: int = 20,
    only_reporting: bool = True,
) -> dict:
    """
    1) Аутентификация по сертификату (СБИС.АутентифицироватьПоСертификату)
    2) СБИС.СписокСлужебныхЭтапов с фильтром по нашей организации

    КПП — передаём ВРУЧНУЮ.
    only_reporting: True — только отчётность; False — в т.ч. требования ФНС и др. служебные.
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}

    kpp = (kpp or "").strip()
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен (передай вручную)", "inn": inn}}

    # даты по умолчанию — последние 30 дней
    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=30)).strftime("%d.%m.%Y")

    # сертификат
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    # авторизация
    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    # НашаОрганизация
    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокСлужебныхЭтапов",
        "params": {
            "Фильтр": {
                "Блокировать": "Да",
                "НашаОрганизация": our_org,
                "ТолькоОтчетность": "Да" if only_reporting else "Нет",
                "ТолькоЭДО": "Нет",
                "ДатаС": date_from,
                "ДатаПо": date_to,
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 0,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)

        if resp.status_code != 200:
            return {
                "success": False,
                "error": {
                    "message": f"HTTP {resp.status_code}",
                    "inn": inn,
                    "raw_head": (resp.text or "")[:500],
                },
            }

        data = resp.json()
        if data.get("error"):
            return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

        result = data.get("result") or {}
        docs = (result.get("Документ") or [])

        # небольшой превью, чтоб глазами понимать что пришло
        preview = []
        for d in docs[:10]:
            stages = []
            for st in (d.get("Этап") or []):
                actions = []
                for a in (st.get("Действие") or []):
                    actions.append(
                        {
                            "name": a.get("Название"),
                            "need_decrypt": a.get("ТребуетРасшифровки"),
                            "need_sign": a.get("ТребуетПодписания"),
                            "sig_type": a.get("ТипПодписи"),
                        }
                    )
                stages.append(
                    {
                        "name": st.get("Название"),
                        "id": st.get("Идентификатор"),
                        "service": st.get("Служебный"),
                        "actions": actions,
                    }
                )

            preview.append(
                {
                    "id": d.get("Идентификатор"),
                    "name": d.get("Название"),
                    "type": d.get("Тип"),
                    "direction": d.get("Направление"),
                    "subtype": d.get("Подтип"),
                    "state": (d.get("Состояние") or {}).get("Код"),
                    "stages": stages,
                }
            )

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "period": {"from": date_from, "to": date_to},
                "session_id_head": (session_id or "")[:8],
                "total_docs": len(docs),
                "docs": docs,
                "preview": preview,
                "raw_result_keys": list(result.keys()),
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СписокСлужебныхЭтапов: {e}", "inn": inn}}

def sbis_prepare_action(
    inn: str,
    *,
    kpp: str,
    doc_id: str,
    stage_id: str,
    action_name: str = "Обработать служебное",
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
) -> dict:
    """
    СБИС.ПодготовитьДействие для служебного этапа.
    Возвращает сырой ответ result, где обычно лежат Вложение (XML/PDF/DOC и т.п.)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}
    if not (kpp or "").strip():
        return {"success": False, "error": {"message": "kpp обязателен", "inn": inn}}
    if not (doc_id or "").strip():
        return {"success": False, "error": {"message": "doc_id обязателен", "inn": inn}}
    if not (stage_id or "").strip():
        return {"success": False, "error": {"message": "stage_id обязателен", "inn": inn}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": doc_id,
                "НашаОрганизация": our_org,
                "Этап": {
                    "Идентификатор": stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumb, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)
        if resp.status_code != 200:
            body_head = (resp.text or "").strip()[:400]
            return {
                "success": False,
                "error": {"message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}", "inn": inn, "raw_head": body_head},
            }

        data = resp.json()
        if data.get("error"):
            return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "session_id": session_id,
                "thumbprint": thumb,
                "raw": data.get("result"),
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка ПодготовитьДействие: {e}", "inn": inn}}

def sbis_download_stage_attachments(
    inn: str,
    *,
    session_id: str,
    prepared_raw: dict | list | None,
    max_files: int = 10,
) -> dict:
    """
    Из result СБИС.ПодготовитьДействие достаёт вложения и скачивает их.
    Поддерживает:
    - Файл.ДвоичныеДанные (base64)
    - Файл.Ссылка (скачиваем по GET с X-SBISSessionID)
    """

    if not prepared_raw:
        return {"success": False, "error": {"message": "prepared_raw пустой"}}

    def _iter_attachments(raw_obj):
        # В реальности СБИС может вернуть dict/ list — делаем мягко.
        if isinstance(raw_obj, dict):
            # иногда вложения лежат прямо в raw_obj["Этап"]["Вложение"]
            etap = raw_obj.get("Этап") if isinstance(raw_obj.get("Этап"), dict) else None
            if etap and isinstance(etap.get("Вложение"), list):
                for v in etap["Вложение"]:
                    yield v
            # иногда "Документ" список
            if isinstance(raw_obj.get("Документ"), list):
                for d in raw_obj["Документ"]:
                    etap2 = d.get("Этап") if isinstance(d.get("Этап"), dict) else None
                    if etap2 and isinstance(etap2.get("Вложение"), list):
                        for v in etap2["Вложение"]:
                            yield v
            return

        if isinstance(raw_obj, list):
            for x in raw_obj:
                yield from _iter_attachments(x)

    files = []
    count = 0

    for att in _iter_attachments(prepared_raw):
        if count >= max_files:
            break

        f = (att or {}).get("Файл") or {}
        name = (f.get("Имя") or f.get("Название") or f.get("Файл") or "").strip() or None
        href = (f.get("Ссылка") or "").strip() or None
        b64 = (f.get("ДвоичныеДанные") or "").strip() or None

        content = b""
        source = None

        try:
            if b64:
                content = base64.b64decode(b64)
                source = "b64"
            elif href:
                r = _sbis_get(href, headers={"X-SBISSessionID": session_id}, timeout=60, inn=inn)
                if r.status_code != 200:
                    files.append(
                        {
                            "name": name,
                            "href": href,
                            "ok": False,
                            "error": f"download HTTP {r.status_code} body_head={(r.text or '')[:200]}",
                        }
                    )
                    continue
                content = r.content or b""
                source = "link"
            else:
                files.append({"name": name, "ok": False, "error": "нет ни ДвоичныеДанные, ни Ссылка"})
                continue

            files.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "source": source,
                    "size": len(content),
                    "bytes": content,
                }
            )
            count += 1

        except Exception as e:
            files.append({"name": name, "href": href, "ok": False, "error": str(e)})

    return {"success": True, "result": {"files": files}}

def fetch_requirement_decrypted_preview(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    org_name: str = "",
    max_preview_chars: int = 1200,
) -> dict:
    """
    Минимальный рабочий шаг:
      - auth
      - ПодготовитьДействие по stage_id
      - скачать вложения (disk.sbis.ru)
      - если Зашифрован=Да — попытаться расшифровать
      - отдать превью (название/размер/тип/кусок XML если это XML)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    # 1) ПодготовитьДействие
    prep = sbis_prepare_action(
        inn,
        kpp=kpp,
        org_name=org_name,
        doc_id=requirement_doc_id,
        stage_id=requirement_stage_id,
    )
    if not prep.get("success"):
        return prep

    prepared_raw = ((prep.get("result") or {}).get("raw") or {})
    files_meta = _extract_files_from_prepare_raw(prepared_raw)

    # 2) Скачивание + (опционально) расшифровка
    files_preview = []
    for f in files_meta:
        name = (f.get("name") or "").strip() or None
        href = (f.get("href") or "").strip() or None
        encrypted_flag = f.get("encrypted")

        if not href:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": "нет ссылки Файл.Ссылка",
                    "encrypted": encrypted_flag,
                }
            )
            continue

        try:
            content, dl_meta = sbis_download_file_by_link(inn, session_id=session_id, href=href)

            # если СБИС сказал, что зашифрован — пробуем decrypt
            if str(encrypted_flag).strip() == "Да":
                content2, dec_meta = _try_decrypt_bytes_with_cert(inn=inn, thumbprint=thumbprint, content=content)
            else:
                content2, dec_meta = content, {"decrypt_ok": False, "decrypt_error": None}

            # превью текста (если похоже на xml)
            text_preview = None
            low_name = (name or "").lower()
            if low_name.endswith(".xml") or (content2[:50].lstrip().startswith(b"<?xml") or content2[:20].lstrip().startswith(b"<")):
                # пробуем основные кодировки
                decoded = None
                for enc in ("windows-1251", "utf-8", "utf-16"):
                    try:
                        decoded = content2.decode(enc)
                        break
                    except Exception:
                        continue
                if decoded is None:
                    decoded = content2.decode("utf-8", errors="ignore")

                decoded = decoded.strip()
                text_preview = decoded[:max_preview_chars]

            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "size": len(content2),
                    "content_type": dl_meta.get("content_type"),
                    "encrypted": encrypted_flag,
                    "decrypt_ok": dec_meta.get("decrypt_ok"),
                    "decrypt_error": dec_meta.get("decrypt_error"),
                    "text_preview": text_preview,
                }
            )

        except Exception as e:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": str(e),
                    "encrypted": encrypted_flag,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "files_found": len(files_meta),
            "files_preview": files_preview,
        },
    }

def _extract_files_from_prepare_raw(prepared_raw: dict) -> list[dict]:
    """
    prepared_raw — это dict из (prep["result"]["raw"]).

    Возвращает список файлов:
      [{"name": str|None, "href": str|None, "sha1": str|None, "encrypted": str|None}, ...]
    """
    files: list[dict] = []

    if not isinstance(prepared_raw, dict):
        return files

    stages = prepared_raw.get("Этап")
    if not isinstance(stages, list):
        return files

    for st in stages:
        if not isinstance(st, dict):
            continue

        влож = st.get("Вложение") or st.get("Вложения")
        if not isinstance(влож, list):
            continue

        for att in влож:
            if not isinstance(att, dict):
                continue

            f = att.get("Файл")
            if not isinstance(f, dict):
                continue

            files.append(
                {
                    "name": (f.get("Имя") or f.get("Название") or att.get("Название") or None),
                    "href": (f.get("Ссылка") or None),
                    "sha1": (f.get("Хеш") or f.get("ХешСумма") or None),
                    "encrypted": (att.get("Зашифрован") or None),
                }
            )

    return files

def sbis_download_file_by_link(
    inn: str,
    *,
    session_id: str,
    href: str,
    timeout: int = 90,
) -> tuple[bytes, dict]:
    """
    Скачивает файл по ссылке (в т.ч. disk.sbis.ru) через прокси NodeMaven.
    Возвращает (bytes, meta).
    """
    if not href:
        raise RuntimeError("Пустая ссылка на файл")

    headers = {"X-SBISSessionID": session_id}

    r = _sbis_get(
        href,
        headers=headers,
        timeout=timeout,
        inn=inn,
    )

    # disk.sbis.ru может отдавать JSON с ошибкой, поэтому сохраняем head
    body_head = ""
    try:
        body_head = (r.text or "")[:200]
    except Exception:
        body_head = "<binary>"

    if r.status_code != 200:
        raise RuntimeError(f"Не удалось скачать файл: HTTP {r.status_code}, body_head={body_head}")

    content = r.content or b""

    meta = {
        "href": href,
        "http_status": r.status_code,
        "content_len": len(content),
        "content_type": r.headers.get("Content-Type"),
        "body_head": body_head,
    }
    return content, meta

def sbis_list_changes(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    org_name: str = "",
    page_size: int = 50,
) -> dict:
    """
    СБИС.СписокИзменений — возвращает расшифрованные файлы/события по требованию.
    ВАЖНО: метод ожидает params.Фильтр (иначе "В объекте нет поля Фильтр").
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокИзменений",
        "params": {
            "Фильтр": {
                "Документ": {"Идентификатор": requirement_doc_id},
                "НашаОрганизация": {"СвЮЛ": {"ИНН": inn, "КПП": kpp, "Название": (org_name or "")}},
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 1,
    }

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка запроса в СБИС: {e}", "inn": inn}}

    if resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {resp.status_code}", "raw": resp.text}}

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": resp.text}}

    if data.get("error"):
        return {"success": False, "error": data["error"]}

    result = data.get("result") or {}

    # аккуратный превью по тому, что пришло
    events = result.get("Событие") or []
    preview = []
    if isinstance(events, list):
        for ev in events[:20]:
            if not isinstance(ev, dict):
                continue
            влож = ev.get("Вложение") or []
            preview.append(
                {
                    "event_name": (ev.get("Название") or ""),
                    "event_time": (ev.get("ДатаВремя") or ev.get("Дата") or ""),
                    "attachments": len(влож) if isinstance(влож, list) else 0,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "events_count": len(events) if isinstance(events, list) else None,
            "events_preview": preview,
            "raw": result,
        },
    }

def fetch_requirement_file_b64(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    action_name: str = "Обработать служебное",
    save_to: str | None = None,  # например "/tmp/requirement.pdf"
) -> dict:
    """
    Возвращает base64 РАСШИФРОВАННОГО файла требования (обычно PDF),
    используя inn/kpp/doc_id/stage_id.

    Важно: для СБИС.ПодготовитьДействие нужно указать Этап.Действие.Название,
    иначе будет "Не указано название действия".

    Скачивание по «Ссылка» должно идти с тем же X-SBISSessionID, что и после auth;
    ответ 403 (в т.ч. с текстом про HMAC/доступ) часто даёт СБИС при другом exit-IP
    или без сессии — ретраи HTTP перебирают прокси из пула (_sbis_request).
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}
    if not action_name:
        return {"success": False, "error": {"message": "action_name обязателен (например 'Обработать служебное')"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    # 1) ПодготовитьДействие — чтобы получить вложение и ссылку (Сертификат внутри Действие, как в Отправить)
    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": requirement_doc_id,
                "Этап": {
                    "Идентификатор": requirement_stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumbprint, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СБИС.ПодготовитьДействие: {e}", "inn": inn}}

    if resp.status_code != 200:
        body_head = (resp.text or "").strip()[:400]
        return {
            "success": False,
            "error": {
                "message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}",
                "body_head": body_head,
            },
        }

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Не смог распарсить JSON ПодготовитьДействие: {e}", "raw": resp.text[:300]}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"JSON-RPC error ПодготовитьДействие: {data['error']}", "inn": inn}}

    raw = data.get("result") or {}
    stages = raw.get("Этап") or []
    if not isinstance(stages, list) or not stages:
        return {"success": False, "error": {"message": "В ответе нет Этап[]", "inn": inn, "keys": list(raw.keys())}}

    st0 = stages[0] or {}
    atts = st0.get("Вложение") or []
    if not isinstance(atts, list) or not atts:
        return {"success": False, "error": {"message": "В ответе нет Этап[0].Вложение[]", "inn": inn}}

    # По доке СБИС: два вложения — XML обмена и требование в формате PDF или DOC. Скачиваем все и отдаём первое (для обратной совместимости).
    attachments_out: list[dict] = []
    for i, att in enumerate(atts):
        att = att or {}
        file_obj = att.get("Файл") or {}
        if not isinstance(file_obj, dict):
            continue
        file_url = (file_obj.get("Ссылка") or "").strip()
        filename = (file_obj.get("Имя") or file_obj.get("Название") or "requirement.bin").strip()
        if not file_url:
            continue
        if i > 0:
            time.sleep(1.0)  # пауза между вложениями
        encrypted_flag = (att.get("Зашифрован") or "").strip()
        try:
            r = _sbis_get(
                file_url,
                headers={"X-SBISSessionID": session_id},
                timeout=120,
                inn=inn,
                total_budget_sec=180,
            )
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code == 403:
            time.sleep(2.0)
            try:
                r = _sbis_get(
                    file_url,
                    headers={"X-SBISSessionID": session_id},
                    timeout=120,
                    inn=inn,
                    total_budget_sec=180,
                )
            except Exception as e:
                return {"success": False, "error": {"message": f"Ошибка повтора скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {r.status_code} при скачивании вложения {i + 1}", "url": file_url},
            }
        content = r.content or b""
        decrypted = content
        if encrypted_flag == "Да":
            try:
                with tempfile.TemporaryDirectory(prefix=f"sbis_req_dec_{inn}_") as td:
                    enc_path = os.path.join(td, f"req_{i}.enc")
                    dec_path = os.path.join(td, f"req_{i}.dec")
                    Path(enc_path).write_bytes(content)
                    run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])
                    decrypted = Path(dec_path).read_bytes()
            except Exception:
                decrypted = content
        is_pdf = decrypted.startswith(b"%PDF") or (filename or "").lower().endswith(".pdf")
        is_doc = (filename or "").lower().endswith((".doc", ".docx"))
        attachments_out.append({
            "filename": filename,
            "b64": base64.b64encode(decrypted).decode("ascii"),
            "size": len(decrypted),
            "is_pdf": is_pdf,
            "is_doc": is_doc,
        })

    if not attachments_out:
        return {"success": False, "error": {"message": "Не удалось скачать ни одного вложения", "inn": inn}}

    # Выбираем вложение: предпочитаем PDF, затем DOC, иначе первое
    chosen = None
    for a in attachments_out:
        if a["is_pdf"] or a["is_doc"]:
            chosen = a
            break
    if not chosen:
        chosen = attachments_out[0]

    saved_to = None
    if save_to:
        try:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_bytes(base64.b64decode(chosen["b64"]))
            saved_to = save_to
        except Exception:
            pass

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "action_name": action_name,
            "filename": chosen["filename"],
            "size": chosen["size"],
            "saved_to": saved_to,
            "b64": chosen["b64"],
            "attachments_count": len(attachments_out),
            "attachments_all": attachments_out,
        },
    }
