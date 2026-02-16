import base64
import json
import subprocess
from datetime import datetime
from typing import Any

import requests

from reports.models import Certificate


CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"

AUTH_URL = "https://online.sbis.ru/auth/service/"
API_URL_DOC_EVENTS = "https://online.sbis.ru/service/?srv=1&protocol=4"


def _run_cmd(args: list[str]) -> str:
    return subprocess.check_output(args, text=True)


def _export_cert_der(csptest_name: str, dest_path: str) -> None:
    _run_cmd(
        [
            CERTMGR_BIN,
            "-export",
            "-cont",
            csptest_name,
            "-dest",
            dest_path,
        ]
    )


def _get_thumbprint_from_cert(cert_path: str) -> str:
    out = _run_cmd([CERTMGR_BIN, "-list", "-file", cert_path])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SHA1 Thumbprint"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip().lower()
    raise RuntimeError("Не удалось вытащить SHA1 Thumbprint из файла сертификата")


def _auth_sbis_by_cert(cert_path: str, thumbprint: str) -> str:
    with open(cert_path, "rb") as f:
        cert_der = f.read()
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    req = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {
            "Сертификат": {
                "ДвоичныеДанные": cert_b64,
            }
        },
        "id": 1,
    }

    resp = requests.post(
        AUTH_URL,
        data=json.dumps(req),
        headers={"Content-Type": "application/json-rpc;charset=utf-8"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    enc_b64 = data.get("result")
    if not enc_b64:
        raise RuntimeError(f"СБИС не вернул result при аутентификации: {data}")

    enc_bin = base64.b64decode(enc_b64)
    enc_path = "/tmp/sbis_auth.enc"
    dec_path = "/tmp/sbis_auth.dec"

    with open(enc_path, "wb") as f:
        f.write(enc_bin)

    _run_cmd(
        [
            CRYPTCP_BIN,
            "-decr",
            "-thumbprint",
            thumbprint,
            enc_path,
            dec_path,
        ]
    )

    with open(dec_path, "rb") as f:
        session_id = f.read().decode("utf-8").strip()
    return session_id


def get_session_id_by_inn(inn: str) -> str:
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        raise RuntimeError("В таблице Certificate нет записи для этого ИНН")
    if not cert.csptest_name:
        raise RuntimeError("Для этого сертификата не заполнено csptest_name")

    cert_path = f"/tmp/sbis_api_{inn}.cer"
    _export_cert_der(cert.csptest_name, cert_path)
    thumbprint = _get_thumbprint_from_cert(cert_path)
    return _auth_sbis_by_cert(cert_path, thumbprint)


def get_incoming_docs(
    session_id: str,
    date_from: datetime,
    date_to: datetime,
) -> list[dict[str, Any]]:
    df = date_from.strftime("%d.%m.%Y")
    dt = date_to.strftime("%d.%m.%Y")

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументовПоСобытиям",
        "params": {
            "Фильтр": {
                "ДатаС": df,
                "ДатаПо": dt,
                "ТипРеестра": "Входящие",
            }
        },
        "id": 1,
    }

    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
        "X-SBISSessionID": session_id,
    }

    resp = requests.post(
        API_URL_DOC_EVENTS,
        json=body,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    if "error" in data and data["error"]:
        raise RuntimeError(f"JSON-RPC error: {data['error']}")

    result = data.get("result") or {}
    registry = result.get("Реестр") or []

    docs: list[dict[str, Any]] = []
    for item in registry:
        doc = item.get("Документ") or {}
        docs.append(doc)

    return docs
