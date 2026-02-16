#!/usr/bin/env python
import base64
import json
import subprocess
from datetime import datetime, timedelta

import requests
from django.core.management.base import BaseCommand

from reports.models import Certificate


CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"

# Аутентификация по сертификату – штатный endpoint [web:1126]
AUTH_URL = "https://online.sbis.ru/auth/service/"

# Почта/входящие документы – как в рабочем async-скрипте (protocol=4) [web:1159]
API_URL_DOC_EVENTS = "https://online.sbis.ru/service/?srv=1&protocol=4"


def run_cmd(args: list[str]) -> str:
    return subprocess.check_output(args, text=True)


def export_cert_der(csptest_name: str, dest_path: str) -> None:
    run_cmd(
        [
            CERTMGR_BIN,
            "-export",
            "-cont",
            csptest_name,
            "-dest",
            dest_path,
        ]
    )


def get_thumbprint_from_cert(cert_path: str) -> str:
    out = run_cmd([CERTMGR_BIN, "-list", "-file", cert_path])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SHA1 Thumbprint"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip().lower()
    raise RuntimeError("Не удалось вытащить SHA1 Thumbprint из файла сертификата")


def auth_sbis_by_cert(cert_path: str, thumbprint: str) -> str:
    """
    Аутентификация по сертификату через СБИС.АутентифицироватьПоСертификату.
    На выходе обычный SESSION_ID строкой. [web:1126]
    """
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

    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
    }

    resp = requests.post(AUTH_URL, data=json.dumps(req), headers=headers, timeout=30)

    print(f"AUTH HTTP status: {resp.status_code} {resp.reason}")
    print("AUTH raw (first 500 chars):")
    print(resp.text[:500])

    resp.raise_for_status()

    try:
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"Ошибка парсинга JSON при аутентификации: {e}") from e

    if "error" in data and data["error"]:
        raise RuntimeError(f"JSON-RPC error при аутентификации: {data['error']}")

    enc_b64 = data.get("result")
    if not enc_b64:
        raise RuntimeError(f"СБИС не вернул result при аутентификации: {data}")

    enc_bin = base64.b64decode(enc_b64)
    enc_path = "/tmp/sbis_auth.enc"
    dec_path = "/tmp/sbis_auth.dec"

    with open(enc_path, "wb") as f:
        f.write(enc_bin)

    run_cmd(
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


def call_list_doc_events(session_id: str, days_back: int = 7) -> None:
    date_to = datetime.now().strftime("%d.%m.%Y")
    date_from = (datetime.now() - timedelta(days=days_back)).strftime("%d.%m.%Y")

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументовПоСобытиям",
        "params": {
            "Фильтр": {
                "ДатаС": date_from,
                "ДатаПо": date_to,
                "ТипРеестра": "Входящие",
            }
        },
        "id": 1,
    }

    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
        "X-SBISSessionID": session_id,
    }

    print(f"Запрос СБИС.СписокДокументовПоСобытиям: {date_from} - {date_to}")
    resp = requests.post(API_URL_DOC_EVENTS, json=body, headers=headers, timeout=30)

    print(f"HTTP status: {resp.status_code} {resp.reason}")
    raw = resp.text
    print("Raw response (first 500 chars):")
    print(raw[:500])

    if resp.status_code != 200:
        return

    try:
        data = resp.json()
    except Exception as e:
        print(f"Ошибка парсинга JSON: {e}")
        return

    if "error" in data and data["error"]:
        print("JSON-RPC error:")
        print(json.dumps(data["error"], ensure_ascii=False, indent=2))
        return

    result = data.get("result")
    if not result or "Реестр" not in result:
        print("Нет поля 'Реестр' в result")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:500])
        return

    registry = result["Реестр"]
    print(f"Всего элементов в Реестре: {len(registry)}")

    keywords = ["фнс", "налоговая", "сверка", "требование"]
    fns_prefixes = ["77"]  # при желании вынеси в настройки

    for i, item in enumerate(registry, start=1):
        doc = item.get("Документ", {})
        kontragent = doc.get("Контрагент", {})

        inn = None
        if "СвЮЛ" in kontragent and "ИНН" in kontragent["СвЮЛ"]:
            inn = kontragent["СвЮЛ"]["ИНН"]
        elif "СвФЛ" in kontragent and "ИНН" in kontragent["СвФЛ"]:
            inn = kontragent["СвФЛ"]["ИНН"]

        title = (doc.get("Название") or "").lower()
        is_fns_inn = bool(inn and any(inn.startswith(p) for p in fns_prefixes))
        is_fns_title = any(k in title for k in keywords)
        is_fns = is_fns_inn or is_fns_title

        if not is_fns:
            continue

        attachments = doc.get("Вложение", [])

        print("----- ФНС событие -----")
        print(f"Дата: {doc.get('Дата', 'N/A')}")
        print(f"Название: {doc.get('Название', 'N/A')}")
        print(f"ИНН отправителя: {inn or 'N/A'}")
        if attachments:
            first = attachments[0] or {}
            print(f"Вложение: {first.get('Название', 'N/A')}")
        else:
            print("Вложений нет")



class Command(BaseCommand):
    help = (
        "Аутентификация по сертификату для ИНН и вызов "
        "СБИС.СписокДокументовПоСобытиям (почта/входящие) через protocol=4"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "inn",
            type=str,
            help="ИНН ЮЛ, для которого проверяем (например 9715472576)",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Сколько дней назад смотреть входящие (по умолчанию 7)",
        )

    def handle(self, *args, **options):
        inn = options["inn"].strip()
        days_back = options["days"]
        self.stdout.write(f"ИНН: {inn}")

        cert = Certificate.objects.filter(inn=inn).first()
        if not cert:
            self.stdout.write(
                self.style.ERROR("В таблице Certificate нет записи для этого ИНН")
            )
            return

        if not cert.csptest_name:
            self.stdout.write(
                self.style.ERROR("Для этого сертификата не заполнено csptest_name")
            )
            return

        cert_path = f"/tmp/sbis_test_{inn}.cer"
        self.stdout.write(
            f"Экспорт серта из контейнера {cert.csptest_name} в {cert_path}"
        )
        export_cert_der(cert.csptest_name, cert_path)

        thumbprint = get_thumbprint_from_cert(cert_path)
        self.stdout.write(f"SHA1 Thumbprint: {thumbprint}")

        self.stdout.write(
            "Запрос SESSION_ID через СБИС.АутентифицироватьПоСертификату..."
        )
        session_id = auth_sbis_by_cert(cert_path, thumbprint)
        self.stdout.write(f"SESSION_ID: {session_id}")

        self.stdout.write("")
        self.stdout.write(
            "Вызов СБИС.СписокДокументовПоСобытиям (ТипРеестра='Входящие')..."
        )
        call_list_doc_events(session_id, days_back)
