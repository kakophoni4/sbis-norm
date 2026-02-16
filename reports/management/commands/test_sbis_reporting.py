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

# Для отчетности по доке используется общий сервис без protocol в урле. [web:1379]
AUTH_URL = "https://online.sbis.ru/auth/service/"
REPORTING_URL = "https://online.sbis.ru/service/?srv=1"


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
    Аутентификация по сертификату через СБИС.АутентифицироватьПоСертификату. [web:1126]
    На выходе обычный SESSION_ID строкой.
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

    headers = {"Content-Type": "application/json-rpc;charset=utf-8"}

    resp = requests.post(AUTH_URL, data=json.dumps(req), headers=headers, timeout=30)

    print(f"AUTH HTTP status: {resp.status_code} {resp.reason}")
    print("AUTH raw (first 300 chars):")
    print(resp.text[:300])

    resp.raise_for_status()

    data = resp.json()
    if "error" in data and data["error"]:
        raise RuntimeError(f"JSON-RPC error при аутентификации: {data['error']}")

    enc_b64 = data.get("result")
    if not enc_b64:
        raise RuntimeError(f"СБИС не вернул result при аутентификации: {data}")

    enc_bin = base64.b64decode(enc_b64)
    enc_path = "/tmp/sbis_report_auth.enc"
    dec_path = "/tmp/sbis_report_auth.dec"

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


def test_stub_nds_extra_package(session_id: str, inn: str) -> None:
    """
    Smoke-тест отчетности по доп НДС:
    вызываем СБИС.ЗаписатьКомплект для формы доп. НДС с тестовыми данными.
    Ожидаем осмысленную JSON-RPC-ошибку валидации, а не method not found. [web:1388][web:1379]
    """
    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ЗаписатьКомплект",
        "params": {
            "Документ": [
                {
                    "Название": "ТЕСТОВЫЙ ДОП НДС (НЕ ОТПРАВЛЯТЬ)",
                    # В бою сюда пойдет реальный подтип/КНД формы доп НДС (например 120085). [web:1362]
                    "Подтип": "120085",
                    "НашаОрганизация": {
                        "СвЮЛ": {
                            "ИНН": inn,
                        }
                    },
                    # Фиктивное вложение – просто чтобы структура была валидной для парсера
                    "Вложение": [
                        {
                            "Направление": "Исходящий",
                            "Подтип": "120085",
                            "Идентификатор": "00000000-0000-0000-0000-000000000000",
                            "Название": "test_nds_extra.xml",
                        }
                    ],
                }
            ]
        },
        "id": 2,
    }

    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
        "X-SBISSessionID": session_id,
    }

    print("")
    print("Тестовый вызов СБИС.ЗаписатьКомплект для доп НДС (черновик)...")
    resp = requests.post(
        REPORTING_URL,
        data=json.dumps(body),
        headers=headers,
        timeout=30,
    )

    print(f"REC_COMP HTTP status: {resp.status_code} {resp.reason}")
    print("REC_COMP raw (first 500 chars):")
    print(resp.text[:500])

    if resp.status_code != 200:
        return

    try:
        data = resp.json()
    except Exception as e:
        print(f"Ошибка парсинга JSON от СБИС.ЗаписатьКомплект: {e}")
        return

    if "error" in data and data["error"]:
        print("JSON-RPC error от СБИС.ЗаписатьКомплект:")
        print(json.dumps(data["error"], ensure_ascii=False, indent=2))
    else:
        print("JSON-RPC result от СБИС.ЗаписатьКомплект:")
        print(json.dumps(data.get("result"), ensure_ascii=False, indent=2))


class Command(BaseCommand):
    help = (
        "Тест API отчетности: аутентификация по сертификату по ИНН и вызов "
        "СБИС.СписокИзменений + пробный СБИС.ЗаписатьКомплект (доп НДС)"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "inn",
            type=str,
            help="ИНН ЮЛ, для которого тестируем отчетность (например 9722082369)",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Глубина по датам для СБИС.СписокИзменений (по умолчанию 7 дней)",
        )

    def handle(self, *args, **options):
        inn = options["inn"].strip()
        days = options["days"]

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

        cert_path = f"/tmp/sbis_report_{inn}.cer"
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

        # Сначала дергаем СБИС.СписокИзменений как reporting API [web:1379][web:1295]
        from_date = datetime.today() - timedelta(days=days)
        to_date = datetime.today()

        df = from_date.strftime("%d.%m.%Y %H:%M:%S")
        dt = to_date.strftime("%d.%m.%Y %H:%M:%S")

        self.stdout.write("")
        self.stdout.write(
            f"Вызов СБИС.СписокИзменений (отчетность) за период {df} - {dt}..."
        )

        body = {
            "jsonrpc": "2.0",
            "method": "СБИС.СписокИзменений",
            "params": {
                "Фильтр": {
                    "ДатаВремяС": df,
                    "ДатаВремяПо": dt,
                    # При необходимости можно явно фиксировать НашаОрганизация [web:1295]
                    # "НашаОрганизация": {
                    #     "СвЮЛ": {
                    #         "ИНН": inn,
                    #         "КПП": "XXXXXXYYY",
                    #     }
                    # }
                }
            },
            "id": 1,
        }

        headers = {
            "Content-Type": "application/json-rpc;charset=utf-8",
            "X-SBISSessionID": session_id,
        }

        resp = requests.post(
            REPORTING_URL, data=json.dumps(body), headers=headers, timeout=30
        )

        self.stdout.write(f"REPORT HTTP status: {resp.status_code} {resp.reason}")
        raw = resp.text
        self.stdout.write("REPORT raw (first 500 chars):")
        self.stdout.write(raw[:500])

        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка парсинга JSON: {e}"))
            return

        if "error" in data and data["error"]:
            self.stdout.write(
                self.style.ERROR(
                    f"JSON-RPC error от reporting-сервиса: "
                    f"{json.dumps(data['error'], ensure_ascii=False)}"
                )
            )
            return

        result = data.get("result") or {}
        docs = result.get("Документ") or []

        self.stdout.write(f"Документов в СписокИзменений: {len(docs)}")

        for i, doc in enumerate(docs[:5], start=1):
            self.stdout.write(f"--- Документ {i} ---")
            self.stdout.write(json.dumps(doc, ensure_ascii=False, indent=2))

        # Smoke-тест доп НДС через СБИС.ЗаписатьКомплект [web:1388]
        self.stdout.write("")
        self.stdout.write("==============================================")
        self.stdout.write("Smoke-тест доп НДС: СБИС.ЗаписатьКомплект")
        self.stdout.write("==============================================")
        test_stub_nds_extra_package(session_id, inn)
