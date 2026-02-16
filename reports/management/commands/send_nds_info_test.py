#!/usr/bin/env python
import base64
import json
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

import requests
import xml.etree.ElementTree as ET
from django.core.management.base import BaseCommand

from reports.models import Certificate


CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"

AUTH_URL = "https://online.sbis.ru/auth/service/"
REPORTING_URL = "https://online.sbis.ru/service/?srv=1"

LOG_DIR = Path("/home/devuser/sbis_api_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


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


def log_http_exchange(prefix: str, url: str, req_headers: dict, req_body: str, resp: requests.Response) -> None:
    log_id = uuid.uuid4().hex[:8]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"{ts}_{prefix}_{log_id}.log"

    lines: list[str] = []
    lines.append(f"=== REQUEST {prefix} ===")
    lines.append(f"URL: {url}")
    lines.append("Headers:")
    for k, v in req_headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("Body:")
    lines.append(req_body)
    lines.append("")
    lines.append(f"=== RESPONSE {prefix} ===")
    lines.append(f"Status: {resp.status_code} {resp.reason}")
    lines.append("Headers:")
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("Body (first 2000 chars):")
    lines.append(resp.text[:2000])

    path.write_text("\n".join(lines), encoding="utf-8")


def auth_sbis_by_cert(cert_path: str, thumbprint: str) -> str:
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

    req_json = json.dumps(req, ensure_ascii=False)
    resp = requests.post(AUTH_URL, data=req_json, headers=headers, timeout=30)

    log_http_exchange("AUTH", AUTH_URL, headers, req_json, resp)

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


def build_svedenia_from_xml(xml_path: str) -> tuple[dict, dict, str, str, str]:
    """
    Парсер nds_info.xml -> блок Сведения + данные по нашей организации + (kod_no, po_mestu, guid).
    guid берем из хвоста атрибута ИдФайл.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    doc = root.find("Документ")
    if doc is None:
        raise RuntimeError("В nds_info.xml не найден тег <Документ>")

    id_file = root.attrib.get("ИдФайл", "")
    guid = ""
    if "_" in id_file:
        parts = id_file.rsplit("_", 1)
        if len(parts) == 2:
            guid = parts[1]

    year = doc.attrib.get("ОтчетГод", "")
    period_code = doc.attrib.get("Период", "")
    nom_korr = doc.attrib.get("НомКорр", "0")
    kod_no = doc.attrib.get("КодНО", "")         # код ИФНС (7722)
    po_mestu = doc.attrib.get("ПоМесту", "")     # код по месту учета (214)
    knd = doc.attrib.get("КНД", "120085")

    np = doc.find("СвНП/НПЮЛ")
    inn = ""
    kpp = ""
    name_full = ""
    if np is not None:
        inn = np.attrib.get("ИННЮЛ", "")
        kpp = np.attrib.get("КПП", "")
        name_full = np.attrib.get("НаимОрг", "")

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": name_full,
            "НазваниеПолное": name_full,
        }
    }

    sved = {
        "Ссылка": "",
        "Номер": "1",
        "Описание": {
            "ИмяФормы": "Доп.листы книги продаж",
            "КНДФормы": knd,
            "ВидДокумента": "Приложение",
            "НомерКорректировки": nom_korr,
            # код по месту учета из XML (214)
            "НОПоМестуУчета": po_mestu,
            # по месту нахождения не заполняем
            "НОПоМестуНахождения": "",
        },
        "Отчетный период": {
            "Год": year,
            "Код": period_code,
            "ИдентификаторВложения": "",
        },
        "Пакет": {
            "ВерсПрог": "tax_service/1.0",
            "СКЗИ": "КриптоПро CSP 5.0",
        },
        "НатуральныйИдентификатор": "",
        "ПрограммаФормированияОтчета": "1C / robotsbis",
    }

    return sved, our_org, kod_no, po_mestu, guid


class Command(BaseCommand):
    help = (
        "Тест API отчетности: собрать комплект доп НДС по nds_info.xml "
        "и вызвать СБИС.ЗаписатьКомплект без отправки (с реальным вложением и подписью), "
        "пишет запросы/ответы в /home/devuser/sbis_api_logs"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "inn",
            type=str,
            help="ИНН ЮЛ, для которого тестируем (например 9722082369)",
        )
        parser.add_argument(
            "--info-path",
            type=str,
            default="/home/devuser/nds_info.xml",
            help="Путь к файлу nds_info.xml",
        )
        parser.add_argument(
            "--info-sign-path",
            type=str,
            default="/home/devuser/nds_info.xml.sgn",
            help="Путь к файлу подписи nds_info.xml (.sgn)",
        )

    def handle(self, *args, **options):
        inn = options["inn"].strip()
        info_path = options["info_path"]
        info_sign_path = options["info_sign_path"]

        self.stdout.write(f"ИНН (для поиска сертификата в БД): {inn}")
        self.stdout.write(f"Файл сведений: {info_path}")
        self.stdout.write(f"Файл подписи сведений: {info_sign_path}")

        if not os.path.exists(info_path):
            self.stdout.write(self.style.ERROR(f"Файл сведений не найден: {info_path}"))
            return

        if not os.path.exists(info_sign_path):
            self.stdout.write(
                self.style.ERROR(f"Файл подписи не найден: {info_sign_path}")
            )
            return

        cert = Certificate.objects.filter(inn=inn).first()
        if not cert:
            self.stdout.write(
                self.style.ERROR("В таблице Certificate нет записи для этого ИНН")
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

        self.stdout.write(
            "Парсим nds_info.xml и строим блок 'Сведения' и 'НашаОрганизация'..."
        )
        sved, our_org, kod_no, po_mestu, guid = build_svedenia_from_xml(info_path)
        self.stdout.write("Сведения:")
        self.stdout.write(json.dumps(sved, ensure_ascii=False, indent=2))
        self.stdout.write("НашаОрганизация из XML:")
        self.stdout.write(json.dumps(our_org, ensure_ascii=False, indent=2))
        self.stdout.write(f"GUID из ИдФайл: {guid}")

        with open(info_path, "rb") as f:
            info_content = f.read()
        with open(info_sign_path, "rb") as f:
            info_sign = f.read()

        info_content_b64 = base64.b64encode(info_content).decode("ascii")
        info_sign_b64 = base64.b64encode(info_sign).decode("ascii")

        file_name = os.path.basename(info_path)

        attachment_id = guid or "00000000-0000-0000-0000-000000000000"

        doc = {
            "Название": "Доп.листы книги продаж (nds_info.xml)",
            "Тип": "ОтчетФНС",
            "ПодТип": sved["Описание"]["КНДФормы"],
            "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "НашаОрганизация": our_org,
            "Участники": {
                "Отправитель": our_org,
                "Получатель": {
                    "ГосударственнаяИнспекция": kod_no,
                },
                "КонечныйПолучатель": {
                    "ГосударственнаяИнспекция": kod_no,
                },
            },
            "Сведения": sved,
            "Вложение": [
                {
                    "Подтип": sved["Описание"]["КНДФормы"],
                    "Направление": "Исходящий",
                    "Идентификатор": attachment_id,
                    "ВерсияФормата": "",
                    "ПодВерсияФормата": "",
                    "Название": file_name,
                    "Категория": "Основное",
                    "Файл": {
                        "Имя": file_name,
                        "ДвоичныеДанные": info_content_b64,
                        "Подпись": [
                            {
                                "ДвоичныеДанные": info_sign_b64
                            }
                        ],
                    },
                }
            ],
        }

        body = {
            "jsonrpc": "2.0",
            "method": "СБИС.ЗаписатьКомплект",
            "params": {
                "Документ": [doc],
            },
            "id": 1,
        }

        headers = {
            "Content-Type": "application/json-rpc;charset=utf-8",
            "X-SBISSessionID": session_id,
        }

        self.stdout.write("")
        self.stdout.write(
            "Вызов СБИС.ЗаписатьКомплект (nds_info + подпись, без отправки)..."
        )

        body_json = json.dumps(body, ensure_ascii=False)
        resp = requests.post(
            REPORTING_URL, data=body_json, headers=headers, timeout=30
        )

        log_http_exchange("REC_COMP", REPORTING_URL, headers, body_json, resp)

        self.stdout.write(f"REC_COMP HTTP status: {resp.status_code} {resp.reason}")
        self.stdout.write("REC_COMP raw (first 500 chars):")
        self.stdout.write(resp.text[:500])

        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка парсинга JSON: {e}"))
            return

        if "error" in data and data["error"]:
            self.stdout.write("JSON-RPC error от СБИС.ЗаписатьКомплект:")
            self.stdout.write(json.dumps(data["error"], ensure_ascii=False, indent=2))
        else:
            self.stdout.write("JSON-RPC result от СБИС.ЗаписатьКомплект:")
            self.stdout.write(
                json.dumps(data.get("result"), ensure_ascii=False, indent=2)
            )
