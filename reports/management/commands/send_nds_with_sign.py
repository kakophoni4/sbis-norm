#!/usr/bin/env python
import base64
import json
import os
import subprocess
from datetime import datetime

import requests
import xml.etree.ElementTree as ET
from django.core.management.base import BaseCommand

from reports.models import Certificate


CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"

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


def sign_xml_detached(xml_path: str, thumbprint: str) -> str:
    """
    Подписывает xml_path отсоединённой подписью .sgn через cryptcp.
    """
    sgn_path = xml_path + ".sgn"

    # cryptcp -sign -detached -thumbprint <sha1> file.xml
    # Подпись создастся рядом, обычно file.sig или file.xml.sig — переименуем в .sgn.
    run_cmd(
        [
            CRYPTCP_BIN,
            "-sign",
            "-detached",
            "-thumbprint",
            thumbprint,
            xml_path,
        ]
    )

    # ищем созданный файл подписи рядом с исходником
    base = os.path.basename(xml_path)
    dir_ = os.path.dirname(xml_path) or "."
    candidates = [
        os.path.join(dir_, base + ".sig"),
        os.path.join(dir_, base + ".sgn"),
        os.path.join(dir_, base + ".p7s"),
    ]
    real_sgn = None
    for c in candidates:
        if os.path.exists(c):
            real_sgn = c
            break

    if not real_sgn:
        raise RuntimeError("cryptcp не создал файл подписи рядом с XML")

    # переименуем в *.sgn, как тебе удобнее
    os.rename(real_sgn, sgn_path)
    return sgn_path



def build_svedenia_and_org_from_info(xml_path: str) -> tuple[dict, dict]:
    """
    Парсер файла сведений декларации НДС -> Сведения + НашаОрганизация. [file:1442][web:1456]
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    doc = root.find("Документ")
    if doc is None:
        raise RuntimeError("В файле сведений не найден тег <Документ>")

    year = doc.attrib.get("ОтчетГод", "")
    period_code = doc.attrib.get("Период", "")
    nom_korr = doc.attrib.get("НомКорр", "0")
    kod_no = doc.attrib.get("КодНО", "")
    knd = doc.attrib.get("КНД", "1151001")

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
            "ИмяФормы": "Декларация по НДС",
            "КНДФормы": knd,
            "ВидДокумента": "Отчет",
            "НомерКорректировки": nom_korr,
            "НоПоМестуУчета": kod_no,
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

    return sved, our_org


class Command(BaseCommand):
    help = (
        "Тест: подписать XML отчета, собрать комплект с подписью и вызвать "
        "СБИС.ЗаписатьКомплект (без отправки)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "inn",
            type=str,
            help="ИНН ЮЛ (для выбора сертификата из БД)",
        )
        parser.add_argument(
            "--report-xml",
            type=str,
            required=True,
            help="Путь к XML отчету (книга продаж/декларация)",
        )
        parser.add_argument(
            "--info-xml",
            type=str,
            required=True,
            help="Путь к XML сведений (как nds_info.xml)",
        )

    def handle(self, *args, **options):
        inn = options["inn"].strip()
        report_xml = options["report_xml"]
        info_xml = options["info_xml"]

        self.stdout.write(f"ИНН: {inn}")
        self.stdout.write(f"XML отчета: {report_xml}")
        self.stdout.write(f"XML сведений: {info_xml}")

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

        self.stdout.write("Запрос SESSION_ID через СБИС.АутентифицироватьПоСертификату...")
        session_id = auth_sbis_by_cert(cert_path, thumbprint)
        self.stdout.write(f"SESSION_ID: {session_id}")

        self.stdout.write("Подписываем XML отчета (отсоединенная подпись)...")
        sgn_path = sign_xml_detached(report_xml, thumbprint)
        self.stdout.write(f"SGN файл: {sgn_path}")

        self.stdout.write("Парсим XML сведений и строим Сведения + НашаОрганизация...")
        sved, our_org = build_svedenia_and_org_from_info(info_xml)
        self.stdout.write("Сведения:")
        self.stdout.write(json.dumps(sved, ensure_ascii=False, indent=2))
        self.stdout.write("НашаОрганизация:")
        self.stdout.write(json.dumps(our_org, ensure_ascii=False, indent=2))

        # Пока без файлового хранилища: передаем только имена файлов и подпись как факт.
        doc = {
            "Название": "ТЕСТ НДС С ПОДПИСЬЮ (НЕ ОТПРАВЛЯТЬ)",
            "Тип": "ОТЧЕТ_НДС",
            "Подтип": sved["Описание"]["КНДФормы"],
            "ДатаВремяСоздания": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            "НашаОрганизация": our_org,
            "Вложение": [
                {
                    "Направление": "Исходящий",
                    "Подтип": sved["Описание"]["КНДФормы"],
                    "Идентификатор": "00000000-0000-0000-0000-000000000001",
                    "Название": os.path.basename(report_xml),
                    "Файл": {
                        "Имя": os.path.basename(report_xml),
                        "Ссылка": "",  # позже заменим на ссылку из файлового хранилища [web:1503]
                    },
                    "Подпись": [
                        {
                            "Файл": {
                                "Имя": os.path.basename(sgn_path),
                                "Ссылка": "",
                            },
                            "Сертификат": {
                                "Отпечаток": thumbprint,
                            },
                        }
                    ],
                }
            ],
            "Сведения": sved,
        }

        body = {
            "jsonrpc": "2.0",
            "method": "СБИС.ЗаписатьКомплект",
            "params": {
                "Документ": [doc]
            },
            "id": 1,
        }

        headers = {
            "Content-Type": "application/json-rpc;charset=utf-8",
            "X-SBISSessionID": session_id,
        }

        self.stdout.write("")
        self.stdout.write("Вызов СБИС.ЗаписатьКомплект (с реальным XML и подписью, без отправки)...")
        resp = requests.post(
            REPORTING_URL, data=json.dumps(body), headers=headers, timeout=30
        )

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
            self.stdout.write(json.dumps(data.get("result"), ensure_ascii=False, indent=2))
