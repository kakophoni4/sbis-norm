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
from .auth import auth_sbis_by_cert
from .client import _sbis_request, _sbis_post
from .crypto import (
    CRYPTCP_BIN,
    CRYPTCP_SIGN_FLAGS,
    export_cert_der,
    get_thumbprint_from_cert,
    run_cmd,
    sign_xml_if_needed,
)

def extract_our_org_from_nds_xml(xml_path: str) -> dict | None:
    """
    Из отчёта НДС (XML) достать нашу организацию: СвНП/НПЮЛ → ИНН, КПП, название.
    Возвращает {"inn": str, "kpp": str, "name": str} или None при ошибке/отсутствии блока.
    """
    if not xml_path or not os.path.isfile(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        doc = root.find("Документ")
        if doc is None:
            return None
        np = doc.find("СвНП/НПЮЛ")
        if np is None:
            return None
        inn = (np.attrib.get("ИННЮЛ") or "").strip()
        kpp = (np.attrib.get("КПП") or "").strip()
        name = (np.attrib.get("НаимОрг") or "").strip()
        if not inn or not kpp or len(kpp) != 9 or not kpp.isdigit():
            return None
        return {"inn": inn, "kpp": kpp, "name": name or f"ИНН {inn}"}
    except Exception:
        return None

def build_svedenia_from_xml(xml_path: str) -> tuple[dict, dict, str, str, str, str]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    doc = root.find("Документ")
    if doc is None:
        raise RuntimeError("В XML не найден тег <Документ>")

    id_file = root.attrib.get("ИдФайл", "")
    format_version = root.attrib.get("ВерсФорм", "")
    guid = ""
    if "_" in id_file:
        parts = id_file.rsplit("_", 1)
        if len(parts) == 2:
            guid = parts[1]

    year = doc.attrib.get("ОтчетГод", "")
    period_code = doc.attrib.get("Период", "")
    nom_korr = doc.attrib.get("НомКорр", "0")
    kod_no = doc.attrib.get("КодНО", "")
    po_mestu = doc.attrib.get("ПоМесту", "")
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
            "ИмяФормы": "Декларация по налогу на добавленную стоимость",
            "КНДФормы": knd,
            "ВидДокумента": "Первичный",
            "НомерКорректировки": nom_korr,
            "НОПоМестуУчета": kod_no,
            "НОПоМестуНахождения": kod_no,
            "Период": [
                {
                    "Год": year,
                    "Код": period_code,
                    "ИдентификаторВложения": "",
                }
            ],
        },
        "Пакет": {
            "ВерсПрог": "1С:БУХГАЛТЕРИЯ 3.0.156.17",
            "СКЗИ": "КриптоПро CSP 5.0",
        },
        "НатуральныйИдентификатор": "",
        "ПрограммаФормированияОтчета": "1С:БУХГАЛТЕРИЯ",
    }

    return sved, our_org, kod_no, po_mestu, guid, format_version

def extract_guid_from_xml_idfile(xml_path: str) -> str:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    id_file = (root.attrib.get("ИдФайл") or "").strip()
    if not id_file:
        raise RuntimeError(f"В XML {xml_path} нет атрибута ИдФайл")

    guid = id_file.rsplit("_", 1)[-1].strip()

    try:
        uuid.UUID(guid)
    except Exception as e:
        raise RuntimeError(f"Некорректный GUID в ИдФайл='{id_file}' ({xml_path}): {e}")

    return guid.upper()

def _build_enclosure(
    file_path: str,
    sign_path: str,
    subtype: str,
    format_version: str,
    title: str,
    category: str = "Основное",
    ident: str | None = None,
) -> dict:
    with open(file_path, "rb") as f:
        content = f.read()
    with open(sign_path, "rb") as f:
        sign = f.read()

    content_b64 = base64.b64encode(content).decode("ascii")
    sign_b64 = base64.b64encode(sign).decode("ascii")
    file_name = os.path.basename(file_path)

    return {
        "Подтип": subtype,
        "Направление": "Исходящий",
        "Идентификатор": ident or "00000000-0000-0000-0000-000000000000",
        "ВерсияФормата": format_version,
        "ПодВерсияФормата": "",
        "Название": title,
        "Категория": category,
        "Файл": {
            "Имя": file_name,
            "ДвоичныеДанные": content_b64,
            "Подпись": [{"ДвоичныеДанные": sign_b64}],
        },
    }

def send_nds_extra(
    inn: str,
    xml_path: str,
    sign_path: str | None = None,
    book_paths: list[str] | None = None,
) -> dict:
    if not os.path.exists(xml_path):
        return {"success": False, "error": {"message": f"Файл сведений не найден: {xml_path}"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        sign_path_final = sign_xml_if_needed(xml_path, sign_path, thumbprint)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подписи: {e}"}}

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    try:
        sved, our_org, kod_no, po_mestu, guid, format_version = build_svedenia_from_xml(xml_path)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка разбора XML: {e}"}}

    subtype_nds = sved["Описание"]["КНДФормы"]

    used_idents: set[str] = set()
    file_id_map: dict[str, str] = {}
    all_files = [xml_path] + (book_paths or [])

    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        ident = extract_guid_from_xml_idfile(file_path)
        if ident in used_idents:
            ident = str(uuid.uuid4()).upper()
        used_idents.add(ident)
        file_id_map[file_path] = ident

    enclosures: list[dict] = []
    main_file_ident = file_id_map.get(xml_path, "")
    if sved.get("Описание", {}).get("Период"):
        sved["Описание"]["Период"][0]["ИдентификаторВложения"] = main_file_ident

    for file_path in all_files:
        ident = file_id_map[file_path]
        if file_path == xml_path:
            sp = sign_path_final
            category = "Основное"
            title = sved.get("Описание", {}).get("ИмяФормы") or "Отчет"
        else:
            sp = sign_xml_if_needed(file_path, None, thumbprint)
            category = "Приложение"
            title = f"Приложение {os.path.basename(file_path)}"

        enclosures.append(
            _build_enclosure(
                file_path=file_path,
                sign_path=sp,
                subtype=subtype_nds,
                format_version=format_version,
                title=title,
                category=category,
                ident=ident,
            )
        )

    file_name = os.path.basename(xml_path)
    doc = {
        "Название": f"Доп.листы книги продаж ({file_name})",
        "Идентификатор": guid.lower() or uuid.uuid4().hex,
        "Тип": "ОтчетФНС",
        "ПодТип": subtype_nds,
        "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Расширение": {"ИдентификаторКомплекта": guid or str(uuid.uuid4())},
        "НашаОрганизация": our_org,
        "Участники": {
            "Отправитель": our_org,
            "Получатель": {"ГосударственнаяИнспекция": kod_no},
            "КонечныйПолучатель": {"ГосударственнаяИнспекция": kod_no},
        },
        "Сведения": sved,
        "Вложение": enclosures,
        "Сертификат": {"Отпечаток": thumbprint, "Ключ": {"Тип": "Клиентский"}},
    }

    body = {"jsonrpc": "2.0", "method": "СБИС.ЗаписатьКомплект", "params": {"Документ": [doc]}, "id": 1}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    body_json = json.dumps(body, ensure_ascii=False)
    resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=body_json, timeout=30)
    log_http_exchange("REC_COMP", REPORTING_URL, headers, body_json, resp)

    if resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {resp.status_code}", "raw": resp.text}}

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": resp.text}}

    if data.get("error"):
        return {"success": False, "error": data["error"]}

    if not isinstance(data, dict) or not data.get("result") or not isinstance(data["result"], list) or not data["result"]:
        return {"success": False, "error": {"message": "Не удалось получить документ из ответа"}}

    today_str = datetime.now().strftime("%d.%m.%Y")
    list_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументов",
        "params": {
            "Фильтр": {"Тип": "ОтчетФНС", "Направление": "Исходящий", "ДатаС": today_str, "ДатаПо": today_str}
        },
        "id": 1,
    }

    list_resp = _sbis_request(
        "POST",
        REPORTING_URL,
        inn=inn,
        headers=headers,
        data=json.dumps(list_body, ensure_ascii=False),
        timeout=30,
    )

    try:
        list_data = list_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": list_resp.text}}

    if not list_data.get("result") or not list_data["result"].get("Документ"):
        return {"success": False, "error": {"message": "Не удалось получить документ из исходящей почты"}}

    logger.info(f"Найденные документы: {list_data['result']['Документ']}")
    for d in list_data["result"]["Документ"]:
        logger.info(f"Документ: {d.get('Идентификатор')}, Статус: {d.get('Статус', 'N/A')}")

    docs = [d for d in list_data["result"]["Документ"] if d.get("Статус") not in ["Отправлен", "Обработан"]]
    if not docs:
        return {"success": False, "error": {"message": "Нет подходящих документов для отправки"}}
    sbis_doc_id = docs[0]["Идентификатор"]

    prep_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": sbis_doc_id,
                "Этап": {"Название": "Отправка", "Действие": {"Название": "Отправить", "Сертификат": {"Отпечаток": thumbprint}}},
            }
        },
        "id": 2,
    }

    prep_json = json.dumps(prep_body, ensure_ascii=False)
    prep_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=prep_json, timeout=30)
    log_http_exchange("PREPARE", REPORTING_URL, headers, prep_json, prep_resp)

    if prep_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {prep_resp.status_code} Prepare", "raw": prep_resp.text}}

    try:
        prep_data = prep_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": prep_resp.text}}

    if prep_data.get("error"):
        return {"success": False, "error": prep_data["error"]}

    attachments = []
    for file_path in all_files:
        if file_path not in file_id_map:
            continue
        file_ident = file_id_map[file_path]
        sig_path = f"{file_path}.sgn"
        try:
            run_cmd([CRYPTCP_BIN, "-sign", "-detached", "-der", *CRYPTCP_SIGN_FLAGS, "-thumbprint", thumbprint, file_path, sig_path])
            with open(sig_path, "rb") as f:
                sig_b64 = base64.b64encode(f.read()).decode("ascii")
            attachments.append({"Идентификатор": file_ident, "Подпись": [{"Файл": {"ДвоичныеДанные": sig_b64}}]})
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка подписи {file_path}: {e}"}}

    exec_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ВыполнитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": sbis_doc_id,
                "Этап": {
                    "Название": "Отправка",
                    "Действие": {"Название": "Отправить", "Сертификат": {"Отпечаток": thumbprint}},
                    "Вложение": attachments,
                },
            }
        },
        "id": 3,
    }

    exec_json = json.dumps(exec_body, ensure_ascii=False)
    exec_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=exec_json, timeout=30)
    log_http_exchange("EXEC", REPORTING_URL, headers, exec_json, exec_resp)

    if exec_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {exec_resp.status_code} Execute", "raw": exec_resp.text}}

    try:
        exec_data = exec_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": exec_resp.text}}

    if exec_data.get("error"):
        return {"success": False, "error": exec_data["error"]}

    return {"success": True, "result": exec_data}

def _b64_to_bytes(data_b64: str) -> bytes:
    if not data_b64:
        return b""

    s = str(data_b64).strip()

    if "," in s and "base64" in s[:100].lower():
        s = s.split(",", 1)[1].strip()

    s = s.replace("\ufeff", "")
    s = re.sub(r"\s+", "", s)

    s = s.replace("-", "+").replace("_", "/")

    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad

    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"Некорректный base64: {e}")

def _extract_idfile_from_xml_bytes(xml_bytes: bytes) -> str:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"Не удалось распарсить XML: {e}")

    id_file = (root.attrib.get("ИдФайл") or "").strip()
    if not id_file:
        raise RuntimeError("В XML нет атрибута ИдФайл")
    return id_file

def _log_decoded_xml(inn: str, kind: str, xml_bytes: bytes) -> dict:
    meta: dict = {"kind": kind, "size": len(xml_bytes)}
    sha = hashlib.sha256(xml_bytes).hexdigest()
    meta["sha256_bytes"] = sha

    try:
        root = ET.fromstring(xml_bytes)
        meta["root_tag"] = root.tag
        meta["idfile"] = ((root.attrib.get("ИдФайл") or "").strip() or None)

        def _get_attr(path, attr):
            el = root.find(path)
            return None if el is None else el.attrib.get(attr)

        meta["nds_values"] = {
            "СумПУ_173.1": _get_attr("Документ/НДС/СумУплНП", "СумПУ_173.1"),
            "НалПУ164": _get_attr("Документ/НДС/СумУпл164", "НалПУ164"),
            "НалВосстОбщ": _get_attr("Документ/НДС/СумУпл164/СумНалОб", "НалВосстОбщ"),
            "НалБаза": _get_attr("Документ/НДС/СумУпл164/СумНалОб/РеалТов20", "НалБаза"),
            "СумНал": _get_attr("Документ/НДС/СумУпл164/СумНалОб/РеалТов20", "СумНал"),
            "НалПредНППриоб": _get_attr("Документ/НДС/СумУпл164/СумНалВыч", "НалПредНППриоб"),
            "НалВычОбщ": _get_attr("Документ/НДС/СумУпл164/СумНалВыч", "НалВычОбщ"),
        }
    except Exception as e:
        meta["xml_parse_error"] = str(e)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rid = uuid.uuid4().hex[:8]
    safe_inn = inn or "no_inn"
    stem = f"{ts}_{safe_inn}_{kind}_{rid}_{sha[:12]}"

    xml_path = ONEC_DECODE_DIR / f"{stem}.xml"
    meta_path = ONEC_DECODE_DIR / f"{stem}.meta.json"

    xml_path.write_bytes(xml_bytes)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    logger.info(f"[1C_DECODE] saved {kind}: {xml_path}")
    return meta

def _normalize_xml_filename_from_idfile(id_file: str) -> str:
    name = (id_file or "").strip()
    if not name:
        raise RuntimeError("Пустой ИдФайл (нельзя построить имя файла)")
    if not name.lower().endswith(".xml"):
        name += ".xml"
    return name

def _extract_book_names_from_main_xml(xml_bytes: bytes) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"Не удалось распарсить основной XML: {e}")

    doc = root.find("Документ")
    if doc is None:
        return None, None

    nds = doc.find("НДС")
    if nds is None:
        return None, None

    buy = nds.find("КнигаПокуп")
    sell = nds.find("КнигаПрод")

    buy_name = buy.attrib.get("НаимКнПок") if buy is not None else None
    sell_name = sell.attrib.get("НаимКнПрод") if sell is not None else None

    buy_name = (buy_name or "").strip() or None
    sell_name = (sell_name or "").strip() or None
    return buy_name, sell_name

def _extract_send_meta_from_exec(exec_data: dict) -> dict:
    """
    exec_data — это полный ответ JSON-RPC из СБИС.ВыполнитьДействие (то, что у тебя в exec_data).
    Возвращает sbis_doc_id, sent_at, sent_date.
    """
    meta = {"sbis_doc_id": None, "sent_at": None, "sent_date": None}

    try:
        r = (exec_data or {}).get("result") or {}
        meta["sbis_doc_id"] = (r.get("Идентификатор") or "").strip() or None

        events = r.get("Событие") or []
        for ev in events:
            grp = ev.get("Группа") or {}
            if grp.get("Название") == "Отправка" or grp.get("Описание") == "Отправлено":
                sent_at = (ev.get("ДатаВремя") or "").strip() or None
                meta["sent_at"] = sent_at
                if sent_at and len(sent_at) >= 10:
                    meta["sent_date"] = sent_at[:10]
                break

        if not meta["sent_date"]:
            ext = r.get("Расширение") or {}
            d = (ext.get("ДатаСоздания") or "").strip() or None
            meta["sent_date"] = d

    except Exception:
        pass

    return meta

def send_nds_extra_1c(
    inn: str,
    main_xml_b64: str,
    book_xml_b64_list: list[str] | None = None,
    validate_book_names: bool = True,
    dry_run: bool = False,
) -> tuple[int, dict]:
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return 403, {"success": False, "comment": "Ошибка доступа: нет подписи по указанному ИНН"}
    if not getattr(cert, "csptest_name", None):
        return 401, {"success": False, "comment": "Указанный ИНН не имеет валидной подписи"}

    if not inn or not main_xml_b64:
        return 400, {
            "success": False,
            "comment": "Ошибка входных данных",
            "error": {"message": "Поля inn и main_xml_b64 обязательны"},
        }

    book_xml_b64_list = book_xml_b64_list or []

    if dry_run:
        try:
            main_bytes = _b64_to_bytes(main_xml_b64)
            try:
                _log_decoded_xml(inn=inn, kind="main_dry", xml_bytes=main_bytes)
            except Exception:
                logger.exception("[1C_DECODE] failed to log main_dry xml")

            main_idfile = _extract_idfile_from_xml_bytes(main_bytes)
            main_filename = _normalize_xml_filename_from_idfile(main_idfile)

            book_filenames: list[str] = []
            for idx, b64 in enumerate(book_xml_b64_list, start=1):
                if not b64:
                    continue
                b = _b64_to_bytes(b64)
                try:
                    _log_decoded_xml(inn=inn, kind=f"book#{idx}_dry", xml_bytes=b)
                except Exception:
                    logger.exception(f"[1C_DECODE] failed to log book#{idx}_dry xml")

                bid = _extract_idfile_from_xml_bytes(b)
                fname = _normalize_xml_filename_from_idfile(bid)
                book_filenames.append(fname)

            expected_buy, expected_sell = (None, None)
            if validate_book_names:
                expected_buy, expected_sell = _extract_book_names_from_main_xml(main_bytes)
                present = set(book_filenames)
                missing: list[str] = []
                if expected_buy and expected_buy not in present:
                    missing.append(expected_buy)
                if expected_sell and expected_sell not in present:
                    missing.append(expected_sell)
                if missing:
                    return 400, {
                        "success": False,
                        "comment": "Ошибка входных данных",
                        "error": {
                            "message": "Имена книг из основного XML не найдены среди переданных book-файлов",
                            "expected_missing": missing,
                            "expected_in_main": {"buy": expected_buy, "sell": expected_sell},
                            "received": sorted(present),
                        },
                    }

            return 200, {
                "success": True,
                "comment": "DRY_RUN: данные приняты и распарсены, отправка в СБИС пропущена",
                "parsed": {
                    "inn": inn,
                    "main": {"idfile": main_idfile, "filename": main_filename},
                    "books": book_filenames,
                    "expected_in_main": {"buy": expected_buy, "sell": expected_sell},
                },
            }

        except Exception as e:
            return 400, {"success": False, "comment": "Ошибка входных данных", "error": {"message": str(e)}}

    result = send_nds_extra_b64_autoname(
        inn=inn,
        main_xml_b64=main_xml_b64,
        book_xml_b64_list=book_xml_b64_list,
        validate_book_names=validate_book_names,
    )

    if isinstance(result, dict) and result.get("success") is True:
        try:
            exec_data = result.get("result") or {}
            meta = _extract_send_meta_from_exec(exec_data)
            result["send_meta"] = meta
        except Exception:
            logger.exception("Failed to extract send_meta from exec result")
        return 200, result

    if isinstance(result, dict) and _looks_like_sbis_error(result):
        return 404, {"success": False, "comment": "Ошибка при отправке в СБИС", "error": result.get("error")}

    return 400, {
        "success": False,
        "comment": "Ошибка входных данных",
        "error": (result.get("error") if isinstance(result, dict) else {"message": "Неизвестная ошибка"}),
    }

def _looks_like_sbis_error(result: dict) -> bool:
    err = result.get("error") if isinstance(result, dict) else None
    if not isinstance(err, dict):
        return False

    msg = str(err.get("message") or "")
    if any(k in err for k in ("raw", "code")):
        return True

    needles = (
        "СБИС",
        "JSON-RPC",
        "HTTP",
        "аутентификац",
        "ЗаписатьКомплект",
        "ПодготовитьДействие",
        "ВыполнитьДействие",
    )
    m_low = msg.lower()
    return any(n.lower() in m_low for n in needles)

def send_nds_extra_b64_autoname(
    inn: str,
    main_xml_b64: str,
    book_xml_b64_list: list[str] | None = None,
    validate_book_names: bool = True,
) -> dict:
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not main_xml_b64:
        return {"success": False, "error": {"message": "main_xml_b64 обязателен"}}

    book_xml_b64_list = book_xml_b64_list or []

    try:
        main_bytes = _b64_to_bytes(main_xml_b64)
        try:
            _log_decoded_xml(inn=inn, kind="main", xml_bytes=main_bytes)
        except Exception:
            logger.exception("[1C_DECODE] failed to log main xml")
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка декодирования main_xml_b64: {e}"}}

    try:
        main_idfile = _extract_idfile_from_xml_bytes(main_bytes)
        main_filename = _normalize_xml_filename_from_idfile(main_idfile)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка чтения ИдФайл основного XML: {e}"}}

    books: list[tuple[str, bytes]] = []
    for idx, b64 in enumerate(book_xml_b64_list, start=1):
        if not b64:
            continue
        try:
            b = _b64_to_bytes(b64)
            try:
                _log_decoded_xml(inn=inn, kind=f"book#{idx}", xml_bytes=b)
            except Exception:
                logger.exception(f"[1C_DECODE] failed to log book#{idx}")

            bid = _extract_idfile_from_xml_bytes(b)
            fname = _normalize_xml_filename_from_idfile(bid)
            books.append((fname, b))
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка книги #{idx}: {e}"}}

    if validate_book_names:
        try:
            expected_buy, expected_sell = _extract_book_names_from_main_xml(main_bytes)
        except Exception as e:
            return {"success": False, "error": {"message": str(e)}}

        actual_names = {name for name, _ in books}
        missing: list[str] = []
        if expected_buy and expected_buy not in actual_names:
            missing.append(expected_buy)
        if expected_sell and expected_sell not in actual_names:
            missing.append(expected_sell)

        if missing:
            return {
                "success": False,
                "error": {
                    "message": "Имена книг из основного XML не найдены среди переданных book-файлов",
                    "expected_missing": missing,
                    "received": sorted(actual_names),
                },
            }

    with tempfile.TemporaryDirectory(prefix=f"sbis_nds_extra_{inn}_") as tmpdir:
        xml_path = os.path.join(tmpdir, main_filename)
        with open(xml_path, "wb") as f:
            f.write(main_bytes)

        book_paths: list[str] = []
        used_names: set[str] = {main_filename.lower()}

        for name, content in books:
            name_l = name.lower()
            if name_l in used_names:
                return {"success": False, "error": {"message": f"Дублирующееся имя файла по ИдФайл: {name}"}}
            used_names.add(name_l)

            p = os.path.join(tmpdir, name)
            with open(p, "wb") as f:
                f.write(content)
            book_paths.append(p)

        return send_nds_extra(inn=inn, xml_path=xml_path, sign_path=None, book_paths=book_paths)
