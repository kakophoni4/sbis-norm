"""
Отправка отчётов ФНС через API СБИС (ОтчетФНС).

Сценарий по документации Saby «API сервиса Отчетность»:
  auth → СБИС.ЗаписатьКомплект → СБИС.ПодготовитьДействие → СБИС.ВыполнитьДействие
(см. https://saby.ru/help/integration/api/reporting ,
     https://saby.ru/help/integration/api/reporting/commands/rec_comp)

Одно основное XML-вложение (без книг). Существующий send-nds-extra-1c не трогаем.
Прокси — через _sbis_request / auth_sbis_by_cert (NodeMaven).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

from reports.models import Certificate

from .auth import auth_sbis_by_cert
from .client import _sbis_request, log_http_exchange
from .constants import REPORTING_URL
from .crypto import export_cert_der, get_thumbprint_from_cert, sign_xml_if_needed
from .nds import (
    _b64_to_bytes,
    _build_enclosure,
    _extract_idfile_from_xml_bytes,
    _extract_send_meta_from_exec,
    _log_decoded_xml,
    _looks_like_sbis_error,
    _normalize_xml_filename_from_idfile,
    extract_guid_from_xml_idfile,
)

logger = logging.getLogger(__name__)

# КНД → (report_type, ИмяФормы) — ИмяФормы обязательно для ФНС (docs ЗаписатьКомплект)
REPORT_BY_KND: dict[str, tuple[str, str]] = {
    "1151001": ("nds", "Декларация по налогу на добавленную стоимость"),
    "1151006": ("profit", "Налоговая декларация по налогу на прибыль организаций"),
    "1151100": (
        "ndfl6",
        "Расчет сумм налога на доходы физических лиц, исчисленных и удержанных налоговым агентом",
    ),
    "1151111": ("rsv", "Расчет по страховым взносам"),
}

REPORT_TYPE_TO_KND: dict[str, str] = {code: knd for knd, (code, _) in REPORT_BY_KND.items()}

# Префикс ИдФайл → report_type
IDFILE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("NO_NDS_", "nds"),
    ("NO_PRIB_", "profit"),
    ("NO_NDFL6", "ndfl6"),
    ("NO_RASCHSV_", "rsv"),
)

VALID_REPORT_TYPES = frozenset(REPORT_TYPE_TO_KND.keys()) | {"auto"}


def detect_report_type_from_idfile(id_file: str) -> str | None:
    name = (id_file or "").strip().upper()
    for prefix, rtype in IDFILE_PREFIXES:
        if name.startswith(prefix.upper()):
            return rtype
    return None


def resolve_report_meta(
    *,
    knd: str,
    id_file: str,
    report_type: str = "auto",
) -> dict[str, str]:
    """
    Возвращает {report_type, knd, form_name}.
    Сверяет явный report_type с КНД / префиксом ИдФайл.
    """
    knd = (knd or "").strip()
    requested = (report_type or "auto").strip().lower()
    if requested not in VALID_REPORT_TYPES:
        raise ValueError(
            f"Неизвестный report_type={report_type!r}. "
            f"Допустимо: auto, {', '.join(sorted(REPORT_TYPE_TO_KND))}"
        )

    by_knd = REPORT_BY_KND.get(knd)
    by_prefix = detect_report_type_from_idfile(id_file)

    if requested == "auto":
        if by_knd:
            rtype, form_name = by_knd
        elif by_prefix and by_prefix in REPORT_TYPE_TO_KND:
            rtype = by_prefix
            expected_knd = REPORT_TYPE_TO_KND[rtype]
            form_name = REPORT_BY_KND[expected_knd][1]
            if knd and knd != expected_knd:
                raise ValueError(
                    f"КНД={knd} не совпадает с типом по ИдФайл ({rtype} → {expected_knd})"
                )
            knd = expected_knd or knd
        else:
            raise ValueError(
                f"Не удалось определить тип отчёта: КНД={knd!r}, ИдФайл={id_file!r}"
            )
    else:
        expected_knd = REPORT_TYPE_TO_KND[requested]
        if knd and knd != expected_knd:
            raise ValueError(
                f"report_type={requested} ожидает КНД={expected_knd}, в XML КНД={knd}"
            )
        if by_prefix and by_prefix != requested:
            raise ValueError(
                f"report_type={requested}, но ИдФайл указывает на {by_prefix}"
            )
        rtype = requested
        form_name = REPORT_BY_KND[expected_knd][1]
        knd = expected_knd

    if not knd:
        raise ValueError("В XML нет КНД и не удалось вывести его из типа отчёта")

    return {"report_type": rtype, "knd": knd, "form_name": form_name}


def build_svedenia_from_report_xml(
    xml_path: str,
    *,
    report_type: str = "auto",
) -> tuple[dict, dict, str, str, str, str, dict[str, str]]:
    """
    Парсит XML отчёта ФНС → (sved, our_org, kod_no, po_mestu, guid, format_version, meta).
    meta: report_type, knd, form_name.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    doc = root.find("Документ")
    if doc is None:
        raise RuntimeError("В XML не найден тег <Документ>")

    id_file = (root.attrib.get("ИдФайл") or "").strip()
    format_version = (root.attrib.get("ВерсФорм") or "").strip()
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
    knd = (doc.attrib.get("КНД") or "").strip()

    meta = resolve_report_meta(knd=knd, id_file=id_file, report_type=report_type)
    knd = meta["knd"]
    form_name = meta["form_name"]

    np = doc.find("СвНП/НПЮЛ")
    if np is None:
        np = doc.find(".//НПЮЛ")
    inn = ""
    kpp = ""
    name_full = ""
    if np is not None:
        inn = (np.attrib.get("ИННЮЛ") or "").strip()
        kpp = (np.attrib.get("КПП") or "").strip()
        name_full = (np.attrib.get("НаимОрг") or "").strip()

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": name_full,
            "НазваниеПолное": name_full,
        }
    }

    # Структура Сведения — как в боевом send_nds_extra + поля из docs ЗаписатьКомплект
    # (ИмяФормы, КНДФормы; период в Описание.Период[] с ИдентификаторВложения)
    sved = {
        "Ссылка": "",
        "Номер": "1",
        "Описание": {
            "ИмяФормы": form_name,
            "КНДФормы": knd,
            "ВидДокумента": "Первичный" if str(nom_korr) in ("0", "00", "") else "Корректирующий",
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
            "ВерсПрог": "tax_service/1.0",
            "СКЗИ": "КриптоПро CSP 5.0",
        },
        "НатуральныйИдентификатор": "",
        "ПрограммаФормированияОтчета": "tax_service",
    }

    return sved, our_org, kod_no, po_mestu, guid, format_version, meta


def _resolve_cert(inn: str) -> Certificate | None:
    cert = (
        Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
        .exclude(csptest_name__isnull=True)
        .exclude(csptest_name="")
        .order_by("-id")
        .first()
    )
    if not cert:
        cert = Certificate.objects.filter(inn=inn).exclude(csptest_name="").order_by("-id").first()
    return cert


def send_report(
    inn: str,
    xml_path: str,
    *,
    report_type: str = "auto",
    sign_path: str | None = None,
) -> dict:
    """
    Боевая отправка одного XML-отчёта ФНС в СБИС (с прокси).
    """
    if not os.path.exists(xml_path):
        return {"success": False, "error": {"message": f"Файл отчёта не найден: {xml_path}"}}

    cert = _resolve_cert(inn)
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        sved, our_org, kod_no, _po_mestu, guid, format_version, meta = build_svedenia_from_report_xml(
            xml_path, report_type=report_type
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка разбора XML: {e}"}}

    xml_inn = ((our_org.get("СвЮЛ") or {}).get("ИНН") or "").strip()
    if xml_inn and xml_inn != inn:
        return {
            "success": False,
            "error": {
                "message": f"ИНН в запросе ({inn}) не совпадает с ИННЮЛ в XML ({xml_inn})",
            },
        }

    try:
        sign_path_final = sign_xml_if_needed(
            xml_path, sign_path, thumbprint, csptest_name=cert.csptest_name
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подписи: {e}"}}

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    subtype = sved["Описание"]["КНДФормы"]
    form_name = sved["Описание"]["ИмяФормы"]

    try:
        file_ident = extract_guid_from_xml_idfile(xml_path)
    except Exception:
        file_ident = str(uuid.uuid4()).upper()

    if sved.get("Описание", {}).get("Период"):
        sved["Описание"]["Период"][0]["ИдентификаторВложения"] = file_ident

    enclosure = _build_enclosure(
        file_path=xml_path,
        sign_path=sign_path_final,
        subtype=subtype,
        format_version=format_version,
        title=form_name,
        category="Основное",
        ident=file_ident,
    )

    file_name = os.path.basename(xml_path)
    doc = {
        "Название": f"{form_name} ({file_name})",
        "Идентификатор": (guid or "").lower() or uuid.uuid4().hex,
        "Тип": "ОтчетФНС",
        "ПодТип": subtype,
        "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Расширение": {"ИдентификаторКомплекта": guid or str(uuid.uuid4())},
        "НашаОрганизация": our_org,
        "Участники": {
            "Отправитель": our_org,
            "Получатель": {"ГосударственнаяИнспекция": kod_no},
            "КонечныйПолучатель": {"ГосударственнаяИнспекция": kod_no},
        },
        "Сведения": sved,
        "Вложение": [enclosure],
        "Сертификат": {"Отпечаток": thumbprint, "Ключ": {"Тип": "Клиентский"}},
    }

    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
        "X-SBISSessionID": session_id,
        # docs: X-API-Version: 2.3.1 для методов API отчётности
        "X-API-Version": "2.3.1",
        "User-Agent": "tax_service/1.0",
    }

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ЗаписатьКомплект",
        "params": {"Документ": [doc]},
        "id": 1,
    }
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
        return {"success": False, "error": {"message": "Не удалось получить документ из ответа ЗаписатьКомплект"}}

    today_str = datetime.now().strftime("%d.%m.%Y")
    list_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументов",
        "params": {
            "Фильтр": {
                "Тип": "ОтчетФНС",
                "Направление": "Исходящий",
                "ДатаС": today_str,
                "ДатаПо": today_str,
            }
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
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON СписокДокументов: {e}", "raw": list_resp.text}}

    if not list_data.get("result") or not list_data["result"].get("Документ"):
        return {"success": False, "error": {"message": "Не удалось получить документ из исходящей почты"}}

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
                "Этап": {
                    "Название": "Отправка",
                    "Действие": {
                        "Название": "Отправить",
                        "Сертификат": {"Отпечаток": thumbprint},
                    },
                },
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
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON Prepare: {e}", "raw": prep_resp.text}}

    if prep_data.get("error"):
        return {"success": False, "error": prep_data["error"]}

    sig_path = f"{xml_path}.sgn"
    try:
        sign_xml_if_needed(xml_path, None, thumbprint, csptest_name=cert.csptest_name)
        with open(sig_path, "rb") as f:
            sig_b64 = base64.b64encode(f.read()).decode("ascii")
        attachments = [
            {"Идентификатор": file_ident, "Подпись": [{"Файл": {"ДвоичныеДанные": sig_b64}}]}
        ]
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подписи {xml_path}: {e}"}}

    exec_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ВыполнитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": sbis_doc_id,
                "Этап": {
                    "Название": "Отправка",
                    "Действие": {
                        "Название": "Отправить",
                        "Сертификат": {"Отпечаток": thumbprint},
                    },
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
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON Execute: {e}", "raw": exec_resp.text}}

    if exec_data.get("error"):
        return {"success": False, "error": exec_data["error"]}

    return {
        "success": True,
        "result": exec_data,
        "report_meta": meta,
    }


def send_report_1c(
    inn: str,
    xml_b64: str,
    *,
    report_type: str = "auto",
    dry_run: bool = False,
) -> tuple[int, dict]:
    """
    Контракт для 1С / внешних клиентов: base64 XML + dry_run.
    Не пересекается с send_nds_extra_1c.
    """
    cert = _resolve_cert(inn)
    if not cert:
        return 403, {"success": False, "comment": "Ошибка доступа: нет подписи по указанному ИНН"}
    if not getattr(cert, "csptest_name", None):
        return 401, {"success": False, "comment": "Указанный ИНН не имеет валидной подписи"}

    if not inn or not xml_b64:
        return 400, {
            "success": False,
            "comment": "Ошибка входных данных",
            "error": {"message": "Поля inn и xml_b64 обязательны"},
        }

    try:
        xml_bytes = _b64_to_bytes(xml_b64)
        try:
            _log_decoded_xml(inn=inn, kind="report_dry" if dry_run else "report", xml_bytes=xml_bytes)
        except Exception:
            logger.exception("[1C_DECODE] failed to log report xml")

        id_file = _extract_idfile_from_xml_bytes(xml_bytes)
        filename = _normalize_xml_filename_from_idfile(id_file)
    except Exception as e:
        return 400, {"success": False, "comment": "Ошибка входных данных", "error": {"message": str(e)}}

    with tempfile.TemporaryDirectory(prefix=f"sbis_report_{inn}_") as tmpdir:
        xml_path = os.path.join(tmpdir, filename)
        with open(xml_path, "wb") as f:
            f.write(xml_bytes)

        try:
            sved, our_org, kod_no, po_mestu, guid, format_version, meta = build_svedenia_from_report_xml(
                xml_path, report_type=report_type
            )
        except Exception as e:
            return 400, {"success": False, "comment": "Ошибка входных данных", "error": {"message": str(e)}}

        xml_inn = ((our_org.get("СвЮЛ") or {}).get("ИНН") or "").strip()
        if xml_inn and xml_inn != inn:
            return 400, {
                "success": False,
                "comment": "Ошибка входных данных",
                "error": {"message": f"ИНН в запросе ({inn}) не совпадает с ИННЮЛ в XML ({xml_inn})"},
            }

        if dry_run:
            period = (sved.get("Описание") or {}).get("Период") or [{}]
            period0 = period[0] if period else {}
            return 200, {
                "success": True,
                "comment": "DRY_RUN: данные приняты и распарсены, отправка в СБИС пропущена",
                "parsed": {
                    "inn": inn,
                    "xml_inn": xml_inn,
                    "kpp": ((our_org.get("СвЮЛ") or {}).get("КПП") or ""),
                    "kod_no": kod_no,
                    "po_mestu": po_mestu,
                    "report_type": meta["report_type"],
                    "knd": meta["knd"],
                    "form_name": meta["form_name"],
                    "idfile": id_file,
                    "filename": filename,
                    "format_version": format_version,
                    "guid": guid,
                    "period": {"year": period0.get("Год"), "code": period0.get("Код")},
                },
            }

        result = send_report(inn=inn, xml_path=xml_path, report_type=report_type)

    if isinstance(result, dict) and result.get("success") is True:
        try:
            exec_data = result.get("result") or {}
            send_meta = _extract_send_meta_from_exec(exec_data)
            result["send_meta"] = send_meta
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
