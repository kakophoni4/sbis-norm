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

from reports.models import Certificate, Organization
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

from .constants import *
from .auth import auth_sbis_by_cert, sbis_auth_session_for_inn
from .client import _sbis_get, _sbis_post, sbis_rpc
from .crypto import export_cert_der, get_thumbprint_from_cert
from .sales_book_extract_pdf import (
    build_sales_book_extract_pdf,
    extract_stamp_meta_from_pdf,
    extract_title_meta_from_pdf,
    normalize_xml_sales_rows,
    parse_sales_rows_from_saby_pdf,
)

logger = logging.getLogger(__name__)


def _is_pdf_still_forming_response(status_code: int, body: str) -> bool:
    """СБИС отдаёт HTTP 500, пока визуальные PDF в архиве ещё не собраны."""
    if int(status_code or 0) not in (500, 503, 409):
        return False
    low = (body or "").lower()
    return any(
        x in low
        for x in (
            "pdf-файлы ещё формируются",
            "pdf-файлы еще формируются",
            "ещё формируются",
            "еще формируются",
            "преобразовать файлы в pdf",
        )
    )


def _download_archive_zip(
    inn: str,
    session_id: str,
    archive_url: str,
    *,
    timeout: int = 30,
    total_budget_sec: int = 35,
    pdf_ready_attempts: int = 5,
    pdf_ready_sleep_sec: float = 8.0,
) -> bytes:
    """
    Скачать ZIP по СсылкаНаАрхив.

    При первой выгрузке СБИС часто отвечает «PDF-файлы ещё формируются» —
    тогда ждём и повторяем ту же ссылку (смена прокси тут бесполезна).
    """
    attempts = max(1, int(pdf_ready_attempts))
    sleep_sec = max(1.0, float(pdf_ready_sleep_sec))
    last_head = ""

    for attempt in range(1, attempts + 1):
        r = _sbis_get(
            archive_url,
            headers={"X-SBISSessionID": session_id},
            timeout=timeout,
            inn=inn,
            total_budget_sec=total_budget_sec,
        )
        body_text = r.text or ""
        last_head = body_text[:240]

        if _is_pdf_still_forming_response(r.status_code, body_text):
            logger.warning(
                "archive PDF still forming inn=%s attempt=%s/%s sleep=%.0fs",
                inn,
                attempt,
                attempts,
                sleep_sec,
            )
            if attempt >= attempts:
                break
            time.sleep(sleep_sec)
            continue

        if r.status_code != 200:
            raise RuntimeError(
                f"Не удалось скачать архив: HTTP {r.status_code}, body_head={last_head}"
            )

        content = r.content or b""
        content_type = (r.headers.get("Content-Type") or "").strip()
        payload_kind = _detect_archive_payload_kind(content=content, content_type=content_type)
        if payload_kind == "json" and _is_pdf_still_forming_response(500, body_text or content.decode("utf-8", "ignore")):
            logger.warning(
                "archive PDF still forming (json body) inn=%s attempt=%s/%s sleep=%.0fs",
                inn,
                attempt,
                attempts,
                sleep_sec,
            )
            if attempt >= attempts:
                break
            time.sleep(sleep_sec)
            continue
        if payload_kind != "zip":
            head_hex = (content[:16] or b"").hex() or "empty"
            raise RuntimeError(
                "Ответ по СсылкаНаАрхив не ZIP "
                f"(detected={payload_kind}, content_type={content_type or 'n/a'}, "
                f"content_length={len(content)}, head16_hex={head_hex})"
            )
        return content

    raise RuntimeError(
        "PDF в архиве СБИС так и не сформировался "
        f"(attempts={attempts}, sleep={sleep_sec}s). body_head={last_head}"
    )

def _detect_archive_payload_kind(content: bytes, content_type: str | None = None) -> str:
    """Определяет формат ответа по сигнатуре байтов + Content-Type."""
    ctype = (content_type or "").lower()
    head = content[:256]
    head_l = head.lower()

    if content.startswith(b"PK\x03\x04"):
        return "zip"
    if content.startswith(b"Rar!\x1a\x07\x00") or content.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "rar"
    if content.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head_l.startswith(b"<?xml"):
        return "xml"
    if "text/html" in ctype or b"<html" in head_l or b"<!doctype html" in head_l:
        return "html"
    if "json" in ctype or head_l.startswith(b"{") or head_l.startswith(b"["):
        return "json"
    if not content:
        return "empty"
    return "unknown"

def _extract_receipt_pdf_from_zip(zip_bytes: bytes) -> bytes:
    """
    В твоём архиве "справка" — это единственный PDF, который НЕ в папке 'PDF/'.
    Берём строго его, и валимся, если найдено не ровно 1.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = zf.namelist()

    pdfs = [n for n in names if n.lower().endswith(".pdf")]
    receipt = [n for n in pdfs if not n.startswith("PDF/")]

    if len(receipt) != 1:
        raise RuntimeError(
            f"Ожидался ровно 1 файл справки (PDF не из папки PDF/). "
            f"found={len(receipt)} receipt={receipt} all_pdfs={pdfs}"
        )

    return zf.read(receipt[0])

def fetch_receipt_pdf_b64_from_archive(
    inn: str,
    sbis_doc_id: str,
    sent_date: str,
) -> dict:
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not sbis_doc_id:
        return {"success": False, "error": {"message": "sbis_doc_id обязателен"}}
    if not sent_date:
        return {"success": False, "error": {"message": "sent_date обязателен (dd.mm.yyyy)"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}}
    if not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Указанный ИНН не имеет валидной подписи"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    list_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументов",
        "params": {
            "Фильтр": {
                "Тип": "ОтчетФНС",
                "Направление": "Исходящий",
                "ДатаС": sent_date,
                "ДатаПо": sent_date,
            }
        },
        "id": 1,
    }

    list_json = json.dumps(list_body, ensure_ascii=False)
    list_resp = _sbis_post(
        REPORTING_URL,
        headers=headers,
        data=list_json,
        timeout=30,
        inn=inn,
    )

    if list_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {list_resp.status_code}", "raw": list_resp.text}}

    try:
        list_data = list_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": list_resp.text}}

    docs = (((list_data.get("result") or {}).get("Документ")) or [])
    doc = next((d for d in docs if d.get("Идентификатор") == sbis_doc_id), None)

    if not doc:
        return {
            "success": False,
            "error": {
                "message": "Документ не найден в исходящих за указанную дату",
                "sbis_doc_id": sbis_doc_id,
                "sent_date": sent_date,
                "found": len(docs),
            },
        }

    archive_url = (doc.get("СсылкаНаАрхив") or "").strip()
    if not archive_url:
        return {"success": False, "error": {"message": "В документе нет СсылкаНаАрхив", "sbis_doc_id": sbis_doc_id}}

    try:
        zip_bytes = _download_archive_zip(inn=inn, session_id=session_id, archive_url=archive_url)
        pdf_bytes = _extract_receipt_pdf_from_zip(zip_bytes)
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
    except Exception as e:
        return {"success": False, "error": {"message": str(e), "sbis_doc_id": sbis_doc_id}}

    return {
        "success": True,
        "result": {
            "sbis_doc_id": sbis_doc_id,
            "sent_date": sent_date,
            "archive_url": archive_url,
            "pdf_filename": "receipt.pdf",
            "pdf_b64": pdf_b64,
        },
    }

def _extract_xml_files_from_zip(zip_bytes: bytes) -> list[tuple[str, bytes]]:
    """
    Возвращает все XML-файлы из zip-архива СБИС.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    out: list[tuple[str, bytes]] = []
    for name in zf.namelist():
        if not name.lower().endswith(".xml"):
            continue
        try:
            out.append((name, zf.read(name)))
        except Exception:
            logger.exception("Не удалось прочитать XML %s из архива", name)
    return out

def _local_xml_tag(tag: str) -> str:
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag

def _merge_element_attrs(node: ET.Element, *, depth: int = 3) -> dict[str, str]:
    """Собирает attrs узла и потомков (для КнПродСтр + СвПокуп)."""
    out: dict[str, str] = {}

    def walk(el: ET.Element, d: int) -> None:
        for k, v in (el.attrib or {}).items():
            ks, vs = str(k), str(v)
            if ks not in out or not out[ks]:
                out[ks] = vs
        if d <= 0:
            return
        for ch in list(el):
            walk(ch, d - 1)

    walk(node, depth)
    return out


def _node_has_counterparty(node: ET.Element, target: str) -> bool:
    target = (target or "").strip()
    if not target:
        return True
    for k, v in (node.attrib or {}).items():
        if target == str(v).strip() and any(h in str(k) for h in ("ИНН", "Ид", "Идентификатор", "Покуп")):
            return True
    for ch in list(node):
        if _node_has_counterparty(ch, target):
            return True
    return False


def _collect_sales_book_rows(
    xml_bytes: bytes,
    *,
    counterparty_id: str | None = None,
    max_rows: int = 500,
) -> dict:
    """
    Возвращает строки книги продаж (раздел 9).
    Предпочтительно родительские КнПродСтр с смерженными attrs покупателя.
    """
    target = (counterparty_id or "").strip()

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        return {"total_rows": 0, "rows": [], "xml_parse_error": str(e)}

    rows: list[dict] = []
    xml_hits = 0
    sales_hints = ("КнигаПрод", "КнПрод", "Разд9", "Продаж")
    row_tag_hints = ("КнПродСтр", "КнигаПродСтр", "Стр")

    def is_row_tag(tag: str) -> bool:
        t = (tag or "").lower()
        return any(h.lower() in t for h in row_tag_hints) and ("стр" in t or t.endswith("str"))

    def walk(node: ET.Element, path: list[str]) -> None:
        nonlocal xml_hits
        current_tag = _local_xml_tag(node.tag)
        current_path = path + [current_tag]
        path_str = "/".join(current_path)
        in_sales_section = any(h.lower() in path_str.lower() for h in sales_hints)

        if in_sales_section and is_row_tag(current_tag):
            if (not target) or _node_has_counterparty(node, target):
                # без фильтра — только строки с полезными attrs
                attrs = _merge_element_attrs(node)
                if target or attrs:
                    xml_hits += 1
                    if len(rows) < max_rows:
                        rows.append({"tag": current_tag, "path": path_str, "attrs": attrs})
            # не спускаемся в дочерние «ложные» хиты по СвПокуп
            return

        for ch in list(node):
            walk(ch, current_path)

    walk(root, [])

    # Фоллбек: старое поведение (лист с ИНН), если row-теги не нашли
    if not rows:
        counterparty_attr_hints = ("ИНН", "Ид", "Идентификатор", "Покуп")

        def walk_fallback(node: ET.Element, path: list[str]) -> None:
            nonlocal xml_hits
            current_tag = _local_xml_tag(node.tag)
            current_path = path + [current_tag]
            attrs = {str(k): str(v) for k, v in (node.attrib or {}).items()}
            path_str = "/".join(current_path)
            in_sales_section = any(h.lower() in path_str.lower() for h in sales_hints)
            if in_sales_section:
                match = False
                if target:
                    for k, v in attrs.items():
                        if any(h.lower() in k.lower() for h in counterparty_attr_hints) and v.strip() == target:
                            match = True
                            break
                else:
                    match = bool(attrs)
                if match:
                    xml_hits += 1
                    if len(rows) < max_rows:
                        rows.append({"tag": current_tag, "path": path_str, "attrs": attrs})
            for ch in list(node):
                walk_fallback(ch, current_path)

        walk_fallback(root, [])

    return {
        "total_rows": xml_hits,
        "rows": rows,
    }

def fetch_sales_book_extract_by_counterparty(
    inn: str,
    *,
    counterparty_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    sbis_doc_id: str | None = None,
    nds_subtype: str | None = None,
    max_docs: int = 30,
    response_format: str = "json",
    rpc_timeout_sec: int = 25,
    rpc_budget_sec: int = 30,
    archive_timeout_sec: int = 20,
    archive_budget_sec: int = 25,
    auth_timeout_sec: int = 14,
    auth_budget_sec: int = 20,
    proxy_prewarm_count: int = 6,
) -> dict:
    """
    Получение выписки книги продаж по контрагенту через API СБИС.

    Используемый endpoint: https://online.sbis.ru/service/?srv=1
    Используемый метод JSON-RPC: СБИС.СписокДокументов

    Дальше берём СсылкаНаАрхив у документа, читаем XML и фильтруем раздел 9 (книга продаж)
    по counterparty_id (ИНН/идентификатор контрагента).

    response_format:
      - json — строки раздела 9
      - pdf — короткий PDF по контрагенту + визуальный штамп исходной книги
    """
    inn = (inn or "").strip()
    counterparty_id = (counterparty_id or "").strip()
    response_format = (response_format or "json").strip().lower()
    if response_format not in ("json", "pdf"):
        return {"success": False, "error": {"message": "format должен быть json или pdf"}}

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if response_format == "pdf" and not counterparty_id:
        return {
            "success": False,
            "error": {"message": "для format=pdf обязателен counterparty_id"},
        }
    # Если counterparty_id не задан — вернём все найденные строки книги продаж (раздел 9).

    today = datetime.now()
    date_to = _normalize_sbis_date(date_to) or today.strftime("%d.%m.%Y")
    date_from = _normalize_sbis_date(date_from) or (today - timedelta(days=120)).strftime("%d.%m.%Y")

    auth = sbis_auth_session_for_inn(
        inn,
        prewarm_proxies=True,
        proxy_want=max(2, int(proxy_prewarm_count)),
        proxy_warmup_budget_sec=max(8, int(auth_budget_sec)),
        auth_timeout_sec=max(8, int(auth_timeout_sec)),
        auth_budget_sec=max(12, int(auth_budget_sec)),
    )
    if not auth.get("success"):
        return auth

    session_id = (((auth.get("result") or {}).get("session_id")) or "").strip()
    if not session_id:
        return {"success": False, "error": {"message": "Не удалось получить session_id", "inn": inn}}

    list_filter = {
        "Тип": "ОтчетФНС",
        "Направление": "Исходящий",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(max_docs))},
    }
    if (nds_subtype or "").strip():
        list_filter["Подтип"] = str(nds_subtype).strip()

    list_params = {"Фильтр": list_filter}

    try:
        data = sbis_rpc(
            inn=inn,
            session_id=session_id,
            method="СБИС.СписокДокументов",
            params=list_params,
            timeout=max(8, int(rpc_timeout_sec)),
            total_budget_sec=max(12, int(rpc_budget_sec)),
        )
    except Exception as e:
        msg = str(e)
        unknown_subtype = "неизвестный тип/подтип документа" in msg.lower()
        if unknown_subtype and "Подтип" in list_filter:
            # Фолбэк: у некоторых организаций/провайдеров подтип может не приниматься,
            # тогда запрашиваем без подтипа и фильтруем уже по данным архива.
            list_filter.pop("Подтип", None)
            try:
                data = sbis_rpc(
                    inn=inn,
                    session_id=session_id,
                    method="СБИС.СписокДокументов",
                    params={"Фильтр": list_filter},
                    timeout=max(8, int(rpc_timeout_sec)),
                    total_budget_sec=max(12, int(rpc_budget_sec)),
                )
            except Exception as e2:
                return {"success": False, "error": {"message": f"Ошибка СБИС.СписокДокументов: {e2}", "inn": inn}}
        else:
            return {"success": False, "error": {"message": f"Ошибка СБИС.СписокДокументов: {e}", "inn": inn}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

    docs = (((data.get("result") or {}).get("Документ")) or [])
    if sbis_doc_id:
        docs = [d for d in docs if (d.get("Идентификатор") or "").strip() == (sbis_doc_id or "").strip()]

    matched_docs: list[dict] = []
    scanned_docs = 0

    for doc in docs:
        if scanned_docs >= max_docs:
            break
        scanned_docs += 1

        doc_id = (doc.get("Идентификатор") or "").strip()
        archive_url = (doc.get("СсылкаНаАрхив") or "").strip()
        if not archive_url:
            continue

        try:
            zip_bytes = _download_archive_zip(
                inn=inn,
                session_id=session_id,
                archive_url=archive_url,
                timeout=max(8, int(archive_timeout_sec)),
                total_budget_sec=max(12, int(archive_budget_sec)),
            )
            xml_files = _extract_xml_files_from_zip(zip_bytes)
        except Exception as e:
            matched_docs.append(
                {
                    "doc_id": doc_id,
                    "name": doc.get("Название"),
                    "archive_url": archive_url,
                    "ok": False,
                    "error": str(e),
                }
            )
            continue

        xml_matches: list[dict] = []
        for xml_name, xml_bytes in xml_files:
            filtered = _collect_sales_book_rows(
                xml_bytes,
                counterparty_id=counterparty_id,
            )
            if (filtered.get("total_rows") or 0) > 0:
                xml_matches.append(
                    {
                        "xml_name": xml_name,
                        "total_rows": filtered.get("total_rows"),
                        "rows": filtered.get("rows") or [],
                    }
                )

        pdf_bytes = b""
        pdf_name = ""
        pdf_rows: list = []
        stamp_meta = None
        if response_format == "pdf":
            try:
                pdf_bytes, pdf_name = _extract_sales_book_pdf_from_zip(zip_bytes)
                pdf_rows = parse_sales_rows_from_saby_pdf(
                    pdf_bytes, counterparty_id=counterparty_id
                )
                stamp_meta = extract_stamp_meta_from_pdf(pdf_bytes)
            except Exception as e:
                logger.info(
                    "sales_book_extract pdf parse skip inn=%s doc=%s err=%s",
                    inn,
                    doc_id[:36],
                    e,
                )
                if not xml_matches:
                    matched_docs.append(
                        {
                            "doc_id": doc_id,
                            "name": doc.get("Название"),
                            "archive_url": archive_url,
                            "ok": False,
                            "error": f"PDF книги продаж: {e}",
                        }
                    )
                    continue

        if xml_matches or pdf_rows:
            matched_docs.append(
                {
                    "doc_id": doc_id,
                    "name": doc.get("Название"),
                    "created_at": doc.get("ДатаВремяСоздания") or doc.get("Дата"),
                    "archive_url": archive_url,
                    "ok": True,
                    "xml_matches": xml_matches,
                    "pdf_filename": pdf_name or None,
                    "pdf_rows_count": len(pdf_rows),
                    "_pdf_bytes": pdf_bytes if response_format == "pdf" else None,
                    "_pdf_rows": pdf_rows if response_format == "pdf" else None,
                    "_stamp_meta": stamp_meta if response_format == "pdf" else None,
                }
            )

    ok_docs = [x for x in matched_docs if x.get("ok")]

    if response_format == "pdf":
        if not ok_docs:
            return {
                "success": False,
                "error": {
                    "message": "Выписка PDF: нет строк по контрагенту",
                    "inn": inn,
                    "counterparty_id": counterparty_id,
                    "period": {"from": date_from, "to": date_to},
                    "scanned_docs": scanned_docs,
                    "attempts": [
                        {k: v for k, v in d.items() if not str(k).startswith("_")}
                        for d in matched_docs
                    ],
                },
            }

        # Берём документ с наибольшим числом строк по контрагенту
        def _row_score(d: dict) -> int:
            pdf_n = len(d.get("_pdf_rows") or [])
            xml_n = sum(int(x.get("total_rows") or 0) for x in (d.get("xml_matches") or []))
            return max(pdf_n, xml_n)

        best = max(ok_docs, key=_row_score)
        rows = list(best.get("_pdf_rows") or [])
        if not rows:
            raw_xml_rows: list[dict] = []
            for xm in best.get("xml_matches") or []:
                raw_xml_rows.extend(xm.get("rows") or [])
            rows = normalize_xml_sales_rows(raw_xml_rows, counterparty_id=counterparty_id)
        if not rows:
            return {
                "success": False,
                "error": {
                    "message": "Выписка PDF: строки контрагента не разобраны",
                    "inn": inn,
                    "counterparty_id": counterparty_id,
                    "sbis_doc_id": best.get("doc_id"),
                },
            }

        source_pdf_bytes = best.get("_pdf_bytes") or b""
        stamp = best.get("_stamp_meta") or extract_stamp_meta_from_pdf(source_pdf_bytes)
        title_meta = extract_title_meta_from_pdf(source_pdf_bytes) if source_pdf_bytes else None
        org = Organization.objects.filter(inn=inn).first()
        cert = Certificate.objects.filter(inn=inn).order_by("-is_active", "-last_used_at").first()
        seller_name = (title_meta.org_name if title_meta and title_meta.org_name else None) or (
            org.name if org else None
        )
        seller_kpp = (getattr(org, "kpp", None) if org else None) or (
            getattr(cert, "kpp", None) if cert else None
        )
        if stamp and not stamp.certificate and cert and cert.thumbprint:
            stamp.certificate = str(cert.thumbprint).upper()

        try:
            out_pdf = build_sales_book_extract_pdf(
                seller_inn=inn,
                seller_kpp=seller_kpp,
                seller_name=seller_name,
                counterparty_id=counterparty_id,
                period_from=date_from,
                period_to=date_to,
                sbis_doc_id=best.get("doc_id") or "",
                rows=rows,
                stamp=stamp,
                title=title_meta,
                source_pdf_name=best.get("pdf_filename"),
                source_pdf_bytes=source_pdf_bytes or None,
            )
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка генерации PDF: {e}", "inn": inn}}

        out_name = f"sales_book_extract_{inn}_{counterparty_id}.pdf"
        return {
            "success": True,
            "result": {
                "inn": inn,
                "counterparty_id": counterparty_id,
                "mode": "by_counterparty_pdf",
                "format": "pdf",
                "period": {"from": date_from, "to": date_to},
                "sbis_doc_id": best.get("doc_id"),
                "doc_name": best.get("name"),
                "source_pdf_filename": best.get("pdf_filename"),
                "matched_rows": len(rows),
                "rows": [r.to_dict() for r in rows],
                "stamp": {
                    "document_id": getattr(stamp, "document_id", None),
                    "sent_line": getattr(stamp, "sent_line", None),
                    "signed_at": getattr(stamp, "signed_at", None),
                    "certificate": getattr(stamp, "certificate", None),
                    "operator": getattr(stamp, "operator", None),
                },
                "pdf_filename": out_name,
                "pdf_b64": base64.b64encode(out_pdf).decode("ascii"),
                "scanned_docs": scanned_docs,
            },
        }

    # json: убираем служебные поля
    public_docs = []
    for d in matched_docs:
        public_docs.append({k: v for k, v in d.items() if not str(k).startswith("_")})

    return {
        "success": True,
        "result": {
            "inn": inn,
            "counterparty_id": counterparty_id,
            "mode": "by_counterparty" if counterparty_id else "all_sales_books",
            "format": "json",
            "endpoint": REPORTING_URL,
            "method": "СБИС.СписокДокументов",
            "period": {"from": date_from, "to": date_to},
            "nds_subtype": nds_subtype,
            "scanned_docs": scanned_docs,
            "timeouts": {
                "auth_timeout_sec": int(auth_timeout_sec),
                "auth_budget_sec": int(auth_budget_sec),
                "rpc_timeout_sec": int(rpc_timeout_sec),
                "rpc_budget_sec": int(rpc_budget_sec),
                "archive_timeout_sec": int(archive_timeout_sec),
                "archive_budget_sec": int(archive_budget_sec),
            },
            "proxy_prewarm_count": int(proxy_prewarm_count),
            "matched_docs_count": len(ok_docs),
            "documents": public_docs,
        },
    }


def _normalize_sbis_date(value: str | None) -> str | None:
    """YYYY-MM-DD или DD.MM.YYYY → DD.MM.YYYY для фильтра СБИС."""
    s = (value or "").strip()
    if not s:
        return None
    if re.match(r"^\d{2}\.\d{2}\.\d{4}$", s):
        return s
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        try:
            return datetime.strptime(s, "%Y-%m-%d").strftime("%d.%m.%Y")
        except ValueError:
            return s
    return s


def _doc_state_info(doc: dict) -> dict:
    state = doc.get("Состояние") if isinstance(doc.get("Состояние"), dict) else {}
    return {
        "code": str(state.get("Код") or "").strip(),
        "name": str(state.get("Название") or "").strip(),
        "description": str(state.get("Описание") or "").strip(),
    }


def _is_accepted_fns_state(state: dict) -> bool:
    """Эвристика: документ принят/сдан/доставлен в ФНС."""
    blob = " ".join(
        [
            str(state.get("code") or ""),
            str(state.get("name") or ""),
            str(state.get("description") or ""),
        ]
    ).lower()
    if not blob.strip():
        return False
    reject_hints = ("отказ", "ошибк", "аннулир", "не принят", "отклон")
    if any(h in blob for h in reject_hints):
        return False
    accept_hints = ("принят", "сдан", "доставлен", "заверш", "выполнен", "обработан", "успеш")
    return any(h in blob for h in accept_hints)


def _sales_book_doc_score(doc: dict) -> int:
    """Приоритет ОтчетФНС, где с большей вероятностью лежит книга продаж (НД по НДС)."""
    name = str(doc.get("Название") or "")
    subtype = str(doc.get("Подтип") or "")
    blob = f"{name} {subtype}".lower()
    score = 0
    if "1151001" in blob:
        score += 120
    if "ндс" in blob:
        score += 100
    if "декларац" in blob:
        score += 60
    if "продаж" in blob or "книга" in blob:
        score += 40
    if "прибыл" in blob or "усн" in blob or "имуществ" in blob:
        score -= 80
    if _is_accepted_fns_state(_doc_state_info(doc)):
        score += 25
    # свежие чуть выше
    created = str(doc.get("ДатаВремяСоздания") or doc.get("Дата") or "")
    if created:
        score += 1
    return score


def _extract_sales_book_pdf_from_zip(zip_bytes: bytes) -> tuple[bytes, str]:
    """
    PDF книги продаж из папки PDF/ архива СБИС.
    Предпочтение: NO_NDS.9* → имя с «продаж»/КнПрод → единственный кандидат.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = [n for n in zf.namelist() if n.lower().endswith(".pdf")]
    pdf_dir = [n for n in names if n.replace("\\", "/").startswith("PDF/") or "/PDF/" in n.replace("\\", "/")]
    pool = pdf_dir or names
    if not pool:
        raise RuntimeError(f"В архиве нет PDF. files={zf.namelist()[:40]}")

    def score(name: str) -> int:
        base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if "no_nds.9" in base or base.startswith("no_nds.9"):
            return 100
        if ".9_" in base or base.startswith("no_nds.9"):
            return 90
        if "продаж" in base or "knprod" in base or "кнпрод" in base:
            return 80
        if "разд9" in base or "razd9" in base:
            return 70
        return 0

    ranked = sorted(pool, key=lambda n: (-score(n), n.lower()))
    best = ranked[0]
    best_score = score(best)
    if best_score == 0:
        # несколько PDF без явных признаков — не угадываем
        if len(pool) != 1:
            raise RuntimeError(
                "Не удалось однозначно выбрать PDF книги продаж. "
                f"candidates={pool[:20]}"
            )
    ties = [n for n in ranked if score(n) == best_score and best_score > 0]
    if len(ties) > 1 and best_score < 100:
        # несколько «продаж» без NO_NDS.9 — ошибка
        nine = [n for n in ties if "no_nds.9" in n.replace("\\", "/").rsplit("/", 1)[-1].lower()]
        if len(nine) == 1:
            best = nine[0]
        elif len(nine) > 1:
            raise RuntimeError(f"Несколько PDF NO_NDS.9: {nine[:10]}")
        else:
            raise RuntimeError(f"Несколько кандидатов книги продаж: {ties[:10]}")

    return zf.read(best), best.replace("\\", "/").rsplit("/", 1)[-1]


def fetch_sales_book_pdf(
    inn: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    sbis_doc_id: str | None = None,
    only_accepted: bool = False,
    max_docs: int = 30,
    rpc_timeout_sec: int = 25,
    rpc_budget_sec: int = 30,
    archive_timeout_sec: int = 20,
    archive_budget_sec: int = 25,
    auth_timeout_sec: int = 14,
    auth_budget_sec: int = 20,
    proxy_prewarm_count: int = 6,
    pdf_ready_attempts: int = 5,
    pdf_ready_sleep_sec: float = 8.0,
) -> dict:
    """
    Скачать подписанный PDF книги продаж из архива исходящего ОтчетФНС.
    """
    inn = (inn or "").strip()
    sbis_doc_id = (sbis_doc_id or "").strip() or None
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}

    today = datetime.now()
    date_to = _normalize_sbis_date(date_to) or today.strftime("%d.%m.%Y")
    date_from = _normalize_sbis_date(date_from) or (today - timedelta(days=120)).strftime("%d.%m.%Y")

    auth = sbis_auth_session_for_inn(
        inn,
        prewarm_proxies=True,
        proxy_want=max(2, int(proxy_prewarm_count)),
        proxy_warmup_budget_sec=max(8, int(auth_budget_sec)),
        auth_timeout_sec=max(8, int(auth_timeout_sec)),
        auth_budget_sec=max(12, int(auth_budget_sec)),
    )
    if not auth.get("success"):
        return auth

    session_id = (((auth.get("result") or {}).get("session_id")) or "").strip()
    if not session_id:
        return {"success": False, "error": {"message": "Не удалось получить session_id", "inn": inn}}

    list_filter = {
        "Тип": "ОтчетФНС",
        "Направление": "Исходящий",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(max_docs))},
    }
    try:
        data = sbis_rpc(
            inn=inn,
            session_id=session_id,
            method="СБИС.СписокДокументов",
            params={"Фильтр": list_filter},
            timeout=max(8, int(rpc_timeout_sec)),
            total_budget_sec=max(12, int(rpc_budget_sec)),
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СБИС.СписокДокументов: {e}", "inn": inn}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

    docs = (((data.get("result") or {}).get("Документ")) or [])
    if sbis_doc_id:
        docs = [d for d in docs if (d.get("Идентификатор") or "").strip() == sbis_doc_id]
    else:
        # Не долбим все ОтчетФНС подряд: сначала НД НДС, иначе СБИС гоняет SR2D по мусору.
        docs = sorted(docs, key=_sales_book_doc_score, reverse=True)

    found: list[dict] = []
    scanned = 0
    # На один ИНН достаточно нескольких лучших кандидатов — книга либо в топе, либо её нет.
    try_limit = min(int(max_docs), 5 if not sbis_doc_id else int(max_docs))
    for doc in docs:
        if scanned >= try_limit:
            break
        doc_id = (doc.get("Идентификатор") or "").strip()
        state = _doc_state_info(doc)
        if only_accepted and not _is_accepted_fns_state(state):
            logger.info(
                "sales_book_pdf skip non-accepted inn=%s doc=%s state=%s",
                inn,
                doc_id[:36],
                state,
            )
            continue
        archive_url = (doc.get("СсылкаНаАрхив") or "").strip()
        if not archive_url:
            continue
        scanned += 1
        score = _sales_book_doc_score(doc)
        logger.info(
            "sales_book_pdf try inn=%s doc=%s score=%s name=%s",
            inn,
            doc_id[:36],
            score,
            (doc.get("Название") or "")[:80],
        )
        try:
            zip_bytes = _download_archive_zip(
                inn=inn,
                session_id=session_id,
                archive_url=archive_url,
                timeout=max(8, int(archive_timeout_sec)),
                total_budget_sec=max(12, int(archive_budget_sec)),
                pdf_ready_attempts=max(1, int(pdf_ready_attempts)),
                pdf_ready_sleep_sec=max(1.0, float(pdf_ready_sleep_sec)),
            )
            pdf_bytes, pdf_name = _extract_sales_book_pdf_from_zip(zip_bytes)
        except Exception as e:
            found.append(
                {
                    "sbis_doc_id": doc_id,
                    "doc_name": doc.get("Название"),
                    "state": state,
                    "score": score,
                    "ok": False,
                    "error": str(e),
                }
            )
            continue
        found.append(
            {
                "sbis_doc_id": doc_id,
                "doc_name": doc.get("Название"),
                "state": state,
                "score": score,
                "ok": True,
                "pdf_filename": pdf_name,
                "pdf_b64": base64.b64encode(pdf_bytes).decode("ascii"),
                "archive_url": archive_url,
            }
        )
        # Книга нашлась — дальше другие ОтчетФНС не трогаем (меньше SR2D/прокси).
        break

    ok_docs = [x for x in found if x.get("ok")]
    if not ok_docs:
        errs = [str(x.get("error") or "") for x in found if x.get("error")]
        forming = any("формир" in e.lower() for e in errs)
        if forming:
            msg = "PDF книги продаж ещё формируется в СБИС (архив не готов)"
        elif not found and scanned == 0:
            msg = "В периоде нет исходящих ОтчетФНС с архивом"
        elif errs:
            msg = f"PDF книги продаж не найден: {errs[0][:180]}"
        else:
            msg = "PDF книги продаж не найден"
        return {
            "success": False,
            "error": {
                "message": msg,
                "inn": inn,
                "period": {"from": date_from, "to": date_to},
                "only_accepted": bool(only_accepted),
                "scanned_docs": scanned,
                "attempts": found,
            },
        }

    # один конкретный doc_id или единственный успешный — плоский result; иначе список
    if sbis_doc_id or len(ok_docs) == 1:
        one = ok_docs[0]
        return {
            "success": True,
            "result": {
                "inn": inn,
                "period": {"from": date_from, "to": date_to},
                "only_accepted": bool(only_accepted),
                "sbis_doc_id": one["sbis_doc_id"],
                "doc_name": one.get("doc_name"),
                "state": one.get("state"),
                "pdf_filename": one.get("pdf_filename"),
                "pdf_b64": one.get("pdf_b64"),
                "archive_url": one.get("archive_url"),
                "matched_count": len(ok_docs),
            },
        }

    return {
        "success": True,
        "result": {
            "inn": inn,
            "period": {"from": date_from, "to": date_to},
            "only_accepted": bool(only_accepted),
            "matched_count": len(ok_docs),
            "documents": [
                {
                    "sbis_doc_id": x["sbis_doc_id"],
                    "doc_name": x.get("doc_name"),
                    "state": x.get("state"),
                    "pdf_filename": x.get("pdf_filename"),
                    "pdf_b64": x.get("pdf_b64"),
                }
                for x in ok_docs
            ],
        },
    }
