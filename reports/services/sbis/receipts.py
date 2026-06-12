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
from .client import _sbis_get, _sbis_post, sbis_rpc
from .crypto import export_cert_der, get_thumbprint_from_cert

def _download_archive_zip(
    inn: str,
    session_id: str,
    archive_url: str,
    *,
    timeout: int = 30,
    total_budget_sec: int = 35,
) -> bytes:
    r = _sbis_get(
        archive_url,
        headers={"X-SBISSessionID": session_id},
        timeout=timeout,
        inn=inn,
        total_budget_sec=total_budget_sec,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Не удалось скачать архив: HTTP {r.status_code}, body_head={r.text[:200]}")
    content = r.content or b""
    content_type = (r.headers.get("Content-Type") or "").strip()
    payload_kind = _detect_archive_payload_kind(content=content, content_type=content_type)
    if payload_kind != "zip":
        head_hex = (content[:16] or b"").hex() or "empty"
        raise RuntimeError(
            "Ответ по СсылкаНаАрхив не ZIP "
            f"(detected={payload_kind}, content_type={content_type or 'n/a'}, "
            f"content_length={len(content)}, head16_hex={head_hex})"
        )
    return content

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

def _collect_sales_book_rows(
    xml_bytes: bytes,
    *,
    counterparty_id: str | None = None,
    max_rows: int = 500,
) -> dict:
    """
    Возвращает строки/узлы книги продаж (раздел 9).
    - если counterparty_id передан: фильтр по контрагенту
    - если counterparty_id пустой: возвращаем все строки раздела 9
    """
    target = (counterparty_id or "").strip()

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        return {"total_rows": 0, "rows": [], "xml_parse_error": str(e)}

    rows: list[dict] = []
    xml_hits = 0

    sales_hints = ("КнигаПрод", "КнПрод", "Разд9", "Продаж")
    counterparty_attr_hints = ("ИНН", "Ид", "Идентификатор", "Покуп")

    def walk(node: ET.Element, path: list[str]) -> None:
        nonlocal xml_hits
        current_tag = _local_xml_tag(node.tag)
        current_path = path + [current_tag]

        attrs = {str(k): str(v) for k, v in (node.attrib or {}).items()}
        path_str = "/".join(current_path)

        in_sales_section = any(h.lower() in path_str.lower() for h in sales_hints)
        if in_sales_section:
            match_by_counterparty = False
            if target:
                for k, v in attrs.items():
                    key_ok = any(h.lower() in k.lower() for h in counterparty_attr_hints)
                    if key_ok and v.strip() == target:
                        match_by_counterparty = True
                        break
            else:
                # Когда контрагент не задан, возвращаем узлы раздела 9,
                # где есть полезные атрибуты (обычно строки/записи книги продаж).
                match_by_counterparty = bool(attrs)

            if match_by_counterparty:
                xml_hits += 1
                if len(rows) < max_rows:
                    rows.append(
                        {
                            "tag": current_tag,
                            "path": path_str,
                            "attrs": attrs,
                        }
                    )

        for ch in list(node):
            walk(ch, current_path)

    walk(root, [])

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
    """
    inn = (inn or "").strip()
    counterparty_id = (counterparty_id or "").strip()

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    # Если counterparty_id не задан — вернём все найденные строки книги продаж (раздел 9).

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=120)).strftime("%d.%m.%Y")

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

        if xml_matches:
            matched_docs.append(
                {
                    "doc_id": doc_id,
                    "name": doc.get("Название"),
                    "created_at": doc.get("ДатаВремяСоздания") or doc.get("Дата"),
                    "archive_url": archive_url,
                    "ok": True,
                    "xml_matches": xml_matches,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "counterparty_id": counterparty_id,
            "mode": "by_counterparty" if counterparty_id else "all_sales_books",
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
            "matched_docs_count": len([x for x in matched_docs if x.get("ok")]),
            "documents": matched_docs,
        },
    }
