"""Парсинг срока ответа / КНД из XML требования ФНС."""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta
from typing import Any


_DATE_ATTR_HINTS = (
    "срок",
    "срокот",
    "датаисполн",
    "срокисполн",
    "срокпредст",
    "срокпредост",
    "датаответ",
    "срокответа",
    "срокнаправл",
)

_KND_ATTR_HINTS = ("кнд",)


def add_working_days(start: date, days: int) -> date:
    """Прибавить N рабочих дней (пн–пт), отсчёт со следующего календарного дня."""
    if days <= 0:
        return start
    cur = start
    left = days
    while left > 0:
        cur += timedelta(days=1)
        if cur.weekday() < 5:
            left -= 1
    return cur


def receipt_due_from_document_date(document_date: date | None) -> date | None:
    """Срок квитанции о приёме: 6 рабочих дней от даты документа (ст. 6.1 НК)."""
    if not document_date:
        return None
    return add_working_days(document_date, 6)


def _local_tag(tag: str) -> str:
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _parse_date_value(raw: str) -> date | None:
    s = (raw or "").strip()
    if not s:
        return None
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d/%m/%Y", "%Y%m%d"):
        try:
            return datetime.strptime(s[:10] if fmt != "%Y%m%d" else s[:8], fmt).date()
        except ValueError:
            continue
    m = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})", s)
    if m:
        try:
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            return None
    return None


def _attr_key_norm(key: str) -> str:
    return re.sub(r"[^0-9a-zа-яё]", "", (key or "").lower())


def parse_requirement_meta_from_xml(xml_bytes: bytes) -> dict[str, Any]:
    """
    Из XML требования: response_due_date, knd.
    """
    out: dict[str, Any] = {"response_due_date": None, "knd": None}
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return out

    due_candidates: list[date] = []

    def walk(node: ET.Element) -> None:
        tag_n = _attr_key_norm(_local_tag(node.tag))
        text = (node.text or "").strip() if node.text else ""

        for k, v in (node.attrib or {}).items():
            kn = _attr_key_norm(str(k))
            val = str(v).strip()
            if any(h in kn for h in _KND_ATTR_HINTS) and re.fullmatch(r"\d{5,8}", val):
                if not out["knd"]:
                    out["knd"] = val
            if any(h in kn for h in _DATE_ATTR_HINTS):
                d = _parse_date_value(val)
                if d:
                    due_candidates.append(d)

        if any(h in tag_n for h in _DATE_ATTR_HINTS) and text:
            d = _parse_date_value(text)
            if d:
                due_candidates.append(d)
        if any(h in tag_n for h in _KND_ATTR_HINTS) and re.fullmatch(r"\d{5,8}", text):
            if not out["knd"]:
                out["knd"] = text

        # КНД часто в атрибуте Документ/@КНД
        if _local_tag(node.tag) == "Документ":
            knd = (node.attrib.get("КНД") or "").strip()
            if re.fullmatch(r"\d{5,8}", knd) and not out["knd"]:
                out["knd"] = knd

        for ch in list(node):
            walk(ch)

    walk(root)
    if due_candidates:
        # ближайший будущий относительно «сейчас» не фильтруем — берём max как крайний срок
        out["response_due_date"] = max(due_candidates)
    return out


def extract_xml_candidates_from_bytes(content: bytes) -> list[bytes]:
    """PDF/XML/ZIP → список XML-байтов для парсинга срока."""
    if not content:
        return []
    head = content.lstrip()[:5]
    if head.startswith(b"<?xml") or head.startswith(b"<"):
        return [content]
    if content.startswith(b"PK\x03\x04"):
        out: list[bytes] = []
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for name in zf.namelist():
                    if not name.lower().endswith(".xml"):
                        continue
                    try:
                        out.append(zf.read(name))
                    except Exception:
                        continue
        except Exception:
            return []
        return out
    return []


def extract_deadlines_from_content(
    content: bytes,
    *,
    document_date: date | None,
    extra_xml_list: list[bytes] | None = None,
) -> dict[str, Any]:
    """
    Собрать response_due_date / knd / receipt_due_date из содержимого + доп. XML вложений.
    """
    xmls = list(extract_xml_candidates_from_bytes(content) or [])
    for x in extra_xml_list or []:
        if x and x not in xmls:
            xmls.append(x)

    response_due: date | None = None
    knd: str | None = None
    for xml_bytes in xmls:
        meta = parse_requirement_meta_from_xml(xml_bytes)
        if meta.get("response_due_date") and (
            response_due is None or meta["response_due_date"] > response_due
        ):
            response_due = meta["response_due_date"]
        if meta.get("knd") and not knd:
            knd = meta["knd"]

    return {
        "response_due_date": response_due,
        "receipt_due_date": receipt_due_from_document_date(document_date),
        "knd": knd,
    }
