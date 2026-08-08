"""Мета требования из СБИС.ПрочитатьДокумент: Срок, КНД, признак «отвечено»."""
from __future__ import annotations

import logging
import re
from datetime import date
from typing import Any

from reports.services.requirement_deadline import parse_date_value, receipt_due_from_document_date

logger = logging.getLogger(__name__)

# Эвристики по тексту состояния/событий СБИС (не квитанция!)
_ANSWERED_HINTS = (
    "отправлен ответ",
    "ответ отправлен",
    "ответ направлен",
    "направлен ответ",
    "документы представлены",
    "представление отправлено",
    "ответ на требование",
    "работа с требованием завершена",
    "требование завершено",
)
_NOT_ANSWER_ONLY_RECEIPT = (
    "отправлена квитанция",
    "квитанция о приеме",
    "квитанция о приёме",
    "подтвердить получение",
    "извещение о получении",
)


def _walk_strings(obj: Any, out: list[str], *, limit: int = 200) -> None:
    if len(out) >= limit:
        return
    if isinstance(obj, str):
        s = obj.strip()
        if s and len(s) < 500:
            out.append(s)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out, limit=limit)
            if len(out) >= limit:
                return
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, out, limit=limit)
            if len(out) >= limit:
                return


def detect_requirement_answered(read_result: dict) -> bool:
    """
    По карточке ПрочитатьДокумент: похоже, что ответ по существу уже ушёл.
    Квитанция о приёме (код 7 / «Отправлена квитанция») сама по себе НЕ считается ответом.
    """
    if not isinstance(read_result, dict):
        return False

    state = read_result.get("Состояние") if isinstance(read_result.get("Состояние"), dict) else {}
    state_blob = " ".join(
        [
            str(state.get("Код") or ""),
            str(state.get("Название") or ""),
            str(state.get("Описание") or ""),
            str(state.get("Примечание") or ""),
        ]
    ).lower()

    # явные намёки в состоянии
    if any(h in state_blob for h in _ANSWERED_HINTS):
        if not any(h in state_blob for h in _NOT_ANSWER_ONLY_RECEIPT) or "ответ" in state_blob:
            return True

    chunks: list[str] = []
    for key in ("Событие", "Этап", "Редакция", "Примечание", "Название"):
        if key in read_result:
            _walk_strings(read_result.get(key), chunks, limit=120)

    blob = " ".join(chunks).lower()
    if any(h in blob for h in _ANSWERED_HINTS):
        # отсечь ложные срабатывания только на квитанции
        if "квитанц" in blob and "ответ" not in blob and "представлен" not in blob:
            return False
        return True

    # вложения с типом/названием ответа (Представление / пояснения)
    atts = read_result.get("Вложение") or []
    if isinstance(atts, dict):
        atts = [atts]
    for a in atts:
        if not isinstance(a, dict):
            continue
        name = str(a.get("Название") or a.get("Имя") or "").lower()
        subtype = str(a.get("Подтип") or "").strip()
        cat = str(a.get("Категория") or "").lower()
        tip = str(a.get("Тип") or "").lower()
        line = f"{name} {subtype} {cat} {tip}"
        if any(
            x in line
            for x in (
                "представлен",
                "ответ на требован",
                "пояснен",
                "сведтреб",
            )
        ):
            return True
    return False


def extract_meta_from_read_document(
    read_result: dict,
    *,
    document_date: date | None = None,
) -> dict[str, Any]:
    """
    Из result ПрочитатьДокумент:
      response_due_date — поле «Срок»
      receipt_due_date — document_date + 6 раб. дней
      knd — Подтип документа, если похож на КНД
      is_answered — эвристика ответа по существу
      state_code / state_name
    """
    result = read_result if isinstance(read_result, dict) else {}
    state = result.get("Состояние") if isinstance(result.get("Состояние"), dict) else {}

    srok_raw = result.get("Срок")
    if srok_raw is None:
        srok_raw = ""
    response_due = parse_date_value(str(srok_raw))

    knd = None
    subtype = str(result.get("Подтип") or result.get("ПодТип") or "").strip()
    if re.fullmatch(r"\d{5,8}", subtype):
        knd = subtype

    return {
        "response_due_date": response_due,
        "receipt_due_date": receipt_due_from_document_date(document_date),
        "knd": knd,
        "is_answered": detect_requirement_answered(result),
        "state_code": str(state.get("Код") or "").strip() or None,
        "state_name": str(state.get("Название") or "").strip() or None,
        "srok_raw": str(srok_raw).strip(),
    }


def fetch_requirement_sbis_meta(
    inn: str,
    *,
    sbis_doc_id: str,
    document_date: date | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Auth (если нет session) + ПрочитатьДокумент + разбор мета.
    Возвращает {success, meta, error}.
    """
    from reports.models import Certificate
    from reports.services.sbis.auth import auth_sbis_by_cert
    from reports.services.sbis.crypto import export_cert_der, get_thumbprint_from_cert
    from reports.services.sbis.requirements import sbis_read_document

    inn = (inn or "").strip()
    sbis_doc_id = (sbis_doc_id or "").strip()
    if not inn or not sbis_doc_id:
        return {"success": False, "error": {"message": "inn и sbis_doc_id обязательны"}, "meta": {}}

    sid = (session_id or "").strip()
    if not sid:
        cert = (
            Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
            .exclude(csptest_name="")
            .order_by("-id")
            .first()
        ) or Certificate.objects.filter(inn=inn).exclude(csptest_name="").order_by("-id").first()
        if not cert or not cert.csptest_name:
            return {"success": False, "error": {"message": "нет сертификата"}, "meta": {}}
        cert_path = f"/tmp/sbis_req_meta_{inn}.cer"
        export_cert_der(cert.csptest_name, cert_path)
        thumb = get_thumbprint_from_cert(cert_path)
        try:
            sid = auth_sbis_by_cert(cert_path, thumb, inn=inn)
        except Exception as e:
            return {"success": False, "error": {"message": str(e)}, "meta": {}}

    read = sbis_read_document(inn, session_id=sid, doc_id=sbis_doc_id)
    if not read.get("success"):
        return {"success": False, "error": read.get("error") or {"message": "read failed"}, "meta": {}}

    meta = extract_meta_from_read_document(read.get("result") or {}, document_date=document_date)
    meta["session_id"] = sid
    return {"success": True, "meta": meta, "error": None}


def apply_sbis_meta_to_requirement(doc, meta: dict, *, mark_answered: bool = True) -> list[str]:
    """
    Обновить поля RequirementDocument из meta. Возвращает список изменённых полей.
    Не затирает уже заполненный response_due_date пустым Срок.
    Не понижает reply_status: sent остаётся sent.
    """
    from reports.models import RequirementDocument

    fields: list[str] = []
    if not meta:
        return fields

    due = meta.get("response_due_date")
    if due and doc.response_due_date != due:
        doc.response_due_date = due
        fields.append("response_due_date")

    if meta.get("receipt_due_date") and not doc.receipt_due_date:
        doc.receipt_due_date = meta["receipt_due_date"]
        fields.append("receipt_due_date")

    if meta.get("knd") and not doc.knd:
        doc.knd = meta["knd"]
        fields.append("knd")

    if mark_answered and meta.get("is_answered"):
        cur = (doc.reply_status or RequirementDocument.REPLY_STATUS_NONE).strip()
        if cur in (RequirementDocument.REPLY_STATUS_NONE, RequirementDocument.REPLY_STATUS_ERROR, ""):
            doc.reply_status = RequirementDocument.REPLY_STATUS_ANSWERED
            fields.append("reply_status")

    if fields:
        doc.save(update_fields=list(dict.fromkeys(fields)))
    return fields
