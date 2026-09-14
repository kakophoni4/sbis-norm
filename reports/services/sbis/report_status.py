"""Пакетная проверка статуса исходящих отчётов и получение КВ/ИВ для 1С.

Этот модуль намеренно не сканирует все организации. 1С передаёт только свои
``sbis_doc_id``; запросы группируются по ИНН, поэтому на пачку документов
используется ровно одна аутентификация и одна сессия СБИС на организацию.
"""

import base64
import hashlib
import io
import logging
import re
import zipfile
from pathlib import Path

from django.conf import settings

from .auth import sbis_auth_session_for_inn
from .client import _sbis_get, sbis_rpc
from .receipts import _download_archive_zip


logger = logging.getLogger(__name__)

METHOD_READ_DOCUMENT = "СБИС.ПрочитатьДокумент"
FILES_ROOT = Path(settings.MEDIA_ROOT) / "one_c_receipts"

# Коды встречаются в списке исходящих документов СБИС. Неизвестный код не
# подменяем догадкой: он возвращается 1С как ``unknown`` вместе с raw_state.
STATUS_BY_CODE = {
    "0": ("created", "Черновик создан"),
    "1": ("preparing", "Подготавливается"),
    "2": ("signing", "Подписывается"),
    "3": ("sent", "Отправлен, ожидается доставка"),
    "4": ("delivered", "Доставлен, ожидается результат обработки"),
    "5": ("processing", "Обрабатывается"),
    "6": ("processing", "Обрабатывается"),
    "7": ("accepted", "Принят"),
    "8": ("rejected", "Отклонён"),
    "9": ("rejected", "Не принят"),
}


def _as_list(value):
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else []


def _attachments(raw: dict) -> list[dict]:
    """Собрать вложения и с карточки, и со всех её этапов."""
    found: list[dict] = []

    def walk(value) -> None:
        if len(found) >= 80:
            return
        if isinstance(value, dict):
            for attachment in _as_list(value.get("Вложение")):
                if isinstance(attachment, dict):
                    found.append(attachment)
            for nested in value.values():
                if isinstance(nested, (dict, list)):
                    walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(raw)
    unique: list[dict] = []
    seen: set[str] = set()
    for attachment in found:
        file_data = attachment.get("Файл") if isinstance(attachment.get("Файл"), dict) else {}
        key = str(
            attachment.get("Идентификатор")
            or file_data.get("Идентификатор")
            or file_data.get("Ссылка")
            or file_data.get("Имя")
            or id(attachment)
        )
        if key not in seen:
            seen.add(key)
            unique.append(attachment)
    return unique


def _find_kv_iv(raw: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for attachment in _attachments(raw):
        file_data = attachment.get("Файл") if isinstance(attachment.get("Файл"), dict) else {}
        filename = str(file_data.get("Имя") or attachment.get("Название") or "")
        upper_name = Path(filename).name.upper()
        if upper_name.startswith("KV_") and not upper_name.startswith("IZ_"):
            result.setdefault("kv", attachment)
        elif upper_name.startswith("IV_") and not upper_name.startswith("IZ_"):
            result.setdefault("iv", attachment)
    return result


def _pdf_url(attachment: dict | None) -> str:
    if not isinstance(attachment, dict):
        return ""
    file_data = attachment.get("Файл") if isinstance(attachment.get("Файл"), dict) else {}
    for source in (attachment, file_data):
        for key in ("СсылкаНаPDF", "СсылкаPDF", "Ссылка"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _state(raw: dict) -> dict:
    state = raw.get("Состояние") if isinstance(raw.get("Состояние"), dict) else {}
    code = str(
        state.get("Код")
        or raw.get("КодСостояния")
        or raw.get("СтатусКод")
        or ""
    ).strip()
    title = str(state.get("Название") or raw.get("Статус") or "").strip()
    description = str(state.get("Описание") or "").strip()
    internal, default_title = STATUS_BY_CODE.get(code, ("unknown", "Неизвестный статус"))
    text = " ".join((title, description)).lower()
    if internal == "unknown":
        if any(x in text for x in ("не принят", "отказ", "отклон", "ошибк")):
            internal = "rejected"
        elif any(x in text for x in ("принят", "сдан", "успеш")):
            internal = "accepted"
        elif any(x in text for x in ("достав", "ожида")):
            internal = "delivered"
    return {
        "code": code or None,
        "status": internal,
        "title": title or default_title,
        "description": description or None,
        "raw_state": state or None,
    }


def _safe_part(value: str) -> str:
    return re.sub(r"[^A-Za-zА-Яа-я0-9_.-]+", "_", value or "")[:120] or "unknown"


def _cache_path(inn: str, doc_id: str, kind: str) -> Path:
    return FILES_ROOT / _safe_part(inn) / _safe_part(doc_id) / f"{kind}.pdf"


def _file_payload(path: Path, *, source: str, include_content: bool) -> dict:
    content = path.read_bytes()
    payload = {
        "state": "ready",
        "filename": path.name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "source": source,
    }
    if include_content:
        payload["content_b64"] = base64.b64encode(content).decode("ascii")
    return payload


def _cached_file(inn: str, doc_id: str, kind: str, *, include_content: bool) -> dict | None:
    path = _cache_path(inn, doc_id, kind)
    if path.is_file() and path.stat().st_size > 1000:
        return _file_payload(path, source="cache", include_content=include_content)
    return None


def _save_pdf(inn: str, doc_id: str, kind: str, content: bytes, *, include_content: bool) -> dict:
    path = _cache_path(inn, doc_id, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return _file_payload(path, source="sbis", include_content=include_content)


def _download_pdf(inn: str, session_id: str, url: str) -> tuple[bytes | None, str | None]:
    try:
        response = _sbis_get(
            url,
            headers={"X-SBISSessionID": session_id},
            timeout=60,
            inn=inn,
            total_budget_sec=75,
        )
    except Exception as exc:
        return None, f"transport_error: {exc}"
    content = response.content or b""
    if response.status_code == 200 and content.startswith(b"%PDF"):
        return content, None
    body = (response.text or "")[:500].lower()
    if any(x in body for x in ("ещё формируется", "еще формируется", "формируется")):
        return None, "forming"
    return None, f"http_{response.status_code}"


def _pdfs_from_archive(inn: str, session_id: str, raw: dict) -> tuple[dict[str, bytes], str | None]:
    """Один fallback-запрос к архиву, если у КВ/ИВ нет прямой ссылки."""
    archive_url = str(raw.get("СсылкаНаАрхив") or "").strip()
    if not archive_url:
        return {}, "no_pdf_url"
    try:
        archive = _download_archive_zip(
            inn,
            session_id,
            archive_url,
            timeout=45,
            total_budget_sec=55,
            pdf_ready_attempts=1,
        )
        zf = zipfile.ZipFile(io.BytesIO(archive))
        files: dict[str, bytes] = {}
        for name in zf.namelist():
            basename = Path(name).name.upper()
            if not basename.endswith(".PDF"):
                continue
            kind = "kv" if basename.startswith("KV_") else "iv" if basename.startswith("IV_") else None
            if kind and kind not in files:
                content = zf.read(name)
                if content.startswith(b"%PDF"):
                    files[kind] = content
        return files, None
    except Exception as exc:
        text = str(exc).lower()
        return {}, "forming" if "формир" in text else f"archive_error: {exc}"


def _files_for_document(
    *, inn: str, doc_id: str, session_id: str, raw: dict, include_content: bool
) -> dict:
    attachments = _find_kv_iv(raw)
    files: dict[str, dict] = {}
    needs_archive = False
    for kind in ("kv", "iv"):
        cached = _cached_file(inn, doc_id, kind, include_content=include_content)
        if cached:
            files[kind] = cached
            continue
        attachment = attachments.get(kind)
        if not attachment:
            files[kind] = {"state": "missing"}
            continue
        url = _pdf_url(attachment)
        if not url:
            files[kind] = {"state": "no_pdf_url"}
            needs_archive = True
            continue
        content, error = _download_pdf(inn, session_id, url)
        if content:
            files[kind] = _save_pdf(inn, doc_id, kind, content, include_content=include_content)
        else:
            files[kind] = {"state": error or "download_error"}
            needs_archive = True

    if needs_archive:
        archive_files, archive_error = _pdfs_from_archive(inn, session_id, raw)
        for kind, content in archive_files.items():
            if files.get(kind, {}).get("state") != "ready":
                files[kind] = _save_pdf(inn, doc_id, kind, content, include_content=include_content)
        for kind in ("kv", "iv"):
            if files.get(kind, {}).get("state") not in ("ready", "missing") and archive_error:
                files[kind]["archive_fallback"] = archive_error
    return files


def _check_one(
    item: dict, *, session_id: str, include_files: bool, include_content: bool
) -> dict:
    inn = str(item["inn"]).strip()
    doc_id = str(item["sbis_doc_id"]).strip()
    result = {
        "external_id": item.get("external_id"),
        "inn": inn,
        "sbis_doc_id": doc_id,
        "success": False,
    }
    try:
        data = sbis_rpc(
            inn=inn,
            session_id=session_id,
            method=METHOD_READ_DOCUMENT,
            params={"Документ": {"Идентификатор": doc_id}},
            timeout=45,
            total_budget_sec=55,
        )
    except Exception as exc:
        result["error"] = {"type": "transport_error", "message": str(exc)}
        return result
    if data.get("error"):
        result["error"] = {"type": "sbis_error", "details": data["error"]}
        return result
    raw = data.get("result") or {}
    if not isinstance(raw, dict):
        result["error"] = {"type": "unexpected_response", "message": "СБИС вернул некорректную карточку документа"}
        return result
    state = _state(raw)
    result.update(success=True, **state)
    if include_files:
        if state["status"] == "accepted":
            result["files"] = _files_for_document(
                inn=inn,
                doc_id=doc_id,
                session_id=session_id,
                raw=raw,
                include_content=include_content,
            )
        else:
            result["files"] = {"kv": {"state": "not_requested"}, "iv": {"state": "not_requested"}}
    return result


def check_report_statuses(
    items: list,
    *,
    include_files: bool = False,
    include_content: bool = False,
) -> dict:
    """Проверить статусы и, опционально, получить КВ/ИВ для пачки 1С."""
    if not isinstance(items, list) or not items:
        return {"success": False, "error": {"message": "items должен быть непустым массивом"}, "items": []}
    if len(items) > 50:
        return {"success": False, "error": {"message": "За один запрос допускается не более 50 документов"}, "items": []}

    output: list[dict | None] = [None] * len(items)
    by_inn: dict[str, list[tuple[int, dict]]] = {}
    for index, raw_item in enumerate(items):
        item = raw_item if isinstance(raw_item, dict) else {}
        inn = str(item.get("inn") or "").strip()
        doc_id = str(item.get("sbis_doc_id") or "").strip()
        if not inn or not doc_id:
            output[index] = {
                "external_id": item.get("external_id"),
                "inn": inn or None,
                "sbis_doc_id": doc_id or None,
                "success": False,
                "error": {"type": "validation_error", "message": "Для каждого элемента обязательны inn и sbis_doc_id"},
            }
            continue
        by_inn.setdefault(inn, []).append((index, {**item, "inn": inn, "sbis_doc_id": doc_id}))

    for inn, group in by_inn.items():
        # Одна авторизация и одна SBIS-сессия на все документы организации.
        auth = sbis_auth_session_for_inn(inn, proxy_want=1, proxy_warmup_budget_sec=6)
        if not auth.get("success"):
            for index, item in group:
                output[index] = {
                    "external_id": item.get("external_id"), "inn": inn,
                    "sbis_doc_id": item["sbis_doc_id"], "success": False,
                    "error": {"type": "auth_error", "details": auth.get("error")},
                }
            continue
        session_id = auth["result"]["session_id"]
        for index, item in group:
            output[index] = _check_one(
                item,
                session_id=session_id,
                include_files=include_files,
                include_content=include_content,
            )

    final_items = [row for row in output if row is not None]
    return {
        "success": all(row.get("success") for row in final_items),
        "items": final_items,
        "summary": {
            "total": len(final_items),
            "ok": sum(bool(row.get("success")) for row in final_items),
            "errors": sum(not bool(row.get("success")) for row in final_items),
            "include_files": bool(include_files),
            "include_content": bool(include_content),
        },
    }
