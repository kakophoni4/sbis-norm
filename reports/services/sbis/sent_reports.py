"""Read-only 1C access to sent FNS reports. No prepare/execute/sign calls."""
import base64
import hashlib
import json
import os
import re
import tempfile
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo

from django.conf import settings

from .auth import sbis_auth_session_for_inn
from .client import sbis_rpc, _sbis_request


class ReportError(Exception):
    def __init__(self, code, message, status=502):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def validate_inn(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{10}|[0-9]{12}", value):
        raise ReportError("invalid_input", "inn: строка из 10 или 12 цифр", 400)
    return value


def validate_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ReportError("invalid_input", "sent_date: YYYY-MM-DD", 400)
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ReportError("invalid_input", "Некорректная sent_date", 400)


def validate_id(value):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ReportError("invalid_input", "sbis_doc_id: UUID документа", 400)


def _root():
    # Outside MEDIA_ROOT: originals must not become publicly accessible via /media/.
    return Path(getattr(settings, "ONEC_SENT_REPORTS_CACHE_DIR",
                        Path(settings.BASE_DIR) / "private_cache" / "sent_reports"))


def _read(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _session(inn):
    auth = sbis_auth_session_for_inn(inn, proxy_want=1, proxy_warmup_budget_sec=6)
    if not auth.get("success"):
        # Do not expose provider URLs, certificates or credentials in public errors.
        raise ReportError("sbis_auth_failed", "Не удалось авторизоваться в СБИС")
    return auth["result"]["session_id"]


def _rpc(inn, session, method, params):
    try:
        data = sbis_rpc(inn=inn, session_id=session, method=method, params=params,
                        timeout=20, total_budget_sec=25)
    except Exception:
        raise ReportError("sbis_transport_error", "СБИС временно недоступен")
    if not isinstance(data, dict) or data.get("error") or not isinstance(data.get("result"), dict):
        raise ReportError("sbis_error", "СБИС не вернул данные документа")
    return data["result"]


def _items(value):
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def _owned(doc, inn):
    org = doc.get("НашаОрганизация") or {}
    return any(str((org.get(k) or {}).get("ИНН", "")) == inn for k in ("СвЮЛ", "СвФЛ"))


def _sent(doc):
    state = str((doc.get("Состояние") or {}).get("Код", ""))
    return (doc.get("Направление") == "Исходящий" and doc.get("Удален") != "Да"
            and state not in ("0", "1", "2")
            and ((doc.get("Расширение") or {}).get("ЕстьДокументооборот") == "Да"
                 or state in ("3", "4", "5", "6", "7", "8", "9")))


def _datetime(value):
    try:
        return datetime.strptime(value, "%d.%m.%Y %H.%M.%S")
    except (TypeError, ValueError):
        return None


def _sent_at(doc):
    # Only actual outgoing declaration events, never creation/receipt timestamps.
    dates = []
    for event in _items(doc.get("Событие")):
        if (event.get("Название") == "ДекларацияНП"
                or str((event.get("Состояние") or {}).get("Код")) == "3"):
            value = _datetime(event.get("ДатаВремя"))
            if value:
                dates.append(value)
    return min(dates).isoformat() if dates else None


def _card(inn, session, doc_id):
    doc = _rpc(inn, session, "СБИС.ПрочитатьДокумент", {"Документ": {"Идентификатор": doc_id}})
    if not _owned(doc, inn) or str(doc.get("Идентификатор", "")).lower() != doc_id.lower():
        raise ReportError("document_mismatch", "Документ не принадлежит указанному ИНН", 404)
    if doc.get("Тип") != "ОтчетФНС" or not _sent(doc):
        raise ReportError("not_sent_report", "Это не отправленный отчёт ФНС", 409)
    return doc


def _date_cache_path(inn, doc):
    identity = {k: doc.get(k) for k in ("Идентификатор", "Редакция")}
    identity["НомерОтправки"] = (doc.get("Расширение") or {}).get("НомерОтправки")
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return _root() / inn / "dates" / (digest + ".json")


def list_sent_reports(inn, days):
    inn = validate_inn(inn)
    if type(days) is not int or not 1 <= days <= 3660:
        raise ReportError("invalid_input", "days: целое число от 1 до 3660", 400)
    today = datetime.now(ZoneInfo("Europe/Moscow")).date()
    since = today - timedelta(days=days - 1)
    deadline = time.monotonic() + 100
    session = _session(inn)
    result, issues, seen, pages = [], [], set(), 0
    complete = False
    try:
        # No date filter: SBIS filters DOCUMENT dates, not SEND dates.
        for page in range(100):
            if time.monotonic() >= deadline:
                raise ReportError("scan_limit", "Лимит времени; повторите запрос, даты уже проверенных документов сохранены")
            raw = _rpc(inn, session, "СБИС.СписокДокументов", {"Фильтр": {
                "Тип": "ОтчетФНС", "Направление": "Исходящий",
                # Session is authenticated for inn; verify ownership below.
                # A partial СвЮЛ filter (INN without KPP) is rejected by reporting API.
                "Навигация": {"РазмерСтраницы": "100", "Страница": str(page)},
            }})
            pages += 1
            docs = _items(raw.get("Документ"))
            new = 0
            for doc in docs:
                doc_id = doc.get("Идентификатор")
                if not doc_id or doc_id in seen:
                    continue
                seen.add(doc_id)
                new += 1
                if not _owned(doc, inn) or not _sent(doc):
                    continue
                cache_path = _date_cache_path(inn, doc)
                cached = _read(cache_path)
                sent_at = cached.get("sent_at") if isinstance(cached, dict) else None
                if not sent_at:
                    if time.monotonic() >= deadline:
                        raise ReportError("scan_limit", "Лимит времени; повторите запрос для продолжения проверки")
                    try:
                        detail = _card(inn, session, doc_id)
                        sent_at = _sent_at(detail)
                    except ReportError as exc:
                        issues.append({"sbis_doc_id": doc_id, "code": exc.code})
                        continue
                    if sent_at:
                        _write(cache_path, {"sent_at": sent_at})
                if not sent_at:
                    issues.append({"sbis_doc_id": doc_id, "code": "send_date_unknown"})
                    continue
                if not since.isoformat() <= sent_at[:10] <= today.isoformat():
                    continue
                ext, state = doc.get("Расширение") or {}, doc.get("Состояние") or {}
                try:
                    doc_date = datetime.strptime(doc.get("Дата", ""), "%d.%m.%Y").date().isoformat()
                except ValueError:
                    doc_date = None
                result.append({
                    "sbis_doc_id": doc_id, "document_date": doc_date,
                    "report_year": ext.get("Год") or None, "period_code": ext.get("КодПериода") or None,
                    "sent_at": sent_at, "sent_date": sent_at[:10],
                    "correction_number": ext.get("НомерКорректировки"),
                    "status_code": state.get("Код"), "status": state.get("Название"),
                    "status_description": state.get("Описание") or "",
                })
            more = (raw.get("Навигация") or {}).get("ЕстьЕще")
            if more == "Нет":
                complete = not issues
                break
            if more != "Да" or not new:
                raise ReportError("pagination_error", "СБИС вернул неполную или повторяющуюся навигацию")
        else:
            raise ReportError("scan_limit", "Достигнут лимит 100 страниц")
    except ReportError as exc:
        issues.append({"code": exc.code, "message": exc.message})
    return {"success": complete, "complete": complete, "inn": inn,
            "date_from": since.isoformat(), "date_to": today.isoformat(),
            "timezone": "Europe/Moscow", "document_type": "ОтчетФНС",
            "items": sorted(result, key=lambda x: (x["sent_at"], x["sbis_doc_id"]), reverse=True),
            "count": len(result), "pages_read": pages, "errors": issues}


def _download(inn, session, url):
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.port not in (None, 443)
            or not any(host == d or host.endswith("." + d) for d in ("sbis.ru", "saby.ru"))):
        raise ReportError("unsafe_file_url", "Недопустимый адрес вложения")
    response = _sbis_request("GET", url, inn=inn, headers={"X-SBISSessionID": session},
                             timeout=20, total_budget_sec=25, allow_redirects=False, stream=True)
    try:
        if response.status_code != 200:
            raise ReportError("file_download_failed", "СБИС не вернул исходный XML")
        chunks, size = [], 0
        deadline = time.monotonic() + 45
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > 64 * 1024 * 1024 or time.monotonic() > deadline:
                raise ReportError("file_limit", "Превышен лимит размера или времени скачивания", 413)
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        response.close()


def download_sent_report(inn, sbis_doc_id, sent_date):
    inn, doc_id, day = validate_inn(inn), validate_id(sbis_doc_id), validate_date(sent_date)
    path = _root() / inn / "packages" / doc_id / (day.isoformat() + ".json")
    cached = _read(path)
    if isinstance(cached, dict) and cached.get("success") and cached.get("files"):
        try:
            if (cached["inn"], cached["sbis_doc_id"], cached["sent_date"]) != (inn, doc_id, day.isoformat()):
                raise ValueError("cache identity mismatch")
            for file in cached["files"]:
                blob = base64.b64decode(file["content_base64"], validate=True)
                if len(blob) != file["size"] or hashlib.sha256(blob).hexdigest() != file["sha256"]:
                    raise ValueError("cache integrity mismatch")
        except (KeyError, TypeError, ValueError):
            pass
        else:
            return {**cached, "cached": True}
    session = _session(inn)
    doc = _card(inn, session, doc_id)
    deadline = time.monotonic() + 100
    sent_at = _sent_at(doc)
    if not sent_at:
        raise ReportError("send_date_unknown", "Не удалось подтвердить дату отправки", 409)
    if sent_at[:10] != day.isoformat():
        raise ReportError("send_date_mismatch", "Дата отправки не совпадает с карточкой СБИС", 409)
    files, seen, total = [], set(), 0
    # Prefer the attachments of the actual send event, not a later edited revision.
    attachments = _items(doc.get("Вложение"))
    for event in _items(doc.get("Событие")):
        event_time = _datetime(event.get("ДатаВремя"))
        if (event_time and event_time.isoformat() == sent_at and event.get("Вложение")
                and (event.get("Название") == "ДекларацияНП"
                     or str((event.get("Состояние") or {}).get("Код")) == "3")):
            attachments = _items(event["Вложение"])
            break
    for attachment in attachments:
        info = attachment.get("Файл") or {}
        name = str(info.get("Имя") or "")
        if (attachment.get("Направление") != "Исходящий"
                or attachment.get("Служебный") != "Нет" or attachment.get("Удален") == "Да"
                or not name.lower().endswith(".xml")):
            continue
        if "/" in name or "\\" in name or any(ord(c) < 32 for c in name):
            raise ReportError("invalid_filename", "Некорректное имя вложения")
        if name in seen:
            raise ReportError("ambiguous_files", "Повторяющееся имя XML в комплекте")
        seen.add(name)
        if len(files) >= 20:
            raise ReportError("package_too_large", "Комплект превышает 20 файлов", 413)
        if time.monotonic() > deadline:
            raise ReportError("download_timeout", "Превышен лимит времени скачивания")
        if attachment.get("Зашифрован") == "Да" or attachment.get("Упакован") == "Да":
            raise ReportError("unsupported_attachment", "XML зашифрован или упакован; комплект не сохранён")
        if not info.get("Ссылка"):
            raise ReportError("missing_file_url", "СБИС не вернул ссылку на исходный XML")
        try:
            content = _download(inn, session, info["Ссылка"])
        except ReportError:
            raise
        except Exception:
            raise ReportError("file_download_failed", "Ошибка скачивания XML")
        total += len(content)
        if len(files) >= 20 or total > 64 * 1024 * 1024:
            raise ReportError("package_too_large", "Комплект превышает 20 файлов или 64 МиБ", 413)
        # Parse solely to reject HTML/errors. Return original bytes, never reserialize XML.
        from defusedxml.ElementTree import fromstring
        try:
            root = fromstring(content)
            if root.tag.split("}")[-1] != "Файл":
                raise ValueError("Not a report XML")
        except Exception:
            raise ReportError("invalid_xml", "Вместо исходного отчёта получен некорректный XML")
        role = "purchase_book" if name.upper().startswith("NO_NDS.8_") else (
            "sales_book" if name.upper().startswith("NO_NDS.9_") else "report")
        files.append({"name": name, "role": role, "size": len(content),
                      "sha256": hashlib.sha256(content).hexdigest(),
                      "content_base64": base64.b64encode(content).decode("ascii")})
    if not files or not any(f["role"] == "report" for f in files):
        raise ReportError("report_xml_missing", "Исходный XML отчёта не найден", 404)
    result = {"success": True, "inn": inn, "sbis_doc_id": doc_id,
              "sent_date": day.isoformat(), "sent_at": sent_at, "cached": False, "files": files}
    # Only complete packages are committed, atomically. Failed downloads are retryable.
    _write(path, result)
    return result
