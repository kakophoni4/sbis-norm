"""
Сервисная логика работы с СБИС:

1. Авторизация по сертификату и получение session_id (SbisSessionService).
2. Получение входящих документов и преобразование их в MailRecord (SbisMailService).

Содержит вспомогательные функции для экспорта сертификата, получения отпечатка,
запроса зашифрованного ключа сессии и его расшифровки с помощью CryptoPro, а также
JSON-RPC обёртку и утилиты для работы с документами СБИС.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

import requests
from django.conf import settings

from ..models import Certificate, CertificateAuditLog
from .sbis import auth_sbis_by_cert, export_cert_der, get_thumbprint_from_cert  # noqa: F401
from .sbis.constants import CertInvalidNoRetryError

logger = logging.getLogger(__name__)

DEFAULT_CERTMGR_PATH = "/opt/cprocsp/bin/amd64/certmgr"
DEFAULT_CRYPTCP_PATH = "/opt/cprocsp/bin/amd64/cryptcp"
DEFAULT_SBIS_AUTH_URL = "https://online.sbis.ru/auth/service/"
DEFAULT_SBIS_SERVICE_URL = "https://online.sbis.ru/service/"
DEFAULT_REQUEST_TIMEOUT = 60  # seconds

SBIS_THUMBPRINT_PATTERN = re.compile(r"SHA1 Thumbprint\s*:\s*([A-Fa-f0-9]+)")

SBIS_AUTH_AUDIT_ACTION = "SBIS_AUTH"


def _csp_use_sudo() -> bool:
    """
    Если True, certmgr/cryptcp вызываются через sudo (ключи в /var/opt/cprocsp/keys/root).
    Нужно, когда Django запущен от devuser, а ключи ставились под root.
    """
    return getattr(settings, "CSP_USE_SUDO", True)
SBIS_FETCH_MAIL_AUDIT_ACTION = "SBIS_FETCH_MAIL"


class SbisAuthError(Exception):
    """Базовое исключение для ошибок авторизации в СБИС."""


class SbisCertificateExportError(SbisAuthError):
    """Ошибка экспорта сертификата certmgr."""


class SbisThumbprintError(SbisAuthError):
    """Ошибка получения отпечатка сертификата."""


class SbisApiError(SbisAuthError):
    """Ошибка вызова HTTP API СБИС."""


class SbisDecryptError(SbisAuthError):
    """Ошибка расшифровки ключа сессии."""


@dataclass
class AttachmentMeta:
    """Метаданные вложения документа СБИС."""
    name: str
    sbis_id: Optional[str] = None
    category: Optional[str] = None
    size: Optional[int] = None


@dataclass
class MailRecord:
    """Нормализованное представление входящего письма из СБИС."""
    inn: str
    requested_date: date
    sbis_document_id: str
    theme: str
    received_at: datetime
    email: Optional[str]
    attachments: List[AttachmentMeta] = field(default_factory=list)
    raw_document: Dict[str, Any] = field(default_factory=dict)


def _sanitize_inn(value: Optional[str]) -> str:
    """Возвращает строковое значение ИНН, пригодное для записи в БД."""
    if isinstance(value, str):
        return value.strip()
    return ""


def export_certificate_base64(
    certificate: Certificate,
    *,
    certmgr_path: Optional[str] = None,
) -> str:
    """
    Экспортирует сертификат из контейнера и возвращает Base64.
    """
    if not certificate.csptest_name:
        raise SbisCertificateExportError("Не указано имя контейнера сертификата (csptest_name)")

    path = certmgr_path or getattr(settings, "CERTMGR_PATH", DEFAULT_CERTMGR_PATH)
    if not path:
        raise SbisCertificateExportError("Путь к утилите certmgr не настроен")

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_path = temp_file.name
    temp_file.close()

    base_cmd = [
        path,
        "-export",
        "-cont",
        certificate.csptest_name,
        "-dest",
        temp_path,
    ]
    command = (["sudo"] + base_cmd) if _csp_use_sudo() else base_cmd

    logger.debug(
        "Экспорт сертификата через certmgr (certificate_id=%s, command=%s)",
        certificate.pk,
        command,
    )

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        if result.stdout:
            logger.debug("certmgr stdout: %s", result.stdout.strip())

        with open(temp_path, "rb") as exported:
            encoded = base64.b64encode(exported.read()).decode("utf-8")

        if not encoded:
            raise SbisCertificateExportError("Экспортированный сертификат пуст")

        return encoded
    except FileNotFoundError as exc:
        raise SbisCertificateExportError(f"certmgr не найден по пути {path}") from exc
    except subprocess.CalledProcessError as exc:
        error_message = (exc.stderr or exc.stdout or "").strip()
        raise SbisCertificateExportError(
            error_message or "Не удалось экспортировать сертификат"
        ) from exc
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning(
                    "Не удалось удалить временный файл сертификата %s",
                    temp_path,
                    exc_info=True,
                )


def ensure_thumbprint(
    certificate: Certificate,
    *,
    certmgr_path: Optional[str] = None,
) -> str:
    """
    Возвращает SHA1 отпечаток сертификата. Если отсутствует — извлекает его,
    обновляет модель сертификата и возвращает.
    """
    if certificate.thumbprint:
        return certificate.thumbprint

    if not certificate.csptest_name:
        raise SbisThumbprintError("Не указано имя контейнера сертификата (csptest_name)")

    path = certmgr_path or getattr(settings, "CERTMGR_PATH", DEFAULT_CERTMGR_PATH)
    if not path:
        raise SbisThumbprintError("Путь к утилите certmgr не настроен")

    base_cmd = [
        path,
        "-list",
        "-cont",
        certificate.csptest_name,
    ]
    command = (["sudo"] + base_cmd) if _csp_use_sudo() else base_cmd

    logger.debug(
        "Получение отпечатка сертификата (certificate_id=%s, command=%s)",
        certificate.pk,
        command,
    )

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SbisThumbprintError(f"certmgr не найден по пути {path}") from exc
    except subprocess.CalledProcessError as exc:
        error_message = (exc.stderr or exc.stdout or "").strip()
        raise SbisThumbprintError(
            error_message or "Не удалось получить отпечаток сертификата"
        ) from exc

    match = SBIS_THUMBPRINT_PATTERN.search(result.stdout or "")
    if not match:
        raise SbisThumbprintError("В выводе certmgr не найден SHA1 thumbprint")

    thumbprint = match.group(1).strip()
    logger.debug(
        "Отпечаток сертификата получен (certificate_id=%s, thumbprint=%s)",
        certificate.pk,
        thumbprint,
    )

    try:
        certificate.thumbprint = thumbprint
        certificate.save(update_fields=["thumbprint"])
    except Exception:
        logger.exception(
            "Не удалось сохранить отпечаток сертификата (certificate_id=%s)",
            certificate.pk,
        )

    return thumbprint


def fetch_encrypted_session_key(
    cert_data_b64: str,
    *,
    auth_url: Optional[str] = None,
    timeout: Optional[float] = None,
    verify: Optional[bool] = None,
    http_session: Optional[requests.Session] = None,
) -> str:
    """
    Делает HTTP-запрос в СБИС и возвращает зашифрованный ключ сессии (Base64).
    """
    url = auth_url or getattr(settings, "SBIS_AUTH_URL", DEFAULT_SBIS_AUTH_URL)
    request_timeout = (
        timeout
        if timeout is not None
        else getattr(settings, "SBIS_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)
    )
    verify_ssl = (
        verify
        if verify is not None
        else getattr(settings, "SBIS_VERIFY_SSL", True)
    )

    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": {"ДвоичныеДанные": cert_data_b64}},
        "id": 1,
    }

    session = http_session or requests.Session()
    close_session = http_session is None

    logger.debug(
        "Отправка запроса на авторизацию в СБИС (url=%s, timeout=%s, verify_ssl=%s)",
        url,
        request_timeout,
        verify_ssl,
    )

    try:
        response = session.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            timeout=request_timeout,
            verify=verify_ssl,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SbisApiError(f"Ошибка запроса к сервису СБИС: {exc}") from exc
    finally:
        if close_session:
            session.close()

    try:
        data = response.json()
    except ValueError as exc:
        raise SbisApiError("Сервис СБИС вернул некорректный JSON") from exc

    if data.get("error"):
        raise SbisApiError(json.dumps(data["error"], ensure_ascii=False))

    result = data.get("result")
    encrypted_key: Optional[str] = None

    if isinstance(result, str):
        encrypted_key = result.strip()
    elif isinstance(result, dict):
        candidate_keys = (
            "Ключ",
            "Key",
            "SessionKey",
            "sessionKey",
            "ДвоичныеДанные",
            "BinaryData",
            "binary",
        )
        for key in candidate_keys:
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                encrypted_key = value.strip()
                break

    if not encrypted_key:
        raise SbisApiError(
            "В ответе сервиса СБИС отсутствует зашифрованный ключ сессии"
        )

    return encrypted_key


def decrypt_session_key(
    encrypted_key_b64: str,
    *,
    thumbprint: str,
    cryptcp_path: Optional[str] = None,
    csptest_name: Optional[str] = None,
) -> str:
    """
    Расшифровывает ключ сессии с помощью cryptcp и возвращает session_id.

    Если передан csptest_name (имя контейнера как в csptest), используется -cont,
    иначе поиск по отпечатку сертификата (-thumbprint).
    """
    if not thumbprint and not csptest_name:
        raise SbisDecryptError(
            "Не указан ни отпечаток сертификата, ни имя контейнера (csptest_name)"
        )

    path = cryptcp_path or getattr(settings, "CRYPTCP_PATH", DEFAULT_CRYPTCP_PATH)
    if not path:
        raise SbisDecryptError("Путь к утилите cryptcp не настроен")

    try:
        encrypted_bytes = base64.b64decode(encrypted_key_b64)
    except (binascii.Error, ValueError) as exc:
        raise SbisDecryptError(f"Некорректная строка Base64: {exc}") from exc

    enc_file = tempfile.NamedTemporaryFile(delete=False)
    enc_file.write(encrypted_bytes)
    enc_file.flush()
    enc_file.close()
    enc_path = enc_file.name

    dec_fd, dec_path = tempfile.mkstemp()
    os.close(dec_fd)

    base_cmd = [path, "-decr"]
    if csptest_name:
        base_cmd += ["-cont", csptest_name]
    else:
        base_cmd += ["-thumbprint", thumbprint]
    base_cmd += [enc_path, dec_path]
    command = (["sudo"] + base_cmd) if _csp_use_sudo() else base_cmd

    logger.debug(
        "Расшифровка ключа сессии через cryptcp (thumbprint=%s, csptest_name=%s, command=%s)",
        thumbprint,
        csptest_name,
        command,
    )

    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        with open(dec_path, "rb") as decrypted_file:
            data = decrypted_file.read()

        try:
            session_id = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            session_id = data.decode("cp1251").strip()

        if not session_id:
            raise SbisDecryptError("Расшифрованный session_id пуст")

        return session_id
    except FileNotFoundError as exc:
        raise SbisDecryptError(f"cryptcp не найден по пути {path}") from exc
    except subprocess.CalledProcessError as exc:
        error_message = (exc.stderr or exc.stdout or "").strip()
        raise SbisDecryptError(
            error_message or "Ошибка команды cryptcp при расшифровке ключа"
        ) from exc
    finally:
        for file_path in (enc_path, dec_path):
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    logger.warning(
                        "Не удалось удалить временный файл %s",
                        file_path,
                        exc_info=True,
                    )



def _sbis_rpc_call(
    session_id: str,
    method: str,
    params: Dict[str, Any],
    *,
    service_url: Optional[str] = None,
    timeout: Optional[float] = None,
    verify: Optional[bool] = None,
    http_session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """
    Унифицированный JSON-RPC запрос в СБИС.
    """
    url = service_url or getattr(settings, "SBIS_SERVICE_URL", DEFAULT_SBIS_SERVICE_URL)
    request_timeout = (
        timeout
        if timeout is not None
        else getattr(settings, "SBIS_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)
    )
    verify_ssl = (
        verify
        if verify is not None
        else getattr(settings, "SBIS_VERIFY_SSL", True)
    )

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-SBISSessionID": session_id,
    }
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }

    session = http_session or requests.Session()
    close_session = http_session is None

    logger.debug(
        "SBIS RPC call (method=%s, url=%s, params=%s)",
        method,
        url,
        params,
    )

    try:
        response = session.post(
            url,
            json=payload,
            headers=headers,
            timeout=request_timeout,
            verify=verify_ssl,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SbisApiError(f"Ошибка RPC-запроса к СБИС: {exc}") from exc
    finally:
        if close_session:
            session.close()

    try:
        data = response.json()
    except ValueError as exc:
        raise SbisApiError("Сервис СБИС вернул некорректный JSON") from exc

    if data.get("error"):
        logger.error("SBIS RPC error (method=%s): %s", method, data["error"])
        raise SbisApiError(json.dumps(data["error"], ensure_ascii=False))

    return data.get("result") or {}


def fetch_incoming_documents(
    session_id: str,
    *,
    days_back: int = 7,
    inn_filter: Optional[str] = None,
    include_keywords: Optional[List[str]] = None,
    fns_prefixes: Optional[List[str]] = None,
    service_url: Optional[str] = None,
    timeout: Optional[float] = None,
    verify: Optional[bool] = None,
    http_session: Optional[requests.Session] = None,
) -> List[Dict[str, Any]]:
    """
    Возвращает список входящих документов за период, опционально фильтруя по ИНН/ключевым словам.
    """
    now = datetime.now()
    date_to = now.strftime("%d.%m.%Y")
    date_from = (now - timedelta(days=max(days_back, 0))).strftime("%d.%m.%Y")

    params = {
        "Фильтр": {
            "ДатаС": date_from,
            "ДатаПо": date_to,
            "ТипРеестра": "Входящие",
        }
    }

    result = _sbis_rpc_call(
        session_id,
        "СБИС.СписокДокументовПоСобытиям",
        params,
        service_url=service_url,
        timeout=timeout,
        verify=verify,
        http_session=http_session,
    )

    registry = result.get("Реестр") or []
    include_keywords = include_keywords or getattr(settings, "FNS_KEYWORDS", [])
    fns_prefixes = fns_prefixes or getattr(settings, "FNS_INN_PREFIXES", [])

    filtered: List[Dict[str, Any]] = []

    for entry in registry:
        document = entry.get("Документ") or {}
        kontragent = document.get("Контрагент") or {}

        inn = None
        if "СвЮЛ" in kontragent:
            inn = kontragent["СвЮЛ"].get("ИНН")
        elif "СвФЛ" in kontragent:
            inn = kontragent["СвФЛ"].get("ИНН")

        # Дополнительный фильтр по ИНН (если требуется совпадение с конкретным получателем)
        if inn_filter and inn != inn_filter:
            continue

        # Определяем, что документ от ФНС
        is_fns = False
        if inn:
            is_fns = any(inn.startswith(prefix) for prefix in fns_prefixes)

        if not is_fns:
            title = str(document.get("Название") or "").lower()
            is_fns = any(keyword.lower() in title for keyword in include_keywords)

        if is_fns:
            filtered.append(document)

    logger.info(
        "Получено %d входящих документов, отфильтровано %d документов ФНС",
        len(registry),
        len(filtered),
    )
    return filtered


def parse_sbis_datetime(value: str) -> datetime:
    """
    Преобразует дату/дату-время СБИС в datetime.
    Поддерживаем форматы:
      - 26.11.2024 15:45:00
      - 26.11.2024 15:45
      - 26.11.2024
    """
    candidates = (
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y",
    )
    clean = (value or "").strip()
    for fmt in candidates:
        try:
            return datetime.strptime(clean[: len(fmt)], fmt)
        except ValueError:
            continue
    raise ValueError(f"Не удалось разобрать дату СБИС: {value!r}")


def filter_documents_by_date(
    documents: List[Dict[str, Any]],
    target_date: date,
) -> List[Dict[str, Any]]:
    """
    Возвращает документы, дата которых совпадает с target_date.
    """
    matches = []
    for doc in documents:
        raw_date = (
            doc.get("ДатаВремя")
            or doc.get("Дата")
            or doc.get("ДатаСоздания")
            or doc.get("ДатаДокумента")
        )
        if not raw_date:
            continue
        try:
            dt = parse_sbis_datetime(str(raw_date))
        except ValueError:
            logger.debug("Не удалось разобрать дату документа: %s", raw_date)
            continue

        if dt.date() == target_date:
            matches.append(doc)

    logger.debug(
        "Документы, совпадающие с датой %s: %d из %d",
        target_date,
        len(matches),
        len(documents),
    )
    return matches


def extract_email_from_doc(doc: Dict[str, Any]) -> Optional[str]:
    """
    Пытается извлечь email из структуры документа.
    Возвращает None, если подходящих полей не найдено.
    """
    candidates = [
        doc.get("Почта"),
        doc.get("Email"),
        doc.get("E-mail"),
        doc.get("АдресПочты"),
        doc.get("АдресЭлектроннойПочты"),
        (doc.get("Контакт") or {}).get("Email"),
        (doc.get("Контакт") or {}).get("E-mail"),
    ]

    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()

    # Попытка вытащить из комментариев/описания
    comment = str(doc.get("Комментарий") or doc.get("Описание") or "")
    email_match = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", comment, re.IGNORECASE)
    if email_match:
        return email_match.group(0)

    return None


def extract_attachments(doc: Dict[str, Any]) -> List[AttachmentMeta]:
    """
    Преобразует блок вложений документа в список AttachmentMeta.
    """
    attachments: List[AttachmentMeta] = []
    raw_attachments = doc.get("Вложение") or doc.get("Вложения") or []

    for item in raw_attachments:
        if not isinstance(item, dict):
            continue
        attachments.append(
            AttachmentMeta(
                name=item.get("Название")
                or item.get("Имя")
                or item.get("ИмяФайла")
                or "без_названия",
                sbis_id=str(item.get("Идентификатор") or item.get("Ид")) if item.get("Идентификатор") or item.get("Ид") else None,
                category=item.get("Категория"),
                size=item.get("Размер"),
            )
        )

    return attachments


@dataclass
class SbisSessionService:
    """
    Высокоуровневый сервис авторизации в СБИС по сертификату.

    Пример использования:
        service = SbisSessionService(certificate=cert)
        session_id = service.authenticate()
    """

    certificate: Certificate
    certmgr_path: Optional[str] = None
    cryptcp_path: Optional[str] = None
    auth_url: Optional[str] = None
    request_timeout: Optional[float] = None
    verify_ssl: Optional[bool] = None
    http_session: Optional[requests.Session] = field(
        default=None, repr=False, compare=False
    )
    progress_callback: Optional[Callable[[str], None]] = field(
        default=None, repr=False, compare=False
    )
    proxy_want: Optional[int] = field(default=None, repr=False, compare=False)
    proxy_warmup_budget_sec: Optional[int] = field(default=None, repr=False, compare=False)

    def authenticate(self) -> str:
        """
        Возвращает session_id через тот же путь, что и send_nds_extra:
        экспорт серта в файл → thumbprint из файла → auth_sbis_by_cert.
        """
        logger.debug(
            "Начало авторизации в СБИС (certificate_id=%s)",
            self.certificate.pk,
        )
        inn_value = _sanitize_inn(getattr(self.certificate, "inn", None)) or "unknown"
        if not self.certificate.csptest_name:
            self._write_audit("ERROR", "Не указано имя контейнера (csptest_name)")
            raise SbisAuthError("Не указано имя контейнера сертификата (csptest_name)")

        def _progress(msg: str) -> None:
            if self.progress_callback:
                self.progress_callback(msg)

        fd, cert_path = tempfile.mkstemp(prefix=f"sbis_auth_{inn_value}_", suffix=".cer")
        os.close(fd)
        try:
            _progress("Экспорт сертификата в файл (certmgr -export)...")
            export_cert_der(self.certificate.csptest_name, cert_path)
            _progress("Отпечаток из файла (certmgr -list -file)...")
            thumbprint = get_thumbprint_from_cert(cert_path)
            _progress("Авторизация в СБИС (HTTP + cryptcp -decr)...")
            auth_kw: dict = {}
            if self.proxy_want is not None:
                auth_kw["proxy_want"] = self.proxy_want
            if self.proxy_warmup_budget_sec is not None:
                auth_kw["proxy_warmup_budget_sec"] = self.proxy_warmup_budget_sec
            session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn_value, **auth_kw)
        except CertInvalidNoRetryError as exc:
            self._write_audit("ERROR", str(exc))
            logger.error(
                "Авторизация в СБИС завершилась ошибкой (certificate_id=%s): %s",
                self.certificate.pk,
                exc,
            )
            raise SbisAuthError(str(exc)) from exc
        except (SbisAuthError, RuntimeError) as exc:
            self._write_audit("ERROR", str(exc))
            logger.error(
                "Авторизация в СБИС завершилась ошибкой (certificate_id=%s): %s",
                self.certificate.pk,
                exc,
                exc_info=not isinstance(exc, RuntimeError),
            )
            raise SbisAuthError(str(exc)) from exc
        except Exception as exc:
            message = f"Неизвестная ошибка авторизации: {exc}"
            self._write_audit("ERROR", message)
            logger.exception(
                "Неизвестная ошибка авторизации в СБИС (certificate_id=%s)",
                self.certificate.pk,
            )
            raise SbisAuthError(message) from exc
        finally:
            if os.path.exists(cert_path):
                try:
                    os.remove(cert_path)
                except OSError:
                    logger.warning("Не удалось удалить временный файл %s", cert_path)

        self._write_audit("SUCCESS", "Получен session_id")
        logger.info(
            "session_id успешно получен (certificate_id=%s)",
            self.certificate.pk,
        )
        return session_id

    def _write_audit(self, status: str, message: str) -> None:
        message = (message or "").strip()
        if len(message) > 1000:
            message = f"{message[:997]}..."

        inn_value = _sanitize_inn(getattr(self.certificate, "inn", None))

        try:
            CertificateAuditLog.objects.create(
                inn=inn_value,
                cert=self.certificate,
                action=SBIS_AUTH_AUDIT_ACTION,
                status=status,
                message=message,
            )
        except Exception:
            logger.exception(
                "Не удалось записать аудит авторизации (certificate_id=%s)",
                self.certificate.pk,
            )

    def _get_certmgr_path(self) -> str:
        return self.certmgr_path or getattr(
            settings, "CERTMGR_PATH", DEFAULT_CERTMGR_PATH
        )

    def _get_cryptcp_path(self) -> str:
        return self.cryptcp_path or getattr(
            settings, "CRYPTCP_PATH", DEFAULT_CRYPTCP_PATH
        )

    def _get_auth_url(self) -> str:
        return self.auth_url or getattr(settings, "SBIS_AUTH_URL", DEFAULT_SBIS_AUTH_URL)

    def _get_request_timeout(self) -> float:
        if self.request_timeout is not None:
            return self.request_timeout
        return getattr(settings, "SBIS_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)

    def _get_verify_ssl(self) -> bool:
        if self.verify_ssl is not None:
            return self.verify_ssl
        return getattr(settings, "SBIS_VERIFY_SSL", True)


@dataclass
class SbisMailService:
    """
    Сервис получения входящих документов (писем) из СБИС.
    """

    certificate: Certificate
    certmgr_path: Optional[str] = None
    cryptcp_path: Optional[str] = None
    auth_url: Optional[str] = None
    service_url: Optional[str] = None
    request_timeout: Optional[float] = None
    verify_ssl: Optional[bool] = None
    http_session: Optional[requests.Session] = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._session_service = SbisSessionService(
            certificate=self.certificate,
            certmgr_path=self.certmgr_path,
            cryptcp_path=self.cryptcp_path,
            auth_url=self.auth_url,
            request_timeout=self.request_timeout,
            verify_ssl=self.verify_ssl,
            http_session=self.http_session,
        )

    def fetch_mail_for_date(
        self,
        requested_date: date,
        *,
        days_back: Optional[int] = None,
        include_attachments: bool = False,
        inn_filter: Optional[str] = None,
        include_keywords: Optional[List[str]] = None,
        fns_prefixes: Optional[List[str]] = None,
    ) -> Optional[MailRecord]:
        """
        Возвращает MailRecord для указанной даты или None, если документы не найдены.
        """
        effective_days_back = (
            days_back
            if days_back is not None
            else getattr(settings, "SBIS_INCOMING_DAYS_BACK", 7)
        )

        try:
            session_id = self._session_service.authenticate()

            documents = fetch_incoming_documents(
                session_id,
                days_back=effective_days_back,
                inn_filter=inn_filter,
                include_keywords=include_keywords,
                fns_prefixes=fns_prefixes,
                service_url=self._get_service_url(),
                timeout=self._get_request_timeout(),
                verify=self._get_verify_ssl(),
                http_session=self.http_session,
            )

            matched = filter_documents_by_date(documents, requested_date)

            if not matched:
                message = f"Документы за {requested_date} не найдены"
                logger.info(message)
                self._write_audit("SUCCESS", message)
                return None

            doc = matched[0]
            raw_date = (
                doc.get("ДатаВремя")
                or doc.get("Дата")
                or doc.get("ДатаСоздания")
                or doc.get("ДатаДокумента")
            )
            if not raw_date:
                raise SbisApiError("У документа отсутствует поле с датой")

            received_at = parse_sbis_datetime(str(raw_date))
            attachments = extract_attachments(doc) if include_attachments else []

            record = MailRecord(
                inn=_sanitize_inn(getattr(self.certificate, "inn", "")),
                requested_date=requested_date,
                sbis_document_id=str(
                    doc.get("Идентификатор")
                    or doc.get("ID")
                    or doc.get("DocID")
                    or ""
                ),
                theme=str(doc.get("Название") or ""),
                received_at=received_at,
                email=extract_email_from_doc(doc),
                attachments=attachments,
                raw_document=doc,
            )

            self._write_audit(
                "SUCCESS",
                f"Получен документ {record.sbis_document_id or 'UNKNOWN_ID'} за {requested_date}",
            )
            logger.info(
                "Получен документ СБИС (certificate_id=%s, doc_id=%s, date=%s)",
                self.certificate.pk,
                record.sbis_document_id,
                requested_date,
            )
            return record
        except SbisAuthError:
            raise  # уже залогировано внутри SbisSessionService
        except Exception as exc:
            message = f"Ошибка получения документов: {exc}"
            self._write_audit("ERROR", message)
            logger.exception(
                "Ошибка получения документов из СБИС (certificate_id=%s)",
                self.certificate.pk,
            )
            raise

    def _write_audit(self, status: str, message: str) -> None:
        message = (message or "").strip()
        if len(message) > 1000:
            message = f"{message[:997]}..."

        inn_value = _sanitize_inn(getattr(self.certificate, "inn", None))

        try:
            CertificateAuditLog.objects.create(
                inn=inn_value,
                cert=self.certificate,
                action=SBIS_FETCH_MAIL_AUDIT_ACTION,
                status=status,
                message=message,
            )
        except Exception:
            logger.exception(
                "Не удалось записать аудит получения писем (certificate_id=%s)",
                self.certificate.pk,
            )

    def _get_service_url(self) -> str:
        return self.service_url or getattr(
            settings, "SBIS_SERVICE_URL", DEFAULT_SBIS_SERVICE_URL
        )

    def _get_request_timeout(self) -> float:
        if self.request_timeout is not None:
            return self.request_timeout
        return getattr(settings, "SBIS_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)

    def _get_verify_ssl(self) -> bool:
        if self.verify_ssl is not None:
            return self.verify_ssl
        return getattr(settings, "SBIS_VERIFY_SSL", True)


__all__ = [
    "AttachmentMeta",
    "MailRecord",
    "SbisSessionService",
    "SbisMailService",
    "SbisAuthError",
    "SbisCertificateExportError",
    "SbisThumbprintError",
    "SbisApiError",
    "SbisDecryptError",
    "export_certificate_base64",
    "ensure_thumbprint",
    "fetch_encrypted_session_key",
    "decrypt_session_key",
    "fetch_incoming_documents",
    "filter_documents_by_date",
    "extract_email_from_doc",
    "extract_attachments",
    "parse_sbis_datetime",
]
