"""Хук на сохранение требования — webhook во внешний сервис (опционально)."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from django.conf import settings

logger = logging.getLogger(__name__)


def _serialize_for_webhook(doc) -> dict:
    return {
        "id": getattr(doc, "id", None),
        "inn": getattr(doc, "inn", None),
        "document_date": str(getattr(doc, "document_date", "") or ""),
        "sbis_doc_id": getattr(doc, "sbis_doc_id", None),
        "sbis_stage_id": getattr(doc, "sbis_stage_id", None),
        "doc_title": getattr(doc, "doc_title", None),
        "content_sha256": getattr(doc, "content_sha256", None),
        "storage_file_name": getattr(doc, "storage_file_name", None),
        "created_at": getattr(doc, "created_at", None).isoformat()
        if getattr(doc, "created_at", None)
        else None,
        # файл не шлём в webhook по умолчанию — внешний сервис тянет GET /requirements/<id>/
        "file_url_hint": f"/api/sbis/requirements/{getattr(doc, 'id', '')}/",
    }


def notify_requirement_saved(doc) -> None:
    """
    Вызывается после успешного сохранения RequirementDocument.
    Лог + опциональный HTTP POST на REQUIREMENTS_WEBHOOK_URL.
    """
    try:
        logger.info(
            "[requirements_notify] saved inn=%s doc_id=%s date=%s title=%s id=%s",
            getattr(doc, "inn", None),
            getattr(doc, "sbis_doc_id", None),
            getattr(doc, "document_date", None),
            (getattr(doc, "doc_title", None) or "")[:80],
            getattr(doc, "id", None),
        )
    except Exception:
        logger.exception("[requirements_notify] log failed")

    url = (getattr(settings, "REQUIREMENTS_WEBHOOK_URL", None) or "").strip()
    if not url:
        return

    payload = _serialize_for_webhook(doc)
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8"}
    token = (getattr(settings, "REQUIREMENTS_WEBHOOK_TOKEN", None) or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-API-Key"] = token

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    timeout = int(getattr(settings, "REQUIREMENTS_WEBHOOK_TIMEOUT_SEC", 15) or 15)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            logger.info(
                "[requirements_notify] webhook ok status=%s id=%s",
                getattr(resp, "status", None),
                getattr(doc, "id", None),
            )
    except urllib.error.HTTPError as e:
        logger.warning(
            "[requirements_notify] webhook HTTP %s id=%s body=%s",
            e.code,
            getattr(doc, "id", None),
            (e.read() or b"")[:300],
        )
    except Exception:
        logger.exception("[requirements_notify] webhook failed id=%s", getattr(doc, "id", None))
