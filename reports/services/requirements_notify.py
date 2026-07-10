"""Хук на сохранение требования — позже сюда отправим во внешний сервис."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def notify_requirement_saved(doc) -> None:
    """
    Вызывается после успешного сохранения RequirementDocument.
    Пока только лог; позже — HTTP/очередь во внешний сервис.
    """
    try:
        logger.info(
            "[requirements_notify] saved inn=%s doc_id=%s date=%s title=%s",
            getattr(doc, "inn", None),
            getattr(doc, "sbis_doc_id", None),
            getattr(doc, "document_date", None),
            (getattr(doc, "doc_title", None) or "")[:80],
        )
    except Exception:
        logger.exception("[requirements_notify] failed")
