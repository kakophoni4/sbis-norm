"""Разрешения для доверенных интеграций с 1С."""

import hmac
import logging

from django.conf import settings
from rest_framework.permissions import BasePermission


logger = logging.getLogger(__name__)


class OneCApiTokenPermission(BasePermission):
    """Проверяет общий ключ 1С из заголовка ``X-1C-API-Token``.

    Если ключ в app.env не задан, доступ намеренно закрыт (fail closed), чтобы
    новый защищённый маршрут нельзя было случайно опубликовать без секрета.
    ``ONEC_API_TOKEN_PREVIOUS`` позволяет без простоя заменить ключ.
    """

    message = "Необходим корректный заголовок X-1C-API-Token."

    def has_permission(self, request, view) -> bool:
        provided = str(request.headers.get("X-1C-API-Token") or "")
        expected = [
            str(getattr(settings, "ONEC_API_TOKEN", "") or ""),
            str(getattr(settings, "ONEC_API_TOKEN_PREVIOUS", "") or ""),
        ]
        expected = [token for token in expected if token]
        if not expected:
            logger.error("[1C_AUTH] ONEC_API_TOKEN is not configured; denying request")
            return False
        return bool(provided) and any(
            hmac.compare_digest(provided, token) for token in expected
        )
