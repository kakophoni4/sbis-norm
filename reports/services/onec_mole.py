"""HTTP-клиент для 1С HTTP-сервиса mole (организации / units)."""
from __future__ import annotations

import base64
import logging
from typing import Any

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def _base_url() -> str:
    return (getattr(settings, "ONE_C_MOLE_BASE_URL", None) or "").rstrip("/")


def _auth_header() -> dict[str, str]:
    user = getattr(settings, "ONE_C_MOLE_USER", "") or ""
    password = getattr(settings, "ONE_C_MOLE_PASSWORD", "") or ""
    if not user:
        raise RuntimeError("ONE_C_MOLE_USER не задан")
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _timeout() -> int:
    return int(getattr(settings, "ONE_C_MOLE_TIMEOUT_SEC", 300) or 300)


def mole_health() -> tuple[int, str]:
    """GET /health — проверка Basic auth и доступности 1С."""
    base = _base_url()
    if not base:
        raise RuntimeError("ONE_C_MOLE_BASE_URL не задан")
    url = f"{base}/health"
    headers = {**_auth_header(), "Accept": "application/json, text/plain, */*"}
    resp = requests.get(url, headers=headers, timeout=min(30, _timeout()))
    return resp.status_code, resp.text


def mole_upload_units(units: list[dict[str, Any]]) -> tuple[int, str]:
    """
    POST /units — массив организаций (JSON).
    1С обрабатывает долго; вызывайте небольшими пакетами.
    """
    base = _base_url()
    if not base:
        raise RuntimeError("ONE_C_MOLE_BASE_URL не задан")
    url = f"{base}/units"
    headers = {
        **_auth_header(),
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json, text/plain, */*",
    }
    resp = requests.post(url, json=units, headers=headers, timeout=_timeout())
    return resp.status_code, resp.text
