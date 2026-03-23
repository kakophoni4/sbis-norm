"""
Внешние подсказки по ИНН → КПП (неофициальные HTTP-источники).

Важно: перед массовым использованием проверьте пользовательское соглашение сайта,
ставьте задержку между запросами, не злоупотребляйте.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Совместимо с ответом star-pro.ru organizationSuggestion
DEFAULT_SUGGESTION_URL = (
    "https://star-pro.ru/proverka-kontragenta/search/organizationSuggestion"
)

# Страница, с которой в браузере уходит XHR (без Referer часто 403 с серверов)
DEFAULT_STAR_PRO_REFERER = (
    "https://star-pro.ru/proverka-kontragenta/poisk-kpp"
)

_INN_RE = re.compile(r"^\d{10}$|^\d{12}$")


def build_star_pro_headers(
    *,
    referer: str | None = None,
    cookie: str | None = None,
) -> dict[str, str]:
    """Заголовки ближе к браузеру — снижает 403 от WAF при запросах не с домашнего IP."""
    ref = (referer or os.environ.get("KPP_SYNC_REFERER") or DEFAULT_STAR_PRO_REFERER).strip()
    h: dict[str, str] = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Origin": "https://star-pro.ru",
        "Referer": ref,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    ck = (cookie or os.environ.get("KPP_SYNC_COOKIE") or "").strip()
    if ck:
        h["Cookie"] = ck
    return h


def fetch_kpp_star_pro(
    inn: str,
    *,
    base_url: str = DEFAULT_SUGGESTION_URL,
    timeout: float = 20.0,
    session: requests.Session | None = None,
    referer: str | None = None,
    cookie: str | None = None,
) -> dict[str, Any]:
    """
    GET JSON, выбирает головную организацию (isMain) или первую запись.

    Returns:
        {"ok": True, "inn", "kpp", "ogrn", "name_short", "raw_count"}
        или {"ok": False, "error": str}
    """
    inn = (inn or "").strip()
    if not _INN_RE.match(inn):
        return {"ok": False, "error": f"Некорректный ИНН: {inn!r}"}

    sess = session or requests.Session()
    headers = build_star_pro_headers(referer=referer, cookie=cookie)
    try:
        r = sess.get(
            base_url,
            params={"searchQuery": inn},
            headers=headers,
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        logger.warning("kpp fetch failed inn=%s: %s", inn, e)
        return {"ok": False, "error": str(e)}
    except ValueError as e:
        return {"ok": False, "error": f"Не JSON: {e}"}

    items = data.get("items") or []
    if not items:
        return {"ok": False, "error": "Пустой список items", "raw_count": 0}

    main = next((x for x in items if x.get("isMain")), items[0])
    kpp = (main.get("kpp") or "").strip()
    if not kpp or len(kpp) != 9 or not kpp.isdigit():
        return {
            "ok": False,
            "error": f"Нет валидного КПП в ответе: {kpp!r}",
            "raw_count": len(items),
        }

    return {
        "ok": True,
        "inn": (main.get("inn") or inn).strip(),
        "kpp": kpp,
        "ogrn": (main.get("ogrn") or "").strip() or None,
        "name_short": (main.get("nameShort") or "").strip() or None,
        "raw_count": len(items),
    }
