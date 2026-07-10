"""Whitelist ИНН для ежедневного сканера требований ФНС."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

_INN_RE = re.compile(r"^(\d{10}|\d{12})\b")


def _parse_inns_from_text(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # "7720959604\tДиспут" или просто ИНН
        m = _INN_RE.match(s.replace(",", " ").replace(";", " "))
        if not m:
            continue
        inn = m.group(1)
        if inn not in seen:
            seen.add(inn)
            out.append(inn)
    return out


def load_inns_file(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.is_file():
        logger.warning("requirements inns file missing: %s", p)
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = p.read_text(encoding="cp1251", errors="ignore")
    return _parse_inns_from_text(text)


def get_requirements_scan_inns() -> list[str]:
    """
    ИНН для сканера требований:
    1) REQUIREMENTS_SCAN_INNS (через запятую в env) — если задано, только оно
    2) иначе файлы из REQUIREMENTS_SCAN_INNS_FILES (через запятую) или дефолт:
       docs/lavki_vane_inns.txt + docs/new_companies_2026-07-10.txt
       (или единый docs/requirements_scan_inns.txt если есть)
    """
    env_list = (getattr(settings, "REQUIREMENTS_SCAN_INNS", None) or "").strip()
    if env_list:
        return _parse_inns_from_text(env_list.replace(",", "\n"))

    base = Path(settings.BASE_DIR)
    files_cfg = (getattr(settings, "REQUIREMENTS_SCAN_INNS_FILES", None) or "").strip()
    if files_cfg:
        paths = [base / p.strip() if not Path(p.strip()).is_absolute() else Path(p.strip()) for p in files_cfg.split(",") if p.strip()]
    else:
        unified = base / "docs" / "requirements_scan_inns.txt"
        if unified.is_file():
            paths = [unified]
        else:
            paths = [
                base / "docs" / "lavki_vane_inns.txt",
                base / "docs" / "new_companies_2026-07-10.txt",
            ]

    merged: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for inn in load_inns_file(path):
            if inn not in seen:
                seen.add(inn)
                merged.append(inn)
    logger.info("requirements scan whitelist: %s inns from %s", len(merged), [str(p) for p in paths])
    return merged
