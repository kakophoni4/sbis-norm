import base64
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ProxyError, SSLError, Timeout

from reports.models import Certificate
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

from .constants import *
from .auth import auth_sbis_by_cert, sbis_auth_session_for_inn
from .client import _sbis_get, _sbis_post, _sbis_request, sbis_rpc
from .crypto import (
    export_cert_der,
    get_fio_from_cert_file,
    get_thumbprint_from_cert,
    parse_kpp_from_cert_file,
    run_cmd,
    sign_xml_if_needed,
    sbis_decrypt_bytes_with_cert_thumbprint,
    _try_decrypt_bytes_with_cert,
)

logger = logging.getLogger(__name__)

def sbis_get_our_org_from_service_info(inn: str, session_id: str, target_inn: str) -> dict | None:
    """
    Достаёт из СБИС.ИнформацияОСлужебныхЭтапах объект нашей организации по ИНН.
    Возвращает объект НашаОрганизация (как в ответе СБИС) или None если не нашли.
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},  # обычно без параметров
        timeout=45,
    )

    if data.get("error"):
        raise RuntimeError(f"СБИС.ИнформацияОСлужебныхЭтапах error: {data['error']}")

    result = data.get("result")
    if not isinstance(result, list):
        # иногда может вернуться не список — лучше сразу увидеть
        raise RuntimeError(f"Unexpected result type: {type(result)}; body={str(result)[:400]}")

    target_inn = (target_inn or "").strip()
    if not target_inn:
        return None

    for item in result:
        org = (item or {}).get("НашаОрганизация") or (item or {}).get("НашаОрганизация".lower()) or None
        # по факту в доке: массив со списком наших организаций — структура может быть как item.НашаОрганизация
        # но встречается и когда item сам = НашаОрганизация. Поэтому подстрахуемся:
        candidate = org if isinstance(org, dict) else (item if isinstance(item, dict) else None)
        if not isinstance(candidate, dict):
            continue

        svul = (candidate.get("СвЮЛ") or {})
        cand_inn = (svul.get("ИНН") or "").strip()
        if cand_inn == target_inn:
            return candidate

    return None

def sbis_list_organizations_from_service_info(
    inn: str,
    session_id: str,
    *,
    timeout: int = 45,
) -> dict:
    """
    СБИС.ИнформацияОСлужебныхЭтапах — разбор всех «наших организаций» из ответа.

    Возвращает dict:
      success: bool
      organizations: [{"inn", "kpp", "name", "raw": dict}, ...]  — по возможности
      error: {...} при ошибке RPC или неожиданной структуре
      raw_result_type: str — для отладки
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
        }

    result = data.get("result")
    raw_type = type(result).__name__

    def _extract_svul_pairs(candidate: dict) -> list[tuple[dict, dict]]:
        """Вернуть пары (родительский объект, СвЮЛ) если есть."""
        out: list[tuple[dict, dict]] = []
        if not isinstance(candidate, dict):
            return out
        svul = candidate.get("СвЮЛ")
        if isinstance(svul, dict):
            out.append((candidate, svul))
        # иногда вложенность иная
        for key in ("НашаОрганизация", "Организация", "ЮЛ"):
            sub = candidate.get(key)
            if isinstance(sub, dict):
                s2 = sub.get("СвЮЛ")
                if isinstance(s2, dict):
                    out.append((sub, s2))
        return out

    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add_from_svul(parent: dict, svul: dict) -> None:
        i = (str(svul.get("ИНН") or "").strip(), str(svul.get("КПП") or "").strip())
        if not i[0] and not i[1]:
            return
        key = (i[0], i[1])
        if key in seen:
            return
        seen.add(key)
        organizations.append(
            {
                "inn": i[0],
                "kpp": i[1],
                "name": (
                    str(svul.get("Название") or svul.get("Наименование") or "").strip()
                ),
                "raw": parent,
            }
        )

    if isinstance(result, list):
        for item in result:
            if not isinstance(item, dict):
                continue
            org = item.get("НашаОрганизация")
            candidates: list[dict] = []
            if isinstance(org, dict):
                candidates.append(org)
            candidates.append(item)
            for cand in candidates:
                for parent, svul in _extract_svul_pairs(cand):
                    _add_from_svul(parent, svul)
    elif isinstance(result, dict):
        # единичный объект или обёртка
        for parent, svul in _extract_svul_pairs(result):
            _add_from_svul(parent, svul)
        for key in ("НашаОрганизация", "Документ", "Организации"):
            sub = result.get(key)
            if isinstance(sub, list):
                for el in sub:
                    if isinstance(el, dict):
                        for parent, svul in _extract_svul_pairs(el):
                            _add_from_svul(parent, svul)
            elif isinstance(sub, dict):
                for parent, svul in _extract_svul_pairs(sub):
                    _add_from_svul(parent, svul)
    else:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": f"Неожиданный тип result: {raw_type}",
                "sample": str(result)[:500] if result is not None else "",
            },
            "raw_result_type": raw_type,
        }

    return {
        "success": True,
        "organizations": organizations,
        "error": None,
        "raw_result_type": raw_type,
    }

def _deep_walk_collect_svul(
    obj: object,
    organizations: list[dict],
    seen: set[tuple[str, str]],
) -> None:
    """Рекурсивно собрать СвЮЛ с ИНН/КПП из произвольного JSON (ответ СБИС)."""
    if isinstance(obj, dict):
        svul = obj.get("СвЮЛ")
        if isinstance(svul, dict):
            inn_v = str(svul.get("ИНН") or "").strip()
            kpp_v = str(svul.get("КПП") or "").strip()
            if inn_v or kpp_v:
                key = (inn_v, kpp_v)
                if key not in seen:
                    seen.add(key)
                    organizations.append(
                        {
                            "inn": inn_v,
                            "kpp": kpp_v,
                            "name": str(
                                svul.get("Название") or svul.get("Наименование") or ""
                            ).strip(),
                            "raw": svul,
                        }
                    )
        for v in obj.values():
            _deep_walk_collect_svul(v, organizations, seen)
    elif isinstance(obj, list):
        for x in obj:
            _deep_walk_collect_svul(x, organizations, seen)

def _filter_service_stages_our_org(
    inn: str,
    kpp: str,
    *,
    org_name: str = "",
    date_from: str,
    date_to: str,
    page_size: int = 50,
) -> dict:
    """Фильтр СБИС.СписокСлужебныхЭтапов (на многих контурах КПП в СвЮЛ обязателен)."""
    kpp = (kpp or "").strip()
    return {
        "Блокировать": "Да",
        "НашаОрганизация": {
            "СвЮЛ": {
                "ИНН": inn,
                "КПП": kpp,
                "Название": (org_name or "").strip(),
                "КодФилиала": "",
            }
        },
        "ТолькоОтчетность": "Да",
        "ТолькоЭДО": "Нет",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }

def sbis_list_organizations_from_service_stages(
    inn: str,
    session_id: str,
    *,
    kpp: str | None = None,
    org_name: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    page_size: int = 50,
    timeout: int = 45,
) -> dict:
    """
    СБИС.СписокСлужебныхЭтапов + рекурсивный разбор СвЮЛ в ответе.

    На контурах СБИС КПП в фильтре часто обязателен («КПП должен быть заполнен»).
    Без kpp HTTP-запрос не выполняется — передайте КПП, возьмите из БД/серта/XML.
    """
    kpp = (kpp or "").strip()
    if not kpp:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": "КПП обязателен для СписокСлужебныхЭтапов на этом контуре СБИС",
                "code": "KPP_REQUIRED",
                "hint": "Передайте kpp=, заполните Organization.kpp, или parse_kpp_from_cert_file()",
            },
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
            "docs_count": None,
        }

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=90)).strftime("%d.%m.%Y")

    filt = _filter_service_stages_our_org(
        inn,
        kpp,
        org_name=org_name,
        date_from=date_from,
        date_to=date_to,
        page_size=page_size,
    )
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.СписокСлужебныхЭтапов",
        params={"Фильтр": filt},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
        }

    result = data.get("result")
    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()
    _deep_walk_collect_svul(result, organizations, seen)

    # как в sbis_list_organizations_from_service_info — без лишнего raw в slim
    slim = []
    for o in organizations:
        slim.append(
            {
                "inn": o["inn"],
                "kpp": o["kpp"],
                "name": o["name"],
            }
        )

    return {
        "success": True,
        "organizations": slim,
        "error": None,
        "raw_result_type": type(result).__name__,
        "source_method": "СписокСлужебныхЭтапов",
        "docs_count": len((result or {}).get("Документ") or [])
        if isinstance(result, dict)
        else None,
    }

def _build_service_stages_filter_minimal(
    inn: str,
    *,
    page_size: int = 20,
    block: bool = True,
    only_reporting: bool = True,
    only_edo: bool = False,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict:
    """
    Минимальный фильтр, чтобы СБИС не ругался и при этом не требовать от нас Billing/SPP.
    Если СБИС у тебя попросит больше реквизитов — расширим позже, но начнём так.
    """
    f = {
        "Блокировать": "Да" if block else "Нет",
        "НашаОрганизация": {"СвЮЛ": {"ИНН": inn}},
        "ТолькоОтчетность": "Да" if only_reporting else "Нет",
        "ТолькоЭДО": "Да" if only_edo else "Нет",
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }
    if date_from:
        f["ДатаС"] = date_from
    if date_to:
        f["ДатаПо"] = date_to
    return {"Фильтр": f}

def sbis_list_service_stages(
    inn: str,
    *,
    kpp: str,
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
    date_from: str | None = None,   # "dd.mm.yyyy"
    date_to: str | None = None,     # "dd.mm.yyyy"
    page_size: int = 20,
    only_reporting: bool = True,
) -> dict:
    """
    1) Аутентификация по сертификату (СБИС.АутентифицироватьПоСертификату)
    2) СБИС.СписокСлужебныхЭтапов с фильтром по нашей организации

    КПП — передаём ВРУЧНУЮ.
    only_reporting: True — только отчётность; False — в т.ч. требования ФНС и др. служебные.
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}

    kpp = (kpp or "").strip()
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен (передай вручную)", "inn": inn}}

    # даты по умолчанию — последние 30 дней
    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=30)).strftime("%d.%m.%Y")

    # сертификат
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    # авторизация
    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    # НашаОрганизация
    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокСлужебныхЭтапов",
        "params": {
            "Фильтр": {
                "Блокировать": "Да",
                "НашаОрганизация": our_org,
                "ТолькоОтчетность": "Да" if only_reporting else "Нет",
                "ТолькоЭДО": "Нет",
                "ДатаС": date_from,
                "ДатаПо": date_to,
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 0,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)

        if resp.status_code != 200:
            return {
                "success": False,
                "error": {
                    "message": f"HTTP {resp.status_code}",
                    "inn": inn,
                    "raw_head": (resp.text or "")[:500],
                },
            }

        data = resp.json()
        if data.get("error"):
            return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

        result = data.get("result") or {}
        docs = (result.get("Документ") or [])

        # небольшой превью, чтоб глазами понимать что пришло
        preview = []
        for d in docs[:10]:
            stages = []
            for st in (d.get("Этап") or []):
                actions = []
                for a in (st.get("Действие") or []):
                    actions.append(
                        {
                            "name": a.get("Название"),
                            "need_decrypt": a.get("ТребуетРасшифровки"),
                            "need_sign": a.get("ТребуетПодписания"),
                            "sig_type": a.get("ТипПодписи"),
                        }
                    )
                stages.append(
                    {
                        "name": st.get("Название"),
                        "id": st.get("Идентификатор"),
                        "service": st.get("Служебный"),
                        "actions": actions,
                    }
                )

            preview.append(
                {
                    "id": d.get("Идентификатор"),
                    "name": d.get("Название"),
                    "type": d.get("Тип"),
                    "direction": d.get("Направление"),
                    "subtype": d.get("Подтип"),
                    "state": (d.get("Состояние") or {}).get("Код"),
                    "stages": stages,
                }
            )

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "period": {"from": date_from, "to": date_to},
                "session_id_head": (session_id or "")[:8],
                "total_docs": len(docs),
                "docs": docs,
                "preview": preview,
                "raw_result_keys": list(result.keys()),
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СписокСлужебныхЭтапов: {e}", "inn": inn}}

REQUIREMENT_LIST_DOC_TYPES = ("RequirementFNS", "RequirementFSS")


def sbis_list_requirement_documents(
    inn: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    page_size: int = 50,
    types: tuple[str, ...] | list[str] = REQUIREMENT_LIST_DOC_TYPES,
    session_id: str | None = None,
) -> dict:
    """
    Входящие требования через СБИС.СписокДокументов (Тип=RequirementFNS/RequirementFSS).

    Важно: СБИС.СписокСлужебныхЭтапов часто НЕ возвращает уже лежащие требования ФНС
    (видит только текущие служебные этапы вроде исходящего НДС). Для сканера нужен этот метод.
    """
    inn = (inn or "").strip()
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}, "docs": []}

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=30)).strftime("%d.%m.%Y")

    if not session_id:
        auth = sbis_auth_session_for_inn(inn)
        if not auth.get("success"):
            return {"success": False, "error": auth.get("error") or {"message": "auth failed"}, "docs": []}
        session_id = (((auth.get("result") or {}).get("session_id")) or "").strip()
    if not session_id:
        return {"success": False, "error": {"message": "нет session_id"}, "docs": []}

    merged: dict[str, dict] = {}
    errors: list[dict] = []
    for tip in types:
        tip = (tip or "").strip()
        if not tip:
            continue
        try:
            data = sbis_rpc(
                inn=inn,
                session_id=session_id,
                method="СБИС.СписокДокументов",
                params={
                    "Фильтр": {
                        "Тип": tip,
                        "Направление": "Входящий",
                        "ДатаС": date_from,
                        "ДатаПо": date_to,
                        "Навигация": {"РазмерСтраницы": str(int(page_size))},
                    }
                },
                timeout=60,
                total_budget_sec=70,
            )
        except Exception as e:
            errors.append({"type": tip, "message": str(e)})
            continue
        if data.get("error"):
            errors.append({"type": tip, "error": data.get("error")})
            continue
        docs = (((data.get("result") or {}).get("Документ")) or [])
        if isinstance(docs, dict):
            docs = [docs]
        for d in docs:
            if not isinstance(d, dict):
                continue
            did = (d.get("Идентификатор") or "").strip()
            if not did:
                continue
            # не затираем уже найденный документ с этапами
            prev = merged.get(did)
            if prev and (prev.get("Этап") or []) and not (d.get("Этап") or []):
                continue
            merged[did] = d

    docs_out = list(merged.values())
    return {
        "success": True,
        "docs": docs_out,
        "errors": errors or None,
        "period": {"from": date_from, "to": date_to},
        "count": len(docs_out),
    }


def sbis_read_document(inn: str, *, session_id: str, doc_id: str, timeout: int = 45) -> dict:
    """СБИС.ПрочитатьДокумент — карточка + Этап[] (нужно, если СписокДокументов без этапов)."""
    doc_id = (doc_id or "").strip()
    if not doc_id:
        return {"success": False, "error": {"message": "doc_id обязателен"}}
    try:
        data = sbis_rpc(
            inn=inn,
            session_id=session_id,
            method="СБИС.ПрочитатьДокумент",
            params={"Документ": {"Идентификатор": doc_id}},
            timeout=timeout,
            total_budget_sec=max(timeout + 5, 50),
        )
    except Exception as e:
        return {"success": False, "error": {"message": str(e)}}
    if data.get("error"):
        return {"success": False, "error": data.get("error")}
    return {"success": True, "result": data.get("result") or {}}


def _iter_doc_attachments(raw: dict | list | None) -> list[dict]:
    """Собрать объекты Вложение из карточки ПрочитатьДокумент (рекурсивно)."""
    out: list[dict] = []

    def walk(obj) -> None:
        if len(out) >= 40:
            return
        if isinstance(obj, dict):
            atts = obj.get("Вложение")
            if isinstance(atts, list):
                for a in atts:
                    if isinstance(a, dict):
                        out.append(a)
            elif isinstance(atts, dict):
                out.append(atts)
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    walk(raw or {})
    # дедуп по идентификатору/ссылке
    seen: set[str] = set()
    uniq: list[dict] = []
    for a in out:
        f = a.get("Файл") if isinstance(a.get("Файл"), dict) else {}
        key = (
            (a.get("Идентификатор") or "").strip()
            or (f.get("Ссылка") or "").strip()
            or (f.get("Имя") or f.get("Название") or "").strip()
            or str(id(a))
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(a)
    return uniq


def fetch_requirement_file_via_read(
    inn: str,
    *,
    requirement_doc_id: str,
    session_id: str | None = None,
    save_to: str | None = None,
) -> dict:
    """
    Скачать файл требования без ПодготовитьДействие.

    Нужен, когда этап уже закрыт («Действие отсутствует или обработано»)
    или СписокДокументов не отдаёт Этап — но карточку и вложения всё ещё можно прочитать.
    """
    inn = (inn or "").strip()
    doc_id = (requirement_doc_id or "").strip()
    if not inn or not doc_id:
        return {"success": False, "error": {"message": "inn и requirement_doc_id обязательны"}}

    cert = (
        Certificate.objects.filter(inn=inn, has_private_key=True)
        .exclude(csptest_name="")
        .order_by("-id")
        .first()
    ) or Certificate.objects.filter(inn=inn).exclude(csptest_name="").order_by("-id").first()
    if not cert or not cert.csptest_name:
        return {"success": False, "error": {"message": "Нет сертификата для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)
    if not session_id:
        try:
            session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
        except Exception as e:
            return {"success": False, "error": {"message": f"auth: {e}", "inn": inn}}

    read = sbis_read_document(inn, session_id=session_id, doc_id=doc_id, timeout=60)
    if not read.get("success"):
        return {"success": False, "error": read.get("error") or {"message": "ПрочитатьДокумент failed"}}

    raw = read.get("result") or {}
    attachments_out: list[dict] = []

    def _maybe_decrypt(content: bytes, encrypted_flag: str) -> bytes:
        if (encrypted_flag or "").strip() != "Да":
            return content
        try:
            with tempfile.TemporaryDirectory(prefix=f"sbis_req_read_dec_{inn}_") as td:
                enc_path = os.path.join(td, "req.enc")
                dec_path = os.path.join(td, "req.dec")
                Path(enc_path).write_bytes(content)
                run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])
                return Path(dec_path).read_bytes()
        except Exception:
            try:
                return _try_decrypt_bytes_with_cert(content, cert.csptest_name) or content
            except Exception:
                return content

    for i, att in enumerate(_iter_doc_attachments(raw)):
        file_obj = att.get("Файл") if isinstance(att.get("Файл"), dict) else {}
        filename = (file_obj.get("Имя") or file_obj.get("Название") or att.get("Название") or "requirement.bin").strip()
        # служебные мелкие квитанции пропускаем позже по выбору PDF
        href = (file_obj.get("Ссылка") or "").strip()
        b64 = (file_obj.get("ДвоичныеДанные") or "").strip()
        encrypted_flag = (att.get("Зашифрован") or "").strip()
        content = b""
        try:
            if b64:
                content = base64.b64decode(b64)
            elif href:
                if i:
                    time.sleep(0.5)
                r = _sbis_get(
                    href,
                    headers={"X-SBISSessionID": session_id},
                    timeout=120,
                    inn=inn,
                    total_budget_sec=180,
                )
                if r.status_code != 200:
                    continue
                content = r.content or b""
            else:
                continue
        except Exception as e:
            logger.info("read-att download skip inn=%s err=%s", inn, e)
            continue
        if not content:
            continue
        decrypted = _maybe_decrypt(content, encrypted_flag)
        attachments_out.append(
            {
                "filename": filename,
                "b64": base64.b64encode(decrypted).decode("ascii"),
                "size": len(decrypted),
                "is_pdf": decrypted.startswith(b"%PDF") or filename.lower().endswith(".pdf"),
                "is_doc": filename.lower().endswith((".doc", ".docx")),
                "is_xml": decrypted.lstrip().startswith(b"<?xml") or filename.lower().endswith(".xml"),
            }
        )

    # fallback: архив / PDF ссылки с карточки
    if not attachments_out:
        for key in ("СсылкаНаАрхив", "СсылкаНаPDF", "Ссылка"):
            url = (raw.get(key) or "").strip()
            if not url:
                continue
            try:
                r = _sbis_get(
                    url,
                    headers={"X-SBISSessionID": session_id},
                    timeout=120,
                    inn=inn,
                    total_budget_sec=180,
                )
                if r.status_code != 200 or not r.content:
                    continue
                content = r.content
                name = "requirement.zip" if content.startswith(b"PK") else (
                    "requirement.pdf" if content.startswith(b"%PDF") else "requirement.bin"
                )
                attachments_out.append(
                    {
                        "filename": name,
                        "b64": base64.b64encode(content).decode("ascii"),
                        "size": len(content),
                        "is_pdf": content.startswith(b"%PDF"),
                        "is_doc": False,
                        "is_xml": False,
                        "source": key,
                    }
                )
                break
            except Exception as e:
                logger.info("read-link %s fail inn=%s err=%s", key, inn, e)

    if not attachments_out:
        return {
            "success": False,
            "error": {
                "message": "ПрочитатьДокумент: нет скачиваемых вложений/ссылок",
                "inn": inn,
                "doc_id": doc_id,
                "keys": list(raw.keys())[:30],
            },
        }

    chosen = None
    for a in attachments_out:
        if a.get("is_pdf") or a.get("is_doc"):
            chosen = a
            break
    if not chosen:
        for a in attachments_out:
            if a.get("is_xml"):
                chosen = a
                break
    if not chosen:
        chosen = attachments_out[0]

    saved_to = None
    if save_to:
        try:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_bytes(base64.b64decode(chosen["b64"]))
            saved_to = save_to
        except Exception:
            pass

    return {
        "success": True,
        "result": {
            "inn": inn,
            "requirement_doc_id": doc_id,
            "requirement_stage_id": None,
            "filename": chosen["filename"],
            "size": chosen["size"],
            "saved_to": saved_to,
            "b64": chosen["b64"],
            "attachments_count": len(attachments_out),
            "attachments_all": attachments_out,
            "executed": False,
            "receipt_sent": False,
            "receipt_skipped": True,
            "download_mode": "read_document",
            "service_stages_done": 0,
        },
    }


def sbis_prepare_action(
    inn: str,
    *,
    kpp: str,
    doc_id: str,
    stage_id: str,
    action_name: str = "Обработать служебное",
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
) -> dict:
    """
    СБИС.ПодготовитьДействие для служебного этапа.
    Возвращает сырой ответ result, где обычно лежат Вложение (XML/PDF/DOC и т.п.)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}
    if not (kpp or "").strip():
        return {"success": False, "error": {"message": "kpp обязателен", "inn": inn}}
    if not (doc_id or "").strip():
        return {"success": False, "error": {"message": "doc_id обязателен", "inn": inn}}
    if not (stage_id or "").strip():
        return {"success": False, "error": {"message": "stage_id обязателен", "inn": inn}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": doc_id,
                "НашаОрганизация": our_org,
                "Этап": {
                    "Идентификатор": stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumb, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)
        body_text = (resp.text or "").strip()
        body_head = body_text[:400]
        data = None
        try:
            data = resp.json() if body_text else None
        except Exception:
            data = None

        # СБИС часто отдаёт бизнес-ошибку как HTTP 500 + jsonrpc.error
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            details = (err.get("details") if isinstance(err, dict) else "") or ""
            combined = f"{msg} {details}".strip()
            already = "уже обработано" in combined.lower()
            return {
                "success": False,
                "already_done": already,
                "error": {
                    "message": f"СБИС error: {err}",
                    "inn": inn,
                    "http_status": resp.status_code,
                    "raw_head": body_head,
                },
            }

        if resp.status_code != 200:
            return {
                "success": False,
                "error": {
                    "message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}",
                    "inn": inn,
                    "raw_head": body_head,
                },
            }

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "session_id": session_id,
                "thumbprint": thumb,
                "raw": (data or {}).get("result") if isinstance(data, dict) else None,
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка ПодготовитьДействие: {e}", "inn": inn}}

def sbis_download_stage_attachments(
    inn: str,
    *,
    session_id: str,
    prepared_raw: dict | list | None,
    max_files: int = 10,
) -> dict:
    """
    Из result СБИС.ПодготовитьДействие достаёт вложения и скачивает их.
    Поддерживает:
    - Файл.ДвоичныеДанные (base64)
    - Файл.Ссылка (скачиваем по GET с X-SBISSessionID)
    """

    if not prepared_raw:
        return {"success": False, "error": {"message": "prepared_raw пустой"}}

    def _iter_attachments(raw_obj):
        # В реальности СБИС может вернуть dict/ list — делаем мягко.
        if isinstance(raw_obj, dict):
            # иногда вложения лежат прямо в raw_obj["Этап"]["Вложение"]
            etap = raw_obj.get("Этап") if isinstance(raw_obj.get("Этап"), dict) else None
            if etap and isinstance(etap.get("Вложение"), list):
                for v in etap["Вложение"]:
                    yield v
            # иногда "Документ" список
            if isinstance(raw_obj.get("Документ"), list):
                for d in raw_obj["Документ"]:
                    etap2 = d.get("Этап") if isinstance(d.get("Этап"), dict) else None
                    if etap2 and isinstance(etap2.get("Вложение"), list):
                        for v in etap2["Вложение"]:
                            yield v
            return

        if isinstance(raw_obj, list):
            for x in raw_obj:
                yield from _iter_attachments(x)

    files = []
    count = 0

    for att in _iter_attachments(prepared_raw):
        if count >= max_files:
            break

        f = (att or {}).get("Файл") or {}
        name = (f.get("Имя") or f.get("Название") or f.get("Файл") or "").strip() or None
        href = (f.get("Ссылка") or "").strip() or None
        b64 = (f.get("ДвоичныеДанные") or "").strip() or None

        content = b""
        source = None

        try:
            if b64:
                content = base64.b64decode(b64)
                source = "b64"
            elif href:
                r = _sbis_get(href, headers={"X-SBISSessionID": session_id}, timeout=60, inn=inn)
                if r.status_code != 200:
                    files.append(
                        {
                            "name": name,
                            "href": href,
                            "ok": False,
                            "error": f"download HTTP {r.status_code} body_head={(r.text or '')[:200]}",
                        }
                    )
                    continue
                content = r.content or b""
                source = "link"
            else:
                files.append({"name": name, "ok": False, "error": "нет ни ДвоичныеДанные, ни Ссылка"})
                continue

            files.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "source": source,
                    "size": len(content),
                    "bytes": content,
                }
            )
            count += 1

        except Exception as e:
            files.append({"name": name, "href": href, "ok": False, "error": str(e)})

    return {"success": True, "result": {"files": files}}

def fetch_requirement_decrypted_preview(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    org_name: str = "",
    max_preview_chars: int = 1200,
) -> dict:
    """
    Минимальный рабочий шаг:
      - auth
      - ПодготовитьДействие по stage_id
      - скачать вложения (disk.sbis.ru)
      - если Зашифрован=Да — попытаться расшифровать
      - отдать превью (название/размер/тип/кусок XML если это XML)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    # 1) ПодготовитьДействие
    prep = sbis_prepare_action(
        inn,
        kpp=kpp,
        org_name=org_name,
        doc_id=requirement_doc_id,
        stage_id=requirement_stage_id,
    )
    if not prep.get("success"):
        return prep

    prepared_raw = ((prep.get("result") or {}).get("raw") or {})
    files_meta = _extract_files_from_prepare_raw(prepared_raw)

    # 2) Скачивание + (опционально) расшифровка
    files_preview = []
    for f in files_meta:
        name = (f.get("name") or "").strip() or None
        href = (f.get("href") or "").strip() or None
        encrypted_flag = f.get("encrypted")

        if not href:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": "нет ссылки Файл.Ссылка",
                    "encrypted": encrypted_flag,
                }
            )
            continue

        try:
            content, dl_meta = sbis_download_file_by_link(inn, session_id=session_id, href=href)

            # если СБИС сказал, что зашифрован — пробуем decrypt
            if str(encrypted_flag).strip() == "Да":
                content2, dec_meta = _try_decrypt_bytes_with_cert(inn=inn, thumbprint=thumbprint, content=content)
            else:
                content2, dec_meta = content, {"decrypt_ok": False, "decrypt_error": None}

            # превью текста (если похоже на xml)
            text_preview = None
            low_name = (name or "").lower()
            if low_name.endswith(".xml") or (content2[:50].lstrip().startswith(b"<?xml") or content2[:20].lstrip().startswith(b"<")):
                # пробуем основные кодировки
                decoded = None
                for enc in ("windows-1251", "utf-8", "utf-16"):
                    try:
                        decoded = content2.decode(enc)
                        break
                    except Exception:
                        continue
                if decoded is None:
                    decoded = content2.decode("utf-8", errors="ignore")

                decoded = decoded.strip()
                text_preview = decoded[:max_preview_chars]

            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "size": len(content2),
                    "content_type": dl_meta.get("content_type"),
                    "encrypted": encrypted_flag,
                    "decrypt_ok": dec_meta.get("decrypt_ok"),
                    "decrypt_error": dec_meta.get("decrypt_error"),
                    "text_preview": text_preview,
                }
            )

        except Exception as e:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": str(e),
                    "encrypted": encrypted_flag,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "files_found": len(files_meta),
            "files_preview": files_preview,
        },
    }

def _extract_files_from_prepare_raw(prepared_raw: dict) -> list[dict]:
    """
    prepared_raw — это dict из (prep["result"]["raw"]).

    Возвращает список файлов:
      [{"name": str|None, "href": str|None, "sha1": str|None, "encrypted": str|None}, ...]
    """
    files: list[dict] = []

    if not isinstance(prepared_raw, dict):
        return files

    stages = prepared_raw.get("Этап")
    if not isinstance(stages, list):
        return files

    for st in stages:
        if not isinstance(st, dict):
            continue

        влож = st.get("Вложение") or st.get("Вложения")
        if not isinstance(влож, list):
            continue

        for att in влож:
            if not isinstance(att, dict):
                continue

            f = att.get("Файл")
            if not isinstance(f, dict):
                continue

            files.append(
                {
                    "name": (f.get("Имя") or f.get("Название") or att.get("Название") or None),
                    "href": (f.get("Ссылка") or None),
                    "sha1": (f.get("Хеш") or f.get("ХешСумма") or None),
                    "encrypted": (att.get("Зашифрован") or None),
                }
            )

    return files

def sbis_download_file_by_link(
    inn: str,
    *,
    session_id: str,
    href: str,
    timeout: int = 90,
) -> tuple[bytes, dict]:
    """
    Скачивает файл по ссылке (в т.ч. disk.sbis.ru) через прокси NodeMaven.
    Возвращает (bytes, meta).
    """
    if not href:
        raise RuntimeError("Пустая ссылка на файл")

    headers = {"X-SBISSessionID": session_id}

    r = _sbis_get(
        href,
        headers=headers,
        timeout=timeout,
        inn=inn,
    )

    # disk.sbis.ru может отдавать JSON с ошибкой, поэтому сохраняем head
    body_head = ""
    try:
        body_head = (r.text or "")[:200]
    except Exception:
        body_head = "<binary>"

    if r.status_code != 200:
        raise RuntimeError(f"Не удалось скачать файл: HTTP {r.status_code}, body_head={body_head}")

    content = r.content or b""

    meta = {
        "href": href,
        "http_status": r.status_code,
        "content_len": len(content),
        "content_type": r.headers.get("Content-Type"),
        "body_head": body_head,
    }
    return content, meta

def sbis_list_changes(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    org_name: str = "",
    page_size: int = 50,
) -> dict:
    """
    СБИС.СписокИзменений — возвращает расшифрованные файлы/события по требованию.
    ВАЖНО: метод ожидает params.Фильтр (иначе "В объекте нет поля Фильтр").
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокИзменений",
        "params": {
            "Фильтр": {
                "Документ": {"Идентификатор": requirement_doc_id},
                "НашаОрганизация": {"СвЮЛ": {"ИНН": inn, "КПП": kpp, "Название": (org_name or "")}},
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 1,
    }

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка запроса в СБИС: {e}", "inn": inn}}

    if resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {resp.status_code}", "raw": resp.text}}

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": resp.text}}

    if data.get("error"):
        return {"success": False, "error": data["error"]}

    result = data.get("result") or {}

    # аккуратный превью по тому, что пришло
    events = result.get("Событие") or []
    preview = []
    if isinstance(events, list):
        for ev in events[:20]:
            if not isinstance(ev, dict):
                continue
            влож = ev.get("Вложение") or []
            preview.append(
                {
                    "event_name": (ev.get("Название") or ""),
                    "event_time": (ev.get("ДатаВремя") or ev.get("Дата") or ""),
                    "attachments": len(влож) if isinstance(влож, list) else 0,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "events_count": len(events) if isinstance(events, list) else None,
            "events_preview": preview,
            "raw": result,
        },
    }

def fetch_requirement_file_b64(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    action_name: str = "Обработать служебное",
    save_to: str | None = None,  # например "/tmp/requirement.pdf"
) -> dict:
    """
    Возвращает base64 РАСШИФРОВАННОГО файла требования (обычно PDF),
    используя inn/kpp/doc_id/stage_id.

    Важно: для СБИС.ПодготовитьДействие нужно указать Этап.Действие.Название,
    иначе будет "Не указано название действия".

    Скачивание по «Ссылка» должно идти с тем же X-SBISSessionID, что и после auth;
    ответ 403 (в т.ч. с текстом про HMAC/доступ) часто даёт СБИС при другом exit-IP
    или без сессии — ретраи HTTP перебирают прокси из пула (_sbis_request).
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}
    if not action_name:
        return {"success": False, "error": {"message": "action_name обязателен (например 'Обработать служебное')"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    # 1) ПодготовитьДействие — чтобы получить вложение и ссылку (Сертификат внутри Действие, как в Отправить)
    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": requirement_doc_id,
                "Этап": {
                    "Идентификатор": requirement_stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumbprint, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СБИС.ПодготовитьДействие: {e}", "inn": inn}}

    if resp.status_code != 200:
        body_head = (resp.text or "").strip()[:400]
        return {
            "success": False,
            "error": {
                "message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}",
                "body_head": body_head,
            },
        }

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Не смог распарсить JSON ПодготовитьДействие: {e}", "raw": resp.text[:300]}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"JSON-RPC error ПодготовитьДействие: {data['error']}", "inn": inn}}

    raw = data.get("result") or {}
    stages = raw.get("Этап") or []
    if not isinstance(stages, list) or not stages:
        return {"success": False, "error": {"message": "В ответе нет Этап[]", "inn": inn, "keys": list(raw.keys())}}

    st0 = stages[0] or {}
    atts = st0.get("Вложение") or []
    if not isinstance(atts, list) or not atts:
        return {"success": False, "error": {"message": "В ответе нет Этап[0].Вложение[]", "inn": inn}}

    # По доке СБИС: два вложения — XML обмена и требование в формате PDF или DOC. Скачиваем все и отдаём первое (для обратной совместимости).
    attachments_out: list[dict] = []
    for i, att in enumerate(atts):
        att = att or {}
        file_obj = att.get("Файл") or {}
        if not isinstance(file_obj, dict):
            continue
        file_url = (file_obj.get("Ссылка") or "").strip()
        filename = (file_obj.get("Имя") or file_obj.get("Название") or "requirement.bin").strip()
        if not file_url:
            continue
        if i > 0:
            time.sleep(1.0)  # пауза между вложениями
        encrypted_flag = (att.get("Зашифрован") or "").strip()
        try:
            r = _sbis_get(
                file_url,
                headers={"X-SBISSessionID": session_id},
                timeout=120,
                inn=inn,
                total_budget_sec=180,
            )
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code == 403:
            time.sleep(2.0)
            try:
                r = _sbis_get(
                    file_url,
                    headers={"X-SBISSessionID": session_id},
                    timeout=120,
                    inn=inn,
                    total_budget_sec=180,
                )
            except Exception as e:
                return {"success": False, "error": {"message": f"Ошибка повтора скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {r.status_code} при скачивании вложения {i + 1}", "url": file_url},
            }
        content = r.content or b""
        decrypted = content
        if encrypted_flag == "Да":
            try:
                with tempfile.TemporaryDirectory(prefix=f"sbis_req_dec_{inn}_") as td:
                    enc_path = os.path.join(td, f"req_{i}.enc")
                    dec_path = os.path.join(td, f"req_{i}.dec")
                    Path(enc_path).write_bytes(content)
                    run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])
                    decrypted = Path(dec_path).read_bytes()
            except Exception:
                decrypted = content
        is_pdf = decrypted.startswith(b"%PDF") or (filename or "").lower().endswith(".pdf")
        is_doc = (filename or "").lower().endswith((".doc", ".docx"))
        attachments_out.append({
            "filename": filename,
            "b64": base64.b64encode(decrypted).decode("ascii"),
            "size": len(decrypted),
            "is_pdf": is_pdf,
            "is_doc": is_doc,
        })

    if not attachments_out:
        return {"success": False, "error": {"message": "Не удалось скачать ни одного вложения", "inn": inn}}

    # Выбираем вложение: предпочитаем PDF, затем DOC, иначе первое
    chosen = None
    for a in attachments_out:
        if a["is_pdf"] or a["is_doc"]:
            chosen = a
            break
    if not chosen:
        chosen = attachments_out[0]

    saved_to = None
    if save_to:
        try:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_bytes(base64.b64decode(chosen["b64"]))
            saved_to = save_to
        except Exception:
            pass

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "action_name": action_name,
            "filename": chosen["filename"],
            "size": chosen["size"],
            "saved_to": saved_to,
            "b64": chosen["b64"],
            "attachments_count": len(attachments_out),
            "attachments_all": attachments_out,
            "executed": False,
            "receipt_sent": False,
            "service_stages_done": 0,
        },
    }


def _file_hash_b64(file_obj: dict) -> str:
    if not isinstance(file_obj, dict):
        return ""
    return (file_obj.get("Хеш") or file_obj.get("Хэш") or "").strip()


def _sign_bytes_detached(data: bytes, *, thumbprint: str, csptest_name: str, suffix: str = "sgn") -> str:
    """Подписать байты отсоединённой подписью, вернуть base64 .sgn."""
    with tempfile.TemporaryDirectory(prefix=f"sbis_{suffix}_") as td:
        path = os.path.join(td, "payload.bin")
        Path(path).write_bytes(data)
        sgn = sign_xml_if_needed(path, None, thumbprint, csptest_name=csptest_name)
        return base64.b64encode(Path(sgn).read_bytes()).decode("ascii")


def sbis_execute_action(
    inn: str,
    *,
    session_id: str,
    doc_id: str,
    stage_id: str,
    action_name: str,
    thumbprint: str,
    fio: str,
    attachments: list[dict],
    stage_name: str | None = None,
) -> dict:
    """СБИС.ВыполнитьДействие для служебного/подтверждающего этапа."""
    stage: dict = {
        "Идентификатор": stage_id,
        "Действие": {
            "Название": action_name,
            "Сертификат": {"Отпечаток": thumbprint, "ИНН": inn, "ФИО": fio},
        },
        "Вложение": attachments,
    }
    if stage_name:
        stage["Название"] = stage_name

    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ВыполнитьДействие",
        params={"Документ": {"Идентификатор": doc_id, "Этап": stage}},
        timeout=90,
        total_budget_sec=120,
    )
    if data.get("error"):
        return {"success": False, "error": data["error"]}
    return {"success": True, "result": data.get("result")}


def sbis_read_document(inn: str, *, session_id: str, doc_id: str) -> dict:
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ПрочитатьДокумент",
        params={"Документ": {"Идентификатор": doc_id}},
        timeout=45,
    )
    if data.get("error"):
        return {"success": False, "error": data["error"]}
    return {"success": True, "result": data.get("result") or {}}


def _iter_prepare_attachments(prepare_raw: dict) -> list[dict]:
    stages = prepare_raw.get("Этап") or []
    if isinstance(stages, dict):
        stages = [stages]
    if not stages:
        return []
    st0 = stages[0] or {}
    atts = st0.get("Вложение") or []
    return [a for a in atts if isinstance(a, dict)] if isinstance(atts, list) else []


def _load_prepare_attachment_bytes(
    inn: str,
    *,
    session_id: str,
    att: dict,
) -> tuple[bytes | None, str]:
    """Достать байты файла из prepare: ДвоичныеДанные или Ссылка. Возвращает (bytes|None, source)."""
    file_obj = att.get("Файл") or {}
    if not isinstance(file_obj, dict):
        return None, "no_file"
    b64 = (file_obj.get("ДвоичныеДанные") or "").strip()
    if b64:
        try:
            return base64.b64decode(b64), "binary"
        except Exception:
            return None, "bad_b64"
    href = (file_obj.get("Ссылка") or "").strip()
    if href:
        try:
            content, _ = sbis_download_file_by_link(inn, session_id=session_id, href=href)
            return content, "href"
        except Exception as e:
            logger.warning("download prepare att failed: %s", e)
            return None, f"href_err:{e}"
    return None, "empty"


def _build_execute_attachments_from_prepare(
    *,
    prepare_raw: dict,
    decrypted_by_id: dict[str, bytes],
    thumbprint: str,
    csptest_name: str,
    inn: str | None = None,
    session_id: str | None = None,
    include_file_payload: bool = False,
    prefer_sign_file: bool = True,
) -> list[dict]:
    """
    Собрать Вложение[] для ВыполнитьДействие.

    Для подтверждения получения (KV_*.xml): подписываем СОДЕРЖИМОЕ файла и шлём
    только Идентификатор+Подпись (как в НДС), без повторной загрузки ДвоичныеДанные.
    Подпись хеша даёт «подпись не соответствует файлу» — не используем, если есть файл.
    """
    stages = prepare_raw.get("Этап") or []
    if isinstance(stages, dict):
        stages = [stages]
    if not stages:
        return []
    st0 = stages[0] or {}
    atts = st0.get("Вложение") or []
    if not isinstance(atts, list):
        return []

    action = st0.get("Действие") or {}
    if isinstance(action, list) and action:
        action = action[0] if isinstance(action[0], dict) else {}
    action_needs_sign = isinstance(action, dict) and str(
        action.get("ТребуетПодписание") or action.get("ТребуетПодписания") or ""
    ).strip() == "Да"

    out: list[dict] = []
    for att in atts:
        if not isinstance(att, dict):
            continue
        att_id = (att.get("Идентификатор") or "").strip()
        if not att_id:
            continue
        file_obj = att.get("Файл") or {}
        if not isinstance(file_obj, dict):
            file_obj = {}
        needs_sign = str(
            att.get("ТребуетПодписание") or att.get("ТребуетПодписания") or ""
        ).strip() == "Да" or action_needs_sign

        item: dict = {"Идентификатор": att_id}
        # СБИС: при наличии Файл.ДвоичныеДанные обязательно Имя, иначе
        # «Не указано имя файла вложения» (HTTP 500 / jsonrpc).
        file_name = (
            (file_obj.get("Имя") or file_obj.get("Название") or att.get("Название") or "")
            .strip()
            or f"attachment_{att_id[:8]}.bin"
        )
        att_title = (att.get("Название") or "").strip()
        if att_title:
            item["Название"] = att_title
        payload = decrypted_by_id.get(att_id)
        source = "decrypted" if payload is not None else ""

        if payload is None and prefer_sign_file and inn and session_id:
            payload, source = _load_prepare_attachment_bytes(inn, session_id=session_id, att=att)

        if payload is not None:
            if include_file_payload:
                item["Файл"] = {
                    "Имя": file_name,
                    "ДвоичныеДанные": base64.b64encode(payload).decode("ascii"),
                }
            if needs_sign or prefer_sign_file:
                try:
                    sig_b64 = _sign_bytes_detached(
                        payload, thumbprint=thumbprint, csptest_name=csptest_name, suffix="att"
                    )
                    item["Подпись"] = [{"Файл": {"ДвоичныеДанные": sig_b64}}]
                    logger.info(
                        "signed att %s source=%s bytes=%s sig_len=%s",
                        att_id[:20],
                        source,
                        len(payload),
                        len(sig_b64),
                    )
                except Exception as e:
                    logger.warning("sign file att %s: %s", att_id[:20], e)
        elif needs_sign:
            # fallback: только если файла нет — подпись хеша (редко нужно)
            hash_b64 = _file_hash_b64(file_obj)
            if hash_b64:
                try:
                    raw_hash = base64.b64decode(hash_b64)
                    sig_b64 = _sign_bytes_detached(
                        raw_hash, thumbprint=thumbprint, csptest_name=csptest_name, suffix="hash"
                    )
                    item["Подпись"] = [{"Файл": {"ДвоичныеДанные": sig_b64}}]
                    logger.warning("signed HASH (no file) att %s — may fail SBIS verify", att_id[:20])
                except Exception as e:
                    logger.warning("sign hash att %s: %s", att_id[:20], e)

        out.append(item)
    return out


def execute_prepared_requirement_stage(
    inn: str,
    *,
    session_id: str,
    doc_id: str,
    stage_id: str,
    action_name: str,
    prepare_raw: dict,
    decrypted_by_id: dict[str, bytes],
    thumbprint: str,
    fio: str,
    csptest_name: str,
) -> dict:
    attachments = _build_execute_attachments_from_prepare(
        prepare_raw=prepare_raw or {},
        decrypted_by_id=decrypted_by_id or {},
        thumbprint=thumbprint,
        csptest_name=csptest_name,
        inn=inn,
        session_id=session_id,
        include_file_payload=bool(decrypted_by_id),
        prefer_sign_file=True,
    )
    return sbis_execute_action(
        inn,
        session_id=session_id,
        doc_id=doc_id,
        stage_id=stage_id,
        action_name=action_name,
        thumbprint=thumbprint,
        fio=fio,
        attachments=attachments,
    )


def acknowledge_requirement_receipt(
    inn: str,
    *,
    session_id: str,
    doc_id: str,
    kpp: str,
    thumbprint: str,
    fio: str,
    csptest_name: str,
    org_name: str = "",
) -> dict:
    """
    Подтверждение получения требования ФНС:
    ПрочитатьДокумент → этап «Подтверждение» / действие «Подтвердить получение»
    (в EDI иногда «Утверждение») → ПодготовитьДействие → подпись → ВыполнитьДействие.
    """
    read = sbis_read_document(inn, session_id=session_id, doc_id=doc_id)
    if not read.get("success"):
        return {"success": False, "error": read.get("error"), "skipped": False}

    result = read.get("result") or {}
    # приоритет: ФНС-требования, затем EDI
    preferred_actions = ("Подтвердить получение", "Утверждение")
    stage_id = None
    action_name = None
    for want in preferred_actions:
        for st in result.get("Этап") or []:
            if not isinstance(st, dict):
                continue
            actions = st.get("Действие") or []
            if isinstance(actions, dict):
                actions = [actions]
            for a in actions:
                if isinstance(a, dict) and (a.get("Название") or "").strip() == want:
                    stage_id = (st.get("Идентификатор") or "").strip()
                    action_name = want
                    break
            if stage_id:
                break
        if stage_id:
            break

    if not stage_id or not action_name:
        available = []
        for st in result.get("Этап") or []:
            if not isinstance(st, dict):
                continue
            actions = st.get("Действие") or []
            if isinstance(actions, dict):
                actions = [actions]
            for a in actions:
                if isinstance(a, dict) and a.get("Название"):
                    available.append(f"{st.get('Название')}/{a.get('Название')}")
        return {
            "success": True,
            "skipped": True,
            "comment": "нет действия Подтвердить получение/Утверждение",
            "available_actions": available[:20],
            "state": (result.get("Состояние") or {}),
        }

    prep = sbis_prepare_action(
        inn,
        kpp=kpp,
        org_name=org_name,
        doc_id=doc_id,
        stage_id=stage_id,
        action_name=action_name,
    )
    if not prep.get("success"):
        err = prep.get("error") or {}
        msg = str(err.get("message") or err).lower()
        if prep.get("already_done") or "уже обработано" in msg:
            return {"success": True, "skipped": True, "comment": "подтверждение уже обработано", "error": err}
        return {"success": False, "error": err, "skipped": False}

    prepare_raw = (prep.get("result") or {}).get("raw") or {}
    session_id = (prep.get("result") or {}).get("session_id") or session_id
    thumbprint = (prep.get("result") or {}).get("thumbprint") or thumbprint

    # Подписываем содержимое KV_*.xml из prepare (не хеш) — иначе СБИС: «подпись не соответствует файлу»
    attachments = _build_execute_attachments_from_prepare(
        prepare_raw=prepare_raw,
        decrypted_by_id={},
        thumbprint=thumbprint,
        csptest_name=csptest_name,
        inn=inn,
        session_id=session_id,
        include_file_payload=False,
        prefer_sign_file=True,
    )
    if not attachments or not any(a.get("Подпись") for a in attachments):
        return {
            "success": False,
            "skipped": False,
            "error": {
                "message": "не удалось подготовить подписи вложений для подтверждения",
                "attachments": attachments,
                "prepare_att_count": len(_iter_prepare_attachments(prepare_raw)),
            },
        }

    exe = sbis_execute_action(
        inn,
        session_id=session_id,
        doc_id=doc_id,
        stage_id=stage_id,
        action_name=action_name,
        thumbprint=thumbprint,
        fio=fio,
        attachments=attachments,
        stage_name="Подтверждение" if action_name == "Подтвердить получение" else None,
    )
    if not exe.get("success"):
        err = exe.get("error") or {}
        msg = str(err.get("message") or err)
        if any(x in msg.lower() for x in ("уже", "выполнен", "закрыт", "нет доступных")):
            return {"success": True, "skipped": True, "comment": msg, "error": err}
        return {"success": False, "error": err, "skipped": False, "attachments_sent": len(attachments)}

    return {
        "success": True,
        "skipped": False,
        "receipt_sent": True,
        "action_name": action_name,
        "stage_id": stage_id,
        "result": exe.get("result"),
    }


def drain_service_stages(
    inn: str,
    *,
    kpp: str,
    session_id: str,
    thumbprint: str,
    fio: str,
    csptest_name: str,
    org_name: str = "",
    date_from_str: str,
    date_to_str: str,
    max_rounds: int = 8,
    only_doc_id: str | None = None,
) -> dict:
    """Цикл СписокСлужебныхЭтапов → prepare → sign → execute (извещения и пр.)."""
    done = 0
    errors: list[str] = []
    for _ in range(max_rounds):
        listed = sbis_list_service_stages(
            inn,
            kpp=kpp,
            org_name=org_name,
            date_from=date_from_str,
            date_to=date_to_str,
            page_size=50,
            only_reporting=False,
        )
        if not listed.get("success"):
            errors.append(str((listed.get("error") or {}).get("message") or listed))
            break
        docs = ((listed.get("result") or {}).get("docs") or [])
        if not docs:
            break
        progressed = False
        for doc in docs:
            doc_id = (doc.get("Идентификатор") or "").strip()
            if not doc_id:
                continue
            if only_doc_id and doc_id != only_doc_id:
                continue
            # не трогаем исходящие НД/НДС в drain требований
            title = doc.get("Название") or ""
            direction = doc.get("Направление") or ""
            if direction == "Исходящий" and ("НДС" in title or title.startswith("НД ")):
                continue
            stages = doc.get("Этап") or []
            if not isinstance(stages, list):
                continue
            for st in stages:
                if not isinstance(st, dict):
                    continue
                stage_id = (st.get("Идентификатор") or "").strip()
                actions = st.get("Действие") or []
                if isinstance(actions, dict):
                    actions = [actions]
                if not actions:
                    continue
                action = actions[0] if isinstance(actions[0], dict) else None
                if not action:
                    continue
                action_name = (action.get("Название") or "").strip()
                if not stage_id or not action_name:
                    continue
                prep = sbis_prepare_action(
                    inn,
                    kpp=kpp,
                    org_name=org_name,
                    doc_id=doc_id,
                    stage_id=stage_id,
                    action_name=action_name,
                )
                if not prep.get("success"):
                    errors.append(str((prep.get("error") or {}).get("message") or prep)[:200])
                    continue
                session_id = (prep.get("result") or {}).get("session_id") or session_id
                thumbprint = (prep.get("result") or {}).get("thumbprint") or thumbprint
                prepare_raw = (prep.get("result") or {}).get("raw") or {}

                decrypted_by_id: dict[str, bytes] = {}
                st_list = prepare_raw.get("Этап") or []
                if isinstance(st_list, dict):
                    st_list = [st_list]
                st0 = (st_list[0] if st_list else {}) or {}
                for att in st0.get("Вложение") or []:
                    if not isinstance(att, dict):
                        continue
                    att_id = (att.get("Идентификатор") or "").strip()
                    file_obj = att.get("Файл") or {}
                    href = (file_obj.get("Ссылка") or "").strip() if isinstance(file_obj, dict) else ""
                    if not att_id or not href:
                        continue
                    try:
                        content, _ = sbis_download_file_by_link(inn, session_id=session_id, href=href)
                        if str(att.get("Зашифрован") or "").strip() == "Да":
                            content2, _ = _try_decrypt_bytes_with_cert(
                                inn=inn, thumbprint=thumbprint, content=content
                            )
                            content = content2
                        decrypted_by_id[att_id] = content
                    except Exception as e:
                        logger.warning("drain download %s: %s", att_id[:16], e)

                exe = execute_prepared_requirement_stage(
                    inn,
                    session_id=session_id,
                    doc_id=doc_id,
                    stage_id=stage_id,
                    action_name=action_name,
                    prepare_raw=prepare_raw,
                    decrypted_by_id=decrypted_by_id,
                    thumbprint=thumbprint,
                    fio=fio,
                    csptest_name=csptest_name,
                )
                if exe.get("success"):
                    done += 1
                    progressed = True
                else:
                    err = exe.get("error") or {}
                    msg = str(err.get("message") or err)
                    if any(x in msg.lower() for x in ("уже", "выполнен", "закрыт", "нет доступных")):
                        progressed = True
                    else:
                        errors.append(msg[:200])
        if not progressed:
            break
    return {"success": True, "service_stages_done": done, "errors": errors[:10]}


def _resolve_requirement_cert(inn: str):
    return (
        Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
        .exclude(csptest_name="")
        .order_by("-id")
        .first()
    ) or Certificate.objects.filter(inn=inn).exclude(csptest_name="").order_by("-id").first()


def finalize_requirement_ack(
    inn: str,
    *,
    kpp: str,
    doc_id: str,
    org_name: str = "",
    date_from_str: str | None = None,
    date_to_str: str | None = None,
    do_drain: bool = False,
) -> dict:
    """
    Квитанция «Утверждение» без повторного скачивания файла.
    Для документов, у которых «Обработать служебное» уже закрыто.
    """
    cert = _resolve_requirement_cert(inn)
    if not cert or not cert.csptest_name:
        return {"success": False, "error": {"message": "нет сертификата"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)
    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"
    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": str(e)}}

    if not date_from_str or not date_to_str:
        today = datetime.now()
        date_to_str = today.strftime("%d.%m.%Y")
        date_from_str = (today - timedelta(days=10)).strftime("%d.%m.%Y")

    drained = {"service_stages_done": 0, "errors": []}
    if do_drain:
        drained = drain_service_stages(
            inn,
            kpp=kpp,
            session_id=session_id,
            thumbprint=thumbprint,
            fio=fio,
            csptest_name=cert.csptest_name,
            org_name=org_name,
            date_from_str=date_from_str,
            date_to_str=date_to_str,
            only_doc_id=doc_id,
        )
    ack = acknowledge_requirement_receipt(
        inn,
        session_id=session_id,
        doc_id=doc_id,
        kpp=kpp,
        thumbprint=thumbprint,
        fio=fio,
        csptest_name=cert.csptest_name,
        org_name=org_name,
    )
    return {
        "success": bool(ack.get("success")),
        "result": {
            "executed": False,
            "service_stages_done": drained.get("service_stages_done", 0),
            "service_stage_errors": drained.get("errors") or [],
            "receipt_sent": bool(ack.get("receipt_sent")),
            "receipt_skipped": bool(ack.get("skipped")),
            "receipt_comment": ack.get("comment"),
            "receipt_error": ack.get("error") if not ack.get("success") else None,
            "state": ack.get("state"),
        },
        "error": ack.get("error") if not ack.get("success") else None,
    }


def fetch_requirement_full(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    action_name: str = "Обработать служебное",
    org_name: str = "",
    date_from_str: str | None = None,
    date_to_str: str | None = None,
    save_to: str | None = None,
    do_drain: bool = False,
) -> dict:
    """
    Полный цикл по доке Saby:
    prepare → download/decrypt → execute → ack Утверждение.
    do_drain=True — дополнительно пройти служебные этапы по этому doc_id (дорого по прокси).

    Если этап уже закрыт («Действие отсутствует или обработано») — fallback:
    скачать файл через ПрочитатьДокумент без prepare/execute.
    """
    stage_id = (requirement_stage_id or "").strip()
    if not stage_id:
        return fetch_requirement_file_via_read(
            inn, requirement_doc_id=requirement_doc_id, save_to=save_to
        )

    base = fetch_requirement_file_b64(
        inn,
        kpp=kpp,
        requirement_doc_id=requirement_doc_id,
        requirement_stage_id=stage_id,
        action_name=action_name,
        save_to=save_to,
    )
    if not base.get("success"):
        err_msg = str((base.get("error") or {}).get("message") or base.get("error") or "").lower()
        if any(
            x in err_msg
            for x in (
                "отсутствует или обработано",
                "уже обработано",
                "нет доступных действий",
                "действие недоступно",
            )
        ):
            fb = fetch_requirement_file_via_read(
                inn, requirement_doc_id=requirement_doc_id, save_to=save_to
            )
            if fb.get("success"):
                return fb
        return base

    cert = _resolve_requirement_cert(inn)
    if not cert or not cert.csptest_name:
        return base

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)
    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"
    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        r = base.get("result") or {}
        r["executed"] = False
        r["execute_error"] = str(e)
        base["result"] = r
        return base

    # Повторный prepare, чтобы получить raw для execute (fetch_requirement_file_b64 не возвращает raw)
    prep = sbis_prepare_action(
        inn,
        kpp=kpp,
        org_name=org_name,
        doc_id=requirement_doc_id,
        stage_id=requirement_stage_id,
        action_name=action_name,
    )
    prepare_raw = ((prep.get("result") or {}).get("raw") or {}) if prep.get("success") else {}
    session_id = ((prep.get("result") or {}).get("session_id") or session_id)
    thumbprint = ((prep.get("result") or {}).get("thumbprint") or thumbprint)

    decrypted_by_id: dict[str, bytes] = {}
    st_list = prepare_raw.get("Этап") or []
    if isinstance(st_list, dict):
        st_list = [st_list]
    st0 = (st_list[0] if st_list else {}) or {}
    prep_atts = [a for a in (st0.get("Вложение") or []) if isinstance(a, dict)]
    all_atts = ((base.get("result") or {}).get("attachments_all") or [])
    for i, att in enumerate(prep_atts):
        att_id = (att.get("Идентификатор") or "").strip()
        if not att_id:
            continue
        if i < len(all_atts) and all_atts[i].get("b64"):
            try:
                decrypted_by_id[att_id] = base64.b64decode(all_atts[i]["b64"])
            except Exception:
                pass

    result = base.get("result") or {}
    if prepare_raw:
        exe = execute_prepared_requirement_stage(
            inn,
            session_id=session_id,
            doc_id=requirement_doc_id,
            stage_id=requirement_stage_id,
            action_name=action_name,
            prepare_raw=prepare_raw,
            decrypted_by_id=decrypted_by_id,
            thumbprint=thumbprint,
            fio=fio,
            csptest_name=cert.csptest_name,
        )
        result["executed"] = bool(exe.get("success"))
        if not exe.get("success"):
            err = exe.get("error") or {}
            msg = str(err.get("message") or err).lower()
            result["execute_error"] = err
            # этап уже закрыт — продолжаем drain/ack
            if any(x in msg for x in ("уже", "выполнен", "закрыт", "нет доступных")):
                result["executed"] = True
                result["execute_already_done"] = True
        else:
            result["execute_result_keys"] = (
                list((exe.get("result") or {}).keys()) if isinstance(exe.get("result"), dict) else None
            )
    else:
        result["executed"] = False
        result["execute_error"] = (prep.get("error") if prep else {"message": "prepare failed"})

    if not date_from_str or not date_to_str:
        today = datetime.now()
        date_to_str = today.strftime("%d.%m.%Y")
        date_from_str = (today - timedelta(days=10)).strftime("%d.%m.%Y")
    if do_drain:
        drained = drain_service_stages(
            inn,
            kpp=kpp,
            session_id=session_id,
            thumbprint=thumbprint,
            fio=fio,
            csptest_name=cert.csptest_name,
            org_name=org_name,
            date_from_str=date_from_str,
            date_to_str=date_to_str,
            only_doc_id=requirement_doc_id,
        )
        result["service_stages_done"] = drained.get("service_stages_done", 0)
        if drained.get("errors"):
            result["service_stage_errors"] = drained["errors"]
    else:
        result["service_stages_done"] = 0

    ack = acknowledge_requirement_receipt(
        inn,
        session_id=session_id,
        doc_id=requirement_doc_id,
        kpp=kpp,
        thumbprint=thumbprint,
        fio=fio,
        csptest_name=cert.csptest_name,
        org_name=org_name,
    )
    result["receipt_sent"] = bool(ack.get("receipt_sent"))
    result["receipt_skipped"] = bool(ack.get("skipped"))
    if not ack.get("success"):
        result["receipt_error"] = ack.get("error")
    elif ack.get("comment"):
        result["receipt_comment"] = ack.get("comment")

    logger.info(
        "fetch_requirement_full inn=%s doc=%s executed=%s receipt_sent=%s receipt_skipped=%s stages=%s",
        inn,
        requirement_doc_id[:24],
        result.get("executed"),
        result.get("receipt_sent"),
        result.get("receipt_skipped"),
        result.get("service_stages_done"),
    )
    base["result"] = result
    return base

