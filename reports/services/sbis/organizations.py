"""СБИС: наши организации (СписокНашихОрганизаций) и нормализация реквизитов."""
from __future__ import annotations

from .client import sbis_rpc


def normalize_sbis_our_org(obj: dict) -> dict:
    """СвЮЛ / СвФЛ → плоский словарь для экспорта."""
    out: dict = {"raw_sbis": obj}
    svul = obj.get("СвЮЛ") if isinstance(obj.get("СвЮЛ"), dict) else {}
    svfl = obj.get("СвФЛ") if isinstance(obj.get("СвФЛ"), dict) else {}

    if svul.get("ИНН"):
        out["inn"] = str(svul["ИНН"]).strip()
        out["kpp"] = str(svul.get("КПП") or "").strip()
        out["name"] = str(svul.get("Название") or svul.get("Наименование") or "").strip()
        out["branch_code"] = str(svul.get("КодФилиала") or "").strip()
        out["country_code"] = str(svul.get("КодСтраны") or "").strip()
        out["entity_type"] = "UL"
    elif svfl.get("ИНН"):
        out["inn"] = str(svfl["ИНН"]).strip()
        out["surname"] = str(svfl.get("Фамилия") or "").strip()
        out["firstname"] = str(svfl.get("Имя") or "").strip()
        out["patronymic"] = str(svfl.get("Отчество") or "").strip()
        parts = [out.get("surname"), out.get("firstname"), out.get("patronymic")]
        out["name"] = " ".join(p for p in parts if p)
        out["entity_type"] = "IP"
    else:
        out["inn"] = ""
        out["name"] = ""

    for key in ("Идентификатор", "ПодключенДокументооборот", "Статус"):
        if key in obj and obj[key] not in (None, ""):
            out[key] = obj[key]

    return out


def sbis_list_our_organizations(
    inn: str,
    session_id: str,
    *,
    filter_inn: str = "",
    filter_kpp: str = "",
    page_size: int = 100,
    timeout: int = 45,
) -> dict:
    """
    СБИС.СписокНашихОрганизаций
    https://saby.ru/help/integration/api/all_methods/company
    """
    filt: dict = {"Навигация": {"РазмерСтраницы": str(int(page_size))}}
    fi = (filter_inn or "").strip()
    fk = (filter_kpp or "").strip()
    if fi or fk:
        svul: dict = {}
        if fi:
            svul["ИНН"] = fi
        if fk:
            svul["КПП"] = fk
        filt["НашаОрганизация"] = {"СвЮЛ": svul}

    data = sbis_rpc(
        inn,
        session_id,
        "СБИС.СписокНашихОрганизаций",
        {"Фильтр": filt},
        timeout=timeout,
    )

    if data.get("error"):
        return {"success": False, "organizations": [], "error": data["error"]}

    result = data.get("result") or {}
    raw_list = result.get("НашаОрганизация") or []
    if isinstance(raw_list, dict):
        raw_list = [raw_list]

    orgs = [normalize_sbis_our_org(x) for x in raw_list if isinstance(x, dict)]
    return {"success": True, "organizations": orgs, "error": None, "navigation": result.get("Навигация")}


def pick_best_sbis_org(orgs: list[dict], target_inn: str) -> dict | None:
    target_inn = (target_inn or "").strip()
    if not orgs:
        return None
    for o in orgs:
        if (o.get("inn") or "").strip() == target_inn:
            return o
    return orgs[0]


def kpp_to_tax_office_code(kpp: str) -> str:
    """Первые 4 цифры КПП ≈ код ИФНС постановки на учёт (для головной организации)."""
    kpp = (kpp or "").strip()
    if len(kpp) >= 4 and kpp[:4].isdigit():
        return kpp[:4]
    return ""
