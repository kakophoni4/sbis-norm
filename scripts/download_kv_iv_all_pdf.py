# -*- coding: utf-8 -*-
"""Скачать PDF квитанций и извещений для всех принятых отчётов из full_picture."""
import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from reports.services.sbis.auth import sbis_auth_session_for_inn
from reports.services.sbis.client import _sbis_get, sbis_rpc


SRC = Path("/app/media/full_picture_result.json")
OUT = Path("/app/media/kv_iv_pdf_all")
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "download_log.json"
WORKERS = 6
METHOD_READ = "СБИС.ПрочитатьДокумент"

# Эти каталоги также проверяются, чтобы старые НДС-файлы не скачивались повторно.
EXISTING_DIRS = [
    Path("/app/media/kv_iv_surrendered"),
    Path("/app/media/kv_iv_complete"),
    Path("/app/media/kv_iv_pdf_nds"),
    OUT,
]

RU = {
    "DIR PARTS": "ДИР ПАРТС", "LAZERDZET": "ЛАЗЕРДЖЭТ",
    "Kontinent": "Континент", "K-PLAST": "К-ПЛАСТ", "Koher": "Кохер",
    "TEK": "ТЭК", "ILIONA": "ИЛИОНА", "Minikey": "Миникей",
    "Afina": "Афина", "Interra Stroy": "Интерра Строй", "GLORIA": "ГЛОРИЯ",
    "Rys": "Рысь", "SPEKTR": "СПЕКТР", "RIKO": "РИКО", "ORION": "ОРИОН",
    "PAROM": "ПАРОМ", "LORRIPLYUS": "ЛОРРИПЛЮС", "PIONER": "ПИОНЕР",
    "LIFT KOMPLEKS": "ЛИФТ КОМПЛЕКС", "IVOLGA": "ИВОЛГА",
    "Aviagaz-Aziya": "Авиагаз-Азия", "Arkada": "Аркада", "BRAVOS": "БРАВОС",
    "Bior": "Биор", "Vizir/Vizit": "Визир-Визит", "Volna": "Волна",
    "Dvenadtsat": "Двенадцать", "Dilemma": "Дилемма", "MIKA": "МИКА",
    "Mostorg": "Мосторг", "OMSR": "ОМСР", "Energiya": "Энергия",
    "Skat": "Скат", "Prodmarket": "Продмаркет",
    "Invest initsiativa": "Инвест-инициатива", "RESPEKT 77": "РЕСПЕКТ 77",
    "OPTIMA": "ОПТИМА",
}
_PRINT_LOCK = threading.Lock()


def log(*args):
    with _PRINT_LOCK:
        print(*args, flush=True)


def safe_name(value: str) -> str:
    for char in '<>:"/\\|?*':
        value = value.replace(char, "_")
    return " ".join(value.split())[:160]


def as_list(value):
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else []


def collect_atts(result: dict) -> list[dict]:
    atts = as_list(result.get("Вложение"))
    for stage in as_list(result.get("Этап")):
        if isinstance(stage, dict):
            atts.extend(as_list(stage.get("Вложение")))
    return [att for att in atts if isinstance(att, dict)]


def find_kv_iv(atts: list[dict]):
    kv = iv = None
    for att in atts:
        file_data = att.get("Файл") or {}
        filename = file_data.get("Имя") or att.get("Название") or ""
        base = Path(str(filename)).name.upper()
        if base.startswith("KV_") and not base.startswith("IZ_"):
            kv = att
        elif base.startswith("IV_") and not base.startswith("IZ_"):
            iv = att
    return kv, iv


def pdf_url(att: dict) -> str:
    """В разных ответах СБИС ссылка встречается и у вложения, и внутри Файл."""
    for source in (att, att.get("Файл") or {}):
        for key in ("СсылкаНаPDF", "СсылкаPDF"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def find_existing(label: str, company: str, short: str, date_safe: str) -> Path | None:
    exact = safe_name(f"{label} ({company}) {date_safe} {short}.pdf")
    simple = safe_name(f"{label} ({company}).pdf")
    for directory in EXISTING_DIRS:
        if not directory.exists():
            continue
        for candidate in (directory / exact, directory / simple):
            if candidate.exists() and candidate.stat().st_size > 1000:
                return candidate
        for candidate in directory.glob("*.pdf"):
            if label in candidate.name and f"({company})" in candidate.name and candidate.stat().st_size > 1000:
                if short in candidate.name or not short:
                    return candidate
    return None


def download_pdf(inn: str, sid: str, url: str, path: Path):
    headers = {"X-SBISSessionID": sid}
    message = ""
    for attempt in range(1, 5):
        try:
            response = _sbis_get(url, headers=headers, timeout=90, inn=inn, total_budget_sec=120)
            content = response.content or b""
            if response.status_code == 200 and content.startswith(b"%PDF"):
                path.write_bytes(content)
                return True, len(content), ""
            message = f"status={response.status_code} head={content[:80]!r}"
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
        log("  retry pdf", attempt, message)
        time.sleep(3 * attempt)
    return False, 0, message


def set_existing(row: dict, kind: str, source: Path, destination: Path):
    if source.resolve() != destination.resolve():
        try:
            shutil.copy2(source, destination)
            row[f"{kind}_file"] = str(destination)
        except Exception:
            row[f"{kind}_file"] = str(source)
    else:
        row[f"{kind}_file"] = str(destination)
    row[f"{kind}_ok"] = True
    row[f"{kind}_skipped"] = True


def process_job(job: dict) -> dict:
    company, inn, doc_id = job["name"], job["inn"], job["doc_id"]
    short = (doc_id or "")[:8]
    date_safe = (job["date"] or "nodate").replace(".", "-")
    row = {**job, "kv_ok": False, "iv_ok": False, "kv_skipped": False,
           "iv_skipped": False, "kv_file": "", "iv_file": "", "error": None}
    log(f"======== {company} {inn} {job['date']} {short} ========")

    targets = {
        "kv": ("квитанция о приеме", job["want_kv"]),
        "iv": ("извещение о вводе", job["want_iv"]),
    }
    needs = {}
    for kind, (label, wanted) in targets.items():
        destination = OUT / safe_name(f"{label} ({company}) {date_safe} {short}.pdf")
        existing = find_existing(label, company, short, date_safe) if wanted else None
        if existing:
            set_existing(row, kind, existing, destination)
            log("  skip", kind, row[f"{kind}_file"])
        needs[kind] = bool(wanted and not existing)
    if not any(needs.values()):
        return row

    try:
        auth = sbis_auth_session_for_inn(inn)
        if not auth.get("success"):
            row["error"] = f"auth fail: {auth.get('error')}"
            log("AUTH FAIL", company, row["error"])
            return row
        response = sbis_rpc(
            inn=inn, session_id=auth["result"]["session_id"], method=METHOD_READ,
            params={"Документ": {"Идентификатор": doc_id}}, timeout=60,
        )
        if response.get("error"):
            row["error"] = f"read error: {response['error']}"
            return row
        kv, iv = find_kv_iv(collect_atts(response.get("result") or {}))
        for kind, att in (("kv", kv), ("iv", iv)):
            if not needs[kind]:
                continue
            label, _wanted = targets[kind]
            if not att:
                row["error"] = (row["error"] or "") + f"; no attachment {kind}"
                continue
            url = pdf_url(att)
            if not url:
                row["error"] = (row["error"] or "") + f"; no pdf url {kind}"
                continue
            path = OUT / safe_name(f"{label} ({company}) {date_safe} {short}.pdf")
            ok, size, error = download_pdf(inn, auth["result"]["session_id"], url, path)
            row[f"{kind}_ok"] = ok
            row[f"{kind}_file"] = str(path) if ok else ""
            if not ok:
                row["error"] = (row["error"] or "") + f"; {kind}: {error}"
            log("  ", "OK" if ok else "FAIL", kind, company, size)
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        log("EXC", company, row["error"])
    return row


data = json.loads(SRC.read_text(encoding="utf-8"))
jobs = []
for org in data.get("orgs") or []:
    for doc in org.get("docs") or []:
        if doc.get("is_shell") or str(doc.get("code")) != "7":
            continue
        if not (doc.get("has_kv") or doc.get("has_iv")):
            continue
        jobs.append({
            "name": RU.get(org.get("name"), org.get("name") or "?"),
            "inn": org.get("inn"), "doc_id": doc.get("doc_id"),
            "date": doc.get("date") or "", "title": doc.get("title") or "",
            "want_kv": bool(doc.get("has_kv")), "want_iv": bool(doc.get("has_iv")),
        })

log("JOBS_ALL_ACCEPTED", len(jobs), "WORKERS", WORKERS, "OUT", OUT)
results = []
with ThreadPoolExecutor(max_workers=WORKERS) as executor:
    futures = [executor.submit(process_job, job) for job in jobs]
    for future in as_completed(futures):
        results.append(future.result())

LOG.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
for kind in ("kv", "iv"):
    log(kind, "ok", sum(bool(row.get(f"{kind}_ok")) for row in results),
        "skipped", sum(bool(row.get(f"{kind}_skipped")) for row in results))
failures = [row for row in results if row.get("error") and not (row["kv_ok"] and row["iv_ok"])]
log("DONE jobs", len(results), "partial_failures", len(failures), "DIR", OUT)
for row in failures:
    log("  FAIL", row["name"], (row["doc_id"] or "")[:8], row["error"])
