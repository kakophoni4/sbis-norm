"""
Добить отправку пакетов НДС, которые уже записаны в СБИС («Отчет создан» /
«Документ уже запущен в обработку»): ПодготовитьДействие → подпись → ВыполнитьДействие.

Параллельно, с ретраями на прокси (472 / timeout).

Пример:
  docker compose exec -T web python manage.py finish_nds_packages_from_folder \\
    /app/media/crtfg --workers 5 --retries 6 --retry-sleep 2
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections

from reports.models import Certificate
from reports.services.sbis import auth_sbis_by_cert, export_cert_der, get_thumbprint_from_cert
from reports.services.sbis.client import _sbis_request
from reports.services.sbis.constants import REPORTING_URL
from reports.services.sbis.crypto import sign_xml_if_needed

_MAIN_RE = re.compile(r"^NO_NDS_\d", re.IGNORECASE)
_BOOK8_RE = re.compile(r"^NO_NDS\.8_", re.IGNORECASE)
_BOOK9_RE = re.compile(r"^NO_NDS\.9_", re.IGNORECASE)
_INN_RE = re.compile(r"NO_NDS_\d+_\d+_(\d{10})", re.IGNORECASE)

_ALREADY_OK = (
    "отсутствует или обработано",
    "уже обработано",
    "нет доступных действий",
    "действие недоступно",
)

_PROXY_HINTS = (
    "proxy",
    "472",
    "tunnel",
    "timed out",
    "timeout",
    "max retries",
    "connection reset",
    "nodemaven",
    "temporary failure",
)


def _pick_one(files: list[Path], pred) -> Path | None:
    hits = [p for p in files if pred(p.name)]
    return sorted(hits, key=lambda p: p.name)[0] if hits else None


def _file_ident(p: Path) -> str:
    return p.name.rsplit(".", 1)[0].split("_")[-1].lower()


def _inn_from_main(name: str) -> str | None:
    m = _INN_RE.search(name)
    return m.group(1) if m else None


def _discover(root: Path) -> list[dict]:
    out: list[dict] = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        xmls = sorted(d.glob("*.xml"))
        if not xmls:
            continue
        main = _pick_one(
            xmls,
            lambda n: bool(_MAIN_RE.match(n))
            and not n.upper().startswith("NO_NDS.8")
            and not n.upper().startswith("NO_NDS.9"),
        )
        if not main:
            continue
        inn = _inn_from_main(main.name)
        books = []
        b8 = _pick_one(xmls, lambda n: bool(_BOOK8_RE.match(n)))
        b9 = _pick_one(xmls, lambda n: bool(_BOOK9_RE.match(n)))
        if b8:
            books.append(b8)
        if b9:
            books.append(b9)
        out.append(
            {
                "org": d.name,
                "inn": inn or "",
                "main": main,
                "books": books,
                "doc_id": _file_ident(main),
            }
        )
    return out


def _err_text(err) -> str:
    if isinstance(err, dict):
        return f"{err.get('message') or ''} {err.get('details') or ''}".strip()
    return str(err or "")


def _is_already_ok(text: str) -> bool:
    t = (text or "").lower()
    return any(x in t for x in _ALREADY_OK)


def _is_proxy_error(text: str) -> bool:
    t = (text or "").lower()
    return any(x in t for x in _PROXY_HINTS)


def _finish_one(pkg: dict, *, retries: int, retry_sleep: float, write) -> dict:
    close_old_connections()
    inn = pkg["inn"]
    org = pkg["org"]
    doc_id = pkg["doc_id"]
    main: Path = pkg["main"]
    books: list[Path] = pkg["books"]
    files = [main] + list(books)
    row = {"org": org, "inn": inn, "doc_id": doc_id, "ok": False, "status": "", "error": None}

    if not inn:
        row["status"] = "no_inn"
        row["error"] = "нет ИНН в имени файла"
        write(f"[{org}] FAIL no_inn")
        return row

    last_err = ""
    for attempt in range(1, max(1, retries) + 1):
        close_old_connections()
        try:
            cert = (
                Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
                .exclude(csptest_name="")
                .order_by("-id")
                .first()
            )
            if not cert:
                row["status"] = "no_cert"
                row["error"] = "нет сертификата"
                write(f"[{org}] FAIL no_cert")
                return row

            cer = f"/tmp/finish_{inn}_{threading.get_ident()}.cer"
            export_cert_der(cert.csptest_name, cer)
            tp = get_thumbprint_from_cert(cer)
            sid = auth_sbis_by_cert(cer, tp, inn=inn)
            headers = {
                "Content-Type": "application/json-rpc;charset=utf-8",
                "X-SBISSessionID": sid,
            }

            prep = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "СБИС.ПодготовитьДействие",
                "params": {
                    "Документ": {
                        "Идентификатор": doc_id,
                        "Этап": {
                            "Название": "Отправка",
                            "Действие": {
                                "Название": "Отправить",
                                "Сертификат": {"Отпечаток": tp},
                            },
                        },
                    }
                },
            }
            pr = _sbis_request(
                "POST",
                REPORTING_URL,
                inn=inn,
                headers=headers,
                data=json.dumps(prep, ensure_ascii=False),
                timeout=60,
                total_budget_sec=90,
            )
            pd = pr.json()
            if pd.get("error"):
                msg = _err_text(pd["error"])
                if _is_already_ok(msg):
                    row["ok"] = True
                    row["status"] = "already_sent"
                    write(f"[{org}] OK already_sent ({inn})")
                    return row
                raise RuntimeError(f"prepare: {msg}")

            atts = []
            for fp in files:
                sign_xml_if_needed(str(fp), None, tp, csptest_name=cert.csptest_name)
                sig_b64 = base64.b64encode(Path(str(fp) + ".sgn").read_bytes()).decode("ascii")
                atts.append(
                    {
                        "Идентификатор": _file_ident(fp),
                        "Подпись": [{"Файл": {"ДвоичныеДанные": sig_b64}}],
                    }
                )

            exe = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "СБИС.ВыполнитьДействие",
                "params": {
                    "Документ": {
                        "Идентификатор": doc_id,
                        "Этап": {
                            "Название": "Отправка",
                            "Действие": {
                                "Название": "Отправить",
                                "Сертификат": {"Отпечаток": tp},
                            },
                            "Вложение": atts,
                        },
                    }
                },
            }
            er = _sbis_request(
                "POST",
                REPORTING_URL,
                inn=inn,
                headers=headers,
                data=json.dumps(exe, ensure_ascii=False),
                timeout=60,
                total_budget_sec=90,
            )
            ed = er.json()
            if ed.get("error"):
                msg = _err_text(ed["error"])
                if _is_already_ok(msg):
                    row["ok"] = True
                    row["status"] = "already_sent"
                    write(f"[{org}] OK already_sent ({inn})")
                    return row
                raise RuntimeError(f"exec: {msg}")

            row["ok"] = True
            row["status"] = "sent"
            write(f"[{org}] OK sent ({inn})")
            return row
        except Exception as e:
            last_err = str(e)
            if _is_proxy_error(last_err) and attempt < retries:
                write(
                    f"[{org}] proxy fail attempt {attempt}/{retries}: {last_err[:120]} — retry"
                )
                time.sleep(max(0.0, retry_sleep) * attempt)
                continue
            row["status"] = "error"
            row["error"] = last_err[:500]
            write(f"[{org}] FAIL {last_err[:220]}")
            return row

    row["status"] = "error"
    row["error"] = last_err[:500]
    write(f"[{org}] FAIL {last_err[:220]}")
    return row


class Command(BaseCommand):
    help = "Добить Подготовить/Выполнить для уже записанных пакетов НДС (параллельно + retry)"

    def add_arguments(self, parser):
        parser.add_argument("folder", type=str)
        parser.add_argument("--workers", type=int, default=5)
        parser.add_argument("--retries", type=int, default=6)
        parser.add_argument("--retry-sleep", type=float, default=2.0)
        parser.add_argument("--inns", type=str, default="", help="Фильтр ИНН через запятую")
        parser.add_argument("--report-json", type=str, default="")

    def handle(self, *args, **options):
        folder = Path(options["folder"])
        if not folder.is_dir():
            raise CommandError(f"Папка не найдена: {folder}")

        packages = _discover(folder)
        inns_filter = {x.strip() for x in (options["inns"] or "").split(",") if x.strip()}
        if inns_filter:
            packages = [p for p in packages if p.get("inn") in inns_filter]

        if not packages:
            raise CommandError("Пакетов не найдено")

        workers = max(1, min(12, int(options["workers"] or 1)))
        retries = max(1, int(options["retries"] or 1))
        retry_sleep = max(0.0, float(options["retry_sleep"] or 0))
        lock = threading.Lock()

        def write(msg: str) -> None:
            with lock:
                self.stdout.write(msg)
                self.stdout.flush()

        write(
            f"packages={len(packages)} workers={workers} retries={retries} retry_sleep={retry_sleep}"
        )

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {
                pool.submit(
                    _finish_one,
                    pkg,
                    retries=retries,
                    retry_sleep=retry_sleep,
                    write=write,
                ): pkg
                for pkg in packages
            }
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:
                    pkg = futs[fut]
                    results.append(
                        {
                            "org": pkg["org"],
                            "inn": pkg["inn"],
                            "doc_id": pkg["doc_id"],
                            "ok": False,
                            "status": "error",
                            "error": str(e)[:500],
                        }
                    )
                    write(f"[{pkg['org']}] FAIL {e}")

        ok_n = sum(1 for r in results if r.get("ok"))
        write(f"Готово: ok={ok_n} err={len(results) - ok_n} total={len(results)}")
        for r in sorted(results, key=lambda x: x.get("org") or ""):
            mark = "OK" if r.get("ok") else "FAIL"
            write(
                f"  {mark} {r.get('org')} {r.get('inn')} {r.get('status')} "
                f"{(r.get('error') or '')[:80]}"
            )

        report = (options.get("report_json") or "").strip()
        if report:
            Path(report).write_text(
                json.dumps(results, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            write(f"report: {report}")
