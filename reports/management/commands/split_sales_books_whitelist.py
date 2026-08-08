"""
Скачать книги продаж по whitelist ИНН и нарезать PDF-выписки по каждому покупателю.

Период — явный date_from/date_to (YYYY-MM-DD или DD.MM.YYYY).
Whitelist — docs/requirements_scan_inns.txt (или REQUIREMENTS_SCAN_INNS*).

Пример:
  python manage.py split_sales_books_whitelist \\
    --date-from 2026-04-01 --date-to 2026-06-30 \\
    --out-dir /data/sales_books --workers 10
"""
from __future__ import annotations

import base64
import csv
import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections

from reports.models import Certificate, Organization
from reports.services.requirements_scan_scope import get_requirements_scan_inns
from reports.services.sbis.client import close_thread_local_sbis_session
from reports.services.sbis.receipts import fetch_sales_book_pdf
from reports.services.sbis.sales_book_extract_pdf import (
    build_sales_book_extract_pdf,
    extract_stamp_meta_from_pdf,
    extract_title_meta_from_pdf,
    parse_sales_rows_from_saby_pdf,
)

logger = logging.getLogger(__name__)


def _is_retryable_failure(note: str) -> bool:
    low = (note or "").lower()
    return any(
        x in low
        for x in (
            "формир",
            "не найден",
            "proxy",
            "503",
            "429",
            "tunnel",
            "timeout",
            "timed out",
            "max retries",
            "connection",
            "временно",
        )
    )


def _pick_source_doc(result: dict) -> dict | None:
    """Один документ с pdf_b64: плоский result или лучший из documents."""
    if result.get("pdf_b64"):
        return result
    docs = [d for d in (result.get("documents") or []) if d.get("pdf_b64")]
    if not docs:
        return None
    if len(docs) == 1:
        return docs[0]

    best = None
    best_n = -1
    for d in docs:
        try:
            raw = base64.b64decode(d["pdf_b64"])
            n = len(parse_sales_rows_from_saby_pdf(raw, counterparty_id=None))
        except Exception:
            n = 0
        if n > best_n:
            best_n = n
            best = d
    return best or docs[0]


class Command(BaseCommand):
    help = "Whitelist: скачать книги продаж и нарезать PDF по контрагентам"

    def add_arguments(self, parser):
        parser.add_argument("--date-from", required=True, help="Начало периода YYYY-MM-DD")
        parser.add_argument("--date-to", required=True, help="Конец периода YYYY-MM-DD")
        parser.add_argument(
            "--out-dir",
            default="/data/sales_books",
            help="Каталог вывода (по умолчанию /data/sales_books)",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=10,
            help="Параллельных компаний (по умолчанию 10)",
        )
        parser.add_argument(
            "--sleep",
            type=float,
            default=0.0,
            help="Пауза между запуском задач при workers=1, сек (по умолчанию 0)",
        )
        parser.add_argument("--limit", type=int, default=0, help="Ограничить число компаний (0 = все)")
        parser.add_argument("--inn", action="append", default=[], help="Только эти ИНН (можно несколько)")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Перезаписывать уже существующие PDF выписок",
        )
        parser.add_argument(
            "--skip-full-book",
            action="store_true",
            help="Не сохранять полную книгу _full.pdf",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только список компаний с сертификатом, без скачивания",
        )
        parser.add_argument(
            "--pdf-ready-attempts",
            type=int,
            default=5,
            help="Сколько раз ждать готовности PDF в архиве СБИС (по умолчанию 5)",
        )
        parser.add_argument(
            "--pdf-ready-sleep",
            type=float,
            default=8.0,
            help="Пауза между ожиданиями PDF, сек (по умолчанию 8)",
        )
        parser.add_argument(
            "--retry-rounds",
            type=int,
            default=2,
            help="Доп. проходы по упавшим ИНН (по умолчанию 2)",
        )
        parser.add_argument(
            "--retry-sleep",
            type=float,
            default=15.0,
            help="Пауза перед повторным проходом, сек (по умолчанию 15)",
        )

    def handle(self, *args, **options):
        date_from = (options["date_from"] or "").strip()
        date_to = (options["date_to"] or "").strip()
        out_dir = Path(options["out_dir"])
        workers = max(1, int(options["workers"] or 10))
        sleep_sec = max(0.0, float(options["sleep"] or 0))
        limit = int(options["limit"] or 0)
        force = bool(options["force"])
        skip_full = bool(options["skip_full_book"])
        dry_run = bool(options["dry_run"])
        pdf_ready_attempts = max(1, int(options["pdf_ready_attempts"] or 5))
        pdf_ready_sleep = max(1.0, float(options["pdf_ready_sleep"] or 8))
        retry_rounds = max(0, int(options["retry_rounds"] or 0))
        retry_sleep = max(0.0, float(options["retry_sleep"] or 0))
        only_inns = [str(x).strip() for x in (options["inn"] or []) if str(x).strip()]

        if only_inns:
            inns = only_inns
        else:
            inns = get_requirements_scan_inns()
        if not inns:
            raise CommandError("Whitelist пуст: нет ИНН для обработки")

        ready: list[str] = []
        skipped_no_cert: list[str] = []
        for inn in inns:
            cert = (
                Certificate.objects.filter(inn=inn, has_private_key=True)
                .order_by("-is_active", "-last_used_at")
                .first()
            )
            if not cert:
                skipped_no_cert.append(inn)
                continue
            ready.append(inn)

        if limit > 0:
            ready = ready[:limit]

        max_wait = (pdf_ready_attempts - 1) * pdf_ready_sleep
        self.stdout.write(
            f"Период {date_from} … {date_to}; whitelist={len(inns)}; "
            f"с сертификатом={len(ready)}; без ключа={len(skipped_no_cert)}; "
            f"workers={workers}; pdf_wait≈{max_wait:.0f}s; "
            f"retry_rounds={retry_rounds}; out={out_dir}"
        )
        if skipped_no_cert[:10]:
            self.stdout.write(
                self.style.WARNING(
                    f"  без сертификата (пример): {', '.join(skipped_no_cert[:10])}"
                    + ("…" if len(skipped_no_cert) > 10 else "")
                )
            )

        if dry_run:
            for inn in ready:
                self.stdout.write(f"  would process {inn}")
            return

        out_dir.mkdir(parents=True, exist_ok=True)
        summary_path = out_dir / "_summary.tsv"
        by_inn: dict[str, dict] = {}
        print_lock = threading.Lock()

        def _run_one(inn: str) -> dict:
            close_old_connections()
            shop_dir = out_dir / inn
            shop_dir.mkdir(parents=True, exist_ok=True)
            try:
                n_extracts, note = self._process_shop(
                    inn=inn,
                    date_from=date_from,
                    date_to=date_to,
                    shop_dir=shop_dir,
                    force=force,
                    skip_full=skip_full,
                    pdf_ready_attempts=pdf_ready_attempts,
                    pdf_ready_sleep=pdf_ready_sleep,
                )
                return {
                    "inn": inn,
                    "status": "ok",
                    "extracts": str(n_extracts),
                    "note": note,
                    "n": n_extracts,
                }
            except Exception as e:
                msg = str(e)[:300]
                if _is_retryable_failure(msg):
                    logger.warning("split_sales_books_whitelist fail inn=%s: %s", inn, msg)
                else:
                    logger.exception("split_sales_books_whitelist fail inn=%s", inn)
                return {
                    "inn": inn,
                    "status": "error",
                    "extracts": "0",
                    "note": msg,
                    "n": 0,
                }
            finally:
                close_thread_local_sbis_session()
                close_old_connections()

        def _run_batch(batch: list[str], *, round_label: str) -> None:
            total = len(batch)
            if not total:
                return
            self.stdout.write(f"— {round_label}: {total} ИНН, workers={workers}")
            self.stdout.flush()
            done = 0

            if workers == 1:
                for i, inn in enumerate(batch, start=1):
                    with print_lock:
                        self.stdout.write(f"[{round_label} {i}/{total}] {inn} …")
                        self.stdout.flush()
                    row = _run_one(inn)
                    by_inn[inn] = {k: row[k] for k in ("inn", "status", "extracts", "note", "n")}
                    with print_lock:
                        if row["status"] == "ok":
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"  OK {inn} extracts={row['extracts']} {row['note']}"
                                )
                            )
                        else:
                            self.stdout.write(self.style.ERROR(f"  FAIL {inn}: {row['note']}"))
                    if sleep_sec and i < total:
                        time.sleep(sleep_sec)
                return

            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_run_one, inn): inn for inn in batch}
                for fut in as_completed(futures):
                    inn = futures[fut]
                    done += 1
                    try:
                        row = fut.result()
                    except Exception as e:
                        row = {
                            "inn": inn,
                            "status": "error",
                            "extracts": "0",
                            "note": str(e)[:300],
                            "n": 0,
                        }
                    by_inn[inn] = {k: row[k] for k in ("inn", "status", "extracts", "note", "n")}
                    with print_lock:
                        if row["status"] == "ok":
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"[{round_label} {done}/{total}] OK {inn} "
                                    f"extracts={row['extracts']} {row['note']}"
                                )
                            )
                        else:
                            self.stdout.write(
                                self.style.ERROR(
                                    f"[{round_label} {done}/{total}] FAIL {inn}: {row['note']}"
                                )
                            )
                        self.stdout.flush()

        _run_batch(ready, round_label="pass1")

        for r_i in range(1, retry_rounds + 1):
            failed = [
                inn
                for inn in ready
                if (by_inn.get(inn) or {}).get("status") != "ok"
                and _is_retryable_failure((by_inn.get(inn) or {}).get("note") or "")
            ]
            if not failed:
                break
            if retry_sleep:
                self.stdout.write(f"— пауза {retry_sleep:.0f}s перед retry#{r_i} ({len(failed)} ИНН)")
                self.stdout.flush()
                time.sleep(retry_sleep)
            _run_batch(failed, round_label=f"retry{r_i}")

        summary_rows = [
            {k: (by_inn.get(inn) or {}).get(k, "") for k in ("inn", "status", "extracts", "note")}
            for inn in sorted(ready)
        ]
        # заполнить inn если вдруг пусто
        for inn, row in zip(sorted(ready), summary_rows):
            row["inn"] = inn
            if not row.get("status"):
                row["status"] = "error"
                row["extracts"] = "0"
                row["note"] = "не обработан"

        ok_shops = sum(1 for r in summary_rows if r.get("status") == "ok")
        err_shops = len(summary_rows) - ok_shops
        total_extracts = sum(int((by_inn.get(r["inn"]) or {}).get("n") or 0) for r in summary_rows if r.get("status") == "ok")

        with summary_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["inn", "status", "extracts", "note"], delimiter="\t")
            w.writeheader()
            w.writerows(summary_rows)

        self.stdout.write(
            self.style.SUCCESS(
                f"Готово: ok={ok_shops} err={err_shops} extracts={total_extracts} "
                f"summary={summary_path}"
            )
        )

    def _process_shop(
        self,
        *,
        inn: str,
        date_from: str,
        date_to: str,
        shop_dir: Path,
        force: bool,
        skip_full: bool,
        pdf_ready_attempts: int = 5,
        pdf_ready_sleep: float = 8.0,
    ) -> tuple[int, str]:
        resp = fetch_sales_book_pdf(
            inn,
            date_from=date_from,
            date_to=date_to,
            only_accepted=False,
            max_docs=30,
            pdf_ready_attempts=pdf_ready_attempts,
            pdf_ready_sleep_sec=pdf_ready_sleep,
        )
        if not resp.get("success"):
            err = resp.get("error") or {}
            raise RuntimeError(err.get("message") or str(err) or "fetch_sales_book_pdf failed")

        result = resp.get("result") or {}
        source = _pick_source_doc(result)
        if not source or not source.get("pdf_b64"):
            raise RuntimeError("PDF книги продаж не найден в ответе")

        pdf_bytes = base64.b64decode(source["pdf_b64"])
        sbis_doc_id = (source.get("sbis_doc_id") or result.get("sbis_doc_id") or "").strip()
        pdf_filename = source.get("pdf_filename") or result.get("pdf_filename") or ""
        period = result.get("period") or {}
        period_from = period.get("from") or date_from
        period_to = period.get("to") or date_to

        if not skip_full:
            full_path = shop_dir / "_full.pdf"
            if force or not full_path.is_file():
                full_path.write_bytes(pdf_bytes)

        rows = parse_sales_rows_from_saby_pdf(pdf_bytes, counterparty_id=None)
        by_buyer: dict[str, list] = defaultdict(list)
        for row in rows:
            buyer = (getattr(row, "buyer_inn", None) or "").strip()
            if buyer and buyer.isdigit() and len(buyer) in (10, 12):
                by_buyer[buyer].append(row)

        if not by_buyer:
            index_path = shop_dir / "_index.tsv"
            with index_path.open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=["buyer_inn", "buyer_name", "rows", "pdf", "status"],
                    delimiter="\t",
                )
                w.writeheader()
            return 0, f"doc={sbis_doc_id[:12]} rows=0 buyers=0"

        stamp = extract_stamp_meta_from_pdf(pdf_bytes)
        title_meta = extract_title_meta_from_pdf(pdf_bytes)
        org = Organization.objects.filter(inn=inn).first()
        cert = Certificate.objects.filter(inn=inn).order_by("-is_active", "-last_used_at").first()
        seller_name = (title_meta.org_name if title_meta and title_meta.org_name else None) or (
            org.name if org else None
        )
        seller_kpp = (getattr(org, "kpp", None) if org else None) or (
            getattr(cert, "kpp", None) if cert else None
        )
        if stamp and not stamp.certificate and cert and cert.thumbprint:
            stamp.certificate = str(cert.thumbprint).upper()

        index_rows: list[dict] = []
        made = 0
        for buyer_inn in sorted(by_buyer.keys()):
            buyer_rows = by_buyer[buyer_inn]
            buyer_name = next((r.buyer_name for r in buyer_rows if getattr(r, "buyer_name", None)), "")
            out_pdf = shop_dir / f"{buyer_inn}.pdf"
            status = "exists"
            if force or not out_pdf.is_file():
                pdf_out = build_sales_book_extract_pdf(
                    seller_inn=inn,
                    seller_kpp=seller_kpp,
                    seller_name=seller_name,
                    counterparty_id=buyer_inn,
                    period_from=period_from,
                    period_to=period_to,
                    sbis_doc_id=sbis_doc_id,
                    rows=buyer_rows,
                    stamp=stamp,
                    title=title_meta,
                    source_pdf_name=pdf_filename,
                    source_pdf_bytes=pdf_bytes,
                )
                out_pdf.write_bytes(pdf_out)
                status = "written"
                made += 1
            else:
                made += 1
            index_rows.append(
                {
                    "buyer_inn": buyer_inn,
                    "buyer_name": buyer_name or "",
                    "rows": str(len(buyer_rows)),
                    "pdf": out_pdf.name,
                    "status": status,
                }
            )

        index_path = shop_dir / "_index.tsv"
        with index_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=["buyer_inn", "buyer_name", "rows", "pdf", "status"],
                delimiter="\t",
            )
            w.writeheader()
            w.writerows(index_rows)

        return made, f"doc={sbis_doc_id[:12]} pdf_rows={len(rows)} buyers={len(by_buyer)}"
