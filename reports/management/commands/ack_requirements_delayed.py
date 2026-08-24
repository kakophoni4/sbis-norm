"""
Отложенное подтверждение получения требований ФНС/СФР.

Сканер только скачивает; квитанцию «Подтвердить получение / Утверждение»
шлём через --delay-days дней после RequirementDocument.created_at.

Пример:
  docker compose exec -T web python manage.py ack_requirements_delayed \\
    --delay-days 4 --workers 4 --limit 200
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from reports.management.commands.fetch_requirements_all_companies import resolve_kpp_for_inn
from reports.models import Certificate, RequirementDocument
from reports.services.sbis import finalize_requirement_ack

logger = logging.getLogger(__name__)

_ALREADY = (
    "отсутствует или обработано",
    "уже обработано",
    "нет доступных действий",
    "действие недоступно",
    "нет действия подтвердить",
)


def _err_text(err) -> str:
    if isinstance(err, dict):
        return f"{err.get('message') or ''} {err.get('details') or ''}".strip()
    return str(err or "")


def _is_already_ok(text: str) -> bool:
    t = (text or "").lower()
    return any(x in t for x in _ALREADY)


def _ack_one(doc_id: int, *, write) -> dict:
    close_old_connections()
    try:
        doc = RequirementDocument.objects.filter(pk=doc_id).first()
        if not doc:
            return {"id": doc_id, "ok": False, "status": "missing"}
        if doc.receipt_acked_at:
            return {"id": doc_id, "inn": doc.inn, "ok": True, "status": "already_marked"}

        inn = doc.inn
        cert = (
            Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
            .exclude(csptest_name="")
            .order_by("-id")
            .first()
        )
        kpp = resolve_kpp_for_inn(inn, cert)
        if not kpp:
            write(f"[{inn}] SKIP no_kpp doc={doc.sbis_doc_id[:24]}")
            return {"id": doc_id, "inn": inn, "ok": False, "status": "no_kpp"}

        today = timezone.localdate()
        date_to = today.strftime("%d.%m.%Y")
        date_from = (today - timedelta(days=30)).strftime("%d.%m.%Y")

        res = finalize_requirement_ack(
            inn,
            kpp=kpp,
            doc_id=doc.sbis_doc_id,
            date_from_str=date_from,
            date_to_str=date_to,
            do_drain=False,
        )
        rr = res.get("result") or {}
        sent = bool(rr.get("receipt_sent"))
        skipped = bool(rr.get("receipt_skipped"))
        comment = (rr.get("receipt_comment") or "") + " " + _err_text(res.get("error"))

        if sent or (res.get("success") and skipped and _is_already_ok(comment)):
            RequirementDocument.objects.filter(pk=doc.pk).update(
                receipt_acked_at=timezone.now()
            )
            write(
                f"[{inn}] OK {doc.sbis_doc_id[:24]} sent={sent} skipped={skipped} {comment[:80]}"
            )
            return {"id": doc_id, "inn": inn, "ok": True, "status": "acked", "sent": sent}

        if skipped and _is_already_ok(comment):
            RequirementDocument.objects.filter(pk=doc.pk).update(
                receipt_acked_at=timezone.now()
            )
            write(f"[{inn}] OK already {doc.sbis_doc_id[:24]} {comment[:80]}")
            return {"id": doc_id, "inn": inn, "ok": True, "status": "already_in_sbis"}

        # «нет действия» без явного already — тоже помечаем, чтобы не крутить вечно
        if skipped and "нет действия" in comment.lower():
            RequirementDocument.objects.filter(pk=doc.pk).update(
                receipt_acked_at=timezone.now()
            )
            write(f"[{inn}] OK no-action {doc.sbis_doc_id[:24]} {comment[:80]}")
            return {"id": doc_id, "inn": inn, "ok": True, "status": "no_action"}

        write(f"[{inn}] FAIL {doc.sbis_doc_id[:24]} {comment[:160] or res}")
        return {
            "id": doc_id,
            "inn": inn,
            "ok": False,
            "status": "error",
            "error": comment[:300] or str(res)[:300],
        }
    except Exception as e:
        logger.exception("ack_requirements_delayed fail id=%s", doc_id)
        write(f"[id={doc_id}] FAIL {e}")
        return {"id": doc_id, "ok": False, "status": "exception", "error": str(e)[:300]}
    finally:
        close_old_connections()


class Command(BaseCommand):
    help = (
        "Подтвердить получение требований, скачанных ≥ N дней назад "
        "(по created_at), у которых ещё нет receipt_acked_at"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--delay-days",
            type=int,
            default=4,
            help="Минимум дней с created_at до ack (по умолчанию 4)",
        )
        parser.add_argument("--workers", type=int, default=4)
        parser.add_argument("--limit", type=int, default=0, help="Макс. документов (0=все)")
        parser.add_argument("--inn", action="append", default=[], help="Только эти ИНН")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument(
            "--include-stubs",
            action="store_true",
            help="Включать .stub (блокировки) — по умолчанию нет",
        )

    def handle(self, *args, **options):
        delay_days = max(0, int(options["delay_days"] or 0))
        cutoff = timezone.now() - timedelta(days=delay_days)
        qs = RequirementDocument.objects.filter(
            receipt_acked_at__isnull=True,
            created_at__lte=cutoff,
        ).order_by("created_at")
        if not options.get("include_stubs"):
            qs = qs.exclude(storage_file_name__endswith=".stub")

        inns = [x.strip() for x in (options.get("inn") or []) if x and x.strip()]
        if inns:
            qs = qs.filter(inn__in=inns)

        limit = int(options.get("limit") or 0)
        ids = list(qs.values_list("id", flat=True))
        if limit > 0:
            ids = ids[:limit]

        self.stdout.write(
            f"К ack: {len(ids)} (delay_days={delay_days}, cutoff={cutoff.isoformat()}, "
            f"dry_run={options['dry_run']})"
        )
        if not ids:
            return
        if options["dry_run"]:
            for pk in ids[:50]:
                d = RequirementDocument.objects.filter(pk=pk).values(
                    "inn", "sbis_doc_id", "created_at", "doc_title"
                ).first()
                self.stdout.write(f"  would ack {d}")
            if len(ids) > 50:
                self.stdout.write(f"  ... и ещё {len(ids) - 50}")
            return

        workers = max(1, min(8, int(options["workers"] or 1)))
        lock = threading.Lock()

        def write(msg: str) -> None:
            with lock:
                self.stdout.write(msg)
                self.stdout.flush()

        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_ack_one, pk, write=write) for pk in ids]
            for fut in as_completed(futs):
                results.append(fut.result())

        ok_n = sum(1 for r in results if r.get("ok"))
        self.stdout.write(
            self.style.SUCCESS(f"Готово: ok={ok_n} err={len(results) - ok_n} total={len(results)}")
        )
