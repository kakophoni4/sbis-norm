"""
Подтянуть из СБИС поле «Срок» и признак «отвечено» для уже сохранённых требований.

  docker compose exec -T web python manage.py backfill_requirement_sbis_meta --limit 20
  docker compose exec -T web python manage.py backfill_requirement_sbis_meta --inn 9707039440
  docker compose exec -T web python manage.py backfill_requirement_sbis_meta --only-missing-due
"""
from __future__ import annotations

import time

from django.core.management.base import BaseCommand
from django.db.models import Q

from reports.models import RequirementDocument
from reports.services.requirement_deadline import receipt_due_from_document_date
from reports.services.requirement_sbis_meta import (
    apply_sbis_meta_to_requirement,
    fetch_requirement_sbis_meta,
)


class Command(BaseCommand):
    help = "Backfill response_due_date (Срок) и reply_status=answered из СБИС.ПрочитатьДокумент"

    def add_arguments(self, parser):
        parser.add_argument("--inn", default="", help="Только этот ИНН")
        parser.add_argument("--limit", type=int, default=0, help="Макс. записей (0 = все)")
        parser.add_argument("--id", type=int, default=0, help="Один id RequirementDocument")
        parser.add_argument(
            "--only-missing-due",
            action="store_true",
            help="Только где response_due_date IS NULL",
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=0.4,
            help="Пауза между документами (сек), по умолчанию 0.4",
        )
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        qs = RequirementDocument.objects.all().order_by("-id")
        inn = str(options.get("inn") or "").strip()
        if inn:
            qs = qs.filter(inn=inn)
        pk = int(options.get("id") or 0)
        if pk:
            qs = qs.filter(id=pk)
        if options.get("only_missing_due"):
            qs = qs.filter(Q(response_due_date__isnull=True) | Q(receipt_due_date__isnull=True))

        limit = int(options.get("limit") or 0)
        if limit > 0:
            qs = qs[:limit]

        dry_run = bool(options.get("dry_run"))
        delay = max(0.0, float(options.get("delay") or 0))
        rows = list(qs)
        self.stdout.write(f"backfill docs={len(rows)} dry_run={dry_run}")

        # session cache per inn
        sessions: dict[str, str] = {}
        ok = err = updated = answered = srok_set = 0

        for doc in rows:
            # receipt_due всегда можно без СБИС
            if not doc.receipt_due_date and doc.document_date and not dry_run:
                doc.receipt_due_date = receipt_due_from_document_date(doc.document_date)
                doc.save(update_fields=["receipt_due_date"])
                updated += 1

            sid = sessions.get(doc.inn)
            res = fetch_requirement_sbis_meta(
                doc.inn,
                sbis_doc_id=doc.sbis_doc_id,
                document_date=doc.document_date,
                session_id=sid,
            )
            if res.get("success") and (res.get("meta") or {}).get("session_id"):
                sessions[doc.inn] = res["meta"]["session_id"]

            if not res.get("success"):
                err += 1
                self.stdout.write(
                    self.style.WARNING(
                        f"  id={doc.id} inn={doc.inn} ERROR {(res.get('error') or {})}"
                    )
                )
                if delay:
                    time.sleep(delay)
                continue

            meta = res.get("meta") or {}
            ok += 1
            if dry_run:
                self.stdout.write(
                    f"  id={doc.id} inn={doc.inn} srok={meta.get('srok_raw')!r} "
                    f"due={meta.get('response_due_date')} answered={meta.get('is_answered')} "
                    f"state={meta.get('state_code')}/{meta.get('state_name')}"
                )
            else:
                # перечитать на случай параллельных правок
                doc.refresh_from_db()
                before_status = doc.reply_status
                before_due = doc.response_due_date
                fields = apply_sbis_meta_to_requirement(doc, meta)
                if fields:
                    updated += 1
                if doc.response_due_date and doc.response_due_date != before_due:
                    srok_set += 1
                if doc.reply_status == RequirementDocument.REPLY_STATUS_ANSWERED and before_status != doc.reply_status:
                    answered += 1
                self.stdout.write(
                    f"  id={doc.id} inn={doc.inn} fields={fields or '-'} "
                    f"due={doc.response_due_date} status={doc.reply_status} "
                    f"srok_raw={meta.get('srok_raw')!r}"
                )

            if delay:
                time.sleep(delay)

        self.stdout.write(
            self.style.SUCCESS(
                f"DONE ok={ok} err={err} updated={updated} srok_set={srok_set} marked_answered={answered}"
            )
        )
