"""
Уже лежащие в БД уведомления о блокировке счёта — снова отдать в CRM (unsynced).

  docker compose exec -T web python manage.py mark_block_notices_for_crm
  docker compose exec -T web python manage.py mark_block_notices_for_crm --dry-run
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from reports.models import RequirementDocument


def _is_block_title(title: str) -> bool:
    t = (title or "").lower().replace("ё", "е")
    if "блокировк" in t and "счет" in t:
        return True
    if "приостановлен" in t and "счет" in t:
        return True
    return False


class Command(BaseCommand):
    help = "Сбросить external_synced_at у уведомлений о блокировке счёта (повторный pull CRM)"

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--inn", default="", help="Только этот ИНН")

    def handle(self, *args, **options):
        dry = bool(options.get("dry_run"))
        inn = str(options.get("inn") or "").strip()
        qs = RequirementDocument.objects.all().order_by("-id")
        if inn:
            qs = qs.filter(inn=inn)

        matched = []
        for doc in qs.iterator(chunk_size=200):
            if _is_block_title(doc.doc_title or "") or str(doc.storage_file_name or "").endswith(".stub"):
                matched.append(doc)

        self.stdout.write(f"block notices found: {len(matched)} dry_run={dry}")
        n_resync = 0
        n_stub_name = 0
        for doc in matched:
            fields = []
            if doc.external_synced_at is not None:
                doc.external_synced_at = None
                fields.append("external_synced_at")
                n_resync += 1
            name = (doc.storage_file_name or "").strip()
            if not name.endswith(".stub") and (not (doc.file_b64 or "").strip() or len(doc.file_b64 or "") < 50):
                doc.storage_file_name = (
                    f"Уведомление о блокировке ({doc.inn}) ({doc.document_date}).stub"
                )
                fields.append("storage_file_name")
                n_stub_name += 1
            if fields and not dry:
                doc.save(update_fields=fields)
            if fields:
                self.stdout.write(
                    f"  id={doc.id} inn={doc.inn} {(doc.doc_title or '')[:70]} → {fields}"
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"DONE resync={n_resync} stub_name={n_stub_name} total_matched={len(matched)}"
            )
        )
