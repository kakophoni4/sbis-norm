"""
Переименовать storage_file_name у записей, где расширение .bin, а по байтам — .p7m / .xml и т.д.

  python manage.py fix_requirement_storage_extensions --dry-run
  python manage.py fix_requirement_storage_extensions
"""
import base64

from django.core.management.base import BaseCommand
from django.db import transaction

from reports.models import RequirementDocument
from reports.requirement_file_sniff import guess_requirement_extension


def _replace_ext(filename: str, new_ext: str) -> str:
    if not filename or "." not in filename:
        return f"file{new_ext}"
    base = filename.rsplit(".", 1)[0]
    return f"{base}{new_ext}"


class Command(BaseCommand):
    help = "Обновить storage_file_name для .bin по фактической сигнатуре (p7m, xml, …)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, что изменилось бы",
        )

    def handle(self, *args, **options):
        dry = options["dry_run"]
        qs = RequirementDocument.objects.exclude(storage_file_name="").filter(
            storage_file_name__iendswith=".bin"
        )
        n = 0
        for r in qs.iterator(chunk_size=100):
            try:
                data = base64.b64decode(r.file_b64)
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"id={r.id}: b64: {e}"))
                continue
            ext = guess_requirement_extension(data)
            if ext == ".bin":
                continue
            old = (r.storage_file_name or "").strip()
            new_name = _replace_ext(old, ext)
            if new_name == old:
                continue
            n += 1
            self.stdout.write(f"id={r.id} ИНН={r.inn}: {old!r} -> {new_name!r}")
            if not dry:
                with transaction.atomic():
                    r.storage_file_name = new_name
                    r.save(update_fields=["storage_file_name"])

        if dry:
            self.stdout.write(self.style.WARNING(f"DRY-RUN: было бы обновлено записей: {n}"))
        else:
            self.stdout.write(self.style.SUCCESS(f"Обновлено записей: {n}"))
