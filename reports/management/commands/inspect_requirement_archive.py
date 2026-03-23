"""
Вскрыть ZIP из RequirementDocument и показать содержимое (имена файлов, размеры, начало).
Убедиться, что внутри архива именно то, что нужно (PDF, XML и т.д.).

Пример:
  python manage.py inspect_requirement_archive
  python manage.py inspect_requirement_archive --id 1
  python manage.py inspect_requirement_archive --inn 9715501379 --limit 3
"""
import base64
import io
import zipfile

from django.core.management.base import BaseCommand

from reports.models import RequirementDocument


class Command(BaseCommand):
    help = "Распаковать и показать содержимое архива из RequirementDocument"

    def add_arguments(self, parser):
        parser.add_argument("--id", type=int, help="ID записи RequirementDocument")
        parser.add_argument("--inn", type=str, help="Фильтр по ИНН")
        parser.add_argument("--limit", type=int, default=5, help="Макс. записей (по умолчанию 5)")

    def handle(self, *args, **options):
        qs = RequirementDocument.objects.all().order_by("-created_at")
        if options.get("id"):
            qs = qs.filter(pk=options["id"])
        if options.get("inn"):
            qs = qs.filter(inn=options["inn"])
        qs = qs[: options.get("limit", 5)]

        for r in qs:
            self.stdout.write(f"\n--- Запись id={r.id} ИНН={r.inn} дата={r.document_date} ---")
            data = base64.b64decode(r.file_b64)
            if not data.startswith(b"PK\x03\x04"):
                self.stdout.write(self.style.WARNING(f"  Не ZIP (первые байты: {data[:8].hex()}), пропуск."))
                continue
            try:
                zf = zipfile.ZipFile(io.BytesIO(data), "r")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Ошибка открытия ZIP: {e}"))
                continue
            for name in zf.namelist():
                info = zf.getinfo(name)
                self.stdout.write(f"  Файл в архиве: {name!r}  размер={info.file_size} Б")
                try:
                    content = zf.read(name)
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"    Ошибка чтения: {e}"))
                    continue
                # Первые байты
                head = content[:80]
                if content.startswith(b"%PDF"):
                    self.stdout.write(f"    Начало: PDF (сигнатура %PDF), всего {len(content)} Б")
                elif content.strip().startswith(b"<"):
                    self.stdout.write(f"    Начало: похоже на XML/HTML, первые 60 симв: {head[:60]}")
                else:
                    self.stdout.write(f"    Первые 50 байт (hex): {head[:50].hex()}")
            zf.close()
        self.stdout.write("")
