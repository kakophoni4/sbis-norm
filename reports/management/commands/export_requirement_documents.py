"""
Собрать требования из БД в один ZIP-архив для просмотра на ПК.
Структура архива: папки по ИНН, внутри файлы с именами «Требование ФНС (ИНН) (дата).pdf» (или .xml).

Пример:
  python manage.py export_requirement_documents --output /tmp/requirements.zip
  python manage.py export_requirement_documents --inn 9715501379 --output /tmp/req_inn.zip
  python manage.py export_requirement_documents --date 2026-03-10 --output /tmp/req_date.zip
  python manage.py export_requirement_documents --date-from 2026-03-01 --date-to 2026-03-20 --output /tmp/req_range.zip
"""
import base64
import zipfile
from datetime import date
from pathlib import Path

from django.core.management.base import BaseCommand

from reports.models import RequirementDocument
from reports.requirement_file_sniff import guess_requirement_extension


class Command(BaseCommand):
    help = "Экспорт требований в ZIP: папки по ИНН, файлы «Требование ФНС (ИНН) (дата).pdf»"

    def add_arguments(self, parser):
        parser.add_argument("--output", "-o", type=str, required=True, help="Путь к создаваемому ZIP-файлу")
        parser.add_argument("--inn", type=str, help="Только этот ИНН")
        parser.add_argument("--date", type=str, help="Только эта дата (ГГГГ-ММ-ДД или ДД.ММ.ГГГГ)")
        parser.add_argument("--date-from", type=str, help="Начало периода (ГГГГ-ММ-ДД)")
        parser.add_argument("--date-to", type=str, help="Конец периода (ГГГГ-ММ-ДД)")

    def _parse_date(self, s: str) -> date | None:
        if not s:
            return None
        s = s.strip()
        for fmt in ("%Y-%m-%d", "%d.%m.%Y"):
            try:
                return date.strptime(s, fmt)
            except ValueError:
                continue
        return None

    def handle(self, *args, **options):
        qs = RequirementDocument.objects.all().order_by("inn", "document_date", "id")

        if options.get("inn"):
            qs = qs.filter(inn=options["inn"])
        if options.get("date"):
            d = self._parse_date(options["date"])
            if d is None:
                self.stdout.write(self.style.ERROR(f"Неверный формат даты: {options['date']} (нужно ГГГГ-ММ-ДД или ДД.ММ.ГГГГ)"))
                return
            qs = qs.filter(document_date=d)
        if options.get("date_from"):
            d = self._parse_date(options["date_from"])
            if d is None:
                self.stdout.write(self.style.ERROR(f"Неверный --date-from: {options['date_from']}"))
                return
            qs = qs.filter(document_date__gte=d)
        if options.get("date_to"):
            d = self._parse_date(options["date_to"])
            if d is None:
                self.stdout.write(self.style.ERROR(f"Неверный --date-to: {options['date_to']}"))
                return
            qs = qs.filter(document_date__lte=d)

        count = qs.count()
        if count == 0:
            self.stdout.write(self.style.WARNING("Нет записей по заданным фильтрам."))
            return

        out_path = Path(options["output"]).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        seen: dict[str, int] = {}
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for r in qs:
                try:
                    data = base64.b64decode(r.file_b64)
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Ошибка декодирования id={r.id}: {e}"))
                    continue
                # Имя файла: из модели или стандартное
                name = (r.storage_file_name or "").strip()
                if not name:
                    ext = guess_requirement_extension(data)
                    name = f"Требование ФНС ({r.inn}) ({r.document_date}){ext}"
                # Путь в архиве: ИНН / имя файла (при дублях по имени — суффикс _2, _3, ...)
                safe_inn = str(r.inn).strip()
                arc_name = name
                key = f"{safe_inn}/{name}"
                if key in seen:
                    seen[key] += 1
                    parts = name.rsplit(".", 1)
                    base_name = parts[0] if len(parts) > 1 else name
                    ext = "." + parts[1] if len(parts) > 1 else ""
                    arc_name = f"{base_name}_{seen[key]}{ext}"
                else:
                    seen[key] = 1
                zf.writestr(f"{safe_inn}/{arc_name}", data)

        self.stdout.write(self.style.SUCCESS(f"Создан архив: {out_path}  (записей: {count})"))
        self.stdout.write(f"Структура: папки по ИНН, внутри файлы «Требование ФНС (ИНН) (дата).pdf».")
