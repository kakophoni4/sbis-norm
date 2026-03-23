"""
Импорт ИНН → КПП из CSV (после выгрузки с ПК, DaData, своего парсера и т.д.).

Формат файла (первая строка — заголовок, разделитель запятая или ;):
  inn,kpp
  9729337785,773301001

Или колонки: ИНН, КПП

Пример:
  .venv/bin/python3 manage.py import_kpp_csv /tmp/kpp.csv
  .venv/bin/python3 manage.py import_kpp_csv /tmp/kpp.csv --sync-certificates --dry-run
"""
import csv
import io
import re
import sys
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import transaction

from reports.models import Certificate, Organization

_INN_CELL = re.compile(r"^inn$|^инн$", re.I)
_KPP_CELL = re.compile(r"^kpp$|^кпп$", re.I)


class Command(BaseCommand):
    help = "Обновить Organization.kpp и/или Certificate.kpp из CSV (inn, kpp)"

    def add_arguments(self, parser):
        parser.add_argument("csv_path", help="Путь к CSV")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать строки, без записи",
        )
        parser.add_argument(
            "--sync-certificates",
            action="store_true",
            help="Обновить Certificate.kpp для совпадающего ИНН",
        )
        parser.add_argument(
            "--ensure-organization",
            action="store_true",
            help="Создать Organization, если нет (name = 'ИНН {inn}')",
        )
        parser.add_argument(
            "--encoding",
            default="utf-8-sig",
            help="Кодировка файла (по умолчанию utf-8-sig для Excel)",
        )

    def handle(self, *args, **options):
        path = Path(options["csv_path"])
        dry = options["dry_run"]
        sync_certs = options["sync_certificates"]
        ensure_org = options["ensure_organization"]
        enc = options["encoding"] or "utf-8-sig"

        if not path.is_file():
            self.stderr.write(self.style.ERROR(f"Файл не найден: {path}\n"))
            sys.exit(1)

        text = path.read_text(encoding=enc)
        buf = io.StringIO(text)
        try:
            dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(buf, dialect=dialect)
        if not reader.fieldnames:
            self.stderr.write(self.style.ERROR("Пустой CSV или нет заголовка\n"))
            sys.exit(1)

        fn = [x.strip() for x in reader.fieldnames if x]
        inn_col = next((c for c in fn if _INN_CELL.match(c.strip())), None)
        kpp_col = next((c for c in fn if _KPP_CELL.match(c.strip())), None)
        if not inn_col or not kpp_col:
            self.stderr.write(
                self.style.ERROR(
                    f"Нужны колонки inn/ИНН и kpp/КПП. Заголовки: {reader.fieldnames}\n"
                )
            )
            sys.exit(1)

        ok = skip = bad = 0
        for row in reader:
            inn = (row.get(inn_col) or "").strip()
            kpp = (row.get(kpp_col) or "").strip()
            if not inn or not kpp:
                bad += 1
                continue
            if len(kpp) != 9 or not kpp.isdigit():
                self.stdout.write(self.style.WARNING(f"Пропуск: ИНН {inn} неверный КПП {kpp!r}"))
                bad += 1
                continue

            org = Organization.objects.filter(inn=inn).first()
            if not org and not ensure_org:
                self.stdout.write(self.style.WARNING(f"Нет Organization для ИНН {inn}, пропуск (или --ensure-organization)"))
                skip += 1
                continue

            self.stdout.write(f"ИНН {inn} → КПП {kpp}")

            if dry:
                ok += 1
                continue

            with transaction.atomic():
                if org:
                    Organization.objects.filter(pk=org.pk).update(kpp=kpp)
                elif ensure_org:
                    Organization.objects.create(inn=inn, kpp=kpp, name=f"ИНН {inn}"[:255])
                if sync_certs:
                    Certificate.objects.filter(inn=inn).update(kpp=kpp)
            ok += 1

        self.stdout.write(
            self.style.SUCCESS(f"Готово: записано/принято {ok}, пропусков {skip}, с ошибками {bad}")
        )
        if dry:
            self.stdout.write(self.style.WARNING("--dry-run: в БД не писали"))
