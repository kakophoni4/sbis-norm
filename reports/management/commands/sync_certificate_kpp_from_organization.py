"""
Заполнить Certificate.kpp из Organization.kpp для совпадающих ИНН.
Удобно, когда КПП уже есть в Organization (например после sync_kpp_from_documents без --sync-certificates).

Пример:
  python manage.py sync_certificate_kpp_from_organization
  python manage.py sync_certificate_kpp_from_organization --dry-run
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q

from reports.models import Certificate, Organization


class Command(BaseCommand):
    help = "Скопировать КПП из Organization в Certificate для совпадающих ИНН"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, сколько записей обновим",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        orgs_with_kpp = Organization.objects.exclude(kpp__isnull=True).exclude(kpp="")
        certs_without_kpp = Certificate.objects.filter(
            csptest_name__isnull=False
        ).exclude(csptest_name="").filter(is_active=True).filter(
            Q(kpp__isnull=True) | Q(kpp="")
        )

        org_by_inn = {o.inn: o.kpp for o in orgs_with_kpp}

        to_update = []
        for cert in certs_without_kpp:
            kpp = org_by_inn.get((cert.inn or "").strip())
            if kpp:
                to_update.append((cert, kpp))

        if dry_run:
            self.stdout.write(
                f"Будет обновлено записей Certificate.kpp: {len(to_update)} (из {len(certs_without_kpp)} без КПП, в Organization с КПП: {len(org_by_inn)})"
            )
            return

        updated = 0
        with transaction.atomic():
            for cert, kpp in to_update:
                cert.kpp = kpp
                cert.save(update_fields=["kpp"])
                updated += 1

        self.stdout.write(
            self.style.SUCCESS(f"Обновлено Certificate.kpp: {updated} записей.")
        )
