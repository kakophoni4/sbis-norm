"""
Проставить has_private_key=True для сертификатов с ключами в CryptoPro.

  docker compose exec web python manage.py sync_has_private_key
  docker compose exec web python manage.py sync_has_private_key --all
"""
from django.core.management.base import BaseCommand

from reports.management.commands.scan_certificates import (
    export_cert_from_container,
    list_hdimage_containers,
    update_private_key_flags,
)
from reports.models import Certificate


class Command(BaseCommand):
    help = "Синхронизировать has_private_key по контейнерам CSP"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="has_private_key=True для всех записей Certificate (без проверки CSP)",
        )

    def handle(self, *args, **options):
        if options["all"]:
            n = Certificate.objects.update(has_private_key=True)
            self.stdout.write(self.style.SUCCESS(f"has_private_key=True для всех: {n}"))
            return

        containers = list_hdimage_containers()
        self.stdout.write(f"Контейнеров CSP: {len(containers)}")

        by_name = Certificate.objects.filter(csptest_name__in=containers).update(has_private_key=True)

        export_ok = 0
        for cert in Certificate.objects.exclude(csptest_name__isnull=True).exclude(csptest_name=""):
            if cert.has_private_key:
                continue
            tmp = f"/tmp/pk_check_{cert.id}.cer"
            if export_cert_from_container(cert.csptest_name, tmp):
                cert.has_private_key = True
                cert.save(update_fields=["has_private_key"])
                export_ok += 1

        update_private_key_flags()

        with_pk = Certificate.objects.filter(has_private_key=True).count()
        total = Certificate.objects.count()
        self.stdout.write(self.style.SUCCESS(f"По имени контейнера: {by_name}"))
        self.stdout.write(f"Дополнительно по export: {export_ok}")
        self.stdout.write(self.style.SUCCESS(f"Итого has_private_key=True: {with_pk} / {total}"))
