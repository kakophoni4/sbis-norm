"""
Синхронизировать has_private_key по хранилищу uMy (PrivateKey Link).

Для SBIS auth нужен сертификат в uMy с привязкой к контейнеру — это делает
sbis_keys_install_linux.sh --install-only / scan_certificates --install-uMy,
затем эта команда.

  docker compose exec web python manage.py sync_has_private_key
  docker compose exec web python manage.py sync_has_private_key --all  # только для отладки
"""
from django.core.management.base import BaseCommand

from reports.management.commands.scan_certificates import update_private_key_flags
from reports.models import Certificate


class Command(BaseCommand):
    help = "Синхронизировать has_private_key по uMy (PrivateKey Link в CryptoPro)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Принудительно has_private_key=True для всех (НЕ для SBIS auth — без проверки uMy)",
        )

    def handle(self, *args, **options):
        if options["all"]:
            self.stdout.write(
                self.style.WARNING(
                    "ВНИМАНИЕ: --all не проверяет uMy. Для test_sbis_auth_all используйте без --all."
                )
            )
            n = Certificate.objects.update(has_private_key=True)
            self.stdout.write(self.style.SUCCESS(f"has_private_key=True для всех: {n}"))
            return

        # Без массового UPDATE False: флаги выставляются по фактическому uMy.
        stats = update_private_key_flags()
        self.stdout.write(
            f"uMy sync: linked={stats.get('linked')} unlinked={stats.get('unlinked')} "
            f"updated={stats.get('updated')} unchanged={stats.get('unchanged')}"
        )

        with_pk = Certificate.objects.filter(has_private_key=True).count()
        total = Certificate.objects.count()
        auth_inns = (
            Certificate.objects.filter(has_private_key=True, is_active=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
            .count()
        )
        self.stdout.write(self.style.SUCCESS(f"has_private_key=True (uMy): {with_pk} / {total}"))
        self.stdout.write(f"ИНН готовых к auth: {auth_inns}")
