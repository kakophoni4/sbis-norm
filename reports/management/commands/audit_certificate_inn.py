"""
Проверка ИНН ЮЛ: Subject сертификата vs таблица Certificate.

  docker compose exec web python manage.py audit_certificate_inn --limit 50
  docker compose exec web python manage.py audit_certificate_inn
"""
from django.core.management.base import BaseCommand
from django.db.models import Count

from reports.management.commands.scan_certificates import (
    FNS_ISSUER_INN,
    CspIndex,
    _inn_from_certmgr_output,
    _subject_text_from_listing,
    certmgr_list_file,
    export_cert_from_container,
    list_hdimage_containers,
    obtain_cert_path,
    parse_cert_info,
    verify_container_has_private_key,
)
from reports.models import Certificate


class Command(BaseCommand):
    help = "Аудит ИНН ЮЛ из Subject (не Issuer ФНС) vs Certificate в БД"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=0, help="N контейнеров (0 = все)")
        parser.add_argument(
            "--db-only",
            action="store_true",
            help="Только статистика по БД, без certmgr",
        )

    def handle(self, *args, **options):
        if options["db_only"]:
            self._audit_db()
            return

        csp_index = CspIndex()
        containers = list_hdimage_containers()
        if options["limit"]:
            containers = containers[: options["limit"]]

        unique_subject_inn: set[str] = set()
        fns_false_positive = 0
        mismatches: list[str] = []
        no_inn = 0
        checked = 0

        for csptest_name in containers:
            has_key = verify_container_has_private_key(csptest_name)
            cert_path, source, _ = obtain_cert_path(csptest_name, csp_index)
            if not cert_path:
                continue
            checked += 1
            out = certmgr_list_file(cert_path)
            subject_inn = _inn_from_certmgr_output(out)
            info = parse_cert_info(cert_path, csptest_name, csp_index)
            resolved = info.get("inn")

            if subject_inn:
                unique_subject_inn.add(subject_inn)
            else:
                no_inn += 1

            if resolved == FNS_ISSUER_INN:
                fns_false_positive += 1

            db_cert = Certificate.objects.filter(csptest_name=csptest_name).first()
            db_inn = db_cert.inn if db_cert else None
            if resolved and db_inn and resolved != db_inn:
                mismatches.append(f"{csptest_name}: cert={resolved} db={db_inn}")

            if len(mismatches) < 10 and resolved != subject_inn and subject_inn:
                mismatches.append(
                    f"{csptest_name}: subject_ИНН_ЮЛ={subject_inn} resolved={resolved} key={has_key}"
                )

        self.stdout.write(self.style.SUCCESS("=== Аудит ИНН из сертификатов ==="))
        self.stdout.write(f"  контейнеров проверено: {checked}")
        self.stdout.write(f"  уникальных ИНН ЮЛ (Subject): {len(unique_subject_inn)}")
        self.stdout.write(f"  без ИНН в Subject: {no_inn}")
        self.stdout.write(f"  ошибочно ИНН ФНС ({FNS_ISSUER_INN}): {fns_false_positive}")

        if mismatches:
            self.stdout.write(self.style.WARNING("Примеры расхождений:"))
            for line in mismatches[:15]:
                self.stdout.write(f"  {line}")

        self.stdout.write("")
        self._audit_db()

    def _audit_db(self):
        self.stdout.write(self.style.SUCCESS("=== Таблица Certificate ==="))
        total = Certificate.objects.count()
        active = Certificate.objects.filter(is_active=True).count()
        unique = (
            Certificate.objects.filter(is_active=True)
            .exclude(inn="")
            .values("inn")
            .distinct()
            .count()
        )
        fns_rows = Certificate.objects.filter(inn=FNS_ISSUER_INN).count()
        self.stdout.write(f"  записей: {total}, активных: {active}")
        self.stdout.write(f"  уникальных ИНН (активные): {unique}")
        if fns_rows:
            self.stdout.write(
                self.style.ERROR(f"  записей с ИНН ФНС {FNS_ISSUER_INN}: {fns_rows} — нужен rescan --clear")
            )

        dupes = (
            Certificate.objects.filter(is_active=True)
            .exclude(inn="")
            .values("inn")
            .annotate(c=Count("id"))
            .filter(c__gt=1)
            .order_by("-c")[:5]
        )
        if dupes:
            self.stdout.write("  ИНН с несколькими активными записями (топ):")
            for row in dupes:
                self.stdout.write(f"    {row['inn']}: {row['c']} шт.")
