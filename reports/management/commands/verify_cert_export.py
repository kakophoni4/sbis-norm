"""
Проверка экспорта сертификатов из контейнеров CryptoPro.

  docker compose exec web python manage.py verify_cert_export
  docker compose exec web python manage.py verify_cert_export --limit 50
"""
import hashlib

from django.core.management.base import BaseCommand

from reports.management.commands.scan_certificates import (
    CspIndex,
    export_cert_from_container,
    get_inn_from_cont_name,
    is_copy_container,
    list_hdimage_containers,
    obtain_cert_path,
    parse_cert_info,
)


class Command(BaseCommand):
    help = "Проверить certmgr -export и fallback .cer из CSP_ROOT"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=0, help="Проверить N контейнеров (0 = все)")
        parser.add_argument(
            "--skip-copies",
            action="store_true",
            help="Пропустить контейнеры «… копия»",
        )

    def handle(self, *args, **options):
        self.stdout.write("Индекс CSP_ROOT...")
        csp_index = CspIndex()
        csp_index.warm_best_cers()
        self.stdout.write(
            f"  ИНН-каталогов: {csp_index.inn_count}, .cer на диске: {csp_index.cer_count}"
        )

        containers = list_hdimage_containers()
        if options["limit"]:
            containers = containers[: options["limit"]]
        total = len(containers)
        self.stdout.write(f"Проверка контейнеров: {total}")

        stats = {
            "export_ok": 0,
            "folder_cer": 0,
            "no_cert": 0,
            "export_fail_folder_ok": 0,
            "skipped_copies": 0,
            "folder_inn_resolved": 0,
        }
        samples_export: list[str] = []
        samples_folder: list[str] = []
        samples_fail: list[str] = []

        skip_copies = options["skip_copies"]

        for csptest_name in containers:
            if skip_copies and is_copy_container(csptest_name):
                stats["skipped_copies"] += 1
                continue

            dest = f"/tmp/verify_{hashlib.sha256(csptest_name.encode()).hexdigest()[:12]}.cer"
            export_ok, export_err = export_cert_from_container(csptest_name, dest)

            cert_path, source, _has_key = obtain_cert_path(csptest_name, csp_index)

            if source == "folder":
                folder_inn = csp_index.get_inn_from_csp_folder_for_cont(csptest_name)
                if folder_inn:
                    stats["folder_inn_resolved"] += 1

            if source == "export":
                stats["export_ok"] += 1
                if len(samples_export) < 5:
                    info = parse_cert_info(cert_path, csptest_name, csp_index)
                    samples_export.append(
                        f"{csptest_name} → ИНН {info.get('inn')} thumb={str(info.get('thumbprint'))[:12]}..."
                    )
            elif source == "folder":
                stats["folder_cer"] += 1
                if not export_ok:
                    stats["export_fail_folder_ok"] += 1
                if len(samples_folder) < 5:
                    info = parse_cert_info(cert_path, csptest_name, csp_index)
                    samples_folder.append(
                        f"{csptest_name} → .cer ИНН {info.get('inn')} ({cert_path})"
                    )
            else:
                stats["no_cert"] += 1
                if len(samples_fail) < 8:
                    inn_hint = (
                        csp_index.get_inn_from_csp_folder_for_cont(csptest_name)
                        or csp_index.get_inn(csptest_name)
                        or get_inn_from_cont_name(csptest_name, csp_index.known_inns)
                        or "?"
                    )
                    cer_avail = (
                        "есть .cer в папке"
                        if inn_hint != "?" and csp_index.get_best_cer_for_inn(str(inn_hint))
                        else "нет .cer"
                    )
                    err_short = (export_err or "нет .cer")[:80]
                    samples_fail.append(
                        f"{csptest_name} (ИНН~{inn_hint}, {cer_avail}): {err_short}"
                    )

        checked = total - stats["skipped_copies"]
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Результат ==="))
        if stats["skipped_copies"]:
            self.stdout.write(f"  пропущено «копия»:         {stats['skipped_copies']} / {total}")
        self.stdout.write(f"  export из контейнера:     {stats['export_ok']} / {checked}")
        self.stdout.write(f"  .cer из CSP_ROOT:         {stats['folder_cer']} / {checked}")
        self.stdout.write(f"    ИНН найден по папке:     {stats['folder_inn_resolved']}")
        self.stdout.write(f"    export не удался:        {stats['export_fail_folder_ok']}")
        self.stdout.write(f"  без серта вообще:         {stats['no_cert']} / {checked}")

        if samples_export:
            self.stdout.write("")
            self.stdout.write("Примеры export OK:")
            for s in samples_export:
                self.stdout.write(f"  {s}")

        if samples_folder:
            self.stdout.write("")
            self.stdout.write("Примеры .cer из папки:")
            for s in samples_folder:
                self.stdout.write(f"  {s}")

        if samples_fail:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING("Примеры без серта:"))
            for s in samples_fail:
                self.stdout.write(f"  {s}")

        ok_total = stats["export_ok"] + stats["folder_cer"]
        self.stdout.write("")
        if checked and ok_total >= checked * 0.8:
            self.stdout.write(
                self.style.SUCCESS(f"OK: сертификат найден для {ok_total}/{checked} контейнеров")
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"Мало сертификатов: {ok_total}/{checked}. "
                    "Для контейнеров без встроенного серта положите .cer в CSP_ROOT/{{ИНН}}/ "
                    "и запустите: python manage.py scan_certificates --install-uMy"
                )
            )
