"""
Проверка авторизации СБИС по одному сертификату (тот же путь, что send_nds_extra).
Запуск: sudo .venv/bin/python manage.py test_sbis_auth_one 9722082369

Если команда зависает после "Контейнер: ...":
  - На сервере должны быть обновлены reports/sbis_service.py (таймаут в run_cmd)
    и reports/services/sbis.py (progress_callback), иначе certmgr ждёт бесконечно.
  - Проверьте вручную (подставьте свой контейнер):
    sudo certmgr -export -cont '\\\\.\\HDIMAGE\\286918236-b48c-96eb-238d-fb295c9c483' -dest /tmp/test.cer
    Если запрашивает пароль/PIN — ключ защищён; без таймаута скрипт будет висеть.
"""
import logging
import sys
import traceback

from django.core.management.base import BaseCommand
from reports.models import Certificate
from reports.services.sbis import SbisSessionService, SbisAuthError


class Command(BaseCommand):
    help = "Проверка авторизации СБИС по одному ИНН (как в send_nds_extra)"

    def add_arguments(self, parser):
        parser.add_argument("inn", nargs="?", default="9722082369", help="ИНН (по умолчанию 9722082369)")
        parser.add_argument("--full-traceback", action="store_true", dest="full_traceback", help="При ошибке вывести полный traceback")
        parser.add_argument("--debug", action="store_true", help="Включить DEBUG-логи (sbis, sbis_service)")

    def handle(self, *args, **options):
        inn = options["inn"]
        show_traceback = options.get("full_traceback", False)
        # Всегда показывать пошаговые логи auth (где зависло: HTTP или cryptcp)
        sbis_log = logging.getLogger("reports.sbis_service")
        sbis_log.setLevel(logging.INFO)
        if not sbis_log.handlers:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(logging.Formatter("  %(message)s"))
            sbis_log.addHandler(h)
        if options.get("debug"):
            logging.getLogger("reports.services.sbis").setLevel(logging.DEBUG)
        self.stdout.write(f"ИНН: {inn}")

        cert = Certificate.objects.filter(inn=inn, has_private_key=True).first()
        if not cert:
            self.stdout.write(self.style.ERROR("Сертификат не найден"))
            sys.exit(1)
        self.stdout.write(f"  Контейнер: {cert.csptest_name[:60]}...")
        self.stdout.write("  (если зависло — обновите sbis_service.py и reports/services/sbis.py на сервере)")
        sys.stdout.flush()

        def progress(msg: str) -> None:
            self.stdout.write(msg)
            sys.stdout.flush()

        try:
            try:
                service = SbisSessionService(certificate=cert, progress_callback=progress)
            except TypeError:
                service = SbisSessionService(certificate=cert)
            session_id = service.authenticate()
            self.stdout.write(self.style.SUCCESS(f"Session ID: {session_id}"))
        except SbisAuthError as e:
            self._log_error(e, show_traceback)
            sys.exit(1)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка: {e}"))
            if getattr(e, "__cause__", None):
                self.stdout.write(self.style.ERROR(f"Причина: {e.__cause__}"))
            if show_traceback:
                self.stdout.write(traceback.format_exc())
            sys.exit(1)

    def _log_error(self, e, show_traceback):
        self.stdout.write(self.style.ERROR(f"Ошибка: {e}"))
        if getattr(e, "__cause__", None):
            self.stdout.write(self.style.ERROR(f"Причина: {e.__cause__}"))
        if show_traceback:
            self.stdout.write(traceback.format_exc())
