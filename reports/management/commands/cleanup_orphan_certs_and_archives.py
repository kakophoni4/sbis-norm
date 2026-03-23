"""
Удалить с машины:
  1) Контейнеры сертификатов КриптоПро, которых нет в таблице Certificate (уже удалённые из БД).
  2) Архивы в ~/mega_signatures, в названии которых нет ни одного ИНН из Certificate.

ИНН в имени файла ищутся как 10-значные числа (ИНН ЮЛ). Если в названии архива есть хотя бы один
ИНН из БД — архив не трогаем.

Примеры:
  # Сначала посмотреть, что будет удалено (ничего не удалять):
  python manage.py cleanup_orphan_certs_and_archives --dry-run

  # Удалить и контейнеры, и архивы. Запускать БЕЗ sudo, из каталога проекта с активированным venv:
  .venv/bin/python manage.py cleanup_orphan_certs_and_archives

  Контейнеры КриптоПро команда вызовет через sudo (CSP_USE_SUDO), пароль спросит при первом csptest.
  Чтобы не вводить пароль, настройте passwordless sudo для csptest (см. docs/sbis_keys_linux_setup.md).

  # Только контейнеры:
  .venv/bin/python manage.py cleanup_orphan_certs_and_archives --certs-only

  # Только архивы:
  .venv/bin/python manage.py cleanup_orphan_certs_and_archives --archives-only --archives-dir ~/mega_signatures

  При запуске через sudo каталог архивов по умолчанию берётся из SUDO_USER (/home/<user>/mega_signatures).
  Сообщения «не удалён … Acquir» — контейнер занят или защищён КриптоПро, его удалить не удалось.
"""
import os
import re
import subprocess
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from reports.models import Certificate


CSPTEST_BIN = "/opt/cprocsp/bin/amd64/csptest"
DEFAULT_ARCHIVES_DIR = os.path.expanduser("~/mega_signatures")
# ИНН ЮЛ — 10 цифр
INN_PATTERN = re.compile(r"\b([0-9]{10})\b")


def run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Запуск команды. Возвращает (успех, stdout или stderr)."""
    use_sudo = getattr(settings, "CSP_USE_SUDO", True)
    if use_sudo and args and args[0] == CSPTEST_BIN:
        args = ["sudo", *args]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "").strip()
        return True, (result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def list_hdimage_containers() -> list[str]:
    """Список имён контейнеров HDIMAGE из csptest."""
    ok, out = run_cmd([CSPTEST_BIN, "-keyset", "-enum_cont", "-fqcn"])
    if not ok:
        return []
    containers = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("\\\\.\\HDIMAGE"):
            containers.append(line)
    return containers


def delete_container(container_name: str) -> tuple[bool, str]:
    """Удалить контейнер КриптоПро. Возвращает (успех, сообщение)."""
    # csptest -keyset -delete -cont '<name>'
    ok, out = run_cmd([CSPTEST_BIN, "-keyset", "-delete", "-cont", container_name], timeout=60)
    if ok:
        return True, "удалён"
    return False, out or "ошибка"


def inns_from_filename(name: str) -> list[str]:
    """Извлечь все 10-значные числа (ИНН) из строки имени файла."""
    return INN_PATTERN.findall(name)


class Command(BaseCommand):
    help = (
        "Удалить контейнеры сертификатов, которых нет в Certificate, "
        "и архивы в ~/mega_signatures, в названии которых нет ИНН из Certificate"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, что было бы удалено, не удалять",
        )
        parser.add_argument(
            "--certs-only",
            action="store_true",
            help="Только контейнеры сертификатов, не трогать архивы",
        )
        parser.add_argument(
            "--archives-only",
            action="store_true",
            help="Только архивы в --archives-dir, не трогать контейнеры",
        )
        parser.add_argument(
            "--archives-dir",
            type=str,
            default=DEFAULT_ARCHIVES_DIR,
            metavar="DIR",
            help=f"Каталог с архивами (по умолчанию {DEFAULT_ARCHIVES_DIR})",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        certs_only = options["certs_only"]
        archives_only = options["archives_only"]
        archives_dir = os.path.expanduser(options["archives_dir"] or DEFAULT_ARCHIVES_DIR)
        # При запуске через sudo ~ раскрывается в /root; каталог архивов у реального пользователя
        if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            sudo_user = os.environ.get("SUDO_USER", "").strip()
            if sudo_user and archives_dir == "/root/mega_signatures":
                archives_dir = os.path.join("/home", sudo_user, "mega_signatures")
                self.stdout.write(f"Используется каталог архивов пользователя {sudo_user}: {archives_dir}")

        if dry_run:
            self.stdout.write(self.style.WARNING("Режим --dry-run: удаление не выполняется"))

        # ИНН и имена контейнеров из БД
        db_inns = set(
            Certificate.objects.values_list("inn", flat=True).distinct()
        )
        db_containers = set(
            Certificate.objects.exclude(csptest_name__isnull=True)
            .exclude(csptest_name="")
            .values_list("csptest_name", flat=True)
            .distinct()
        )

        self.stdout.write(f"В БД Certificate: ИНН {len(db_inns)}, контейнеров {len(db_containers)}")

        # —— Контейнеры: удалить те, которых нет в БД ——
        if not archives_only:
            containers = list_hdimage_containers()
            self.stdout.write(f"На машине контейнеров: {len(containers)}")

            to_delete = [c for c in containers if c not in db_containers]
            self.stdout.write(f"Контейнеров не из БД (к удалению): {len(to_delete)}")

            deleted_containers = 0
            for cont in to_delete:
                if dry_run:
                    self.stdout.write(f"  [dry-run] удалили бы контейнер: {cont[:80]}...")
                    deleted_containers += 1
                    continue
                ok, msg = delete_container(cont)
                if ok:
                    self.stdout.write(self.style.SUCCESS(f"  удалён: {cont[:70]}"))
                    deleted_containers += 1
                else:
                    short_msg = (msg[:55] + "…") if len(msg) > 55 else msg
                    self.stdout.write(self.style.WARNING(f"  не удалён {cont[:50]}: {short_msg}"))

            if to_delete and not dry_run:
                self.stdout.write(f"Удалено контейнеров: {deleted_containers}")

        # —— Архивы: удалить те, в названии которых нет ИНН из БД ——
        if not certs_only:
            if not os.path.isdir(archives_dir):
                self.stdout.write(self.style.WARNING(f"Каталог архивов не найден: {archives_dir}"))
            else:
                entries = list(Path(archives_dir).iterdir())
                to_remove = []
                for p in entries:
                    if not p.is_file():
                        continue
                    name = p.name
                    inns_in_name = inns_from_filename(name)
                    # Нет ни одного ИНН из БД в названии → удалить
                    if not inns_in_name or not any(inn in db_inns for inn in inns_in_name):
                        to_remove.append(p)

                self.stdout.write(f"Архивов без ИНН из БД (к удалению): {len(to_remove)}")

                removed = 0
                for p in to_remove:
                    if dry_run:
                        self.stdout.write(f"  [dry-run] удалили бы: {p.name[:70]}")
                        removed += 1
                        continue
                    try:
                        p.unlink()
                        self.stdout.write(self.style.SUCCESS(f"  удалён: {p.name[:70]}"))
                        removed += 1
                    except OSError as e:
                        self.stdout.write(self.style.WARNING(f"  не удалён {p.name[:50]}: {e}"))

                if to_remove and not dry_run:
                    self.stdout.write(f"Удалено архивов: {removed}")

        self.stdout.write("Готово.")
