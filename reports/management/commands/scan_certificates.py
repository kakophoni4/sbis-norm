import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand

from reports.models import Certificate


CSPTEST_BIN = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CSP_ROOT = Path("/var/opt/cprocsp/keys/root")


def run_cmd(args: list[str]) -> str:
    """Запуск внешней команды и возврат stdout как строки."""
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout


def list_hdimage_containers() -> list[str]:
    """Вернуть список имён контейнеров вида \\.\HDIMAGE\... из csptest."""
    out = run_cmd([CSPTEST_BIN, "-keyset", "-enum_cont", "-fqcn"])
    containers = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("\\\\.\\HDIMAGE"):
            containers.append(line)
    return containers


def export_cert_from_container(container_name: str, dest_path: str) -> bool:
    """
    Экспортировать сертификат из контейнера в файл DER.
    Возвращает True при успехе, False при ошибке (контейнер недоступен, нет серта и т.д.).
    """
    result = subprocess.run(
        [CERTMGR_BIN, "-export", "-cont", container_name, "-dest", dest_path],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def parse_cert_date(s: str) -> datetime | None:
    """Парсинг дат вида '14/10/2024 11:58:46 UTC'."""
    try:
        s = s.replace(" UTC", "")
        dt = datetime.strptime(s, "%d/%m/%Y %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def get_inn_from_csp_folder(csptest_name: str) -> str | None:
    """ИНН из каталога CSP_ROOT/{inn}/, где лежит контейнер."""
    if not csptest_name:
        return None
    container_id = csptest_name.rsplit("\\", 1)[-1].strip()
    if container_id.endswith(" копия"):
        container_id = container_id[:-6].strip()
    if not container_id or not CSP_ROOT.is_dir():
        return None
    for inn_dir in CSP_ROOT.iterdir():
        if not inn_dir.is_dir():
            continue
        inn = inn_dir.name
        if not re.fullmatch(r"\d{10,12}", inn):
            continue
        if (inn_dir / container_id).is_dir():
            return inn
        for sub in inn_dir.iterdir():
            if sub.is_dir() and sub.name == container_id:
                return inn
    return None


def _inn_from_subject_line(subject_line: str) -> str | None:
    for pattern in (r"ИНН ЮЛ=([0-9]+)", r"ИНН ФЛ=([0-9]+)", r"ИНН=([0-9]+)"):
        m = re.search(pattern, subject_line)
        if m:
            return m.group(1)
    return None


def resolve_certificate_inn(subject_line: str | None, csptest_name: str) -> str | None:
    """ИНН ЮЛ из Subject; иначе из папки CSP; иначе ИНН ФЛ/физлица."""
    inn_ul = _inn_from_subject_line(subject_line or "") if subject_line else None
    if inn_ul and len(inn_ul) == 10:
        return inn_ul
    folder_inn = get_inn_from_csp_folder(csptest_name)
    if folder_inn:
        return folder_inn
    return inn_ul


def parse_cert_info(cert_path: str, csptest_name: str = "") -> dict:
    """
    Распарсить вывод `certmgr -list -file`:
    - ИНН из Subject (не Issuer)
    - SHA1 Thumbprint
    - not_before / not_after
    """
    out = run_cmd([CERTMGR_BIN, "-list", "-file", cert_path])

    subject_line = None
    thumb = None
    not_before = None
    not_after = None

    for line in out.splitlines():
        line = line.strip()

        if line.startswith("Subject"):
            subject_line = line

        if line.startswith("SHA1 Thumbprint"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                thumb = parts[1].strip().lower()

        if line.startswith("Not valid before"):
            ts = line.split(":", 1)[1].strip()
            not_before = parse_cert_date(ts)

        if line.startswith("Not valid after"):
            ts = line.split(":", 1)[1].strip()
            not_after = parse_cert_date(ts)

    inn = resolve_certificate_inn(subject_line, csptest_name)

    return {
        "inn": inn,
        "thumbprint": thumb,
        "not_before": not_before,
        "not_after": not_after,
    }


def update_private_key_flags():
    """
    Пройти по uMy и обновить has_private_key/hdimage_path
    для уже известных thumbprint'ов.
    """
    out = run_cmd([CERTMGR_BIN, "-list", "-store", "uMy"])

    current_thumb = None
    has_pk = False
    container_line = None

    def flush():
        nonlocal current_thumb, has_pk, container_line
        if not current_thumb:
            return
        cert = Certificate.objects.filter(thumbprint=current_thumb.lower()).first()
        if not cert:
            current_thumb = None
            has_pk = False
            container_line = None
            return
        cert.has_private_key = has_pk
        if container_line:
            parts = container_line.split(":", 1)
            if len(parts) == 2:
                cert.hdimage_path = parts[1].strip()
        cert.save(update_fields=["has_private_key", "hdimage_path"])
        current_thumb = None
        has_pk = False
        container_line = None

    for line in out.splitlines():
        line = line.rstrip()

        if line.startswith("SHA1 Thumbprint"):
            flush()
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_thumb = parts[1].strip().lower()

        if "PrivateKey Link" in line:
            has_pk = "Yes" in line

        if line.startswith("Container"):
            container_line = line

    flush()


class Command(BaseCommand):
    help = "Сканирует HDIMAGE-контейнеры CryptoPro и актуализирует таблицу Certificate"

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Очистить таблицу Certificate и заново загрузить все из контейнеров",
        )

    def handle(self, *args, **options):
        now = datetime.now(timezone.utc)

        if options["clear"]:
            n = Certificate.objects.count()
            Certificate.objects.all().delete()
            self.stdout.write(self.style.WARNING(f"Удалено записей Certificate: {n}"))

        self.stdout.write("Сканирование контейнеров CryptoPro...")

        containers = list_hdimage_containers()
        self.stdout.write(f"Найдено контейнеров: {len(containers)}")

        created = 0
        updated = 0
        skipped = 0

        for csptest_name in containers:
            self.stdout.write(f"  контейнер: {csptest_name}")

            tmp_cert = f"/tmp/csp_scan_{abs(hash(csptest_name))}.cer"
            if not export_cert_from_container(csptest_name, tmp_cert):
                self.stdout.write(
                    self.style.WARNING(f"    пропуск: не удалось экспортировать (Keyset/контейнер недоступен)")
                )
                skipped += 1
                continue
            info = parse_cert_info(tmp_cert, csptest_name)

            inn = info.get("inn")
            thumb = info.get("thumbprint")

            if not inn or not thumb:
                self.stdout.write(
                    f"    предупреждение: не удалось извлечь ИНН/Thumbprint, контейнер пропущен"
                )
                continue

            cert = Certificate.objects.filter(csptest_name=csptest_name).first()
            if cert:
                cert.inn = inn
                cert.thumbprint = thumb
                cert.not_before = info.get("not_before")
                cert.not_after = info.get("not_after")
                cert.last_seen_at = now
                cert.save(
                    update_fields=["inn", "thumbprint", "not_before", "not_after", "last_seen_at"]
                )
                updated += 1
                continue

            cert = Certificate.objects.create(
                inn=inn,
                csptest_name=csptest_name,
                hdimage_path="",
                thumbprint=thumb,
                source="LOCAL",
                not_before=info.get("not_before"),
                not_after=info.get("not_after"),
                has_private_key=False,
                last_seen_at=now,
                meta={},
            )
            created += 1
            self.stdout.write(
                f"    создан Certificate id={cert.id} для ИНН {inn}"
            )

        update_private_key_flags()

        total = Certificate.objects.count()
        active = Certificate.objects.filter(is_active=True).count()
        with_pk = Certificate.objects.filter(has_private_key=True).count()
        unique_inns = (
            Certificate.objects.exclude(inn="").values_list("inn", flat=True).distinct().count()
        )
        auth_inns = (
            Certificate.objects.filter(has_private_key=True, is_active=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
            .count()
        )

        self.stdout.write("")
        self.stdout.write("Статистика по таблице Certificate:")
        self.stdout.write(f"  всего записей: {total}")
        self.stdout.write(f"  активных:      {active}")
        self.stdout.write(f"  уникальных ИНН: {unique_inns}")
        self.stdout.write(f"  has_private_key (uMy PrivateKey Link): {with_pk}")
        self.stdout.write(f"  ИНН готовых к auth (has_private_key): {auth_inns}")
        if skipped:
            self.stdout.write(self.style.WARNING(f"  пропущено (экспорт не удался): {skipped}"))
