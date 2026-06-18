import hashlib
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from reports.models import Certificate


CSPTEST_BIN = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CSP_ROOT = Path("/var/opt/cprocsp/keys/root")
INN_DIR_RE = re.compile(r"^\d{10,12}$")
CER_GLOBS = ("*.cer", "*.crt", "*.CER", "*.CRT")


def _csp_use_sudo() -> bool:
    return getattr(settings, "CSP_USE_SUDO", True)


def _csp_cmd(bin_path: str, args: list[str]) -> list[str]:
    cmd = [bin_path, *args]
    if _csp_use_sudo():
        cmd = ["sudo", *cmd]
    return cmd


def run_cmd(args: list[str], *, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or f"exit code {result.returncode}"
        raise RuntimeError(err)
    return result.stdout or ""


def list_hdimage_containers() -> list[str]:
    out = run_cmd(_csp_cmd(CSPTEST_BIN, ["-keyset", "-enum_cont", "-fqcn"]))
    containers = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("\\\\.\\HDIMAGE"):
            containers.append(line)
    return containers


def export_cert_from_container(container_name: str, dest_path: str) -> tuple[bool, str]:
    """Экспорт серта из контейнера. Возвращает (ok, stderr/stdout при ошибке)."""
    result = subprocess.run(
        _csp_cmd(CERTMGR_BIN, ["-export", "-cont", container_name, "-dest", dest_path]),
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True, ""
    err = (result.stderr or result.stdout or "").strip()
    return False, err


def certmgr_list_file(cert_path: str) -> str:
    return run_cmd(_csp_cmd(CERTMGR_BIN, ["-list", "-file", cert_path]), check=False)


def parse_cert_date(s: str) -> datetime | None:
    try:
        s = s.replace(" UTC", "")
        dt = datetime.strptime(s, "%d/%m/%Y %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def normalize_container_id(csptest_name: str) -> str:
    name = csptest_name.rsplit("\\", 1)[-1].strip()
    if name.endswith(" копия"):
        name = name[:-6].strip()
    return name


def get_inn_from_container_name(csptest_name: str) -> str | None:
    name = normalize_container_id(csptest_name)
    m = re.search(r"\d{10}", name)
    if m:
        return m.group(0)
    m = re.search(r"\d{12}", name)
    return m.group(0) if m else None


class CspIndex:
    """Один проход по CSP_ROOT: индекс контейнеров и .cer по ИНН."""

    def __init__(self):
        self.container_dirs: dict[str, tuple[str, Path]] = {}
        self.cers_by_inn: dict[str, list[Path]] = {}
        self.best_cer_by_inn: dict[str, Path] = {}
        self.inn_count = 0
        self.cer_count = 0
        self._build()

    def _register_container_dir(self, inn: str, path: Path, depth: int) -> None:
        if depth > 4:
            return
        self.container_dirs.setdefault(path.name, (inn, path))
        try:
            for child in path.iterdir():
                if child.is_dir():
                    self._register_container_dir(inn, child, depth + 1)
        except OSError:
            pass

    def _collect_cers(self, inn_dir: Path) -> list[Path]:
        found: list[Path] = []
        for pattern in CER_GLOBS:
            found.extend(inn_dir.rglob(pattern))
        return list(dict.fromkeys(p for p in found if p.is_file()))

    def _build(self) -> None:
        if not CSP_ROOT.is_dir():
            return
        for inn_dir in sorted(CSP_ROOT.iterdir()):
            if not inn_dir.is_dir() or not INN_DIR_RE.match(inn_dir.name):
                continue
            inn = inn_dir.name
            self.inn_count += 1
            cers = self._collect_cers(inn_dir)
            if cers:
                self.cers_by_inn[inn] = cers
                self.cer_count += len(cers)
            try:
                for sub in inn_dir.iterdir():
                    if sub.is_dir():
                        self._register_container_dir(inn, sub, 1)
            except OSError:
                pass

    def warm_best_cers(self) -> None:
        for inn, cers in self.cers_by_inn.items():
            best = _pick_best_cer(cers, require_valid=True)
            if best:
                self.best_cer_by_inn[inn] = best

    def find_container_dir(self, csptest_name: str) -> tuple[str | None, Path | None]:
        cid = normalize_container_id(csptest_name)
        if not cid:
            return None, None
        return self.container_dirs.get(cid, (None, None))

    def get_inn(self, csptest_name: str) -> str | None:
        inn, _ = self.find_container_dir(csptest_name)
        return inn

    def get_best_cer_for_inn(self, inn: str) -> Path | None:
        if inn in self.best_cer_by_inn:
            return self.best_cer_by_inn[inn]
        cers = self.cers_by_inn.get(inn, [])
        best = _pick_best_cer(cers, require_valid=True)
        if best:
            self.best_cer_by_inn[inn] = best
        return best

    def cers_in_dir(self, directory: Path) -> list[Path]:
        found: list[Path] = []
        for pattern in CER_GLOBS:
            found.extend(directory.glob(pattern))
        return list(dict.fromkeys(p for p in found if p.is_file()))

    def find_best_cer_near_container(self, csptest_name: str) -> tuple[str | None, Path | None]:
        inn, cont_dir = self.find_container_dir(csptest_name)
        if cont_dir and cont_dir.is_dir():
            best = _pick_best_cer(self.cers_in_dir(cont_dir), require_valid=True)
            if best:
                return inn, best
        if inn:
            return inn, self.get_best_cer_for_inn(inn)
        name_inn = get_inn_from_container_name(csptest_name)
        if name_inn:
            return name_inn, self.get_best_cer_for_inn(name_inn)
        return None, None


def _inn_from_subject_line(subject_line: str) -> str | None:
    for pattern in (r"ИНН ЮЛ=([0-9]+)", r"ИНН ФЛ=([0-9]+)", r"ИНН=([0-9]+)"):
        m = re.search(pattern, subject_line)
        if m:
            return m.group(1)
    return None


def resolve_certificate_inn(
    subject_line: str | None, csptest_name: str, csp_index: CspIndex | None = None
) -> str | None:
    if subject_line:
        m = re.search(r"ИНН ЮЛ=([0-9]+)", subject_line)
        if m:
            return m.group(1)
    if csp_index:
        folder_inn = csp_index.get_inn(csptest_name)
    else:
        folder_inn = None
    if folder_inn:
        return folder_inn
    name_inn = get_inn_from_container_name(csptest_name)
    if name_inn and len(name_inn) == 10:
        return name_inn
    if subject_line:
        return _inn_from_subject_line(subject_line)
    return name_inn


def parse_certmgr_listing(
    out: str, csptest_name: str = "", csp_index: CspIndex | None = None
) -> dict:
    subject_line = None
    thumb = None
    not_before = None
    not_after = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Subject") or line.startswith("Субъект"):
            subject_line = line
        lower = line.lower()
        if "sha1 thumbprint" in lower or (
            "thumbprint" in lower and line.split(":", 1)[0].strip().lower().endswith("thumbprint")
        ):
            parts = line.split(":", 1)
            if len(parts) == 2:
                thumb = parts[1].strip().lower()
        if line.startswith("Not valid before"):
            not_before = parse_cert_date(line.split(":", 1)[1].strip())
        if line.startswith("Not valid after"):
            not_after = parse_cert_date(line.split(":", 1)[1].strip())

    inn = resolve_certificate_inn(subject_line, csptest_name, csp_index)
    return {
        "inn": inn,
        "thumbprint": thumb,
        "not_before": not_before,
        "not_after": not_after,
    }


def _pick_best_cer(cer_paths: list[Path], *, require_valid: bool) -> Path | None:
    now = datetime.now(timezone.utc)
    best: Path | None = None
    best_not_after: datetime | None = None
    fallback: Path | None = None
    fallback_na: datetime | None = None
    for cer in cer_paths:
        if not cer.is_file():
            continue
        out = certmgr_list_file(str(cer))
        if not out or "thumbprint" not in out.lower():
            continue
        info = parse_certmgr_listing(out, "")
        not_after = info.get("not_after")
        if not_after and (fallback_na is None or not_after > fallback_na):
            fallback = cer
            fallback_na = not_after
        if not_after and not_after > now:
            if best_not_after is None or not_after > best_not_after:
                best_not_after = not_after
                best = cer
    if require_valid:
        return best or fallback
    return best or fallback


def obtain_cert_path(csptest_name: str, csp_index: CspIndex) -> tuple[str | None, str]:
    dest = f"/tmp/csp_scan_{hashlib.sha256(csptest_name.encode()).hexdigest()}.cer"
    ok, _ = export_cert_from_container(csptest_name, dest)
    if ok:
        out = certmgr_list_file(dest)
        if out and "thumbprint" in out.lower():
            info = parse_certmgr_listing(out, csptest_name, csp_index)
            if info.get("thumbprint"):
                if info.get("inn"):
                    return dest, "export"
                inn = csp_index.get_inn(csptest_name) or get_inn_from_container_name(csptest_name)
                if inn:
                    return dest, "export"

    _, folder_cer = csp_index.find_best_cer_near_container(csptest_name)
    if folder_cer:
        return str(folder_cer), "folder"
    return None, ""


def parse_cert_info(cert_path: str, csptest_name: str = "", csp_index: CspIndex | None = None) -> dict:
    out = certmgr_list_file(cert_path)
    if not out:
        return {"inn": None, "thumbprint": None, "not_before": None, "not_after": None}
    return parse_certmgr_listing(out, csptest_name, csp_index)


def update_private_key_flags():
    out = run_cmd(_csp_cmd(CERTMGR_BIN, ["-list", "-store", "uMy"]))

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
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Только сводка (без строк по каждому контейнеру)",
        )

    def handle(self, *args, **options):
        now = datetime.now(timezone.utc)
        quiet = options["quiet"]

        if options["clear"]:
            n = Certificate.objects.count()
            Certificate.objects.all().delete()
            self.stdout.write(self.style.WARNING(f"Удалено записей Certificate: {n}"))

        self.stdout.write("Сканирование контейнеров CryptoPro...")

        self.stdout.write("Индекс CSP_ROOT (один проход)...")
        csp_index = CspIndex()
        csp_index.warm_best_cers()
        self.stdout.write(
            f"  ИНН-каталогов: {csp_index.inn_count}, .cer: {csp_index.cer_count}, "
            f"папок контейнеров: {len(csp_index.container_dirs)}"
        )

        containers = list_hdimage_containers()
        self.stdout.write(f"Найдено контейнеров: {len(containers)}")

        created = 0
        updated = 0
        skipped_export = 0
        skipped_parse = 0

        for csptest_name in containers:
            if not quiet:
                self.stdout.write(f"  контейнер: {csptest_name}")

            cert_path, source = obtain_cert_path(csptest_name, csp_index)
            if not cert_path:
                skipped_export += 1
                if not quiet:
                    self.stdout.write(
                        self.style.WARNING(
                            "    пропуск: нет серта в контейнере и .cer в CSP_ROOT/{inn}/"
                        )
                    )
                continue

            info = parse_cert_info(cert_path, csptest_name, csp_index)
            inn = info.get("inn")
            thumb = info.get("thumbprint")

            if not inn:
                inn = csp_index.get_inn(csptest_name) or get_inn_from_container_name(csptest_name)

            if not inn or not thumb:
                skipped_parse += 1
                if not quiet:
                    self.stdout.write(
                        self.style.WARNING(
                            f"    пропуск: не удалось извлечь ИНН/Thumbprint (источник: {source})"
                        )
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
                if not quiet:
                    self.stdout.write(f"    обновлён ИНН {inn} ({source})")
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
            if not quiet:
                self.stdout.write(f"    создан Certificate id={cert.id} для ИНН {inn} ({source})")

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
        self.stdout.write(f"  создано: {created}, обновлено: {updated}")
        if skipped_export:
            self.stdout.write(self.style.WARNING(f"  пропущено (нет .cer): {skipped_export}"))
        if skipped_parse:
            self.stdout.write(self.style.WARNING(f"  пропущено (парсинг): {skipped_parse}"))
