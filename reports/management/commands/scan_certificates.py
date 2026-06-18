import hashlib
import re
import subprocess
from dataclasses import dataclass
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
DEFAULT_EXPORT_TIMEOUT = 10
DEFAULT_VERIFY_KEY_TIMEOUT = 5
DEFAULT_INST_TIMEOUT = 15


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


def export_cert_from_container(
    container_name: str, dest_path: str, *, timeout: int = DEFAULT_EXPORT_TIMEOUT
) -> tuple[bool, str]:
    """Экспорт серта из контейнера. Возвращает (ok, stderr/stdout при ошибке)."""
    try:
        result = subprocess.run(
            _csp_cmd(CERTMGR_BIN, ["-export", "-cont", container_name, "-dest", dest_path]),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout ({timeout}s)"
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


def is_copy_container(csptest_name: str) -> bool:
    """Контейнер с суффиксом « копия» (типично при переносе с Windows). Имя полное — так в csptest/certmgr."""
    return csptest_name.rsplit("\\", 1)[-1].strip().endswith(" копия")


def get_inn_from_container_name(csptest_name: str) -> str | None:
    name = normalize_container_id(csptest_name)
    m = re.search(r"\d{10}", name)
    if m:
        return m.group(0)
    m = re.search(r"\d{12}", name)
    return m.group(0) if m else None


def get_inn_from_cont_name(csptest_name: str, known_inns: set[str]) -> str | None:
    """ИНН из имени контейнера (7730322740atrium), без ложных совпадений внутри UUID."""
    name = normalize_container_id(csptest_name)
    m = re.match(r"^(\d{12}|\d{10})", name)
    if m:
        return m.group(1)[:10] if len(m.group(1)) >= 10 else m.group(1)
    # UUID/текстовые имена — не ищем подстроку ИНН в known_inns (даёт ложные совпадения)
    return get_inn_from_container_name(csptest_name)


class CspIndex:
    """Один проход по CSP_ROOT: индекс контейнеров и .cer по ИНН."""

    def __init__(self):
        self.container_dirs: dict[str, tuple[str, Path]] = {}
        self.cers_by_inn: dict[str, list[Path]] = {}
        self.best_cer_by_inn: dict[str, Path] = {}
        self.inn_count = 0
        self.cer_count = 0
        self.known_inns: set[str] = set()
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
            self.known_inns.add(inn)
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

    def get_inn_from_csp_folder_for_cont(self, csptest_name: str) -> str | None:
        """ИНН каталога CSP_ROOT/{inn}/, где лежит подпапка контейнера (UUID и т.п.)."""
        inn, _ = self.find_container_dir(csptest_name)
        if inn:
            return inn
        cid = normalize_container_id(csptest_name)
        if not cid:
            return None
        tokens = [cid]
        if " " in cid:
            tokens.insert(0, cid.split()[0])
        if not CSP_ROOT.is_dir():
            return None
        for inn_dir in CSP_ROOT.iterdir():
            if not inn_dir.is_dir() or not INN_DIR_RE.match(inn_dir.name):
                continue
            inn = inn_dir.name
            for token in tokens:
                if (inn_dir / token).is_dir():
                    return inn
                try:
                    for sub in inn_dir.iterdir():
                        if sub.is_dir() and sub.name in (token, cid):
                            return inn
                except OSError:
                    pass
        return None

    def resolve_inn_for_container(
        self,
        csptest_name: str,
        subject_line: str | None = None,
        certmgr_out: str | None = None,
    ) -> str | None:
        subject_full = subject_line or ""
        if certmgr_out and not subject_full:
            subject_full = _subject_text_from_listing(certmgr_out)
        if subject_full:
            inn = _inn_from_text(subject_full)
            if inn:
                return inn
        if certmgr_out:
            inn = _inn_from_certmgr_output(certmgr_out)
            if inn:
                return inn
        for resolver in (
            lambda: self.get_inn(csptest_name),
            lambda: self.get_inn_from_csp_folder_for_cont(csptest_name),
            lambda: get_inn_from_cont_name(csptest_name, self.known_inns),
        ):
            inn = resolver()
            if inn and inn != FNS_ISSUER_INN:
                return inn
        return None

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
        folder_inn = self.get_inn_from_csp_folder_for_cont(csptest_name)
        if folder_inn:
            best = self.get_best_cer_for_inn(folder_inn)
            if best:
                return folder_inn, best
        if inn:
            best = self.get_best_cer_for_inn(inn)
            if best:
                return inn, best
        name_inn = get_inn_from_cont_name(csptest_name, self.known_inns)
        if name_inn:
            best = self.get_best_cer_for_inn(name_inn)
            if best:
                return name_inn, best
        return None, None


# ИНН ФНС в Issuer — никогда не использовать как ИНН организации
FNS_ISSUER_INN = "7707329152"


def _inn_from_text(text: str) -> str | None:
    """ИНН из Subject (предпочтительно ИНН ЮЛ, не Issuer ФНС)."""
    if not text:
        return None
    for pattern in (r"ИНН ЮЛ=([0-9]+)", r"ИНН ФЛ=([0-9]+)", r"ИНН=([0-9]+)"):
        m = re.search(pattern, text)
        if m:
            inn = m.group(1)
            if inn == FNS_ISSUER_INN:
                continue
            return inn
    return None


def _inn_from_certmgr_output(out: str) -> str | None:
    """ИНН ЮЛ только из блока Subject (Issuer ФНС содержит ИНН ЮЛ=7707329152)."""
    subject = _subject_text_from_listing(out)
    return _inn_from_text(subject) if subject else None


def _subject_text_from_listing(out: str) -> str:
    """Склеить Subject / Субъект из certmgr (включая переносы строк)."""
    parts: list[str] = []
    in_subject = False
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Subject") or line.startswith("Субъект"):
            in_subject = True
            parts.append(line.split(":", 1)[-1].strip() if ":" in line else "")
            continue
        if in_subject:
            if not line:
                continue
            if re.match(
                r"^(Issuer|Издатель|Not valid|SHA1|Serial|Extended|Signature|Public)",
                line,
                re.I,
            ):
                break
            parts.append(line)
    return " ".join(p for p in parts if p)


def _inn_from_subject_line(subject_line: str) -> str | None:
    return _inn_from_text(subject_line)


def resolve_certificate_inn(
    subject_line: str | None,
    csptest_name: str,
    csp_index: CspIndex | None = None,
    certmgr_out: str | None = None,
) -> str | None:
    if csp_index:
        return csp_index.resolve_inn_for_container(csptest_name, subject_line, certmgr_out)
    if certmgr_out:
        inn = _inn_from_certmgr_output(certmgr_out)
        if inn:
            return inn
    if subject_line:
        inn = _inn_from_text(subject_line)
        if inn:
            return inn
    return get_inn_from_container_name(csptest_name)


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

    inn = resolve_certificate_inn(subject_line, csptest_name, csp_index, out)
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


def obtain_cert_path(
    csptest_name: str,
    csp_index: CspIndex,
    *,
    export_timeout: int = DEFAULT_EXPORT_TIMEOUT,
    verify_key_timeout: int = DEFAULT_VERIFY_KEY_TIMEOUT,
) -> tuple[str | None, str, bool]:
    """
    Путь к .cer, источник (export/folder), есть ли ключ в контейнере.
    Сначала csptest -verifycontext; export только если ключ есть (иначе certmgr висит).
    """
    has_key = verify_container_has_private_key(csptest_name, timeout=verify_key_timeout)

    if has_key:
        dest = f"/tmp/csp_scan_{hashlib.sha256(csptest_name.encode()).hexdigest()}.cer"
        ok, _ = export_cert_from_container(csptest_name, dest, timeout=export_timeout)
        if ok:
            out = certmgr_list_file(dest)
            if out and "thumbprint" in out.lower():
                info = parse_certmgr_listing(out, csptest_name, csp_index)
                if info.get("thumbprint") and (
                    info.get("inn")
                    or csp_index.resolve_inn_for_container(csptest_name, certmgr_out=out)
                ):
                    return dest, "export", True

    _, folder_cer = csp_index.find_best_cer_near_container(csptest_name)
    if folder_cer:
        return str(folder_cer), "folder", has_key

    return None, "", has_key


def _subject_from_listing(out: str) -> str | None:
    text = _subject_text_from_listing(out)
    return text or None


@dataclass
class ScanCandidate:
    csptest_name: str
    inn: str
    thumbprint: str
    not_before: datetime | None
    not_after: datetime | None
    cert_path: str
    source: str
    has_container_key: bool = False


def verify_container_has_private_key(
    csptest_name: str, *, timeout: int = DEFAULT_VERIFY_KEY_TIMEOUT
) -> bool:
    """csptest -verifycontext: в контейнере реально есть приватный ключ."""
    try:
        result = subprocess.run(
            _csp_cmd(CSPTEST_BIN, ["-keyset", "-container", csptest_name, "-verifycontext"]),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return False
    combined = f"{result.stdout}\n{result.stderr}".lower()
    return result.returncode == 0 or "success" in combined


def parse_umy_thumbprint_link(thumbprint: str) -> tuple[bool, str | None]:
    """PrivateKey Link : Yes для thumbprint в хранилище uMy."""
    out = run_cmd(_csp_cmd(CERTMGR_BIN, ["-list", "-store", "uMy"]), check=False)
    thumb = thumbprint.lower().strip()
    block_thumb: str | None = None
    has_pk = False
    container: str | None = None
    for line in out.splitlines():
        line = line.rstrip()
        if line.startswith("SHA1 Thumbprint"):
            if block_thumb == thumb and has_pk:
                return True, container
            parts = line.split(":", 1)
            block_thumb = parts[1].strip().lower() if len(parts) == 2 else None
            has_pk = False
            container = None
        elif block_thumb == thumb:
            if "PrivateKey Link" in line:
                has_pk = "Yes" in line
            if line.startswith("Container"):
                container = line.split(":", 1)[1].strip() if ":" in line else None
    if block_thumb == thumb and has_pk:
        return True, container
    return False, container


def install_cert_to_umy(
    cert_path: str, container_name: str, *, timeout: int = DEFAULT_INST_TIMEOUT
) -> tuple[bool, str]:
    """certmgr -inst -store uMy — PrivateKey Link для cryptcp -decr / SBIS auth."""
    try:
        result = subprocess.run(
            _csp_cmd(
                CERTMGR_BIN,
                ["-inst", "-store", "uMy", "-file", cert_path, "-cont", container_name],
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout ({timeout}s)"
    if result.returncode == 0:
        return True, ""
    err = (result.stderr or result.stdout or "").strip()
    return False, err


def install_cert_to_umy_verified(
    cert_path: str, container_name: str, thumbprint: str
) -> tuple[bool, str]:
    ok, err = install_cert_to_umy(cert_path, container_name)
    if not ok:
        return False, err or "certmgr -inst failed"
    has_link, _ = parse_umy_thumbprint_link(thumbprint)
    if has_link:
        return True, ""
    return False, "PrivateKey Link: No (ключ не в этом контейнере — нужен другой -cont)"


def _candidate_rank(cand: ScanCandidate) -> tuple:
    na = cand.not_after or datetime.min.replace(tzinfo=timezone.utc)
    copy_penalty = 0 if is_copy_container(cand.csptest_name) else 1
    return (cand.has_container_key, na, copy_penalty)


def group_candidates_by_inn(candidates: list[ScanCandidate]) -> dict[str, list[ScanCandidate]]:
    grouped: dict[str, list[ScanCandidate]] = {}
    for cand in candidates:
        grouped.setdefault(cand.inn, []).append(cand)
    for inn in grouped:
        grouped[inn].sort(key=_candidate_rank, reverse=True)
    return grouped


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
    help = (
        "Сканирует HDIMAGE-контейнеры CryptoPro, актуализирует Certificate. "
        "С --install-uMy ставит серт в uMy (PrivateKey Link) как sbis_keys_install_linux.sh."
    )

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
        parser.add_argument(
            "--install-uMy",
            action="store_true",
            help="Установить лучший сертификат на ИНН в uMy (certmgr -inst -store uMy -cont ...)",
        )
        parser.add_argument(
            "--skip-copies",
            action="store_true",
            help="Пропустить контейнеры с суффиксом « копия» (обычно не нужно — это валидные имена в csptest)",
        )
        parser.add_argument(
            "--all-containers",
            action="store_true",
            help="Запись в БД для каждого контейнера (по умолчанию — один лучший на ИНН)",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Обработать только N контейнеров (0 = все)",
        )
        parser.add_argument(
            "--export-timeout",
            type=int,
            default=DEFAULT_EXPORT_TIMEOUT,
            help=f"Таймаут certmgr -export в секундах (по умолчанию {DEFAULT_EXPORT_TIMEOUT})",
        )

    def handle(self, *args, **options):
        now = datetime.now(timezone.utc)
        quiet = options["quiet"]
        skip_copies = options["skip_copies"]
        best_per_inn = not options["all_containers"]
        install_umy = options["install_uMy"]
        export_timeout = options["export_timeout"]
        verify_key_timeout = DEFAULT_VERIFY_KEY_TIMEOUT

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
        if options["limit"]:
            containers = containers[: options["limit"]]
        total_containers = len(containers)
        self.stdout.write(f"Найдено контейнеров: {total_containers}")
        if skip_copies:
            self.stdout.write("  (--skip-copies: контейнеры «… копия» будут пропущены)")
        if best_per_inn:
            self.stdout.write("  (в БД — один лучший контейнер на ИНН; --all-containers для всех)")

        created = 0
        updated = 0
        skipped_export = 0
        skipped_parse = 0
        skipped_copies = 0
        skipped_expired = 0
        installed_umy = 0
        install_umy_failed = 0
        skipped_no_key = 0
        candidates: list[ScanCandidate] = []

        for idx, csptest_name in enumerate(containers, start=1):
            if skip_copies and is_copy_container(csptest_name):
                skipped_copies += 1
                continue

            if quiet and idx % 50 == 0:
                self.stdout.write(f"  ... {idx}/{total_containers}")
                self.stdout.flush()

            if not quiet:
                self.stdout.write(f"  контейнер: {csptest_name}")

            cert_path, source, has_key = obtain_cert_path(
                csptest_name,
                csp_index,
                export_timeout=export_timeout,
                verify_key_timeout=verify_key_timeout,
            )
            if not cert_path:
                skipped_export += 1
                if not has_key:
                    skipped_no_key += 1
                if not quiet:
                    self.stdout.write(
                        self.style.WARNING(
                            "    пропуск: нет серта"
                            + (" (нет ключа в контейнере)" if not has_key else "")
                        )
                    )
                continue

            info = parse_cert_info(cert_path, csptest_name, csp_index)
            inn = info.get("inn") or csp_index.resolve_inn_for_container(csptest_name)
            thumb = info.get("thumbprint")
            not_after = info.get("not_after")

            if not inn or not thumb:
                skipped_parse += 1
                if not quiet:
                    self.stdout.write(
                        self.style.WARNING(
                            f"    пропуск: не удалось извлечь ИНН/Thumbprint (источник: {source})"
                        )
                    )
                continue

            if not_after and not_after <= now:
                skipped_expired += 1
                if not quiet:
                    self.stdout.write(self.style.WARNING(f"    пропуск: сертификат просрочен ({inn})"))
                continue

            candidates.append(
                ScanCandidate(
                    csptest_name=csptest_name,
                    inn=inn,
                    thumbprint=thumb,
                    not_before=info.get("not_before"),
                    not_after=not_after,
                    cert_path=cert_path,
                    source=source,
                    has_container_key=has_key,
                )
            )
            if not quiet:
                self.stdout.write(f"    кандидат ИНН {inn} ({source})")

        by_inn = group_candidates_by_inn(candidates)
        if best_per_inn:
            to_persist = [group[0] for group in by_inn.values() if group]
            with_key = sum(1 for c in to_persist if c.has_container_key)
            self.stdout.write(
                f"Кандидатов: {len(candidates)}, ИНН: {len(to_persist)}, "
                f"с ключом в контейнере: {with_key}"
            )
        else:
            to_persist = candidates
            by_inn = group_candidates_by_inn(candidates)

        install_pk_ok = 0
        winners_by_inn: dict[str, ScanCandidate] = {}
        for cand in to_persist:
            winner = cand
            if install_umy:
                tried = by_inn.get(cand.inn, [cand])
                last_err = ""
                installed = False
                for try_cand in tried:
                    ok, err = install_cert_to_umy_verified(
                        try_cand.cert_path, try_cand.csptest_name, try_cand.thumbprint
                    )
                    if ok:
                        winner = try_cand
                        installed_umy += 1
                        install_pk_ok += 1
                        installed = True
                        if not quiet:
                            self.stdout.write(
                                f"  uMy OK {winner.inn} ← {winner.csptest_name}"
                                + (" (ключ в контейнере)" if winner.has_container_key else "")
                            )
                        break
                    last_err = err or last_err
                if not installed:
                    install_umy_failed += 1
                    if not quiet:
                        self.stdout.write(
                            self.style.WARNING(
                                f"  uMy FAIL {cand.inn} ({len(tried)} конт.): {(last_err or '')[:120]}"
                            )
                        )

            winners_by_inn[winner.inn] = winner

            cert = Certificate.objects.filter(csptest_name=winner.csptest_name).first()
            if not cert and best_per_inn:
                cert = (
                    Certificate.objects.filter(inn=winner.inn, is_active=True)
                    .order_by("-not_after", "-last_seen_at")
                    .first()
                )

            if cert:
                cert.inn = winner.inn
                cert.csptest_name = winner.csptest_name
                cert.thumbprint = winner.thumbprint
                cert.not_before = winner.not_before
                cert.not_after = winner.not_after
                cert.last_seen_at = now
                cert.is_active = True
                cert.save(
                    update_fields=[
                        "inn",
                        "csptest_name",
                        "thumbprint",
                        "not_before",
                        "not_after",
                        "last_seen_at",
                        "is_active",
                    ]
                )
                updated += 1
                if not quiet:
                    self.stdout.write(f"  обновлён ИНН {winner.inn} ({winner.source})")
                continue

            Certificate.objects.create(
                inn=winner.inn,
                csptest_name=winner.csptest_name,
                hdimage_path="",
                thumbprint=winner.thumbprint,
                source="LOCAL",
                not_before=winner.not_before,
                not_after=winner.not_after,
                has_private_key=False,
                last_seen_at=now,
                meta={"scan_source": winner.source},
            )
            created += 1
            if not quiet:
                self.stdout.write(f"  создан Certificate для ИНН {winner.inn} ({winner.source})")

        if best_per_inn:
            for inn, winner in winners_by_inn.items():
                n = (
                    Certificate.objects.filter(inn=inn)
                    .exclude(csptest_name=winner.csptest_name)
                    .update(is_active=False)
                )
                if n and not quiet:
                    self.stdout.write(f"  деактивировано дублей ИНН {inn}: {n}")

        Certificate.objects.update(has_private_key=False)
        update_private_key_flags()

        total = Certificate.objects.count()
        active = Certificate.objects.filter(is_active=True).count()
        with_pk = Certificate.objects.filter(has_private_key=True).count()
        with_pk_active = Certificate.objects.filter(has_private_key=True, is_active=True).count()
        unique_inns = (
            Certificate.objects.filter(is_active=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
            .count()
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
        self.stdout.write(f"  has_private_key (uMy): {with_pk} (активных: {with_pk_active})")
        self.stdout.write(f"  ИНН готовых к auth: {auth_inns}")
        self.stdout.write(f"  создано: {created}, обновлено: {updated}")
        if skipped_copies:
            self.stdout.write(f"  пропущено «копия»: {skipped_copies}")
        if skipped_export:
            self.stdout.write(self.style.WARNING(f"  пропущено (нет серта): {skipped_export}"))
        if skipped_no_key:
            self.stdout.write(f"  из них без ключа в контейнере: {skipped_no_key}")
        if skipped_parse:
            self.stdout.write(self.style.WARNING(f"  пропущено (парсинг): {skipped_parse}"))
        if skipped_expired:
            self.stdout.write(self.style.WARNING(f"  пропущено (просрочен): {skipped_expired}"))
        if install_umy:
            self.stdout.write(
                self.style.SUCCESS(
                    f"  установлено в uMy: {installed_umy} "
                    f"(PrivateKey Link: {install_pk_ok}), ошибок: {install_umy_failed}"
                )
            )
        elif auth_inns == 0 and with_pk == 0:
            self.stdout.write(
                self.style.WARNING(
                    "  Подсказка: для SBIS auth нужен uMy — запустите с --install-uMy "
                    "или scripts/ops/sbis_keys_install_linux.sh --install-only"
                )
            )
