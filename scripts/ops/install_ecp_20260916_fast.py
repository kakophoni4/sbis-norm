#!/usr/bin/env python3
"""Install the 19 remaining keysets from the 2026-09-16 delivery safely.

This is the batch form of the verified ZERO procedure.  It first puts every
raw keyset in a *new* numeric probe directory and reads its own certificate.
Only a successfully exported certificate with a legal-entity INN is then
copied flat to ``keys/root/<INN>``.  An old directory is moved, intact, to a
timestamped backup before replacement.  Finally it verifies the new
container, installs its public certificate with a PrivateKey Link in uMy and
updates exactly one active Django Certificate record per INN.

It does not call SBIS, run a global certificate scan, delete any key, or
touch organizations not represented by this delivery.

Run on the host, from /opt/sbis-norm:
  python3 scripts/ops/install_ecp_20260916_fast.py \
    --source /root/new_ecp_stage_20260916/.import_20260916_v2 --apply
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from import_ecp_archives_additive import REQUIRED_KEY_FILES, read_container_name


# The two duplicate archives (2560.zip and Zero.zip) are intentionally absent.
# Every path was verified from manifest.tsv of the already extracted delivery.
KEYSETS: tuple[tuple[str, str], ...] = (
    ("unpacked_001/1", "1.zip"),
    ("unpacked_002/2", "2.zip"),
    ("unpacked_003/2560", "2560 (2).rar"),
    ("unpacked_004/2560", "2560 (2).zip"),
    ("unpacked_005/2560", "2560 СЕМЬ ПЯДЕЙ.zip"),
    ("unpacked_006/2560", "2560.rar"),
    ("unpacked_008/3", "3.zip"),
    ("unpacked_009/4", "4.zip"),
    ("unpacked_010/1", "Desktop (3).zip / 1"),
    ("unpacked_010/2", "Desktop (3).zip / 2"),
    ("unpacked_011/gjlgbcb/2560", "gjlgbcb.rar / 2560"),
    ("unpacked_011/gjlgbcb/2816", "gjlgbcb.rar / 2816"),
    ("unpacked_011/gjlgbcb/3072", "gjlgbcb.rar / 3072"),
    ("unpacked_012/Азарт/2560", "Азарт.zip"),
    ("unpacked_013/Диспут/2560", "Диспут (4).zip"),
    # ZERO (9729355495) was already installed and authenticated successfully
    # by the verified one-by-one procedure, so it is deliberately skipped.
    ("unpacked_016/Зинтер/2816", "Зинтер (4).zip"),
    ("unpacked_017/Легем/3072", "Легем (4).zip"),
    ("unpacked_018/ПБС/2816", "ПБС.zip"),
    ("unpacked_019/3072", "РОСА (2).rar"),
)

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="required: make the described recoverable changes")
    parser.add_argument("--csp-root", type=Path, default=Path("/var/opt/cprocsp/keys/root"))
    parser.add_argument("--first-probe-inn", default="9900000001")
    return parser.parse_args()


def docker(*command: str, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "web", *command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def host(*command: str, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def csp_name(container: str) -> str:
    # This is the exact spelling used by the successful ZERO verification.
    return r"\\\\.\HDIMAGE" + "\\\\" + container


def cert_details(container: str, label: str) -> dict[str, str] | None:
    cert = f"/tmp/ecp_20260916_{label}.cer"
    exported = docker(CERTMGR, "-export", "-cont", csp_name(container), "-dest", cert)
    if exported.returncode:
        return None
    listed = docker(CERTMGR, "-list", "-file", cert)
    if listed.returncode:
        return None
    text = listed.stdout + listed.stderr
    subject = re.search(r"^Subject\s*:\s*(.+)$", text, re.MULTILINE)
    inn = re.search(r"ИНН ЮЛ=(\d{10,12})", subject.group(1) if subject else "")
    thumb = re.search(r"^SHA1 Thumbprint\s*:\s*([0-9a-fA-F]+)\s*$", text, re.MULTILINE)
    before = re.search(r"^Not valid before\s*:\s*(.+)$", text, re.MULTILINE)
    after = re.search(r"^Not valid after\s*:\s*(.+)$", text, re.MULTILINE)
    if not inn or not thumb or not before or not after:
        return None
    try:
        not_after = datetime.strptime(after.group(1).strip(), "%d/%m/%Y %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(before.group(1).strip(), "%d/%m/%Y %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return {
        "inn": inn.group(1),
        "thumbprint": thumb.group(1).lower(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "subject": subject.group(1),
        "cert_path": cert,
    }


def verify(container: str) -> bool:
    result = docker(CSPTEST, "-keyset", "-container", csp_name(container), "-verifycontext")
    return result.returncode == 0


def copy_flat(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for filename in REQUIRED_KEY_FILES:
        item = source / filename
        if not item.is_file():
            raise RuntimeError(f"missing {item}")
        target = destination / filename
        shutil.copy2(item, target)
        os.chmod(target, 0o600)
    os.chmod(destination, 0o700)


def read_candidates(source_root: Path, csp_root: Path, first_probe: int) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for index, (relative, archive) in enumerate(KEYSETS, start=0):
        source = source_root / relative
        if not source.is_dir() or not all((source / name).is_file() for name in REQUIRED_KEY_FILES):
            raise RuntimeError(f"source keyset is incomplete: {source}")
        container = read_container_name(source / "name.key")
        probe = csp_root / str(first_probe + index)
        if probe.exists():
            raise RuntimeError(f"reserved probe directory already exists: {probe}")
        candidates.append({"source": source, "archive": archive, "container": container, "probe": probe})
    return candidates


def write_database(records: list[dict[str, str]]) -> None:
    payload = json.dumps(records, ensure_ascii=False)
    code = r'''
import json, sys
from datetime import datetime
from django.utils import timezone
from reports.models import Certificate

for item in json.load(sys.stdin):
    inn = item["inn"]
    cont = item["container"]
    cert = Certificate.objects.filter(inn=inn, csptest_name=cont).first()
    if cert is None:
        cert = Certificate.objects.filter(inn=inn).order_by("-has_private_key", "-not_after", "-id").first()
    if cert is None:
        cert = Certificate(inn=inn, csptest_name=cont, source="LOCAL")
    cert.csptest_name = cont
    cert.thumbprint = item["thumbprint"]
    cert.not_before = datetime.fromisoformat(item["not_before"])
    cert.not_after = datetime.fromisoformat(item["not_after"])
    cert.source = "LOCAL"
    cert.has_private_key = True
    cert.is_active = True
    cert.last_seen_at = timezone.now()
    cert.save()
    Certificate.objects.filter(inn=inn, is_active=True).exclude(pk=cert.pk).update(is_active=False)
    print(f"DB OK {inn} id={cert.pk}")
'''
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "python", "manage.py", "shell", "-c", code],
        input=payload,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Django update failed: " + (result.stdout + result.stderr)[-2000:])
    print(result.stdout, end="")


def main() -> int:
    opt = args()
    if not opt.apply:
        print("Refusing to change keys without --apply", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Run as root", file=sys.stderr)
        return 2
    if not opt.source.is_dir() or not re.fullmatch(r"\d{10}", opt.first_probe_inn):
        print("Invalid --source or --first-probe-inn", file=sys.stderr)
        return 2
    first_probe = int(opt.first_probe_inn)
    try:
        candidates = read_candidates(opt.source, opt.csp_root, first_probe)
    except RuntimeError as exc:
        print(f"PREFLIGHT ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Preflight OK: {len(candidates)} unique keysets; no old key was changed yet.")
    for candidate in candidates:
        copy_flat(candidate["source"], candidate["probe"])  # type: ignore[arg-type]
    restarted = host("docker", "compose", "restart", "web")
    if restarted.returncode:
        print(restarted.stdout + restarted.stderr, file=sys.stderr)
        return 1

    usable: list[dict[str, object]] = []
    for index, candidate in enumerate(candidates, start=1):
        container = str(candidate["container"])
        if not verify(container):
            print(f"SKIP not visible: {candidate['archive']} -> {container}")
            continue
        details = cert_details(container, str(index))
        if not details:
            print(f"SKIP cannot export/parse: {candidate['archive']} -> {container}")
            continue
        candidate.update(details)
        usable.append(candidate)
        print(f"CERT {details['inn']} until {details['not_after']} <- {candidate['archive']}")

    # If the same company has several fresh keys, keep the one valid longest.
    selected: dict[str, dict[str, object]] = {}
    for candidate in usable:
        inn = str(candidate["inn"])
        old = selected.get(inn)
        if old is None or str(candidate["not_after"]) > str(old["not_after"]):
            selected[inn] = candidate
    print(f"Selected {len(selected)} certificates for installation.")
    if not selected:
        print("Nothing installed; probe directories were kept for diagnosis.", file=sys.stderr)
        return 1

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_root = Path("/root/ecp_backups_20260916") / f"batch_{stamp}"
    backup_root.mkdir(parents=True, exist_ok=False)
    installed: list[dict[str, str]] = []
    rollback: list[tuple[Path, Path | None]] = []

    try:
        for inn, candidate in selected.items():
            target = opt.csp_root / inn
            backup: Path | None = None
            if target.exists():
                backup = backup_root / f"{inn}.before_new"
                shutil.move(str(target), str(backup))
            copy_flat(candidate["source"], target)  # type: ignore[arg-type]
            rollback.append((target, backup))
        restarted = host("docker", "compose", "restart", "web")
        if restarted.returncode:
            raise RuntimeError("web restart after key copy failed")

        for inn, candidate in selected.items():
            container = str(candidate["container"])
            if not verify(container):
                raise RuntimeError(f"new container not visible for INN {inn}: {container}")
            checked = cert_details(container, "final_" + inn)
            if not checked or checked["inn"] != inn:
                raise RuntimeError(f"certificate mismatch after final copy for INN {inn}")
            installed_result = docker(CERTMGR, "-inst", "-store", "uMy", "-file", checked["cert_path"], "-cont", csp_name(container), timeout=45)
            if installed_result.returncode:
                raise RuntimeError(f"uMy install failed for INN {inn}: {(installed_result.stdout + installed_result.stderr)[-500:]}")
            installed.append({
                "inn": inn,
                "container": container,
                "thumbprint": checked["thumbprint"],
                "not_before": checked["not_before"],
                "not_after": checked["not_after"],
            })
            print(f"UMY OK {inn} {checked['not_after']}")
        write_database(installed)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Restoring every changed real INN directory from backup...", file=sys.stderr)
        for target, backup in reversed(rollback):
            failed = backup_root / (target.name + ".failed_new")
            if target.exists():
                shutil.move(str(target), str(failed))
            if backup and backup.exists():
                shutil.move(str(backup), str(target))
        host("docker", "compose", "restart", "web")
        return 1

    # Keep failed probes for diagnosis; move only successful duplicate probes
    # outside CSP so future global scans never see a second copy of a key.
    probe_backup = backup_root / "verified_probe_copies"
    probe_backup.mkdir()
    successful = {str(item["container"]) for item in selected.values()}
    for candidate in candidates:
        probe = candidate["probe"]
        if str(candidate["container"]) in successful and probe.exists():  # type: ignore[union-attr]
            shutil.move(str(probe), str(probe_backup / probe.name))  # type: ignore[union-attr]
    host("docker", "compose", "restart", "web")
    print(f"DONE installed={len(installed)} backup={backup_root}")
    print("No SBIS authentication was run, so no proxy traffic was spent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
