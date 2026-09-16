#!/usr/bin/env python3
"""Discover owners of raw CryptoPro keysets without touching uMy or Django.

The archives delivered on 2026-09-16 contain eight keysets whose archive
names do not identify an organization.  CryptoPro only exposes their X.509
certificate after the six raw *.key files are placed flat in a numeric
HDIMAGE directory.  This command creates *new, reserved* numeric probe
directories, exports each certificate and prints its legal-entity INN.

It deliberately does not install certificates into uMy, modify Certificate
records, replace an existing INN directory, call SBIS, or clean up anything.
The printed mapping is the required input for the separate installation step.

Run on the server as root, from /opt/sbis-norm:
  python scripts/ops/probe_unknown_ecp_keysets.py \
    --source /root/new_ecp_stage_20260916/.import_20260916_v2
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED = (
    "header.key",
    "masks.key",
    "masks2.key",
    "name.key",
    "primary.key",
    "primary2.key",
)

# These are exactly the containers from 2.zip, 3.zip, 4.zip, Desktop (3).zip
# (two keys) and gjlgbcb.rar (three keys).  The names contain no organization
# INN, and none was present in the Certificate table on 2026-09-16.
UNKNOWN_CONTAINERS = (
    "3c50e154-05c0-4365-85fe-e61323c94b02 копия",
    "9ea0447b-4d3e-45d0-8b29-2f327a47b96d копия",
    "cd1a2b8f-f1cc-46bb-aabb-d95b6b565e70 копия",
    "e77ab8d5-1f3c-4df8-9d71-c4f5363ed0a0 копия",
    "17cab447-9d04-4273-a8c8-f88f30e25ead копия",
    "82b922ea-f653-ac84-c073-1431486ead0b копия",
    "6abaa6ba-a561-e4a7-2352-0f695c7388a8 копия",
    "fb00d365-7a0c-5431-715e-ff9266712c11 копия",
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="existing .import_*_v2 directory")
    parser.add_argument(
        "--csp-root",
        type=Path,
        default=Path("/var/opt/cprocsp/keys/root"),
        help="CryptoPro HDIMAGE root",
    )
    parser.add_argument(
        "--first-probe-inn",
        type=int,
        default=9900000001,
        help="first unused 10-digit temporary directory name",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/root/ecp_probe_20260916.tsv"),
        help="TSV report to create",
    )
    return parser.parse_args()


def raw_container_name(name_key: Path) -> str:
    raw = name_key.read_bytes()
    if len(raw) < 4 or raw[:3] != b"\x30,\x16":
        raise ValueError("unexpected name.key header")
    length = raw[3]
    value = raw[4 : 4 + length].rstrip(b"\xff")
    name = value.decode("cp1251").strip()
    if not name or any(char in name for char in ("/", "\\", "\x00")):
        raise ValueError("unsafe or empty CryptoPro container name")
    return name


def discover_sources(source: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for header in source.glob("unpacked_*/**/header.key"):
        keyset = header.parent
        if not all((keyset / filename).is_file() for filename in REQUIRED):
            continue
        name = raw_container_name(keyset / "name.key")
        if name in UNKNOWN_CONTAINERS:
            if name in found:
                raise RuntimeError(f"same unknown container appears twice: {name}")
            found[name] = keyset
    missing = set(UNKNOWN_CONTAINERS) - set(found)
    if missing:
        raise RuntimeError("keysets not found in --source: " + ", ".join(sorted(missing)))
    return found


def run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def export_certificate(container: str, slot: str) -> tuple[bool, str]:
    cert = f"/tmp/ecp_probe_{slot}.cer"
    csp_container = "\\\\\\\\.\\HDIMAGE\\" + container
    export = run(
        [
            "docker", "compose", "exec", "-T", "web",
            "/opt/cprocsp/bin/amd64/certmgr", "-export", "-cont", csp_container, "-dest", cert,
        ],
        timeout=30,
    )
    if export.returncode:
        return False, (export.stdout + export.stderr).strip()
    listed = run(
        [
            "docker", "compose", "exec", "-T", "web",
            "/opt/cprocsp/bin/amd64/certmgr", "-list", "-file", cert,
        ],
        timeout=30,
    )
    if listed.returncode:
        return False, (listed.stdout + listed.stderr).strip()
    return True, listed.stdout + listed.stderr


def field(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def main() -> int:
    args = arguments()
    if os.geteuid() != 0:
        print("ERROR: run as root", file=sys.stderr)
        return 2
    if not args.source.is_dir():
        print(f"ERROR: source does not exist: {args.source}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"\d{10}", str(args.first_probe_inn)):
        print("ERROR: --first-probe-inn must be a 10-digit number", file=sys.stderr)
        return 2
    if shutil.which("docker") is None:
        print("ERROR: docker is not available", file=sys.stderr)
        return 2

    sources = discover_sources(args.source)
    planned: list[tuple[str, Path, Path]] = []
    for offset, container in enumerate(UNKNOWN_CONTAINERS):
        probe = args.csp_root / str(args.first_probe_inn + offset)
        if probe.exists():
            print(f"ERROR: probe directory already exists, nothing changed: {probe}", file=sys.stderr)
            return 1
        planned.append((container, sources[container], probe))

    print("=== PLAN: eight unknown keysets ===")
    for container, source, probe in planned:
        print(f"{probe.name}\t{source}\t{container}")

    # The directories are new and are intentionally retained after the probe.
    # Retention makes the result auditable and allows a later mapping-driven
    # installation to move/copy exactly the verified source material.
    try:
        for _, source, probe in planned:
            probe.mkdir(mode=0o700)
            for filename in REQUIRED:
                target = probe / filename
                shutil.copy2(source / filename, target)
                os.chmod(target, 0o600)
            os.chmod(probe, 0o700)
    except Exception as exc:
        print(f"ERROR while creating a new probe directory: {exc}", file=sys.stderr)
        print("No existing CryptoPro directory was modified.", file=sys.stderr)
        return 1

    restarted = run(["docker", "compose", "restart", "web"], timeout=60)
    if restarted.returncode:
        print(restarted.stdout + restarted.stderr, file=sys.stderr)
        print("ERROR: probe files were created but web restart failed; do not install them.", file=sys.stderr)
        return 1

    rows: list[dict[str, str]] = []
    print("\n=== RESULT ===")
    for container, source, probe in planned:
        ok, text = export_certificate(container, probe.name)
        row = {
            "probe_directory": str(probe),
            "source_keyset": str(source),
            "container": container,
            "inn_ul": field(text, r"Subject\s*:\s*.*?ИНН ЮЛ=(\d+)") if ok else "",
            "thumbprint": field(text, r"SHA1 Thumbprint\s*:\s*([0-9a-fA-F]+)").lower() if ok else "",
            "not_after": field(text, r"Not valid after\s*:\s*(.+)") if ok else "",
            "status": "OK" if ok else "EXPORT_FAILED",
        }
        rows.append(row)
        if ok:
            print(
                f"OK   inn={row['inn_ul'] or '?'} valid_to={row['not_after'] or '?'} "
                f"container={container}"
            )
        else:
            tail = " ".join(text.splitlines()[-3:])
            print(f"FAIL probe={probe.name} container={container}: {tail}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as report:
        writer = csv.DictWriter(report, fieldnames=list(rows[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nTSV report: {args.output}")
    print("No uMy, Django Certificate records, real INN directories, or SBIS requests were changed.")
    return 0 if all(row["status"] == "OK" and row["inn_ul"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
