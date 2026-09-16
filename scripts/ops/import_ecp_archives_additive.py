#!/usr/bin/env python3
"""Safely stage CryptoPro containers from ZIP/RAR archives.

The source archives contain Windows-style CryptoPro key files. A direct copy
of name.key under an invented directory name is not an HDIMAGE container on
Linux. CryptoPro uses the name encoded inside name.key. This tool follows the
project's old, working installer: read and normalize that name, recreate a
Linux-compatible name.key, and place the six files under the real name.

It never calls certmgr, changes uMy, talks to SBIS, updates Django, overwrites
an existing directory, or deletes data. Those occur only in a later verified
step after the new containers can be enumerated and exported.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_KEY_FILES = {
    "header.key", "masks.key", "masks2.key", "name.key", "primary.key", "primary2.key"
}
NAME_KEY_SIZE = 300
GUID_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage CryptoPro keysets without changing uMy or DB")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--csp-root", type=Path, default=Path("/var/opt/cprocsp/keys/root"))
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def extract_archive(archive: Path, destination: Path) -> None:
    if archive.suffix.lower() == ".zip":
        command = ["unzip", "-oq", str(archive), "-d", str(destination)]
    elif archive.suffix.lower() == ".rar" and shutil.which("unrar"):
        command = ["unrar", "x", "-o+", str(archive), f"{destination}{os.sep}"]
    elif archive.suffix.lower() == ".rar" and shutil.which("unar"):
        command = ["unar", "-f", "-o", str(destination), str(archive)]
    else:
        raise RuntimeError("unrar or unar is required for RAR archives")
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def read_container_name(name_key: Path) -> str:
    raw = name_key.read_bytes()
    if len(raw) < 4 or raw[0] != 0x30 or raw[2] != 0x16:
        raise ValueError("name.key is not the expected CryptoPro ASN.1 form")
    name_len = raw[3]
    if len(raw) < 4 + name_len:
        raise ValueError("name.key is truncated")
    encoded = raw[4 : 4 + name_len].rstrip(b"\xff")
    try:
        original = encoded.decode("cp1251").strip()
    except UnicodeDecodeError:
        original = encoded.decode("ascii", "ignore").strip()
    if not original:
        raise ValueError("empty container name in name.key")

    # Same normalization used by the original working installer. Windows often
    # stores a GUID without dashes and a truncated suffix "копи".
    pieces = original.split(None, 1)
    hex_part = re.sub(r"[^0-9a-fA-F]", "", pieces[0])[:32]
    suffix = pieces[1] if len(pieces) > 1 else ""
    if suffix == "копи":
        suffix = "копия"
    if GUID_RE.fullmatch(hex_part):
        normalized = (
            f"{hex_part[:8]}-{hex_part[8:12]}-{hex_part[12:16]}-"
            f"{hex_part[16:20]}-{hex_part[20:]}"
        )
        if suffix:
            normalized += f" {suffix}"
    else:
        normalized = f"{pieces[0]} {suffix}".strip()

    # In some FNS container names spaces occur before the actual suffix, so
    # it is not the second token. The exported Windows name is truncated to
    # "копи"; Linux CSP expects the complete "копия" name.
    if normalized.endswith(" копи"):
        normalized = f"{normalized[:-4]}копия"

    if any(char in normalized for char in ("/", "\\", "\x00")) or normalized in {".", ".."}:
        raise ValueError("unsafe container name in name.key")
    if len(normalized.encode("cp1251", "strict")) > NAME_KEY_SIZE - 4:
        raise ValueError("container name is too long")
    return normalized


def write_linux_name_key(destination: Path, container_name: str) -> None:
    encoded = container_name.encode("cp1251")
    if len(encoded) > 251:
        raise ValueError("container name is too long for name.key")
    value = bytes([0x30, 2 + len(encoded), 0x16, len(encoded)]) + encoded
    destination.write_bytes(value + (b"\xff" * (NAME_KEY_SIZE - len(value))))


def list_keysets(extracted: Path) -> list[Path]:
    result: list[Path] = []
    for header in sorted(extracted.rglob("header.key")):
        keyset = header.parent
        names = {item.name.lower() for item in keyset.iterdir() if item.is_file()}
        if REQUIRED_KEY_FILES.issubset(names):
            result.append(keyset)
        else:
            print(f"WARN incomplete keyset skipped: {keyset}", file=sys.stderr)
    return result


def keyset_fingerprint(keyset: Path) -> str:
    """Fingerprint without exposing any private-key content in logs."""
    digest = hashlib.sha256()
    for filename in sorted(REQUIRED_KEY_FILES):
        data = (keyset / filename).read_bytes()
        digest.update(filename.encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def copy_keyset(source: Path, destination: Path, container_name: str) -> None:
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing container: {destination}")
    destination.mkdir(mode=0o700)
    try:
        for filename in REQUIRED_KEY_FILES - {"name.key"}:
            target = destination / filename
            shutil.copy2(source / filename, target)
            os.chmod(target, 0o600)
        write_linux_name_key(destination / "name.key", container_name)
        os.chmod(destination / "name.key", 0o600)
        os.chmod(destination, 0o700)
    except Exception:
        shutil.rmtree(destination)
        raise


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.batch):
        print("ERROR: --batch may contain only A-Z, a-z, 0-9, _ and -", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("ERROR: run as root.", file=sys.stderr)
        return 1
    if not args.source.is_dir():
        print(f"ERROR: source directory does not exist: {args.source}", file=sys.stderr)
        return 2
    if not shutil.which("unzip"):
        print("ERROR: unzip is required.", file=sys.stderr)
        return 1

    archives = sorted(
        path for path in args.source.iterdir()
        if path.is_file() and path.suffix.lower() in {".zip", ".rar"}
    )
    if not archives:
        print(f"ERROR: no ZIP/RAR archives in {args.source}", file=sys.stderr)
        return 1

    work_dir = args.source / f".import_{args.batch}_v2"
    work_dir.mkdir(parents=True, exist_ok=True)
    manifest = work_dir / "manifest.tsv"
    if args.apply:
        args.csp_root.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str, str, str]] = []
    pending: list[tuple[Path, Path, str, Path]] = []
    planned: dict[str, str] = {}
    print(f"Source archives: {len(archives)}")
    print(f"Mode: {'APPLY' if args.apply else 'PLAN'}")
    print(f"CryptoPro HDIMAGE root: {args.csp_root}")

    for archive_index, archive in enumerate(archives, start=1):
        extracted = work_dir / f"unpacked_{archive_index:03d}"
        if not extracted.exists():
            extracted.mkdir()
            try:
                extract_archive(archive, extracted)
            except subprocess.CalledProcessError as exc:
                print(f"WARN cannot extract {archive.name}: {exc.stderr.strip()}", file=sys.stderr)
                continue
        for keyset in list_keysets(extracted):
            try:
                container_name = read_container_name(keyset / "name.key")
            except ValueError as exc:
                print(f"WARN {archive.name} / {keyset.name}: {exc}", file=sys.stderr)
                continue
            destination = args.csp_root / container_name
            fingerprint = keyset_fingerprint(keyset)
            previous_fingerprint = planned.get(container_name)
            if previous_fingerprint:
                if previous_fingerprint == fingerprint:
                    print(f"SKIP exact duplicate: {archive.name} -> {container_name}")
                    continue
                print(
                    f"ERROR same container name but different key material: {container_name}",
                    file=sys.stderr,
                )
                return 1
            planned[container_name] = fingerprint
            rows.append((archive.name, str(keyset), container_name, str(destination)))
            pending.append((archive, keyset, container_name, destination))
            print(f"[{len(rows)}] {archive.name} -> {container_name}")

    with manifest.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file, delimiter="\t")
        writer.writerow(("archive", "keyset_source", "container_name", "crypto_destination"))
        writer.writerows(rows)

    print(f"\nKeysets discovered: {len(rows)}")
    print(f"Manifest: {manifest}")
    if not args.apply:
        print("No CryptoPro files were changed. Re-run with --apply to create the listed containers.")
        return 0

    # All-or-nothing preflight: no new container is copied when any target
    # collides with an existing one.
    existing = [str(destination) for _, _, _, destination in pending if destination.exists()]
    if existing:
        print("ERROR: existing container directories found; nothing was copied:", file=sys.stderr)
        for destination in existing:
            print(f"  {destination}", file=sys.stderr)
        return 1

    created: list[Path] = []
    try:
        for _, keyset, container_name, destination in pending:
            copy_keyset(keyset, destination, container_name)
            created.append(destination)
    except Exception as exc:
        for destination in reversed(created):
            shutil.rmtree(destination, ignore_errors=True)
        print(f"ERROR {container_name}: {exc}; created containers were rolled back", file=sys.stderr)
        return 1
    print("\nContainers were copied only. uMy, Certificate table and SBIS were not changed.")
    print("Next: restart web and enumerate/export only these names before any certificate installation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
