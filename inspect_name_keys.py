#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from pathlib import Path

FOLDERS = ["7708429417"]

def normalize(raw: str) -> str:
    raw = re.sub(r"[\x00-\x1f]", "", raw)
    raw = re.sub(r"[яЯ]{2,}$", "я", raw).strip()
    raw = raw.lstrip("0,").lstrip("*")

    parts = raw.split(None, 1)          # ['24c5f8080-fc3f-...', 'копия']
    hex_part = parts[0]
    suffix = parts[1] if len(parts) > 1 else ""

    hex_digits = re.sub(r"[^0-9a-fA-F]", "", hex_part)[:32]
    if len(hex_digits) < 32:
        return raw                         # fallback

    formatted = (
        f"{hex_digits[:8]}-{hex_digits[8:12]}-"
        f"{hex_digits[12:16]}-{hex_digits[16:20]}-"
        f"{hex_digits[20:32]}"
    )
    return f"{formatted} {suffix}".strip()

def dump(folder: Path):
    path = folder / "name.key"
    if not path.exists():
        print(f"❌ {folder}: name.key не найден")
        return

    raw_bytes = path.read_bytes()
    decoded = raw_bytes.decode("cp1251", errors="ignore")
    clean = normalize(decoded)

    print("=" * 70)
    print("Folder :", folder)
    print("Raw    :", raw_bytes[:40], "…")
    print("Decoded:", decoded[:80], "…")
    print("Result :", clean)
    print("=" * 70)

if __name__ == "__main__":
    base = Path(__file__).resolve().parent
    for name in FOLDERS:
        folder = base / name
        if folder.exists():
            dump(folder)
