#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass

CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CSPTEST = "/opt/cprocsp/bin/amd64/csptest"

BASE_DIR = Path(__file__).resolve().parent
TARGET_USER = "devuser"                
HDIMAGE_BASE = Path(f"/var/opt/cprocsp/keys/{TARGET_USER}")

@dataclass
class ContainerSource:
    inn: str
    path: Path

SOURCES = [
    ContainerSource("7715600802", BASE_DIR / "7715600802"),
]

def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)

def ensure_cryptopro():
    if not Path(CERTMGR).exists():
        sys.exit(" CryptoPro CSP не установлен или не найден certmgr.")

def read_container_id(src: Path) -> str | None:
    name_key = src / "name.key"
    if not name_key.exists():
        print(f" Нет name.key в {src}")
        return None
    data = name_key.read_bytes().decode("cp1251", errors="ignore")

    match = re.search(
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\s+[^\r\n]+)?)',
        data, re.IGNORECASE
    )
    if match:
        name = re.sub(r'(.)\1+$', r'\1', match.group(1)).strip()
        print(f" name.key → {name}")
        return name

    uuid_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', data, re.IGNORECASE)
    if uuid_match:
        uuid = uuid_match.group(0)
        q_match = re.search(r'"([^"]+)"', data)
        name = f"{uuid} {q_match.group(1)}" if q_match else uuid
        name = re.sub(r'(.)\1+$', r'\1', name).strip()
        print(f" name.key → {name}")
        return name

    print(f"  Не удалось распознать имя. Фрагмент: {data[:200]!r}")
    return None

def copy_container(src: Path, container_id: str) -> Path:
    dst = HDIMAGE_BASE / container_id
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.is_file():
            shutil.copy2(item, dst / item.name)
    os.chmod(dst, 0o700)
    for item in dst.iterdir():
        os.chmod(item, 0o600)
    shutil.chown(dst, TARGET_USER, TARGET_USER)
    for item in dst.iterdir():
        shutil.chown(item, TARGET_USER, TARGET_USER)
    return dst

def ensure_certificate(container_name: str):
    try:
        run([CERTMGR, "-list", "-cont", container_name])
        print(" Сертификат уже доступен.")
    except subprocess.CalledProcessError:
        print(" Устанавливаем сертификат в uMy ...")
        run([CERTMGR, "-import", "-store", "uMy", "-cont", container_name])

def verify(container_name: str):
    print(" Проверка контейнера...")
    try:
        res = run([CSPTEST, "-keyset", "-info", "-cont", container_name])
        if "Error" in res.stdout or "Error" in res.stderr:
            print("  Есть предупреждения:\n", res.stdout or res.stderr)
        else:
            print(" OK")
    except subprocess.CalledProcessError as e:
        print(f" csptest не прошёл\nSTDERR: {e.stderr}")

def main():
    if os.geteuid():
        sys.exit("  Запускайте скрипт от root (sudo).")
    ensure_cryptopro()

    if not HDIMAGE_BASE.exists():
        HDIMAGE_BASE.mkdir(parents=True, exist_ok=True)
        shutil.chown(HDIMAGE_BASE, TARGET_USER, TARGET_USER)
        os.chmod(HDIMAGE_BASE, 0o700)

    installed: dict[str, str] = {}

    for source in SOURCES:
        if not source.path.exists():
            print(f"\n Каталог {source.path} не найден.")
            continue

        print("\n" + "="*60)
        print(f" Установка контейнера для ИНН {source.inn}")
        print("="*60)

        name = read_container_id(source.path)
        if not name:
            continue

        if len(name) > 230:
            print(f"  Обрезаем имя: {name[:230]}")
            name = name[:230]

        dest = copy_container(source.path, name)
        container_name = f"\\\\.\\HDIMAGE\\{name}"
        print(f" Скопировано в {dest}")
        print(f"   CryptoPro имя: {container_name}")
        ensure_certificate(container_name)
        verify(container_name)
        installed[source.inn] = container_name

    if installed:
        config_path = BASE_DIR / "business_logic" / "config.py"
        print("\nОбновите CRYPTO_PRO_CONTAINER_NAME / CRYPTO_CONTAINERS в config.py:")
        for inn, name in installed.items():
            print(f"    '{inn}': r'{name}'")
        print("\nПроверьте и при необходимости подредактируйте config.py вручную.")

if __name__ == "__main__":
    main()
