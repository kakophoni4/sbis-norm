#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import shutil
import subprocess
import sys
import pwd
from pathlib import Path

CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CSPTEST = "/opt/cprocsp/bin/amd64/csptest"

BASE_DIR = Path(__file__).resolve().parent
TARGET_USER = "devuser"
HDIMAGE_BASE = Path(f"/var/opt/cprocsp/keys/{TARGET_USER}")

CONTAINER_INN = "7708429417"
CONTAINER_PATH = BASE_DIR / CONTAINER_INN

NAME_KEY_SIZE = 300
KEEP_STAR = True  # True: Сохранять "*" в имени, False: Убирать
PIN = ""  # Укажите PIN здесь, если контейнер защищён, напр. "12345678"

def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка выполнения: {e}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
        raise

def extract_and_normalize_name(src: Path) -> str | None:
    name_key = src / "name.key"
    if not name_key.exists():
        print(f"❌ Нет name.key в {src}")
        return None

    raw = name_key.read_bytes()
    if len(raw) < 4 or raw[0] != 0x30 or raw[2] != 0x16:
        print("❌ Некорректный формат ASN.1 в name.key")
        return None

    str_len = raw[3]
    if len(raw) < 4 + str_len:
        print("❌ Слишком короткий name.key")
        return None

    name_bytes = raw[4:4 + str_len]

    # Убираем trailing ff
    end = len(name_bytes)
    while end > 0 and name_bytes[end - 1] == 0xff:
        end -= 1
    name_bytes = name_bytes[:end]

    # Декодируем
    try:
        raw_name = name_bytes.decode('cp1251')
    except UnicodeDecodeError:
        raw_name = name_bytes.decode('ascii', 'ignore')
    raw_name = raw_name.strip()

    # Убираем "*" только если KEEP_STAR = False
    if not KEEP_STAR and raw_name.startswith('*'):
        raw_name = raw_name[1:].strip()

    # Нормализация GUID
    parts = raw_name.split(None, 1)
    hex_part = parts[0]
    suffix = parts[1] if len(parts) > 1 else ""

    # Добавляем "я" если суффикс "копи"
    if suffix == "копи":
        suffix = "копия"

    hex_digits = re.sub(r"[^0-9a-fA-F]", "", hex_part)[:32]
    if len(hex_digits) < 32:
        print(f"⚠️ Недостаточно hex-цифр: {hex_digits}")
        return raw_name

    formatted = (
        f"{hex_digits[:8]}-{hex_digits[8:12]}-"
        f"{hex_digits[12:16]}-{hex_digits[16:20]}-"
        f"{hex_digits[20:32]}"
    )
    normalized = f"{formatted} {suffix}".strip()
    print(f"📝 Оригинальное имя (из ASN.1): {raw_name}")
    print(f"✅ Нормализованное (KEEP_STAR={KEEP_STAR}): {normalized}")
    return normalized

def create_asn1_name_key(dst: Path, container_name: str):
    bytes_name = container_name.encode('cp1251')
    str_len = len(bytes_name)
    seq_len = 2 + str_len
    asn1 = bytes([0x30, seq_len, 0x16, str_len]) + bytes_name
    padding_len = NAME_KEY_SIZE - len(asn1)
    if padding_len < 0:
        raise ValueError("Имя слишком длинное для name.key")
    full_bytes = asn1 + (b'\xff' * padding_len)
    name_key_path = dst / "name.key"
    name_key_path.write_bytes(full_bytes)
    print(f"✏️ Создан правильный ASN.1 name.key ({len(full_bytes)} байт) для '{container_name}'")
    # Debug: Вывод hexdump
    print("🔍 Hexdump name.key:")
    result = run(["hexdump", "-C", str(name_key_path)])
    print(result.stdout[:500])  # Первые строки

def copy_container(src: Path, container_name: str) -> Path:
    # Очистка всех старых папок для этого ИНН
    for old_dir in HDIMAGE_BASE.glob(f"*{container_name.split()[0]}*"):
        if old_dir.is_dir() and old_dir != HDIMAGE_BASE:
            print(f"🗑️ Удаляем старую папку: {old_dir}")
            shutil.rmtree(old_dir)

    dst = HDIMAGE_BASE / container_name
    print(f"📦 Копируем контейнер...")
    dst.mkdir(parents=True, exist_ok=True)
    
    for item in src.iterdir():
        if item.is_file() and item.name != "name.key":
            shutil.copy2(item, dst / item.name)
    
    create_asn1_name_key(dst, container_name)
    
    os.chmod(str(dst), 0o700)
    
    uid = pwd.getpwnam(TARGET_USER).pw_uid
    gid = pwd.getpwnam(TARGET_USER).pw_gid
    for root, dirs, files in os.walk(str(dst)):
        for d in dirs:
            dir_path = os.path.join(root, d)
            os.chmod(dir_path, 0o700)
            os.chown(dir_path, uid, gid)
        for f in files:
            file_path = os.path.join(root, f)
            os.chmod(file_path, 0o600)
            os.chown(file_path, uid, gid)
    
    print(f"✅ Скопировано в: {dst}")
    return dst

def verify_container_visible(container_name: str) -> bool:
    full_name = f"\\\\.\\HDIMAGE\\{container_name}"
    print(f"🔍 Проверяем видимость: {full_name}")
    try:
        result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"])
        if full_name in result.stdout:
            print("✅ CryptoPro видит контейнер!")
            return True
        else:
            print("❌ CryptoPro НЕ видит контейнер")
            print("   Доступные контейнеры:")
            for line in result.stdout.splitlines():
                if line.startswith('\\\\.\\HDIMAGE\\'):
                    print(f"     {line}")
            return False
    except Exception as e:
        print(f"❌ Ошибка проверки: {e}")
        return False

def install_certificate(full_name: str, pin: str = "") -> bool:
    print("📥 Устанавливаем сертификат...")
    cmd = [CERTMGR, "-inst", "-cont", full_name]
    if pin:
        cmd.extend(["-pin", pin])
    try:
        run(cmd)
        print("✅ Сертификат установлен!")
        return True
    except Exception as e:
        print(f"❌ Ошибка установки: {e}")
        return False

def main():
    if os.geteuid() != 0:
        sys.exit("❌ Запускайте от root (sudo)")
    
    if not CONTAINER_PATH.exists():
        sys.exit(f"❌ Папка для ИНН {CONTAINER_INN} не найдена: {CONTAINER_PATH}")
    
    print("="*60)
    print(f"🔐 Установка контейнера для ИНН {CONTAINER_INN}")
    print("="*60)
    
    HDIMAGE_BASE.mkdir(parents=True, exist_ok=True)
    uid = pwd.getpwnam(TARGET_USER).pw_uid
    gid = pwd.getpwnam(TARGET_USER).pw_gid
    os.chown(str(HDIMAGE_BASE), uid, gid)
    os.chmod(str(HDIMAGE_BASE), 0o700)
    
    container_name = extract_and_normalize_name(CONTAINER_PATH)
    if not container_name:
        sys.exit("❌ Не удалось извлечь имя контейнера")
    
    copy_container(CONTAINER_PATH, container_name)
    
    full_name = f"\\\\.\\HDIMAGE\\{container_name}"
    print(f"🔗 Полное имя: {full_name}")
    
    if not verify_container_visible(container_name):
        print("⚠️ Контейнер не виден. Проверьте name.key и перезапустите.")
    
    install_certificate(full_name, PIN)
    
    print("\n" + "="*60)
    print("✅ УСТАНОВКА ЗАВЕРШЕНА")
    print("="*60)
    
    print("\n🔍 Все видимые контейнеры после установки:")
    result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn", "-verifyc"])
    print(result.stdout)

if __name__ == "__main__":
    main()
