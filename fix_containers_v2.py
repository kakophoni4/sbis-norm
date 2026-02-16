#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import sys
from pathlib import Path

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"

BASE_DIR = Path(__file__).resolve().parent
TARGET_USER = "devuser"
HDIMAGE_BASE = Path(f"/var/opt/cprocsp/keys/{TARGET_USER}")

def run(cmd, check=True):
    """Запуск команды"""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result

def extract_container_name(src_path):
    """Извлекает имя контейнера из name.key"""
    name_key = src_path / "name.key"
    if not name_key.exists():
        return None
    
    # Читаем сырые байты
    raw_bytes = name_key.read_bytes()
    
    # Пробуем найти GUID-подобную строку
    raw_str = raw_bytes.decode("cp1251", errors="ignore")
    
    # Убираем управляющие символы и мусор
    import re
    # Ищем паттерн GUID: 8-4-4-4-12 hex символов
    guid_pattern = r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
    match = re.search(guid_pattern, raw_str)
    
    if match:
        return match.group(1)
    
    # Альтернативный способ - убираем префикс и суффикс
    if raw_str.startswith("0,"):
        raw_str = raw_str[2:]
    if raw_str.startswith("\x16"):
        raw_str = raw_str[1:]
    if raw_str.startswith("*"):
        raw_str = raw_str[1:]
    
    # Берем только до первого пробела или спец символа
    clean_name = re.split(r'[\x00-\x1f\s]', raw_str)[0]
    
    # Проверяем, похоже ли на GUID
    if len(clean_name) >= 32 and '-' in clean_name:
        return clean_name
    
    return None

def create_proper_name_key(container_name):
    """Создает правильный name.key в формате КриптоПро"""
    # Формат: префикс + длина + имя + padding
    prefix = b'\x30\x2c\x16'  # Это константа для HDIMAGE
    name_bytes = container_name.encode('cp1251')
    
    # Полная строка: префикс + имя
    full_data = prefix + name_bytes
    
    # Дополняем до 276 байт (стандартный размер)
    padded = full_data.ljust(276, b'\xff')
    
    return padded

def install_from_test_sharing():
    """Устанавливает контейнеры из test sharing"""
    test_sharing = BASE_DIR / "test sharing"
    if not test_sharing.exists():
        print(f"❌ Папка {test_sharing} не найдена")
        return
    
    success_count = 0
    results = {}
    
    # Перебираем все папки в test sharing
    for inn_dir in sorted(test_sharing.iterdir()):
        if not inn_dir.is_dir():
            continue
        
        inn = inn_dir.name
        print(f"\n{'='*60}")
        print(f"🔐 Обрабатываем ИНН {inn}")
        
        # Извлекаем имя контейнера
        container_name = extract_container_name(inn_dir)
        if not container_name:
            print(f"❌ Не удалось извлечь имя контейнера")
            continue
        
        print(f"📦 Имя контейнера: {container_name}")
        
        # Целевая папка
        dst_path = HDIMAGE_BASE / container_name
        
        # Удаляем старую если есть
        if dst_path.exists():
            print(f"🗑️  Удаляем старую версию")
            shutil.rmtree(dst_path)
        
        # Создаем папку
        dst_path.mkdir(parents=True, exist_ok=True)
        
        # Копируем файлы
        for item in inn_dir.iterdir():
            if item.is_file():
                if item.name == "name.key":
                    # Создаем правильный name.key
                    proper_name_key = create_proper_name_key(container_name)
                    (dst_path / "name.key").write_bytes(proper_name_key)
                    print(f"   ✏️  Создан правильный name.key")
                else:
                    # Копируем остальные файлы как есть
                    shutil.copy2(item, dst_path / item.name)
                    print(f"   📄 {item.name}")
        
        # Устанавливаем права
        os.chmod(dst_path, 0o700)
        for item in dst_path.iterdir():
            os.chmod(item, 0o600)
        
        # Меняем владельца
        shutil.chown(dst_path, TARGET_USER, TARGET_USER)
        for item in dst_path.iterdir():
            shutil.chown(item, TARGET_USER, TARGET_USER)
        
        print(f"✅ Скопировано в: {dst_path}")
        
        # Проверяем видимость
        print("🔍 Проверяем...")
        result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"], check=False)
        full_name = f"\\\\.\\HDIMAGE\\{container_name}"
        
        if full_name in result.stdout:
            print(f"✅ КриптоПро ВИДИТ контейнер!")
            success_count += 1
            results[inn] = full_name
            
            # Пробуем установить сертификат
            cert_file = dst_path / "1.cer"
            if cert_file.exists():
                print("📥 Устанавливаем сертификат...")
                try:
                    run([CERTMGR, "-inst", "-file", str(cert_file), "-store", "uMy"])
                    print("✅ Сертификат установлен!")
                except:
                    print("⚠️  Сертификат не установлен (возможно уже есть)")
        else:
            print(f"❌ КриптоПро НЕ видит контейнер")
    
    # Итоги
    print(f"\n{'='*60}")
    print(f"📊 ИТОГИ")
    print(f"{'='*60}")
    print(f"✅ Успешно: {success_count}")
    
    if results:
        print(f"\n📝 Для config.py:")
        print("\nCRYPTO_CONTAINERS = {")
        for inn, path in results.items():
            print(f"    '{inn}': r'{path}',")
        print("}")
    
    # Все контейнеры
    print(f"\n🔍 Все видимые контейнеры:")
    result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"], check=False)
    for line in result.stdout.split('\n'):
        if 'HDIMAGE' in line:
            print(f"   {line.strip()}")

def main():
    if os.geteuid() != 0:
        sys.exit("❌ Запускайте от root: sudo python3 fix_containers_v2.py")
    
    # Создаем базовую папку
    HDIMAGE_BASE.mkdir(parents=True, exist_ok=True)
    shutil.chown(HDIMAGE_BASE, TARGET_USER, TARGET_USER)
    os.chmod(HDIMAGE_BASE, 0o700)
    
    print("🚀 Установка контейнеров КриптоПро")
    print(f"📂 База: {HDIMAGE_BASE}")
    
    install_from_test_sharing()

if __name__ == "__main__":
    main()
