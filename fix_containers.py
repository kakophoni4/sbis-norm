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

# Маппинг ИНН -> правильное имя контейнера (БЕЗ звездочки и префиксов)
CONTAINERS = {
    "7708429417": "24c5f8080-fc3f-e38f-7e44-f6b33f21e51",
    "7733418962": "c2ee2b9b-36eb-449f-bbbe-3e20440c11ef",
    "7733419099": "2fddc0c7-833b-4de5-b653-62802ed45965",
    "7733430705": "43ff8521-9996-4218-a475-97a2a36fcb11",
    "30721654": "e98a5a032-bfba-29b5-3efc-288e86118be",
}

def run(cmd, check=True):
    """Запуск команды"""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result

def install_container(inn: str, container_name: str):
    """Установка одного контейнера"""
    print(f"\n{'='*60}")
    print(f"🔐 Устанавливаем контейнер для ИНН {inn}")
    print(f"📦 Имя: {container_name}")
    
    # Путь к исходным файлам
    src_path = BASE_DIR / "test sharing" / inn
    if not src_path.exists():
        print(f"❌ Папка {src_path} не найдена")
        return False
    
    # Путь назначения
    dst_path = HDIMAGE_BASE / container_name
    
    # Удаляем старый контейнер если есть
    if dst_path.exists():
        print(f"🗑️  Удаляем старый контейнер")
        shutil.rmtree(dst_path)
    
    # Создаем папку
    dst_path.mkdir(parents=True, exist_ok=True)
    
    # Копируем все файлы КРОМЕ name.key
    for item in src_path.iterdir():
        if item.is_file() and item.name != "name.key":
            shutil.copy2(item, dst_path / item.name)
            print(f"   📄 {item.name}")
    
    # Создаем ПРАВИЛЬНЫЙ name.key (просто имя контейнера в UTF-8)
    name_key_path = dst_path / "name.key"
    name_key_path.write_text(container_name, encoding="utf-8")
    print(f"   ✏️  Создан правильный name.key")
    
    # Устанавливаем права
    os.chmod(dst_path, 0o700)
    for item in dst_path.iterdir():
        os.chmod(item, 0o600)
    
    # Меняем владельца
    shutil.chown(dst_path, TARGET_USER, TARGET_USER)
    for item in dst_path.iterdir():
        shutil.chown(item, TARGET_USER, TARGET_USER)
    
    print(f"✅ Контейнер скопирован в: {dst_path}")
    
    # Проверяем видимость
    print("🔍 Проверяем видимость...")
    try:
        result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"], check=False)
        full_name = f"\\\\.\\HDIMAGE\\{container_name}"
        
        if full_name in result.stdout:
            print(f"✅ КриптоПро ВИДИТ контейнер: {full_name}")
            
            # Пробуем установить сертификат
            print("📥 Устанавливаем сертификат...")
            try:
                run([CERTMGR, "-inst", "-cont", full_name, "-store", "uMy"])
                print("✅ Сертификат установлен!")
                return True
            except subprocess.CalledProcessError as e:
                print(f"⚠️  Не удалось установить сертификат")
                print(f"   Ошибка: {e.stderr}")
                # Но контейнер видим - это уже хорошо
                return True
        else:
            print(f"❌ КриптоПро НЕ видит контейнер")
            print(f"   Доступные контейнеры:")
            for line in result.stdout.split('\n'):
                if 'HDIMAGE' in line:
                    print(f"   - {line.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

def main():
    if os.geteuid() != 0:
        sys.exit("❌ Запускайте от root: sudo python3 fix_containers.py")
    
    # Создаем базовую папку
    HDIMAGE_BASE.mkdir(parents=True, exist_ok=True)
    shutil.chown(HDIMAGE_BASE, TARGET_USER, TARGET_USER)
    os.chmod(HDIMAGE_BASE, 0o700)
    
    print("🚀 Начинаем установку контейнеров")
    print(f"📂 База: {HDIMAGE_BASE}")
    
    success_count = 0
    results = {}
    
    for inn, container_name in CONTAINERS.items():
        if install_container(inn, container_name):
            success_count += 1
            results[inn] = f"\\\\.\\HDIMAGE\\{container_name}"
    
    # Итоговый отчет
    print(f"\n{'='*60}")
    print(f"📊 ИТОГИ УСТАНОВКИ")
    print(f"{'='*60}")
    print(f"✅ Успешно установлено: {success_count}/{len(CONTAINERS)}")
    
    if results:
        print(f"\n📝 Добавьте в config.py:")
        print("\nCRYPTO_CONTAINERS = {")
        for inn, path in results.items():
            print(f"    '{inn}': r'{path}',")
        print("}")
    
    # Показываем все видимые контейнеры
    print(f"\n🔍 Все видимые контейнеры:")
    result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"], check=False)
    for line in result.stdout.split('\n'):
        if 'HDIMAGE' in line:
            print(f"   {line.strip()}")

if __name__ == "__main__":
    main()
