#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Установщик сертификатов CryptoPro - ПРАВИЛЬНОЕ чтение name.key
"""
import os
import sys
import subprocess
import shutil
import re
from pathlib import Path

# Пути к утилитам CryptoPro
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CSPTEST = "/opt/cprocsp/bin/amd64/csptest"

# Базовая директория проекта
BASE_DIR = Path(__file__).resolve().parent.parent

# Директории с сертификатами
CERT_DIRS = {
    "7715600802": BASE_DIR / "7715600802",
    "9715376022": BASE_DIR / "9715376022",
}

# Целевая директория для контейнеров CryptoPro HDIMAGE
HDIMAGE_BASE = Path("/var/opt/cprocsp/keys/root")


def check_cryptopro():
    """Проверка установки CryptoPro"""
    if not os.path.exists(CERTMGR):
        print("❌ CryptoPro CSP не установлен!")
        sys.exit(1)
    print("✅ CryptoPro CSP найден")


def get_container_name_from_keys(source_dir):
    """
    Извлекает имя контейнера из файла name.key
    """
    name_key_file = source_dir / "name.key"
    
    if not name_key_file.exists():
        print(f"❌ Файл name.key не найден!")
        return None
    
    try:
        # Читаем как бинарные данные
        with open(name_key_file, 'rb') as f:
            data = f.read()
        
        # Декодируем с cp1251 (Windows кириллица)
        text = data.decode('cp1251', errors='ignore')
        
        # Ищем UUID с возможным текстом после
        # Паттерн: UUID (8-4-4-4-12) + возможно пробел и слово (включая кириллицу)
        pattern = r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\s+[а-яА-Яa-zA-Z0-9_-]+)?)'
        match = re.search(pattern, text, re.IGNORECASE)
        
        if match:
            container_name = match.group(1).strip()
            
            # ВАЖНО: Убираем повторяющиеся символы в конце
            # "копияяяяя" -> "копия"
            # Используем regex: убираем все повторения последнего символа (оставляем только 1)
            container_name = re.sub(r'(.)\1+$', r'\1', container_name)
            
            if container_name:
                print(f"📝 Имя контейнера из name.key: {container_name}")
                return container_name
        
        # Для второго контейнера - другой формат
        # "0ООО "МОДЭМ-ПРОЭКТ"-96b2-a3906f9c85e4яяяяя"
        
        # Ищем полный UUID
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuid_match = re.search(uuid_pattern, text, re.IGNORECASE)
        
        if uuid_match:
            uuid_str = uuid_match.group(0)
            
            # Ищем название организации в кавычках
            quotes_pattern = r'"([^"]+)"'
            quotes_match = re.search(quotes_pattern, text)
            
            if quotes_match:
                org_name = quotes_match.group(1).strip()
                container_name = f'{uuid_str} {org_name}'
            else:
                container_name = uuid_str
            
            # Убираем повторяющиеся символы в конце
            container_name = re.sub(r'(.)\1+$', r'\1', container_name)
            
            if container_name:
                print(f"📝 Имя контейнера из name.key: {container_name}")
                return container_name
        
        print(f"⚠️  Не удалось извлечь имя контейнера")
        print(f"   Первые 200 символов: {text[:200]}")
        return None
        
    except Exception as e:
        print(f"❌ Ошибка чтения name.key: {e}")
        import traceback
        traceback.print_exc()
        return None

def list_all_existing_containers():
    """
    Выводит список ВСЕХ существующих контейнеров в системе
    """
    print(f"\n{'='*60}")
    print("📋 Существующие контейнеры в системе:")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            [CERTMGR, "-list"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        
        # Парсим вывод
        containers = []
        current_container = None
        current_info = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Container :' in line or 'Container name:' in line:
                if current_container:
                    containers.append(current_info)
                
                container_name = line.split(':', 1)[1].strip()
                current_container = container_name
                current_info = {'name': container_name, 'inn': None, 'subject': None}
            
            if current_container:
                if 'ИНН=' in line or 'INN=' in line:
                    inn_match = re.search(r'(?:ИНН|INN)=(\d+)', line)
                    if inn_match:
                        current_info['inn'] = inn_match.group(1)
                
                if 'Subject:' in line:
                    current_info['subject'] = line
        
        if current_container:
            containers.append(current_info)
        
        if containers:
            for i, cont in enumerate(containers, 1):
                print(f"\n{i}. Контейнер: {cont['name']}")
                if cont['inn']:
                    print(f"   ИНН: {cont['inn']}")
                if cont['subject']:
                    print(f"   {cont['subject'][:100]}")
        else:
            print("⚠️  Контейнеры не найдены")
        
        return containers
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return []


def install_container(inn, source_dir):
    """
    Устанавливает контейнер
    """
    print(f"\n{'='*60}")
    print(f"📦 Установка контейнера для ИНН: {inn}")
    print(f"{'='*60}")
    
    if not source_dir.exists():
        print(f"❌ Директория не найдена: {source_dir}")
        return None
    
    # Проверяем файлы
    required_files = ["header.key", "name.key", "primary.key", "masks.key"]
    missing = [f for f in required_files if not (source_dir / f).exists()]
    
    if missing:
        print(f"❌ Отсутствуют файлы: {', '.join(missing)}")
        return None
    
    print(f"✅ Все файлы контейнера найдены")
    
    # Получаем имя контейнера
    container_id = get_container_name_from_keys(source_dir)
    
    if not container_id:
        print(f"❌ Не удалось определить имя контейнера")
        return None
    
    # Проверяем длину имени (Linux ограничение 255 символов)
    if len(container_id) > 200:
        print(f"⚠️  Имя контейнера слишком длинное ({len(container_id)} символов), обрезаем")
        container_id = container_id[:200]
    
    # Целевая директория
    target_dir = HDIMAGE_BASE / container_id
    
    # Удаляем старый
    if target_dir.exists():
        print(f"🗑️  Удаление старого контейнера...")
        shutil.rmtree(target_dir, ignore_errors=True)
    
    # Создаем
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"❌ Ошибка создания директории: {e}")
        print(f"   Имя: {container_id}")
        print(f"   Длина: {len(container_id)}")
        return None
    
    # Копируем ВСЕ файлы
    print(f"📋 Копирование файлов контейнера...")
    for file in source_dir.iterdir():
        if file.is_file():
            shutil.copy2(file, target_dir / file.name)
            print(f"   ✓ {file.name}")
    
    # Права
    print(f"🔒 Установка прав доступа...")
    os.chmod(target_dir, 0o700)
    for file in target_dir.iterdir():
        if file.is_file():
            os.chmod(file, 0o600)
    
    # Имя для CryptoPro
    full_container_name = f"\\\\.\\HDIMAGE\\{container_id}"
    
    print(f"✅ Контейнер установлен")
    print(f"📍 Путь: {target_dir}")
    print(f"📍 Имя: {full_container_name}")
    
    return full_container_name


def verify_container(container_name):
    """Проверяет контейнер"""
    print(f"\n🔍 Проверка контейнера...")
    
    try:
        result = subprocess.run(
            [CSPTEST, "-keyset", "-container", container_name, "-verifycontext"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        
        if "success" in output.lower() or result.returncode == 0:
            print("✅ Контейнер работает!")
            return True
        else:
            print("❌ Контейнер не работает")
            print(f"   {output[:300]}")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False


def verify_certificate(container_name, inn):
    """Проверяет сертификат"""
    print(f"\n📜 Проверка сертификата...")
    
    try:
        result = subprocess.run(
            [CERTMGR, "-list", "-container", container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        
        if "Certificate:" in output or "Subject:" in output:
            print("✅ Сертификат найден!")
            
            if inn in output:
                print(f"✅ ИНН {inn} подтвержден")
            
            for line in output.split('\n')[:25]:
                if any(x in line for x in ['Subject:', 'Issuer:', 'ИНН', 'Serial:']):
                    print(f"   {line.strip()}")
            
            return True
        else:
            print("⚠️  Сертификат не найден")
            return False
            
    except Exception as e:
        print(f"⚠️  Ошибка: {e}")
        return False


def update_config_file(containers_map):
    """Обновляет config.py"""
    config_path = BASE_DIR / "scripts" / "ops" / "config.py"
    
    print(f"\n{'='*60}")
    print("📝 Обновление config.py")
    print(f"{'='*60}")
    
    if not config_path.exists():
        print(f"⚠️  config.py не найден")
        print("\nCRYPTO_CONTAINERS = {")
        for inn, container_name in containers_map.items():
            print(f"    '{inn}': r'{container_name}',")
        print("}")
        return
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        in_section = False
        section_found = False
        
        for line in lines:
            if 'CRYPTO_CONTAINERS' in line and '=' in line:
                in_section = True
                section_found = True
                new_lines.append("CRYPTO_CONTAINERS = {\n")
                for inn, container_name in containers_map.items():
                    new_lines.append(f"    '{inn}': r'{container_name}',\n")
                new_lines.append("}\n")
                continue
            
            if in_section and '}' in line:
                in_section = False
                continue
            
            if not in_section:
                new_lines.append(line)
        
        if not section_found:
            new_lines.append("\nCRYPTO_CONTAINERS = {\n")
            for inn, container_name in containers_map.items():
                new_lines.append(f"    '{inn}': r'{container_name}',\n")
            new_lines.append("}\n")
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        print(f"✅ config.py обновлен")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")


def main():
    """Главная функция"""
    print("="*60)
    print("🔐 Установщик сертификатов CryptoPro")
    print("="*60)
    
    check_cryptopro()
    
    if os.geteuid() != 0:
        print("\n⚠️  Требуются права root!")
        sys.exit(1)
    
    # Показываем существующие контейнеры
    existing = list_all_existing_containers()
    
    # Установка
    containers_map = {}
    success_count = 0
    
    for inn, cert_dir in CERT_DIRS.items():
        container_name = install_container(inn, cert_dir)
        if container_name:
            if verify_container(container_name):
                verify_certificate(container_name, inn)
                containers_map[inn] = container_name
                success_count += 1
            else:
                containers_map[inn] = container_name
    
    # Итог
    print(f"\n{'='*60}")
    print(f"📊 Результат:")
    print(f"{'='*60}")
    print(f"   Установлено: {len(containers_map)}/{len(CERT_DIRS)}")
    print(f"   Работают: {success_count}/{len(CERT_DIRS)}")
    
    if containers_map:
        update_config_file(containers_map)
    
    print(f"\n{'='*60}")
    print("📝 Установленные контейнеры:")
    print(f"{'='*60}")
    for inn, container_name in containers_map.items():
        print(f"ИНН {inn}:")
        print(f"  {container_name}")
    
    print(f"\n{'='*60}")
    print("📝 Следующие шаги:")
    print(f"{'='*60}")
    print("1. Перезапустите Docker:")
    print("   docker-compose restart")
    print("\n2. Проверьте через API")
    

if __name__ == "__main__":
    main()
