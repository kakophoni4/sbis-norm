# -*- coding: utf-8 -*-
import subprocess
import argparse
import os
import base64
import tempfile
import sys
import re

# Пути к утилитам КриптоПро.
CSPTEST_PATH = '/opt/cprocsp/bin/amd64/csptest'
CRYPT_CP_PATH = '/opt/cprocsp/bin/amd64/cryptcp'

def find_unique_container_guid():
    """
    Находит GUID единственного доступного ключевого контейнера.
    """
    print("[*] Поиск уникального GUID контейнера...")
    try:
        enum_cmd = f"{CSPTEST_PATH} -keys -enum_cont -fqcn -verifyc"
        result = subprocess.run(
            ['bash', '-c', enum_cmd],
            capture_output=True, text=True, encoding='utf-8', check=True
        )

        for line in result.stdout.splitlines():
            if 'HDIMAGE' in line:
                # Ищем GUID в строке
                match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', line)
                if match:
                    guid = match.group(1)
                    print(f"[+] Найден GUID контейнера: {guid}")
                    # Возвращаем полное имя, так как утилиты могут требовать его
                    return line.strip()

        print("[-] Не удалось найти GUID в выводе csptest.")
        print("--- Raw csptest output ---")
        print(result.stdout)
        print("--------------------------")
        return None

    except Exception as e:
        print(f"[!] Ошибка при поиске контейнера: {e}")
        return None

def decrypt_with_container(container_name, encrypted_b64_string):
    """
    Расшифровывает данные, используя ключевой контейнер.
    """
    print(f"[*] Расшифровка с помощью контейнера '{container_name}'...")
    try:
        encrypted_data = base64.b64decode(encrypted_b64_string)
    except base64.binascii.Error as e:
        print(f"[!] Ошибка декодирования Base64: {e}")
        return None

    temp_files = {}
    try:
        with tempfile.NamedTemporaryFile(delete=False) as encrypted_file:
            encrypted_file.write(encrypted_data)
            temp_files['encrypted'] = encrypted_file.name
        
        temp_files['decrypted'] = temp_files['encrypted'] + ".dec"

        # Используем bash -c для надежной передачи имени с кириллицей
        decr_cmd = f"'{CRYPT_CP_PATH}' -decr -container '{container_name}' -f '{temp_files['encrypted']}' '{temp_files['decrypted']}'"
        
        subprocess.run(['bash', '-c', decr_cmd], capture_output=True, text=True, encoding='utf-8', check=True)
        
        with open(temp_files['decrypted'], 'r', encoding='utf-8') as f:
            return f.read().strip()

    except subprocess.CalledProcessError as e:
        print(f"[!] Ошибка при расшифровке: {e.stderr}")
        return None
    except Exception as e:
        print(f"[!] Ошибка при работе с временными файлами: {e}")
        return None
    finally:
        for path in temp_files.values():
            if os.path.exists(path):
                os.remove(path)

def main():
    parser = argparse.ArgumentParser(
        description="Расшифровывает строку Base64, используя единственный найденный контейнер КриптоПро."
    )
    parser.add_argument(
        "encrypted_b64_string", 
        help="Зашифрованная строка сессии в формате Base64."
    )
    
    args = parser.parse_args()

    # Находим контейнер по GUID и используем его полное имя
    container_full_name = find_unique_container_guid()
    
    if container_full_name:
        decrypted_session = decrypt_with_container(container_full_name, args.encrypted_b64_string)
        if decrypted_session:
            print("\n" + "=" * 50)
            print("УСПЕШНО РАСШИФРОВАНО!")
            print("Ключ сессии:", decrypted_session)
            print("=" * 50)
        else:
            print("\n[!] Не удалось расшифровать ключ сессии.")

if __name__ == "__main__":
    main()