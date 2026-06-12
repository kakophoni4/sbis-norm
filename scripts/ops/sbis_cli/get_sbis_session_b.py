# -*- coding: utf-8 -*-
import os
import sys
import base64
import tempfile
import subprocess
import requests
import json
import re  # �thumbprint

# --- Локальные импорты ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_utils_linux import decrypt_data
from config import CRYPTO_PRO_CONTAINER_NAME

def read_env_variable(key):
    """Читает переменную из файла app.env."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app.env')
    try:
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    k, v = line.strip().split('=', 1)
                    if k == key:
                        return v.strip()
    except FileNotFoundError:
        return None
    return None

def get_public_cert_b64(container_name):
    """Извлекает сертификат, используя чистое имя контейнера."""
    print(f"[*] Извлечение сертификата из контейнера '{container_name}'...")
    cert_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as cert_file:
            cert_file_path = cert_file.name
        
        command = [
            '/opt/cprocsp/bin/amd64/certmgr',
            '-export',
            '-cont', container_name,
            '-dest', cert_file_path
        ]
        
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(result.stdout)  # Для отладки
        
        with open(cert_file_path, 'rb') as f:
            cert_bytes = f.read()
        
        print("[+] Сертификат успешно экспортирован.")
        return base64.b64encode(cert_bytes).decode('utf-8')

    except subprocess.CalledProcessError as e:
        print(f"[!] Ошибка certmgr при экспорте: {e.stderr}")
        return None
    finally:
        if cert_file_path and os.path.exists(cert_file_path):
            os.remove(cert_file_path)

def get_thumbprint(container_name):
    """Получает SHA1 Thumbprint сертификата из контейнера."""
    print(f"[*] Получение thumbprint из контейнера '{container_name}'...")
    command = [
        '/opt/cprocsp/bin/amd64/certmgr',
        '-list',
        '-cont', container_name
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Ошибка при получении thumbprint: {result.stderr}")
        return None
    
    # Парсим вывод на SHA1 Thumbprint
    match = re.search(r'SHA1 Thumbprint\s*:\s*([a-fA-F0-9]+)', result.stdout)
    if match:
        thumb = match.group(1).strip()
        print(f"[+] Thumbprint: {thumb}")
        return thumb
    print("[!] Thumbprint не найден в выводе.")
    return None

def get_encrypted_session_key(auth_url, cert_b64):
    """Получает зашифрованный ключ от СБИС."""
    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
        "id": 1
    }
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    print("\n[*] Отправка запроса на аутентификацию в СБИС...")
    response = requests.post(auth_url, json=payload, headers=headers, timeout=60)
    response.raise_for_status()
    response_data = response.json()
    if "error" in response_data:
        raise Exception(response_data['error'])
    print("[+] Зашифрованный ключ сессии успешно получен.")
    return response_data.get("result")

def main():
    """Основная логика."""
    sbis_auth_url = read_env_variable('SBIS_AUTH_URL') or "https://online.sbis.ru/auth/service/"
    
    print("="*50)
    print("Запуск процесса получения сессии СБИС...")
    print(f"Используемый контейнер: {CRYPTO_PRO_CONTAINER_NAME}")
    print("="*50)

    public_cert_b64 = get_public_cert_b64(CRYPTO_PRO_CONTAINER_NAME)
    if not public_cert_b64:
        return

    encrypted_key = get_encrypted_session_key(sbis_auth_url, public_cert_b64)
    if not encrypted_key:
        return

    thumb = get_thumbprint(CRYPTO_PRO_CONTAINER_NAME)
    if not thumb:
        return

    print("\n[*] Расшифровка ключа сессии...")
    session_id = decrypt_data(encrypted_key, CRYPTO_PRO_CONTAINER_NAME, thumb)  # Передаём thumb

    if session_id:
        print("\n" + "=" * 50)
        print("УСПЕШНО!")
        print("Расшифрованный ключ сессии СБИС:")
        print(session_id)
        print("=" * 50)
    else:
        print("\n" + "=" * 50)
        print("НЕУДАЧА.")
        print("=" * 50)

if __name__ == "__main__":
    main()
