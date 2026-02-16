import requests
import base64
import json
import os
import subprocess

CONTAINER_NAME = r'\\.\HDIMAGE\77fd6caf-4298-447a-872c-994f9a63a5c2 копия'  # Полное имя с префиксом и экранированием
SBIS_AUTH_URL = "https://online.sbis.ru/auth/service/"

CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP = "/opt/cprocsp/bin/amd64/cryptcp"

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nError: {result.stderr.decode('utf-8', errors='ignore')}")
    return result.stdout

def get_certificate_from_container(container):
    # Используем shell-редирект вместо -out
    cmd = f"{CERTMGR} -export -dest der -cont '{container}' > temp_cert.der"
    run_command(cmd)

    if not os.path.exists("temp_cert.der") or os.path.getsize("temp_cert.der") == 0:
        raise ValueError("Certificate export failed: file is missing or empty")

    with open("temp_cert.der", "rb") as f:
        cert_der = f.read()

    os.remove("temp_cert.der")
    return base64.b64encode(cert_der).decode('utf-8')

def decrypt_session_key(encrypted_session_id, container):
    try:
        encrypted_data = base64.b64decode(encrypted_session_id)

        with open("temp.enc", "wb") as f:
            f.write(encrypted_data)

        # Убрал -f, если нужно — верни. Добавь -nochain или другие флаги, если требуется
        cmd = f"{CRYPTCP} -decr -cont '{container}' -in 'temp.enc' -out 'temp.dec'"
        run_command(cmd)

        with open("temp.dec", "r") as f:
            session_id = f.read().strip()

        os.remove("temp.enc")
        os.remove("temp.dec")

        return session_id

    except Exception as e:
        raise RuntimeError(f"Decryption error: {e}")

def authenticate_with_container(container):
    cert_data = get_certificate_from_container(container)

    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {
            "Сертификат": {
                "ДвоичныеДанные": cert_data
            }
        },
        "id": 1
    }

    headers = {'Content-Type': 'application/json; charset=utf-8'}

    response = requests.post(SBIS_AUTH_URL, data=json.dumps(payload), headers=headers)
    response.raise_for_status()
    result = response.json().get("result")
    if not result:
        raise ValueError("No encrypted key in response")
    return result

if __name__ == "__main__":
    try:
        encrypted_key = authenticate_with_container(CONTAINER_NAME)

        print("=" * 50)
        print("ENCRYPTED SESSION KEY:")
        print(encrypted_key)
        print("=" * 50)

        session_id = decrypt_session_key(encrypted_key, CONTAINER_NAME)

        print("\n" + "=" * 50)
        print("DECRYPTED SESSION ID:")
        print(session_id)
        print("=" * 50)

    except Exception as e:
        print(f"Critical error: {e}")
