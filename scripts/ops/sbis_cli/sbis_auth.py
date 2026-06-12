#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import base64
import json
import os
import subprocess
import tempfile
import requests
import re

CRYPTCP_PATH = "/opt/cprocsp/bin/amd64/cryptcp"
CERTMGR_PATH = "/opt/cprocsp/bin/amd64/certmgr"
SBIS_AUTH_URL = "https://online.sbis.ru/auth/service/"

def run_command(cmd):
    """Вспомогательная функция для запуска внешних команд."""
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

def ensure_key_link(container, password):
    """
    Принудительно создает связку "сертификат-ключ", используя флаг -pass.
    """
    cert_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as f:
            cert_path = f.name
        
        cmd_export = [CERTMGR_PATH, "-export", "-cont", container, "-dest", cert_path]
        p_export = run_command(cmd_export)
        if p_export.returncode != 0:
            print("[!] Ошибка экспорта сертификата:")
            print(f"   Stdout: {p_export.stdout.strip()}")
            print(f"   Stderr: {p_export.stderr.strip()}")
            return False

        cmd_install = [CERTMGR_PATH, "-inst", "-store", "uMy", "-file", cert_path, "-cont", container]
        if password is not None:
            cmd_install.extend(["-pass", password])
        
        p_install = run_command(cmd_install)
        if p_install.returncode != 0 and "already exists" not in p_install.stderr and "уже существует" not in p_install.stderr:
            print("[!] Ошибка установки/привязки сертификата:")
            print(f"   Stdout: {p_install.stdout.strip()}")
            print(f"   Stderr: {p_install.stderr.strip()}")
            return False
            
        return True
    finally:
        if cert_path and os.path.exists(cert_path):
            os.remove(cert_path)

def export_cert_b64(container):
    """Экспортирует сертификат из контейнера в формат Base64."""
    cert_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as f:
            cert_path = f.name
        p = run_command([CERTMGR_PATH, "-export", "-cont", container, "-dest", cert_path])
        if p.returncode != 0:
            print("[!] Ошибка экспорта сертификата для СБИС:")
            print(f"   Stdout: {p.stdout.strip()}")
            print(f"   Stderr: {p.stderr.strip()}")
            return None
        with open(cert_path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")
    finally:
        if cert_path and os.path.exists(cert_path):
            os.remove(cert_path)

def get_sbis_token(cert_b64):
    """Аутентификация в СБИС для получения зашифрованного токена."""
    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
        "id": 1
    }
    try:
        r = requests.post(SBIS_AUTH_URL, data=json.dumps(payload), headers={"Content-Type": "application/json; charset=utf-8"})
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            print(f"[!] Ошибка от API СБИС: {data['error']}")
            return None
        return data.get("result")
    except requests.exceptions.RequestException as e:
        print(f"[!] Ошибка при запросе к СБИС: {e}")
        return None

def try_decrypt_token(container, token_b64, password):
    """
    Пытается расшифровать токен, используя -pass и разные форматы входа.
    """
    in_der_path, in_b64_path = None, None
    try:
        # Подготовка входных файлов: бинарного (DER) и текстового (Base64)
        with tempfile.NamedTemporaryFile(delete=False) as f_in_der:
            in_der_path = f_in_der.name
            f_in_der.write(base64.b64decode("".join(token_b64.split())))
        
        in_b64_path = in_der_path + ".b64"
        with open(in_b64_path, "w", encoding="utf-8") as f:
            f.write(token_b64)

        # Перебор вариантов
        for mode, infile in (("DER", in_der_path), ("Base64", in_b64_path)):
            out_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False) as f_out:
                    out_path = f_out.name
                os.remove(out_path)

                cmd = [CRYPTCP_PATH, "-decr", "-cont", container]
                if password is not None:
                    cmd.extend(["-pass", password])
                cmd.extend(["-f", infile, out_path])
                
                p = run_command(cmd)
                
                if p.returncode == 0 and os.path.exists(out_path):
                    with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                        return f.read().strip()
                else:
                    print(f"[i] Попытка расшифровки не удалась (вход: {mode})")
                    if p.stdout: print(f"   Stdout: {p.stdout.strip()}")
                    if p.stderr: print(f"   Stderr: {p.stderr.strip()}")
            finally:
                if out_path and os.path.exists(out_path):
                    os.remove(out_path)
    finally:
        if in_der_path and os.path.exists(in_der_path):
            os.remove(in_der_path)
        if in_b64_path and os.path.exists(in_b64_path):
            os.remove(in_b64_path)
            
    return None

def main():
    parser = argparse.ArgumentParser(description="Авторизация в СБИС (Linux, CryptoPro)")
    parser.add_argument("--container", required=True, help="Полное FQCN имя контейнера")
    parser.add_argument("--password", help="Пароль от контейнера (используется флаг -pass)")
    args = parser.parse_args()

    # Устанавливаем пароль в пустую строку, если он не передан, но флаг есть
    password = args.password if args.password is not None else ""

    print(f"[*] Используем контейнер: {args.container}")
    print(f"[*] Используем пароль: '{password}'")

    print("\n--- Шаг 1: Экспорт сертификата для СБИС ---")
    cert_b64 = export_cert_b64(args.container)
    if not cert_b64:
        return

    print("\n--- Шаг 2: Запрос токена в СБИС ---")
    token_b64 = get_sbis_token(cert_b64)
    if not token_b64:
        return
    print("[+] Зашифрованный токен получен.")

    print("\n--- Шаг 3: Расшифровка токена ---")
    session_id = try_decrypt_token(args.container, token_b64, password)
    
    if not session_id:
        print("\n[!] Не удалось расшифровать токен.")
        return

    print("\n" + "="*60)
    print("УСПЕХ! Сессия СБИС:")
    print(session_id)
    print("="*60)

if __name__ == "__main__":
    main()
