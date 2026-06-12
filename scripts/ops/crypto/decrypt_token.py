#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import base64
import os
import subprocess
import tempfile

CRYPTCP_PATH = '/opt/cprocsp/bin/amd64/cryptcp'

def decrypt_b64_with_container(encrypted_b64, container_name, inn):
    b64_clean = ''.join(encrypted_b64.split())
    try:
        enc_bytes = base64.b64decode(b64_clean, validate=True)
    except Exception as e:
        print(f"[!] Некорректная Base64 строка: {e}")
        return None

    fin, fout = None, None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(enc_bytes)
            fin = os.path.abspath(f.name)
        fout = fin + '.dec'
        if os.path.exists(fout):
            os.remove(fout)

        # Самый первый, каноничный синтаксис из itog_
        cmd = [CRYPTCP_PATH, '-decr', '-cont', container_name, '-f', fin, fout]
        
        print(f"[*] Выполняю команду: {' '.join(cmd)}")
        
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        if proc.returncode == 0 and os.path.exists(fout):
            with open(fout, 'r', encoding='utf-8', errors='ignore') as r:
                return r.read().strip()

        print('[!] Ошибка cryptcp при расшифровке.')
        if proc.stdout:
            print('   Stdout:', proc.stdout)
        if proc.stderr:
            print('   Stderr:', proc.stderr)
        return None
    finally:
        for p in (fin, fout):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="Минимальный скрипт для расшифровки токена СБИС.")
    parser.add_argument("encrypted_b64_string", help="Зашифрованная строка Base64.")
    parser.add_argument("--container", required=True, help="Полное имя контейнера (FQCN).")
    parser.add_argument("--inn", required=True, help="ИНН владельца сертификата.")
    args = parser.parse_args()

    decrypted_token = decrypt_b64_with_container(args.encrypted_b64_string, args.container, args.inn)

    if decrypted_token:
        print("\n" + "="*50)
        print("Расшифрованный токен:")
        print(decrypted_token)
        print("="*50)
    else:
        print("\n[!] Расшифровка не удалась.")

if __name__ == "__main__":
    main()
