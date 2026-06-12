#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import json
import tempfile
from pathlib import Path
import subprocess
import requests

CRYPTCP = "/opt/cprocsp/bin/amd64/cryptcp"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
PROVTYPE = "80"
PROVNAME = "Crypto-Pro GOST R 34.10-2012 KC1 CSP"

CONTAINER = r'\\.\HDIMAGE\77fd6caf-4298-447a-872c-994f9a63a5c2 копия'
SBIS_AUTH_URL = "https://online.sbis.ru/auth/service/"

def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)

def export_cert(container: str) -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as tmp:
        tmp_path = Path(tmp.name)
    try:
        run([CERTMGR, "-export", "-cont", container, "-dest", str(tmp_path)])
        data = tmp_path.read_bytes()
        return base64.b64encode(data).decode()
    finally:
        tmp_path.unlink(missing_ok=True)

def decrypt(encrypted_b64: str, container: str) -> str:
    ciphertext = base64.b64decode(encrypted_b64)
    with tempfile.NamedTemporaryFile(delete=False) as enc_file:
        enc_file.write(ciphertext)
        enc_path = Path(enc_file.name)
    dec_path = enc_path.with_suffix(".dec")
    try:
        run([
            CRYPTCP, "-decr",
            "-cont", container,
            "-provtype", PROVTYPE,
            "-provname", PROVNAME,
            str(enc_path),
            str(dec_path),
        ])
        return dec_path.read_text(encoding="utf-8").strip()
    finally:
        enc_path.unlink(missing_ok=True)
        dec_path.unlink(missing_ok=True)

def main():
    try:
        cert_b64 = export_cert(CONTAINER)
        payload = {
            "jsonrpc": "2.0",
            "method": "СБИС.АутентифицироватьПоСертификату",
            "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
            "id": 1,
        }
        resp = requests.post(SBIS_AUTH_URL, json=payload, timeout=60)
        if resp.status_code >= 400:
            print(f"[!] HTTP {resp.status_code}")
            print(resp.text)
            resp.raise_for_status()

        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"Ответ с ошибкой: {json.dumps(data['error'], ensure_ascii=False)}")

        encrypted = data.get("result")
        if not encrypted:
            raise RuntimeError(f"result пуст: {json.dumps(data, ensure_ascii=False)}")

        session_id = decrypt(encrypted, CONTAINER)
        print("=" * 60)
        print("УСПЕХ")
        print("Сессия:", session_id)
        print("=" * 60)
    except Exception as exc:
        print("Critical error:", exc)

if __name__ == "__main__":
    main()
