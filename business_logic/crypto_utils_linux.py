import subprocess
import os
import base64
import tempfile

CRYPTCP = '/opt/cprocsp/bin/amd64/cryptcp'
PROVIDER = 'Crypto-Pro GOST R 34.10-2012 KC1 CSP'

def decrypt_data(encrypted_b64: str, container_name: str, thumbprint: str, cert_path: str | None = None) -> str:
    encrypted_bytes = base64.b64decode(encrypted_b64)

    with tempfile.NamedTemporaryFile(delete=False) as encrypted_file:
        encrypted_file.write(encrypted_bytes)
        encrypted_path = encrypted_file.name

    decrypted_path = encrypted_path + ".dec"

    attempts = [
        (
            [
                CRYPTCP,
                "-decr",
                "-cont", container_name,
                "-provtype", "80",
                "-provname", PROVIDER,
                encrypted_path,
                decrypted_path,
            ],
            "по контейнеру",
        ),
        (
            [
                CRYPTCP,
                "-decr",
                "-thumbprint", thumbprint,
                "-provtype", "80",
                "-provname", PROVIDER,
                encrypted_path,
                decrypted_path,
            ],
            "по thumbprint'у",
        ),
    ]

    errors = []

    try:
        for cmd, label in attempts:
            res = subprocess.run(
                cmd,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if res.returncode == 0 and os.path.exists(decrypted_path):
                with open(decrypted_path, "r", encoding="utf-8") as out:
                    return out.read().strip()

            errors.append(
                f"Попытка {label} не удалась.\n"
                f"Команда: {' '.join(cmd)}\n"
                f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
            )

        raise RuntimeError("\n\n".join(errors))

    finally:
        for path in (encrypted_path, decrypted_path):
            if os.path.exists(path):
                os.remove(path)
