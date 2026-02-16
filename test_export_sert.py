#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"

EXPORT_BASE = pathlib.Path("/tmp/exported_certs")
DER_DIR = EXPORT_BASE / "der"
PEM_DIR = EXPORT_BASE / "pem"
DER_DIR.mkdir(parents=True, exist_ok=True)
PEM_DIR.mkdir(parents=True, exist_ok=True)

def run(cmd):
    try:
        res = subprocess.run(
            cmd,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return res.stdout
    except subprocess.CalledProcessError as err:
        print(f"[!] Ошибка при выполнении {' '.join(cmd)}:\n{err.stderr}")
        return ""

def sanitize(name: str) -> str:
    clean = re.sub(r"[^\wА-Яа-яЁё .-]", "_", name, flags=re.UNICODE)
    clean = clean.strip().strip(".")
    return clean or "container"

def list_containers():
    output = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"])
    return [line.strip() for line in output.splitlines() if line.startswith(r"\\.\HDIMAGE")]

def export_cert(container: str, filename: pathlib.Path, base64: bool = False):
    cmd = [CERTMGR, "-export", "-container", container, "-dest", str(filename)]
    if base64:
        cmd.append("-base64")
    run(cmd)

def main():
    containers = list_containers()
    if not containers:
        print("Контейнеры не найдены.")
        return

    for cont in containers:
        print(f"\n=== {cont} ===")

        verify = run([CSPTEST, "-keyset", "-container", cont, "-verifycontext"])
        if "AcquireContext: OK" not in verify:
            print("  [!] Не удалось открыть контейнер, пропускаю.")
            continue

        name_part = sanitize(cont.split("\\")[-1])
        der_path = DER_DIR / f"{name_part}.cer"
        pem_path = PEM_DIR / f"{name_part}.pem"

        export_cert(cont, der_path, base64=False)
        export_cert(cont, pem_path, base64=True)

        # достаём Subject и ИНН для справки
        info = run([CERTMGR, "-list", "-container", cont])
        subject_match = re.search(r"Subject\s*:\s*(.+)", info)
        inn_match = re.search(r"ИНН(?:\s*[А-Я]+)?=([0-9]+)", subject_match.group(1)) if subject_match else None

        print(f"  Subject : {subject_match.group(1) if subject_match else 'N/A'}")
        print(f"  ИНН     : {inn_match.group(1) if inn_match else 'N/A'}")
        print(f"  DER     : {der_path}")
        print(f"  PEM     : {pem_path}")

if __name__ == "__main__":
    if not sys.executable:
        print("Запустите через python3.")
    main()
