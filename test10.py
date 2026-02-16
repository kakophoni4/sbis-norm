#!/usr/bin/env python3
import subprocess
import re
import sys

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"

def run(cmd):
    """Запуск утилиты и возврат stdout"""
    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout
    except subprocess.CalledProcessError as err:
        print(f"[!] Команда {' '.join(cmd)} завершилась с ошибкой:\n{err.stderr}")
        return ""

def get_containers():
    """Считывает список контейнеров (как делает csptest -enum_cont -fqcn)"""
    output = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"])
    containers = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(r"\\.\HDIMAGE"):
            containers.append(line)
    return containers

def extract_inn(cert_output):
    """Ищет ИНН внутри блока Subject."""
    subject_match = re.search(r"Subject\s*:\s*(.+)", cert_output)
    if not subject_match:
        return None, None
    subject = subject_match.group(1)
    # ИНН может идти как “ИНН ЮЛ=...”, “ИНН ФЛ=...”, просто “ИНН=...”
    inn_match = re.search(r"ИНН(?:\s*[А-Я]+)?=([0-9]+)", subject)
    inn_ul_match = re.search(r"ИНН ЮЛ=([0-9]+)", subject)
    inn = inn_match.group(1) if inn_match else None
    inn_ul = inn_ul_match.group(1) if inn_ul_match else None
    return subject, inn_ul or inn

def main():
    containers = get_containers()
    if not containers:
        print("Контейнеры не найдены.")
        return

    for cont in containers:
        print(f"\n=== {cont} ===")
        # Проверяем, что контейнер существует и читается
        verify_out = run([CSPTEST, "-keyset", "-container", cont, "-verifycontext"])
        if "AcquireContext: OK" not in verify_out:
            print("  [!] Не удалось открыть контейнер (см. выше). Пропускаю.")
            continue

        cert_out = run([CERTMGR, "-list", "-container", cont])
        if not cert_out.strip():
            print("  [!] Certmgr ничего не вернул.")
            continue

        subject, inn = extract_inn(cert_out)
        if subject:
            print(f"  Subject : {subject}")
        else:
            print("  Subject : не найден.")
        if inn:
            print(f"  ИНН     : {inn}")
        else:
            print("  ИНН     : не найден.")

if __name__ == "__main__":
    if not sys.executable:
        print("Запускайте скрипт через Python 3.")
    main()
