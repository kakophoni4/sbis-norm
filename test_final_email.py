#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Set

import requests

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP = "/opt/cprocsp/bin/amd64/cryptcp"

DEFAULT_AUTH_URL = "https://online.sbis.ru/auth/service/"
DEFAULT_SERVICE_URL = "https://online.sbis.ru/service/?srv=1&protocol=4"

ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.env")


# ------------------------ УТИЛИТЫ СИСТЕМЫ ------------------------ #

def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Обёртка над subprocess.run с человекочитаемыми ошибками."""
    try:
        return subprocess.run(
            cmd,
            check=check,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[!] Команда {' '.join(cmd)} завершилась с ошибкой:")
        print(exc.stderr or exc.stdout)
        raise


def read_env() -> dict:
    """Простейший парсер app.env (формат KEY=VALUE)."""
    env = {}
    if not os.path.exists(ENV_FILE):
        return env

    with open(ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    return env


def resolve_setting(env: dict, key: str, default: str) -> str:
    return os.environ.get(key) or env.get(key) or default


# ------------------------ КОНТЕЙНЕРЫ ------------------------ #

@dataclass
class ContainerInfo:
    """Данные по одному контейнеру CryptoPro."""
    name: str
    subject: str
    inns: List[str] = field(default_factory=list)

    def display_name(self) -> str:
        return self.name.replace("\\\\", "\\")


def parse_inns(subject: str) -> List[str]:
    """Извлекает все встречающиеся ИНН из Subject."""
    inns = re.findall(r"ИНН(?:\s*[А-Я]+)?=([0-9]{10,12})", subject or "")
    return list(dict.fromkeys(inns))  # уникализируем, сохраняя порядок


def list_containers() -> List[ContainerInfo]:
    """Возвращает список всех контейнеров с Subject и ИНН."""
    result = run([CSPTEST, "-keyset", "-enum_cont", "-fqcn"])
    containers = []
    seen = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith(r"\\.\HDIMAGE"):
            if line in seen:
                continue
            seen.add(line)

            info = run([CERTMGR, "-list", "-container", line], check=False)
            subject_match = re.search(r"Subject\s*:\s*(.+)", info.stdout)
            subject = subject_match.group(1).strip() if subject_match else ""
            inns = parse_inns(subject)

            containers.append(ContainerInfo(name=line, subject=subject, inns=inns))

    return containers


def select_container_by_inn(containers: List[ContainerInfo], inn: str) -> Optional[ContainerInfo]:
    for container in containers:
        if inn in container.inns:
            return container
    return None


# ------------------------ РАБОТА С СЕРТИФИКАТОМ ------------------------ #

def export_cert_base64(container_name: str) -> str:
    """Экспортирует сертификат из контейнера в Base64 (как ждёт СБИС)."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        run([CERTMGR, "-export", "-container", container_name, "-dest", tmp_path])
        with open(tmp_path, "rb") as cert_file:
            return base64.b64encode(cert_file.read()).decode("utf-8")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def get_thumbprint(container_name: str) -> str:
    """Получает SHA1 Thumbprint сертификата из контейнера."""
    info = run([CERTMGR, "-list", "-container", container_name])
    match = re.search(r"SHA1 Thumbprint\s*:\s*([A-Fa-f0-9]+)", info.stdout)
    if not match:
        raise RuntimeError("SHA1 Thumbprint не найден в выводе certmgr.")
    return match.group(1)


def decrypt_data(encrypted_b64: str, container_name: str, thumbprint: str, cert_path: str) -> str:
    encrypted_bytes = base64.b64decode(encrypted_b64)

    with tempfile.NamedTemporaryFile(delete=False) as encrypted_file:
        encrypted_file.write(encrypted_bytes)
        encrypted_path = encrypted_file.name

    decrypted_path = encrypted_path + ".dec"

    attempts = []
    if thumbprint:
        attempts.append((["-thumbprint", thumbprint], "по thumbprint'у"))

    attempts.append((["-cont", container_name], "по контейнеру"))

    errors = []

    try:
        for extra_args, desc in attempts:
            cmd = [
                CRYPTCP,
                "-decr",
                "-cert", cert_path,
                "-provtype", "80",
                "-provname", "Crypto-Pro GOST R 34.10-2012 KC1 CSP",
                *extra_args,
                encrypted_path,
                decrypted_path,
            ]

            result = subprocess.run(
                cmd,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if result.returncode == 0 and os.path.exists(decrypted_path):
                with open(decrypted_path, "r", encoding="utf-8") as f:
                    return f.read().strip()

            errors.append(
                f"Попытка расшифровки {desc} не удалась.\n"
                f"Команда: {' '.join(cmd)}\n"
                f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )

        raise RuntimeError("\n\n".join(errors))

    finally:
        for path in (encrypted_path, decrypted_path):
            if os.path.exists(path):
                os.remove(path)

# ------------------------ АВТОРИЗАЦИЯ В СБИС ------------------------ #

def request_session(auth_url: str, cert_b64: str) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
        "id": 1
    }
    response = requests.post(auth_url, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


# ------------------------ СБИС: ВЫГРУЗКА ПОЧТЫ ------------------------ #

def fetch_incoming_documents(service_url: str, session_id: str, days: int) -> dict:
    date_to = datetime.now().strftime("%d.%m.%Y")
    date_from = (datetime.now() - timedelta(days=days)).strftime("%d.%m.%Y")

    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументовПоСобытиям",
        "params": {
            "Фильтр": {
                "ДатаС": date_from,
                "ДатаПо": date_to,
                "ТипРеестра": "Входящие"
            }
        },
        "id": 1
    }
    headers = {"Content-Type": "application/json; charset=utf-8", "X-SBISSessionID": session_id}
    response = requests.post(service_url, json=payload, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def pretty_print_mail(result: dict, focus_inns: Optional[Set[str]] = None) -> None:
    registry = result.get("result", {}).get("Реестр")
    if not registry:
        print("  Не найдено входящих документов за указанный период.")
        return

    for item in registry:
        doc = item.get("Документ", {})
        kontragent = doc.get("Контрагент", {})

        inn = None
        if "СвЮЛ" in kontragent:
            inn = kontragent["СвЮЛ"].get("ИНН")
        elif "СвФЛ" in kontragent:
            inn = kontragent["СвФЛ"].get("ИНН")

        attachments = doc.get("Вложение", [])
        dt = doc.get("Дата", "N/A")
        title = doc.get("Название", "N/A")

        flag = ""
        if focus_inns and inn in focus_inns:
            flag = " 9"

        print("\n" + "=" * 70)
        print(f"  Дата: {dt}")
        print(f"  Тема: {title}{flag}")
        print(f"  Отправитель (ИНН): {inn or 'N/A'}")

        if attachments:
            print("  Вложения:")
            for att in attachments:
                print(f"    • {att.get('Название', '—')}")
        else:
            print("  Вложения: нет")
    print("\n" + "=" * 70)


# ------------------------ CLI ------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="Авторизация в СБИС по сертификату и вывод входящих документов по указанному ИНН."
    )
    parser.add_argument("--inn", help="ИНН организации, чьим сертификатом авторизуемся", required=False)
    parser.add_argument("--days", type=int, default=7, help="За сколько дней смотреть входящие (по умолчанию 7)")
    parser.add_argument("--list", action="store_true", help="Только вывести список контейнеров и их ИНН")
    parser.add_argument("--dump", action="store_true", help="Вывести полный JSON-ответ API (для отладки)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("  Выполните скрипт от root (sudo), иначе CryptoPro не даст доступ к контейнерам.")
        sys.exit(1)

    env = read_env()
    auth_url = resolve_setting(env, "SBIS_AUTH_URL", DEFAULT_AUTH_URL)
    service_url = resolve_setting(env, "SBIS_SERVICE_URL", DEFAULT_SERVICE_URL)

    containers = list_containers()
    if not containers:
        print("Контейнеры не найдены.")
        sys.exit(1)

    if args.list or not args.inn:
        print("Доступные контейнеры:")
        for cont in containers:
            inns = ", ".join(cont.inns) if cont.inns else "ИНН не найден"
            print(f" • {cont.display_name()} | {inns} | Subject: {cont.subject}")
        if not args.inn:
            print("\nУкажите ИНН через --inn, чтобы запустить авторизацию. Пример:\n"
                  "  sudo python3 sbis_mail_by_inn.py --inn 7715600802")
        sys.exit(0)

    # Подбираем контейнер по ИНН
    container = select_container_by_inn(containers, args.inn)
    if not container:
        print(f"  Контейнер с ИНН {args.inn} не найден.\n"
              "   Список доступных контейнеров:")
        for cont in containers:
            inns = ", ".join(cont.inns) if cont.inns else "ИНН не найден"
            print(f" • {cont.display_name()} | {inns} | Subject: {cont.subject}")
        sys.exit(1)

    print("=" * 80)
    print(" Авторизация в СБИС")
    print(f"Контейнер: {container.display_name()}")
    print(f"Subject : {container.subject}")
    print("=" * 80)

    try:
        cert_b64 = export_cert_base64(container.name)
        cert_bytes = base64.b64decode(cert_b64)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as cert_file:
            cert_file.write(cert_bytes)
            cert_path = cert_file.name
        thumbprint = get_thumbprint(container.name)
        encrypted_key = request_session(auth_url, cert_b64)
        try:
    	    session_id = decrypt_data(encrypted_key, container.name, thumbprint, cert_path)
        finally:
            if os.path.exists(cert_path):
                os.remove(cert_path)
    except Exception as exc:
        print(f"\n Ошибка на этапе авторизации: {exc}")
        sys.exit(1)

    print(" Авторизация успешна. Сессионный ключ получен.")
    print(f"SessionID (первые 20 символов): {session_id[:20]}...\n")

    # Тянем «почту»
    try:
        result = fetch_incoming_documents(service_url, session_id, args.days)
    except Exception as exc:
        print(f" Ошибка при обращении к СБИС: {exc}")
        sys.exit(1)

    if args.dump:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    focus_inns = set(container.inns)
    pretty_print_mail(result, focus_inns=focus_inns)


if __name__ == "__main__":
    main()
