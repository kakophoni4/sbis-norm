# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import os
import sys
import base64
import tempfile
import subprocess
import re
from datetime import datetime, timedelta
from app.config import settings

# Добавляем путь для импорта модулей авторизации по сертификату
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_utils_linux import decrypt_data
from config import CRYPTO_PRO_CONTAINER_NAME

# ============= ФУНКЦИИ ДЛЯ РАБОТЫ С СЕРТИФИКАТОМ =============

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

async def get_encrypted_session_key(session, cert_b64):
    """Получает зашифрованный ключ от СБИС (асинхронная версия)."""
    payload = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
        "id": 1
    }
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    print("\n[*] Отправка запроса на аутентификацию в СБИС...")

    async with session.post(settings.SBIS_AUTH_URL, json=payload, headers=headers) as resp:
        response_data = await resp.json()
        if "error" in response_data:
            raise Exception(response_data['error'])
        print("[+] Зашифрованный ключ сессии успешно получен.")
        return response_data.get("result")

# ============= МОДИФИЦИРОВАННАЯ ФУНКЦИЯ АВТОРИЗАЦИИ =============

async def get_session_id_by_certificate(session):
    """Авторизация по сертификату вместо логина/пароля."""
    print("="*50)
    print("Запуск процесса получения сессии СБИС по сертификату...")
    print(f"Используемый контейнер: {CRYPTO_PRO_CONTAINER_NAME}")
    print("="*50)

    # Получаем публичный сертификат
    public_cert_b64 = get_public_cert_b64(CRYPTO_PRO_CONTAINER_NAME)
    if not public_cert_b64:
        print("❌ Не удалось получить сертификат")
        return None

    # Получаем зашифрованный ключ от СБИС
    encrypted_key = await get_encrypted_session_key(session, public_cert_b64)
    if not encrypted_key:
        print("❌ Не удалось получить зашифрованный ключ")
        return None

    # Получаем thumbprint для расшифровки
    thumb = get_thumbprint(CRYPTO_PRO_CONTAINER_NAME)
    if not thumb:
        print("❌ Не удалось получить thumbprint")
        return None

    # Расшифровываем ключ сессии
    print("\n[*] Расшифровка ключа сессии...")
    session_id = decrypt_data(encrypted_key, CRYPTO_PRO_CONTAINER_NAME, thumb)

    if session_id:
        print("\n" + "=" * 50)
        print("✅ УСПЕШНО!")
        print(f"Сессия: {session_id[:10]}...")
        print("=" * 50)
        return session_id
    else:
        print("\n❌ Не удалось расшифровать ключ сессии")
        return None

# ============= ФУНКЦИИ ДЛЯ РАБОТЫ С ДОКУМЕНТАМИ (БЕЗ ИЗМЕНЕНИЙ) =============

async def get_fns_documents(session, session_id, days_back=7):
    """Получение документов от ФНС."""
    if not session_id:
        return

    date_to = datetime.now().strftime("%d.%m.%Y")
    date_from = (datetime.now() - timedelta(days=days_back)).strftime("%d.%m.%Y")

    docs_data = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументовПоСобытиям",
        "params": {
            "Фильтр": {"ДатаС": date_from, "ДатаПо": date_to, "ТипРеестра": "Входящие"}
        },
        "id": 1
    }

    headers = {"X-SBISSessionID": session_id}

    async with session.post("https://online.sbis.ru/service/?srv=1&protocol=4", 
                           json=docs_data, headers=headers) as resp:
        result = await resp.json()

        if "result" in result and "Реестр" in result["result"]:
            print(f"\n📧 Документы найдены за период {date_from} - {date_to}")
            print("-" * 50)

            fns_docs_found = False
            for doc in result["result"]["Реестр"]:
                document = doc.get("Документ", {})
                kontragent = document.get("Контрагент", {})

                # Извлекаем ИНН
                inn = None
                if "СвЮЛ" in kontragent and "ИНН" in kontragent["СвЮЛ"]:
                    inn = kontragent["СвЮЛ"]["ИНН"]
                elif "СвФЛ" in kontragent and "ИНН" in kontragent["СвФЛ"]:
                    inn = kontragent["СвФЛ"]["ИНН"]

                # Проверяем, является ли документ от ФНС
                title = document.get("Название", "").lower()
                keywords = ["фнс", "налоговая", "сверка", "требование"]
                is_fns = (inn and inn.startswith("77")) or any(keyword in title for keyword in keywords)

                if is_fns:
                    fns_docs_found = True
                    attachments = document.get("Вложение", [])

                    print(f"📋 Документ от ФНС:")
                    print(f"   Дата: {document.get('Дата', 'N/A')}")
                    print(f"   Тема: {document.get('Название', 'N/A')}")
                    print(f"   Отправитель (ИНН): {inn or 'N/A'}")

                    if attachments:
                        print(f"   Название файла: {attachments[0].get('Название', 'N/A')}")
                        print("   Присутствует вложение: ✅ Да")
                    else:
                        print("   Присутствует вложение: ❌ Нет")
                    print("-" * 50)

            if not fns_docs_found:
                print("ℹ️ Документов от ФНС за указанный период не найдено")
        else:
            print("ℹ️ Нет документов в ответе")

# ============= ГЛАВНАЯ ФУНКЦИЯ =============

async def main(days_back=7):
    """Главная функция - теперь с авторизацией по сертификату."""
    async with aiohttp.ClientSession() as session:
        # Используем авторизацию по сертификату вместо логина/пароля
        session_id = await get_session_id_by_certificate(session)

        if session_id:
            await get_fns_documents(session, session_id, days_back)
        else:
            print("❌ Не удалось авторизоваться по сертификату")

# ============= ДОПОЛНИТЕЛЬНЫЕ ТЕСТОВЫЕ ФУНКЦИИ =============

async def test_list_changes_with_cert(days_back=7):
    """Тестовая функция для проверки различных методов API с сертификатной авторизацией."""
    async with aiohttp.ClientSession() as session:
        session_id = await get_session_id_by_certificate(session)

        if not session_id:
            print("❌ Не удалось авторизоваться по сертификату")
            return

        # Здесь можно вызвать любые тестовые функции из оригинального скрипта
        # Например:
        date_to = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        date_from = (datetime.now() - timedelta(days=days_back)).strftime("%d.%m.%Y %H:%M:%S")

        request_data = {
            "jsonrpc": "2.0",
            "method": "СБИС.СписокИзменений",
            "params": {
                "Фильтр": {
                    "ДатаВремяС": date_from,
                    "ДатаВремяПо": date_to,
                    "Направление": "Входящий"
                }
            },
            "id": 1
        }

        headers = {"X-SBISSessionID": session_id}
        print(f"\n🔍 Тестовый запрос с сертификатной авторизацией: {date_from} - {date_to}")

        async with session.post(settings.SBIS_SERVICE_URL, json=request_data, headers=headers) as resp:
            result = await resp.json()
            print(f"Статус: {resp.status}")
            if "result" in result:
                print("✅ Запрос успешно выполнен с сертификатной авторизацией")
            elif "error" in result:
                print(f"❌ Ошибка: {result['error']}")

# ============= ТОЧКА ВХОДА =============

if __name__ == "__main__":
    # Основной запуск - получение документов за последние 7 дней
    asyncio.run(main(days_back=7))

    # Или можно запустить тестовую функцию:
    # asyncio.run(test_list_changes_with_cert(days_back=3))
