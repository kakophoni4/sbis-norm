# -*- coding: utf-8 -*-
import os
import sys
import base64
import tempfile
import subprocess
import asyncio
import aiohttp
import json
import re
from datetime import datetime, timedelta

# Добавляем путь для локальных импортов
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_utils_linux import decrypt_data
from config import (
    CRYPTO_PRO_CONTAINER_NAME,
    SBIS_AUTH_URL,
    SBIS_SERVICE_URL,
    FNS_INN_PREFIXES,
    FNS_KEYWORDS,
    DOCUMENTS_PERIOD_DAYS
)


class SBISCertAuth:
    """Класс для авторизации в СБИС по сертификату"""

    def __init__(self, container_name):
        self.container_name = container_name
        self.session_id = None
        self.thumbprint = None

    def get_public_cert_b64(self):
        """Извлекает сертификат из контейнера"""
        print(f"[*] Извлечение сертификата из контейнера '{self.container_name}'...")
        cert_file_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".cer") as cert_file:
                cert_file_path = cert_file.name

            command = [
                '/opt/cprocsp/bin/amd64/certmgr',
                '-export',
                '-cont', self.container_name,
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

    def get_thumbprint(self):
        """Получает SHA1 Thumbprint сертификата"""
        print(f"[*] Получение thumbprint из контейнера '{self.container_name}'...")
        command = [
            '/opt/cprocsp/bin/amd64/certmgr',
            '-list',
            '-cont', self.container_name
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Ошибка при получении thumbprint: {result.stderr}")
            return None

        match = re.search(r'SHA1 Thumbprint\s*:\s*([a-fA-F0-9]+)', result.stdout)
        if match:
            thumb = match.group(1).strip()
            print(f"[+] Thumbprint: {thumb}")
            self.thumbprint = thumb
            return thumb
        print("[!] Thumbprint не найден в выводе.")
        return None

    async def get_encrypted_session_key(self, session, cert_b64):
        """Получает зашифрованный ключ от СБИС"""
        payload = {
            "jsonrpc": "2.0",
            "method": "СБИС.АутентифицироватьПоСертификату",
            "params": {"Сертификат": {"ДвоичныеДанные": cert_b64}},
            "id": 1
        }
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        print("\n[*] Отправка запроса на аутентификацию в СБИС...")

        async with session.post(SBIS_AUTH_URL, json=payload, headers=headers, timeout=60) as response:
            response.raise_for_status()
            response_data = await response.json()
            if "error" in response_data:
                raise Exception(response_data['error'])
            print("[+] Зашифрованный ключ сессии успешно получен.")
            return response_data.get("result")

    async def authenticate(self, session):
        """Полный процесс авторизации"""
        print("="*50)
        print("Запуск процесса авторизации СБИС по сертификату...")
        print(f"Используемый контейнер: {self.container_name}")
        print("="*50)

        # Получаем сертификат
        public_cert_b64 = self.get_public_cert_b64()
        if not public_cert_b64:
            return None

        # Получаем thumbprint
        thumb = self.get_thumbprint()
        if not thumb:
            return None

        # Получаем зашифрованный ключ
        encrypted_key = await self.get_encrypted_session_key(session, public_cert_b64)
        if not encrypted_key:
            return None

        # Расшифровываем ключ
        print("\n[*] Расшифровка ключа сессии...")
        session_id = decrypt_data(encrypted_key, self.container_name, thumb)

        if session_id:
            print("\n" + "=" * 50)
            print(" АВТОРИЗАЦИЯ УСПЕШНА!")
            print(f"Session ID: {session_id[:20]}...")
            print("=" * 50)
            self.session_id = session_id
            return session_id
        else:
            print("\n Ошибка авторизации")
            return None


class SBISDocumentChecker:
    """Класс для проверки документов от ФНС"""

    def __init__(self, session_id):
        self.session_id = session_id

    async def get_fns_documents(self, session, days_back=7):
        """Получает и фильтрует документы от ФНС"""
        if not self.session_id:
            print(" Нет активной сессии")
            return []

        date_to = datetime.now().strftime("%d.%m.%Y")
        date_from = (datetime.now() - timedelta(days=days_back)).strftime("%d.%m.%Y")

        print(f"\n Проверка документов за период: {date_from} - {date_to}")

        # Запрос документов
        docs_data = {
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

        headers = {"X-SBISSessionID": self.session_id}

        async with session.post(SBIS_SERVICE_URL, json=docs_data, headers=headers) as resp:
            result = await resp.json()

            if "error" in result:
                print(f" Ошибка API: {result['error']}")
                return []

            fns_documents = []

            if "result" in result and "Реестр" in result["result"]:
                print(f"📋 Найдено документов: {len(result['result']['Реестр'])}")

                for doc in result["result"]["Реестр"]:
                    document = doc.get("Документ", {})
                    kontragent = document.get("Контрагент", {})

                    # Извлекаем ИНН
                    inn = None
                    if "СвЮЛ" in kontragent and "ИНН" in kontragent["СвЮЛ"]:
                        inn = kontragent["СвЮЛ"]["ИНН"]
                    elif "СвФЛ" in kontragent and "ИНН" in kontragent["СвФЛ"]:
                        inn = kontragent["СвФЛ"]["ИНН"]

                    # Проверяем название документа
                    title = document.get("Название", "").lower()

                    # Фильтруем документы от ФНС
                    is_fns = False
                    if inn:
                        for prefix in FNS_INN_PREFIXES:
                            if inn.startswith(prefix):
                                is_fns = True
                                break

                    if not is_fns:
                        for keyword in FNS_KEYWORDS:
                            if keyword.lower() in title:
                                is_fns = True
                                break

                    if is_fns:
                        fns_documents.append(document)
                        self.print_document_info(document, inn)
            else:
                print(" Нет документов в указанном периоде")

            return fns_documents

    def print_document_info(self, document, inn):
        """Выводит информацию о документе"""
        print("\n" + "="*50)
        print(" ДОКУМЕНТ ОТ ФНС:")
        print(f" Дата: {document.get('Дата', 'N/A')}")
        print(f" Тема: {document.get('Название', 'N/A')}")
        print(f" Отправитель (ИНН): {inn or 'N/A'}")

        attachments = document.get("Вложение", [])
        if attachments:
            print(f"📎 Вложения:")
            for att in attachments:
                print(f"   - {att.get('Название', 'N/A')}")
        else:
            print("📎 Вложения: Нет")

        print("="*50)

    async def get_documents_with_changes(self, session, days_back=7):
        """Альтернативный метод через СписокИзменений"""
        if not self.session_id:
            print(" Нет активной сессии")
            return []

        date_to = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        date_from = (datetime.now() - timedelta(days=days_back)).strftime("%d.%m.%Y %H:%M:%S")

        print(f"\n Проверка изменений за период: {date_from} - {date_to}")

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

        headers = {"X-SBISSessionID": self.session_id}

        async with session.post(SBIS_SERVICE_URL, json=request_data, headers=headers) as resp:
            result = await resp.json()

            if "error" in result:
                print(f" Ошибка API: {result['error']}")
                return []

            fns_documents = []

            if "result" in result and "Документ" in result["result"]:
                for doc in result["result"]["Документ"]:
                    kontragent = doc.get("Контрагент", {})
                    inn = None

                    if "СвЮЛ" in kontragent:
                        inn = kontragent["СвЮЛ"].get("ИНН", "")
                    elif "СвФЛ" in kontragent:
                        inn = kontragent["СвФЛ"].get("ИНН", "")

                    # Проверяем ИНН ФНС
                    if inn and any(inn.startswith(prefix) for prefix in FNS_INN_PREFIXES):
                        fns_documents.append(doc)
                        self.print_document_info(doc, inn)

            return fns_documents


async def main():
    """Главная функция"""
    async with aiohttp.ClientSession() as session:
        # Авторизация по сертификату
        auth = SBISCertAuth(CRYPTO_PRO_CONTAINER_NAME)
        session_id = await auth.authenticate(session)

        if not session_id:
            print(" Не удалось авторизоваться")
            return

        # Проверка документов
        checker = SBISDocumentChecker(session_id)

        # Используем основной метод
        print("\n" + "="*70)
        print(" ПРОВЕРКА ДОКУМЕНТОВ ОТ ФНС")
        print("="*70)

        fns_docs = await checker.get_fns_documents(session, days_back=DOCUMENTS_PERIOD_DAYS)

        if fns_docs:
            print(f"\n Найдено документов от ФНС: {len(fns_docs)}")
        else:
            print("\n Новых документов от ФНС не найдено")

        # Опционально: проверка через метод СписокИзменений
        # print("\n Дополнительная проверка через СписокИзменений...")
        # await checker.get_documents_with_changes(session, days_back=DOCUMENTS_PERIOD_DAYS)


if __name__ == "__main__":
    asyncio.run(main())
