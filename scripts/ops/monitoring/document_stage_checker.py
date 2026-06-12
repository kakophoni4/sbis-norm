# -*- coding: utf-8 -*-
import requests
import base64
import os
import json
import uuid
import copy
import argparse
from datetime import datetime

# Импортируем модули из основного проекта
from crypto_session_decryptor import CryptoSessionDecryptor
import config

# --- Конфигурация ---
SBIS_AUTH_URL = config.SBIS_AUTH_URL
SBIS_SERVICE_URL = config.SBIS_SERVICE_URL
CERT_AUTH_PATH = config.CERT_AUTH_PATH

def hide_binary_data_in_dict(data):
    """Рекурсивно скрывает большие двоичные данные в словарях/списках для логирования."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "ДвоичныеДанные" and isinstance(value, str) and len(value) > 100:
                data[key] = f"<двоичные данные скрыты, длина: {len(value)}>";
            else:
                hide_binary_data_in_dict(value);
    elif isinstance(data, list):
        for item in data:
            hide_binary_data_in_dict(item);
    return data

class SabyAPIClient:
    """
    Класс для взаимодействия с API СБИС.
    Скопирован из 31.py для сохранения независимости скриптов.
    """
    def __init__(self, auth_url=SBIS_AUTH_URL, service_url=SBIS_SERVICE_URL, proxy=None, user_agent=None):
        self.auth_url = auth_url
        self.service_url = service_url
        self.proxy = proxy
        self.user_agent = user_agent if user_agent else "DocStageChecker/1.0"
        self.session_id = None
        self.request_id = 0

    def _make_request(self, url, method, params):
        self.request_id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self.request_id}
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        if self.user_agent:
            headers['User-Agent'] = self.user_agent
        if self.session_id:
            headers['X-SBISSessionID'] = self.session_id
        
        print(f"\n======= Запрос {method} =======")
        log_payload = hide_binary_data_in_dict(copy.deepcopy(payload))
        print(f"Тело запроса:\n{json.dumps(log_payload, indent=2, ensure_ascii=False)}")
        
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
        try:
            response = requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=60)
            response.raise_for_status()
            response_data = response.json()
        except requests.RequestException as e:
            print(f"Критическая ошибка запроса: {e}")
            return None

        print(f"\n======= Ответ =======")
        log_response_data = hide_binary_data_in_dict(copy.deepcopy(response_data))
        print(f"Тело ответа:\n{json.dumps(log_response_data, indent=2, ensure_ascii=False)}")

        if "error" in response_data:
            print(f"Ошибка API: {response_data['error']}")
            return None
        return response_data.get("result")

    def connect_by_cert(self, cert_path, cert_fio_for_decrypt):
        print("\n--- Этап 1: Аутентификация по сертификату ---")
        if not os.path.exists(cert_path):
            print(f"Ошибка: Файл сертификата не найден: {cert_path}")
            return False
        with open(cert_path, "rb") as f:
            cert_data_base64 = base64.b64encode(f.read()).decode('utf-8')
        
        auth_params = {"Сертификат": {"ДвоичныеДанные": cert_data_base64}}
        encrypted_key = self._make_request(self.auth_url, "СБИС.АутентифицироватьПоСертификату", auth_params)
        
        if not encrypted_key:
            print("Не удалось получить зашифрованный ключ сессии.")
            return False
            
        print("\nЗашифрованный ключ сессии получен. Расшифровываем...")
        decryptor = CryptoSessionDecryptor(certificate_fio=cert_fio_for_decrypt)
        session_id = decryptor.decrypt(encrypted_key)
        
        if session_id:
            self.session_id = session_id
            print(f"Авторизация успешна. Session ID: {self.session_id}")
            return True
        else:
            print("Не удалось расшифровать ключ сессии.")
            return False

    def get_document_history(self, document_id):
        """Получает историю событий (этапов) для документа."""
        print(f"\n--- Запрос истории для документа ID: {document_id} ---")
        params = {
            "Фильтр": {
                "ИдентификаторДокумента": document_id,
                "ДопПоля": "СписокПоДокументу"
            },
            "Навигация": {
                "РазмерСтраницы": "50" # Запрашиваем до 50 событий
            }
        }
        result = self._make_request(self.service_url, "СБИС.СписокИзменений", params)
        return result

def main():
    parser = argparse.ArgumentParser(description="Скрипт для проверки этапов прохождения документа в СБИС.")
    parser.add_argument("document_id", help="Идентификатор документа (или комплекта) для проверки.")
    args = parser.parse_args()

    document_id = args.document_id
    signer_fio_for_search = config.SIGNER_FIO_FOR_SEARCH

    print(f"=== ПРОВЕРКА ЭТАПОВ ДОКУМЕНТА ID: {document_id} ===")

    client = SabyAPIClient()

    # Этап 1: Авторизация
    if not client.connect_by_cert(CERT_AUTH_PATH, signer_fio_for_search):
        print("Ошибка авторизации по сертификату! Выполнение прервано.")
        return

    # Этап 2: Запрос истории
    history = client.get_document_history(document_id)

    if history and history.get('Документ'):
        print(f"\n\n--- ИСТОРИЯ СОБЫТИЙ ДЛЯ ДОКУМЕНТА {document_id} ---")
        # События могут быть вложены в разные документы внутри одного комплекта
        all_events = []
        for doc in history['Документ']:
            if 'Событие' in doc and doc['Событие']:
                all_events.extend(doc['Событие'])
        
        # Сортируем все события по времени
        sorted_events = sorted(all_events, key=lambda x: datetime.strptime(x['ДатаВремя'], '%d.%m.%Y %H.%M.%S'))

        if not sorted_events:
            print("Для данного документа не найдено событий.")
            return

        for event in sorted_events:
            event_time = event.get('ДатаВремя', 'Нет данных')
            event_name = event.get('Название', 'Без названия')
            event_comment = event.get('Комментарий', '')
            print(f"[{event_time}] -> {event_name}")
            if event_comment:
                print(f"    Комментарий: {event_comment}")
        print("-------------------------------------------------")

    else:
        print("\nНе удалось получить историю документа или история пуста.")

if __name__ == "__main__":
    main()
