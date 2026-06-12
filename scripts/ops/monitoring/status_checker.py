# -*- coding: utf-8 -*-
import json
import time
import requests
import os
from datetime import datetime

# --- Константы ---
STATUS_FILE = 'status_links.json'
LOG_FILE = 'status_checker.log'
CHECK_INTERVALS_MINUTES = [1, 15] # Интервалы проверки в минутах

def log_message(message):
    """Записывает сообщение в лог-файл и выводит в консоль."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_string = f"[{timestamp}] {message}"
    print(log_string)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_string + '\n')

def get_links_from_status_file():
    """Читает файл статуса и извлекает из него ссылки для проверки."""
    if not os.path.exists(STATUS_FILE):
        log_message(f"Ошибка: Файл статуса '{STATUS_FILE}' не найден.")
        return None, None

    with open(STATUS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    doc_id = data.get('Идентификатор')
    links_to_check = {
        "Кабинет (отправитель)": data.get('СсылкаДляНашаОрганизация'),
    }
    
    # Добавляем ссылки на вложения, если они есть
    attachments = data.get('Вложение', [])
    if attachments:
        links_to_check['HTML-версия'] = attachments[0].get('СсылкаНаHTML')
        links_to_check['PDF-версия'] = attachments[0].get('СсылкаНаPDF')

    # Убираем пустые ссылки
    links_to_check = {name: url for name, url in links_to_check.items() if url}

    if not links_to_check:
        log_message("В файле статуса не найдено ссылок для проверки.")
        return doc_id, None

    return doc_id, links_to_check

def check_link(name, url):
    """Выполняет GET-запрос по URL и логирует результат."""
    try:
        log_message(f"Проверяем ссылку '{name}'...")
        response = requests.get(url, timeout=30)
        log_message(f"-> Статус-код: {response.status_code}")
        # Простая проверка на наличие в ответе слов о готовности
        if "готовится" in response.text or "обрабатывается" in response.text:
            log_message(f"ПРЕДУПРЕЖДЕНИЕ: Ответ по ссылке '{name}' все еще содержит статус 'в обработке'.")
        else:
            log_message(f"SUCCESS: Ответ по ссылке '{name}' выглядит корректно.")

    except requests.RequestException as e:
        log_message(f"ОШИБКА при проверке ссылки '{name}': {e}")

def main():
    """Основная функция скрипта."""
    log_message("--- Запуск скрипта проверки статуса отчета ---")
    
    doc_id, links = get_links_from_status_file()
    if not links:
        log_message("Работа скрипта завершена из-за отсутствия ссылок.")
        return

    log_message(f"Найдены ссылки для документа с ID: {doc_id}")
    for name, url in links.items():
        log_message(f"- {name}: {url}")

    last_check_time = 0
    for interval in CHECK_INTERVALS_MINUTES:
        sleep_duration_seconds = (interval * 60) - last_check_time
        if sleep_duration_seconds > 0:
            log_message(f"Следующая проверка через {int(sleep_duration_seconds / 60)} мин. ({sleep_duration_seconds} сек)...")
            time.sleep(sleep_duration_seconds)
        
        log_message(f"--- Начинается проверка (интервал {interval} мин) ---")
        for name, url in links.items():
            check_link(name, url)
        
        last_check_time = interval * 60

    log_message("--- Все проверки завершены ---")

if __name__ == "__main__":
    main()
