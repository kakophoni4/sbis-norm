# -*- coding: utf-8 -*-
import requests
import base64
import os
import json
import uuid
import copy
from datetime import datetime

# Импортируем наши модули
from crypto_session_decryptor import CryptoSessionDecryptor
from crypto_cert_finder import get_thumbprint_by_fio
import config # Импортируем наш новый модуль конфигурации

# --- Конфигурация ---
# Все значения теперь загружаются из config.py, который читает .env
SBIS_AUTH_URL = config.SBIS_AUTH_URL
SBIS_SERVICE_URL = config.SBIS_SERVICE_URL
TEST_REPORTS_DIR = config.TEST_REPORTS_DIR
CERT_AUTH_PATH = config.CERT_AUTH_PATH


def hide_binary_data_in_dict(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "ДвоичныеДанные" and isinstance(value, str):
                data[key] = f"<двоичные данные скрыты, длина: {len(value)}>"
            else:
                hide_binary_data_in_dict(value)
    elif isinstance(data, list):
        for item in data:
            hide_binary_data_in_dict(item)
    return data


def create_test_files():
    if not os.path.exists(TEST_REPORTS_DIR):
        os.makedirs(TEST_REPORTS_DIR)
    file_paths = [
        os.path.join(TEST_REPORTS_DIR, f)
        for f in os.listdir(TEST_REPORTS_DIR)
        if os.path.isfile(os.path.join(TEST_REPORTS_DIR, f)) and not f.endswith('.p7s')
    ]
    print(f"Найдены файлы для отправки в '{TEST_REPORTS_DIR}': {len(file_paths)} шт.")
    return file_paths


class SabyAPIClient:
    def __init__(self, auth_url=SBIS_AUTH_URL, service_url=SBIS_SERVICE_URL, proxy=None, user_agent=None):
        self.auth_url = auth_url
        self.service_url = service_url
        self.proxy = proxy
        self.user_agent = user_agent
        self.session_id = None
        self.request_id = 0
        self.cert_thumbprint = None

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
            response = requests.post(url, json=payload, headers=headers, proxies=proxies)
            response_data = response.json()
        except Exception as e:
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

    def upload_report_komplekt(self, file_paths, sender_inn, sender_kpp, sender_name, tax_office_code, thumbprint,
                               billing_id, theme):
        print("\n--- Создание комплекта отчетности (НДС) ---")
        if not billing_id:
            print("Критическая ошибка: ИдентификаторБиллинга не предоставлен!")
            return None
        attachments = []
        for file_path in file_paths:
            with open(file_path, "rb") as f:
                content_base64 = base64.b64encode(f.read()).decode('utf-8')
            file_name = os.path.basename(file_path)
            attachment_id = str(uuid.uuid4()).replace('-', '')
            attachment = {
                "Идентификатор": attachment_id,
                "Название": "Налоговая декларация по налогу на добавленную стоимость",
                "Категория": "Основное",
                "ПодТип": "1151001",
                "Направление": "Исходящий",
                "ВерсияФормата": "5.11",
                "ПодВерсияФормата": "",
                "Файл": {"Имя": file_name, "ДвоичныеДанные": content_base64}
            }
            attachments.append(attachment)
        if not attachments: return None
        document_id = str(uuid.uuid4())
        komplekt_params = {
            "Документ": [{
                "Идентификатор": document_id,
                "Примечание": theme,
                "Тип": "ОтчетФНС",
                "ПодТип": "1151001",
                "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "НашаОрганизация": {

                    "СвЮЛ": {"ИНН": sender_inn, "КПП": sender_kpp, "Название": sender_name,
                             "НазваниеПолное": sender_name}
                },
                "Участники": {
                    "Отправитель": {
                                    "СвЮЛ": {"ИНН": sender_inn, "КПП": sender_kpp, "Название": sender_name}},
                    "Получатель": {"ГосударственнаяИнспекция": tax_office_code},
                    "КонечныйПолучатель": {"ГосударственнаяИнспекция": tax_office_code}
                },
                "Вложение": attachments,
                "Сертификат": {"Отпечаток": thumbprint, "Ключ": {"Тип": "Клиентский"}},
                "Сведения": {
                    "Описание": {
                        "ВидДокумента": "первичный",
                        "ИмяФормы": "Налоговая декларация по налогу на добавленную стоимость",
                        "КНДФормы": "1151001",
                        "КолФайл": str(len(attachments)),
                        "НОПоМестуНахождения": tax_office_code,
                        "НОПоМестуУчета": tax_office_code,
                        "УполномоченнаяБухгалтерия": "false",
                        "Период": [
                            {"Год": "2025", "ИдентификаторВложения": attachments[0]["Идентификатор"], "Код": "22"}]
                    },
                    "Пакет": {"ВерсПрог": "API Integration 1.0", "КодыОшибок": "0",
                              "ПрограммаФормированияОтчета": "Custom API Client"}
                }
            }]
        }
        result = self._make_request(self.service_url, "СБИС.ЗаписатьКомплект", komplekt_params)
        if result and isinstance(result, list) and len(result) > 0 and "Идентификатор" in result[0]:
            doc_id = result[0]["Идентификатор"]
            print(f"Комплект отчетности создан. ID: {doc_id}")
            return doc_id
        else:
            print("Ошибка создания комплекта отчетности.")
            return None

    def prepare_report_for_send(self, document_id, cert_fio, cert_position, cert_inn):
        print("\n--- Подготовка отчета к отправке ---")
        prepare_params = {
            "Документ": {"Идентификатор": document_id, "Этап": {"Действие": {
                "Название": "Отправить",
                "Сертификат": {"ФИО": cert_fio, "Должность": cert_position, "ИНН": cert_inn}
            }}}
        }
        result = self._make_request(self.service_url, "СБИС.ПодготовитьДействие", prepare_params)
        if not result: return None
        attachments_to_sign = []
        if "Этап" in result and result["Этап"]:
            for etapa in result["Этап"]:
                if "Вложение" in etapa:
                    for attachment in etapa["Вложение"]:
                        if attachment.get("Файл", {}).get("Хеш"):
                            attachments_to_sign.append({
                                "id": attachment["Идентификатор"], "name": attachment.get("Файл", {}).get("Имя"),
                                "hash": attachment.get("Файл", {}).get("Хеш")
                            })
        if not attachments_to_sign: return None
        print(f"Требуется подписать {len(attachments_to_sign)} вложений.")
        return attachments_to_sign

    def sign_report_files(self, attachments_to_sign, local_files_map):
        print("\n--- Поиск готовых подписей ---")
        signed_files = []
        for attachment in attachments_to_sign:
            file_name = attachment['name']
            original_file_path = local_files_map.get(file_name)
            if not original_file_path: continue
            signature_file_path = original_file_path + '.p7s'
            if not os.path.exists(signature_file_path):
                print(f"Критическая ошибка: файл подписи не найден по пути {signature_file_path}")
                return None
            with open(signature_file_path, "rb") as f:
                signature_bytes = f.read()
            signature_base64 = base64.b64encode(signature_bytes).decode('utf-8')
            signed_files.append({
                "attachment_id": attachment['id'], "signature_base64": signature_base64,
                "signature_filename": os.path.basename(signature_file_path)
            })
        print("Все подписи найдены.")
        return signed_files

    def send_report_to_fns(self, document_id, signed_files):
        print("\n--- Отправка отчета в ФНС ---")
        attachments_with_signatures = []
        for signed_file in signed_files:
            attachments_with_signatures.append({
                "Идентификатор": signed_file["attachment_id"],
                "Подпись": [{"Файл": {"ДвоичныеДанные": signed_file["signature_base64"],
                                      "Имя": signed_file["signature_filename"]}}]
            })
        send_params = {
            "Документ": {"Идентификатор": document_id, "Этап": [{
                "Действие": [{"Название": "Отправить", "Сертификат": [{"Отпечаток": self.cert_thumbprint}]}],
                "Вложение": attachments_with_signatures
            }]}
        }
        send_result = self._make_request(self.service_url, "СБИС.ВыполнитьДействие", send_params)
        if send_result:
            print("Отчет успешно отправлен в ФНС!")
            status_info = self.get_document_status(document_id)
            if status_info:
                print("\n--- Ссылки для просмотра статуса и документа ---")
                if "СсылкаДляНашаОрганизация" in status_info:
                    print(f"Ссылка на просмотр в кабинете (для отправителя): {status_info['СсылкаДляНашаОрганизация']}")
                if "Событие" in status_info and status_info["Событие"]:
                    for event in status_info["Событие"]:
                        if "Вложение" in event and event["Вложение"]:
                            for attach in event["Вложение"]:
                                if "СсылкаНаHTML" in attach:
                                    print(f"Ссылка на HTML-версию: {attach['СсылкаНаHTML']}")
                                if "СсылкаНаPDF" in attach:
                                    print(f"Ссылка на PDF-версию: {attach['СсылкаНаPDF']}")
                if "Состояние" in status_info:
                    print(f"Текущий статус: {status_info['Состояние']['Название']}")
                with open("status_links.json", "w", encoding="utf-8") as f:
                    json.dump(status_info, f, ensure_ascii=False, indent=2)
                print("Ссылки и статус сохранены в status_links.json")
            return True
        else:
            print(f"Ошибка отправки отчета в ФНС с ID {document_id}.")
            return False

    def get_document_status(self, document_id):
        print(f"\n--- Запрос статуса документа ID: {document_id} ---")
        status_params = {
            "Документ": {"Идентификатор": document_id}
        }
        result = self._make_request(self.service_url, "СБИС.ПрочитатьДокумент", status_params)
        if result:
            print("Статус получен успешно.")
            return result
        else:
            print("Ошибка получения статуса.")
            return None


def main():
    # --- Константы для сценария (теперь из config.py) ---
    sender_inn = config.SENDER_INN
    sender_kpp = config.SENDER_KPP
    sender_name = config.SENDER_NAME
    sender_billing_id = config.SENDER_BILLING_ID
    tax_office_code = config.TAX_OFFICE_CODE
    signer_fio = config.SIGNER_FIO
    signer_fio_for_search = config.SIGNER_FIO_FOR_SEARCH
    signer_position = config.SIGNER_POSITION
    signer_inn = config.SIGNER_INN
    email_theme = config.EMAIL_THEME

    client = SabyAPIClient(user_agent="NDS_Report_Sender/1.0")

    print("=== ОТПРАВКА ДЕКЛАРАЦИИ ПО НДС В ФНС (ЧЕРЕЗ СЕРТИФИКАТ) ===")

    # Этап 1: Авторизация по сертификату
    if not client.connect_by_cert(CERT_AUTH_PATH, signer_fio_for_search):
        print("Ошибка авторизации по сертификату!")
        return

    # Этап 2: Получение отпечатка сертификата
    print("\n--- Этап 2: Получение отпечатка сертификата ---")
    thumbprint = get_thumbprint_by_fio(signer_fio_for_search)
    if not thumbprint:
        print(f"Не удалось получить отпечаток для '{signer_fio_for_search}'!")
        return
    print(f"Отпечаток сертификата для отправки: {thumbprint}")
    client.cert_thumbprint = thumbprint # Сразу сохраняем в клиент

    # Этап 3: Подготовка файлов
    print("\n--- Этап 3: Подготовка файлов ---")
    test_files = create_test_files()
    if not test_files:
        print("Нет файлов для отправки!")
        return
    local_files_map = {os.path.basename(f): f for f in test_files}

    # Этап 4: Создание комплекта отчетности
    document_id = client.upload_report_komplekt(
        file_paths=test_files, sender_inn=sender_inn, sender_kpp=sender_kpp,
        sender_name=sender_name, tax_office_code=tax_office_code,
        thumbprint=thumbprint, billing_id=sender_billing_id, theme=email_theme
    )
    if not document_id:
        print("Ошибка создания комплекта!")
        return

    # Этап 5: Подготовка к отправке
    attachments_to_sign = client.prepare_report_for_send(
        document_id=document_id, cert_fio=signer_fio,
        cert_position=signer_position, cert_inn=signer_inn
    )
    if not attachments_to_sign:
        print("Ошибка подготовки к отправке!")
        return

    # Этап 6: Поиск готовых подписей
    signed_files = client.sign_report_files(attachments_to_sign, local_files_map)
    if not signed_files:
        print("Ошибка подписания!")
        return

    # Этап 7: Отправка в ФНС
    success = client.send_report_to_fns(document_id=document_id, signed_files=signed_files)

    if success:
        print("\n УСПЕХ! Декларация по НДС отправлена в ФНС!")
    else:
        print("\n ОШИБКА! Не удалось отправить декларацию.")


if __name__ == "__main__":
    main()