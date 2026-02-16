# -*- coding: utf-8 -*-
import requests
import base64
import os
import json
import uuid
import copy
from datetime import datetime
from django.conf import settings

# Вспомогательная функция для скрытия больших двоичных данных в логах
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
    Адаптирован для использования внутри Django-проекта.
    """
    def __init__(self, proxy=None, user_agent=None):
        self.auth_url = settings.SBIS_AUTH_URL
        self.service_url = settings.SBIS_SERVICE_URL
        self.proxy = proxy
        self.user_agent = user_agent if user_agent else "DjangoSbisClient/1.0"
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
        
        # В реальном проекте здесь должно быть логирование, а не print
        # print(f"\n======= Запрос {method} =======")
        # log_payload = hide_binary_data_in_dict(copy.deepcopy(payload))
        # print(f"Тело запроса:\n{json.dumps(log_payload, indent=2, ensure_ascii=False)}")
        
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
        try:
            response = requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=60)
            response.raise_for_status()
            response_data = response.json()
        except requests.RequestException as e:
            # print(f"Критическая ошибка запроса: {e}")
            # В реальном проекте здесь нужно возбуждать исключение
            raise e

        if "error" in response_data:
            # print(f"Ошибка API: {response_data['error']}")
            raise Exception(f"Ошибка API СБИС: {response_data['error']}")
            
        return response_data.get("result")

    def connect_by_cert(self, cert_path, cert_fio_for_decrypt):
        """
        ВНИМАНИЕ: Этот метод зависит от Windows CryptoAPI через скрипты
        crypto_session_decryptor.py и crypto_cert_finder.py.
        Он не будет работать в Linux-контейнере.
        Для его работы требуется отдельный Windows-воркер.
        """
        # Динамический импорт, чтобы избежать падения в Linux-среде
        from бизнес.crypto_session_decryptor import CryptoSessionDecryptor

        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Файл сертификата не найден: {cert_path}")
            
        with open(cert_path, "rb") as f:
            cert_data_base64 = base64.b64encode(f.read()).decode('utf-8')
        
        auth_params = {"Сертификат": {"ДвоичныеДанные": cert_data_base64}}
        encrypted_key = self._make_request(self.auth_url, "СБИС.АутентифицироватьПоСертификату", auth_params)
        
        if not encrypted_key:
            raise ConnectionError("Не удалось получить зашифрованный ключ сессии от СБИС.")
            
        decryptor = CryptoSessionDecryptor(certificate_fio=cert_fio_for_decrypt)
        session_id = decryptor.decrypt(encrypted_key)
        
        if session_id:
            self.session_id = session_id
            return True
        else:
            raise ConnectionError("Не удалось расшифровать ключ сессии.")

    def upload_report_komplekt(self, document_model):
        """
        Создает комплект отчетности на основе модели Document из Django.
        """
        attachments = []
        for file_rel_path in document_model.files:
            file_abs_path = os.path.join(settings.MEDIA_ROOT, file_rel_path)
            with open(file_abs_path, "rb") as f:
                content_base64 = base64.b64encode(f.read()).decode('utf-8')
            
            file_name = os.path.basename(file_abs_path)
            attachment_id = str(uuid.uuid4()).replace('-', '')
            
            attachment = {
                "Идентификатор": attachment_id,
                "Название": document_model.report_type.name,
                "Категория": "Основное",
                "ПодТип": document_model.report_type.code,
                "Направление": "Исходящий",
                "ВерсияФормата": document_model.report_type.format_version,
                "Файл": {"Имя": file_name, "ДвоичныеДанные": content_base64}
            }
            attachments.append(attachment)

        if not attachments:
            raise ValueError("Нет файлов для создания комплекта.")

        komplekt_params = {
            "Документ": [{
                "Идентификатор": str(document_model.id),
                "Примечание": document_model.theme,
                "Тип": "ОтчетФНС",
                "ПодТип": document_model.report_type.code,
                "ДатаВремяСоздания": document_model.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "НашаОрганизация": {
                    "СвЮЛ": {
                        "ИНН": document_model.organization.inn, 
                        "КПП": document_model.organization.kpp, 
                        "Название": document_model.organization.name
                    }
                },
                "Участники": {
                    "Отправитель": {"СвЮЛ": {"ИНН": document_model.organization.inn, "КПП": document_model.organization.kpp}},
                    "Получатель": {"ГосударственнаяИнспекция": document_model.recipient.code},
                },
                "Вложение": attachments,
                # "Сертификат": {"Отпечаток": thumbprint}, # Отпечаток нужно будет получить и передать отдельно
                "Сведения": document_model.svedeniya
            }]
        }
        
        result = self._make_request(self.service_url, "СБИС.ЗаписатьКомплект", komplekt_params)
        
        if result and isinstance(result, list) and len(result) > 0 and "Идентификатор" in result[0]:
            doc_id = result[0]["Идентификатор"]
            return doc_id
        else:
            raise Exception("Ошибка создания комплекта отчетности в СБИС.")

    def get_document_history(self, document_id):
        """Получает историю событий (этапов) для документа."""
        params = {
            "Фильтр": {
                "ИдентификаторДокумента": document_id,
                "ДопПоля": "СписокПоДокументу"
            },
            "Навигация": {"РазмерСтраницы": "50"}
        }
        result = self._make_request(self.service_url, "СБИС.СписокИзменений", params)
        return result
