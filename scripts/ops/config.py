# -*- coding: utf-8 -*-

# Полный псевдоним ключевого контейнера, который понимает certmgr.
CRYPTO_PRO_CONTAINER_NAME = r'\\.\\HDIMAGE\\77fd6caf-4298-447a-872c-994f9a63a5c2 копия'

# ФИО владельца сертификата (для информации)
CERTIFICATE_FIO = 'ПАТЕНКОВА'

import os
from typing import List

# СБИС настройки
SBIS_AUTH_URL = "https://online.sbis.ru/auth/service/"
SBIS_SERVICE_URL = "https://online.sbis.ru/service/?srv=1&protocol=4"

# FNS фильтрация
FNS_INN_PREFIXES = ["770", "771", "772", "773", "774", "775", "7718", "7736"]
FNS_KEYWORDS = [
    "ФНС", "налоговая", "сверка", "требование",
    "уведомление", "инспекция", "ИФНС", "фнс", "акт сверки"
]

# Период проверки документов (дни)
DOCUMENTS_PERIOD_DAYS = 3600

# Контейнеры сертификатов
CRYPTO_PRO_CONTAINER_NAME = r'\\.\HDIMAGE\77fd6caf-4298-447a-872c-994f9a63a5c2 копия'
CRYPTO_CONTAINERS = {
    '7715600802': r'\\.\HDIMAGE\77fd6caf-4298-447a-872c-994f9a63a5c2 копия',
}
