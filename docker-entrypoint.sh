#!/bin/bash
set -e

echo "🔐 Инициализация CryptoPro..."

# 1. Создаём директорию для ключей, если её нет
mkdir -p /var/opt/cprocsp/keys/root

# 2. Устанавливаем правильные права на директорию CryptoPro
chmod 1777 /var/opt/cprocsp/keys
chmod 700 /var/opt/cprocsp/keys/root

# 3. Инициализируем CryptoPro (создаём служебные файлы)
echo "🔧 Инициализация CryptoPro CSP..."
/opt/cprocsp/sbin/amd64/cpconfig -license -set 00000-00000-00000-00000-00000 2>/dev/null || true
/opt/cprocsp/sbin/amd64/cpconfig -ini '\config\random' -add string '/dev/urandom' 2>/dev/null || true

# 4. Запускаем установку сертификатов
echo "🔐 Установка сертификатов CryptoPro..."
if [ -f /app/business_logic/install_certificates.py ]; then
    python3 /app/business_logic/install_certificates.py
else
    echo "⚠️ Скрипт install_certificates.py не найден!"
fi

# 5. Проверяем результат
echo ""
echo "📋 Проверка установленных контейнеров:"
/opt/cprocsp/bin/amd64/certmgr -list 2>&1 | head -50 || echo "⚠️ Контейнеры не найдены"

echo ""
echo "✅ Инициализация завершена"
echo ""

# Запускаем основную команду
exec "$@"
