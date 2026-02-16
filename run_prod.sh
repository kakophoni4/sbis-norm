#!/bin/bash

# Скрипт для запуска проекта в продакшен-режиме
# Убедитесь, что у вас есть права на выполнение: chmod +x run_prod.sh

echo "--- Запуск миграций базы данных ---"
python manage.py migrate --noinput

echo "--- Сбор статических файлов ---"
# Отвечаем 'yes' на вопрос о перезаписи существующих файлов
python manage.py collectstatic --noinput

echo "--- Запуск Celery воркера в фоновом режиме ---"
# Запускаем Celery как демон (в фоне)
# Убедитесь, что Redis запущен
celery -A tax_service worker --loglevel=info --detach

echo "--- Запуск Gunicorn веб-сервера ---"
# Запускаем Gunicorn с использованием файла конфигурации
# Он будет работать в текущем окне терминала.
# Для запуска в фоне используйте 'gunicorn -c gunicorn_config.py tax_service.wsgi:application &'
# или настройте systemd сервис.
gunicorn -c gunicorn_config.py tax_service.wsgi:application
