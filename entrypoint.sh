#!/bin/sh

# Ожидание доступности базы данных
echo "Waiting for postgres..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL started"

# Применение миграций базы данных
echo "Applying database migrations..."
python manage.py migrate

# Запуск Gunicorn сервера
echo "Starting Gunicorn..."
exec gunicorn tax_service.wsgi:application --bind 0.0.0.0:8000 --workers 4
