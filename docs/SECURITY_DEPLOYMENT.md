# Безопасное развёртывание SBIS API

## Сетевая схема

В production Django не должен быть доступен напрямую. Единственная внешняя
точка для 1С — HTTPS Nginx:

```text
1С -> https://api.crmkanasha.org -> Nginx :443 -> 127.0.0.1:8000 -> Django
```

В `docker-compose.yml` PostgreSQL больше не имеет опубликованного порта, а
Gunicorn привязан только к `127.0.0.1:8000`. Контейнеры продолжают общаться
друг с другом по внутренней Docker-сети.

## Обязательные переменные `app.env`

```env
DEBUG=false
DJANGO_ALLOWED_HOSTS=api.crmkanasha.org,localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=https://api.crmkanasha.org
DJANGO_SECURE_SSL_REDIRECT=true
ONEC_API_TOKEN=<длинный-случайный-ключ>
```

Если `DEBUG=false`, но `DJANGO_ALLOWED_HOSTS` отсутствует, Django намеренно
не запускается. Это исключает случайный возврат к `ALLOWED_HOSTS = ['*']`.

## HTTPS Nginx

На `api.crmkanasha.org` разрешать только следующие маршруты:

- `POST /api/sbis/send-nds-extra-1c/`;
- `POST /api/sbis/send-report-1c/`;
- `POST /api/sbis/report-statuses-1c/`.

Остальные пути должны отвечать `404`. Проверка `X-1C-API-Token` остаётся в
Django и не зависит от Nginx.

## SSH и firewall

До запрета пароля создать обычного sudo-пользователя с ключом SSH, открыть
вторую сессию и проверить `sudo`. После этого отключить root/password login.
Снаружи оставлять только `22`, `80`, `443`; прямые Docker-порты не публиковать.
Нельзя полагаться только на UFW для Docker-портов: Docker может обходить
стандартные правила INPUT, поэтому важнее убрать `ports` из Compose.
