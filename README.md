# Микросервис для работы с СБИС и ФНС

Django-микросервис для отправки налоговой отчётности (НДС), получения входящих документов СБИС, скачивания требований ФНС и управления сертификатами CryptoPro.

## Требования

- [Docker](https://www.docker.com/products/docker-desktop/)

## Быстрый старт

```bash
docker-compose up --build -d
```

Проверка статуса:

```bash
docker-compose ps
```

После запуска:

- **API:** http://localhost:8000/api/docs/
- **Админка:** http://localhost:8000/admin/

## Логи

```bash
docker-compose logs -f
docker-compose logs -f web
docker-compose logs -f worker
```

## Остановка

```bash
docker-compose down
```

## Дополнительные команды

Сертификаты CryptoPro (полная цепочка для SBIS auth):

```bash
# 1. Проверка: сколько контейнеров видят сертификат
docker-compose exec web python manage.py verify_cert_export

# 2. Сканирование + установка в uMy (PrivateKey Link) + запись в БД
docker-compose exec web python manage.py scan_certificates --install-uMy --quiet

# 3. Синхронизация has_private_key из uMy
docker-compose exec web python manage.py sync_has_private_key

# 4. Тест авторизации в СБИС
docker-compose exec web python manage.py test_sbis_auth_one 9722082369
```

Альтернатива шагу 2 на хосте (до scan): `sudo bash scripts/ops/sbis_keys_install_linux.sh --install-only`

Создание суперпользователя:

```bash
docker-compose exec web python manage.py createsuperuser
```

Миграции:

```bash
docker-compose exec web python manage.py migrate
```
