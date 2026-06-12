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

Создание суперпользователя:

```bash
docker-compose exec web python manage.py createsuperuser
```

Миграции:

```bash
docker-compose exec web python manage.py migrate
```
