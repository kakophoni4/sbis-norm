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

### Массовая проверка auth и сбор реквизитов для 1С

**1. Полный auth-скан** (~1000 ИНН, результат в `/app/media/sbis_auth_scan/`):

```bash
docker-compose exec web python manage.py test_sbis_auth_all --quiet --workers 12 --delay 0
```

Повтор только `proxy_error` из прошлого отчёта:

```bash
docker-compose exec web python manage.py test_sbis_auth_all --quiet --workers 4 \
  --from-csv /app/media/sbis_auth_scan/sbis_auth_report_YYYYMMDD_HHMMSS.csv \
  --category proxy_error
```

Фоновый прогон на сервере:

```bash
nohup docker compose exec -T web python manage.py test_sbis_auth_all \
  --quiet --workers 12 --delay 0 > /tmp/sbis_auth_all.log 2>&1 &
tail -f /tmp/sbis_auth_all.log
```

**2. Список валидных ИНН** — файл `valid_inns_final.txt` (по одному ИНН в строке), положить в контейнер или смонтировать в `/app/`.

**3. Сбор реквизитов** (`collect_org_data`) — CSV/JSON в `/app/media/org_export/`:

```bash
# Тест на 10 ИНН
docker-compose exec web python manage.py collect_org_data \
  --from-file valid_inns_final.txt --limit 10 --sbis --workers 4

# Полный прогон (~670 ИНН)
docker-compose exec web python manage.py collect_org_data \
  --from-file valid_inns_final.txt \
  --auth-csv /app/media/sbis_auth_scan/sbis_auth_report_YYYYMMDD_HHMMSS.csv \
  --sbis --workers 4 --quiet
```

Мониторинг во время сбора:

```bash
docker-compose exec web tail -f /app/media/org_export/collect_org_LIVE.log
docker-compose exec web cat /app/media/org_export/collect_org_LIVE.status.json
```

Выгрузка на хост:

```bash
docker cp $(docker-compose ps -q web):/app/media/org_export/organizations_YYYYMMDD_HHMMSS.csv .
```

Колонки в файле (только для 1С): ИНН, КПП, ОГРН, наименования, код налогового органа, ЮЛ/ИП, ФИО ИП, сроки ЭЦП, ЭЦПОтозвана.

**Не запускайте** `sbis_keys_install_linux.sh` на хосте — CryptoPro там не видит контейнеры. Только внутри Docker:

```bash
docker compose exec web bash /app/scripts/ops/sbis_keys_install_linux.sh --install-only
```

Альтернатива шагу 2 (то же, что `--install-uMy` выше):

Создание суперпользователя:

```bash
docker-compose exec web python manage.py createsuperuser
```

Миграции:

```bash
docker-compose exec web python manage.py migrate
```
