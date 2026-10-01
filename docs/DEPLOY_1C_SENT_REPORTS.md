# Развертывание новых методов 1С

Сервер SBIS: `146.19.125.77`, проект `/opt/sbis-norm` (не CRM-сервер `.32`).
Запускать от root. Новый пакет `defusedxml` требует пересборки web.
БД, beat, worker и VPN для этого обновления не перезапускаются.

## 1. Проверить и обновить

```bash
cd /opt/sbis-norm
git status --short
git rev-parse HEAD
git pull --ff-only origin main
```

Сохранить предыдущий commit ID. Если pull сообщает о конфликте локальных
изменений, остановиться, не применять reset/checkout и не затирать изменения.

## 2. Собрать и проверить до переключения

```bash
cd /opt/sbis-norm
docker compose build web && \
docker compose run --rm --no-deps --entrypoint python web manage.py test reports.test_sent_reports --settings=tax_service.test_settings && \
docker compose up -d --no-deps web && \
docker compose exec -T web python manage.py check
```

Тесты используют изолированные настройки и моки, не обращаются в СБИС или production-БД.
Проект примонтирован в контейнер: после git pull код уже изменён на диске.
Не считать старые gunicorn-процессы гарантией отката до пересоздания.

## 3. Разрешить маршруты в nginx

```bash
cd /opt/sbis-norm
python3 scripts/ops/enable_sent_reports_nginx.py
```

Скрипт проверяет известную конфигурацию `/etc/nginx/sites-enabled/01-crmkanasha-ssl`,
следует существующей ссылке, создаёт резервную копию вне `sites-enabled`,
добавляет только два маршрута в существующий whitelist и выставляет timeout 180s.
При ошибке проверки/перезагрузки восстанавливает конфиг. Если конфиг отличается
от ожидаемого, прекращает работу до записи. SNI/stream/Xray не изменяет.

## 4. Проверить защиту снаружи

```bash
for route in sent-reports-1c sent-report-xml-1c; do
  curl -sS -o /dev/null -w "$route: %{http_code}\n" \
    -X POST "https://api.crmkanasha.org/api/sbis/$route/" \
    -H 'Content-Type: application/json' --data '{}'
done
```

Ожидается 401 или 403 без токена. 404 означает, что маршрут не открыт;
502 — проблема upstream. Не применять `-k`: сертификат HTTPS должен проверяться.

## 5. Живая проверка

По инструкции [API_1C_SENT_REPORTS.md](API_1C_SENT_REPORTS.md) выполнить с токеном
список по ЗЕРО (`9729355495`, 30 дней), затем скачать документ из ответа.
Повторное скачивание должно вернуть `cached:true`. Проверить основной XML,
книги, дату/период, отсутствие квитанций. Не публиковать токен или Base64 в чат.
До этой проверки не утверждать, что интеграция полностью подтверждена на production.

## Откат

Не выполнять `git reset --hard`. Для отката кода подготовить revert конкретного
коммита, пересобрать web и повторить проверки. Для nginx использовать напечатанный
скриптом каталог резервной копии: восстановить `config` в исходный resolved path,
затем `nginx -t && systemctl reload nginx`. Не копировать backup в `sites-enabled`.
Не удалять тома CryptoPro, БД и каталог закрытого кеша.
