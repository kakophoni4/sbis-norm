# Заполнение КПП по ИНН (`sync_org_kpp`)

## Модели

- **`Organization.kpp`** — уже было в проекте; команда пишет сюда.
- **`Certificate.kpp`** — добавлено поле; заполняется только с флагом `--sync-certificates`.

## Миграция

```bash
python manage.py migrate reports
```

## Использование

### Если ИНН только в `Certificate` (нет строк в `Organization`)

Проверка без записи:

```bash
.venv/bin/python3 manage.py sync_org_kpp --from-certificates --dry-run
```

Записать КПП в сертификаты (+ пауза между запросами):

```bash
.venv/bin/python3 manage.py sync_org_kpp --from-certificates --delay 1.5
```

То же + создать/обновить `Organization` по данным API (имя из `nameShort`):

```bash
.venv/bin/python3 manage.py sync_org_kpp --from-certificates --delay 1.5 --ensure-organization
```

### Если организации уже в БД

Проверка без записи:

```bash
python manage.py sync_org_kpp --dry-run
```

Заполнить пустые КПП (пауза 1 с между запросами):

```bash
python manage.py sync_org_kpp --delay 1.0
```

Один ИНН + обновить и сертификаты с тем же ИНН:

```bash
python manage.py sync_org_kpp --only-inn 9729337785 --sync-certificates
```

Перезаписать все КПП:

```bash
python manage.py sync_org_kpp --force
```

Другой endpoint (тот же формат JSON: `items[].inn`, `items[].kpp`, опционально `isMain`):

```bash
python manage.py sync_org_kpp --url 'https://example.com/suggest?query='
```

## Важно

Источник по умолчанию — публичный JSON **star-pro.ru**; это не официальный API ФНС.  
Проверьте **правила сайта**, не шлите запросы слишком часто (`--delay`).

### 403 Forbidden с сервера (VPS)

Сайт часто режет **IP датацентра** или запросы без «браузерных» заголовков. В коде уже выставлены **Referer / Origin / User-Agent** как у Chrome.

Если всё равно **403**:

1. Сохраните из DevTools (F12 → Network → запрос `organizationSuggestion` → Request Headers) строку **`Cookie`** в файл, например `/home/devuser/.secrets/star_pro_cookie.txt` (одна строка, без лишних переносов).
2. Запуск:
   ```bash
   .venv/bin/python3 manage.py sync_org_kpp --from-certificates --cookie-file /home/devuser/.secrets/star_pro_cookie.txt --delay 1.5
   ```
3. Либо переменная окружения: `export KPP_SYNC_COOKIE='...'` (и при необходимости `KPP_SYNC_REFERER`).

Cookie со временем протухает — обновляйте. Для массовой заливки надёжнее **официальные выгрузки ФНС** или платный справочник.

## КПП из своих отправленных документов (без внешних запросов)

В XML отчётов НДС в блоке **СвНП/НПЮЛ** уже есть ИНН и КПП нашей организации. Можно просканировать сохранённые файлы документов и вытащить оттуда КПП:

```bash
.venv/bin/python3 manage.py sync_kpp_from_documents --dry-run
.venv/bin/python3 manage.py sync_kpp_from_documents --sync-certificates
```

Команда смотрит документы со статусами SENT, CONFIRMED, UPLOADED, открывает их `files` (пути относительно MEDIA_ROOT), парсит XML и обновляет `Organization.kpp` и при необходимости `Certificate.kpp`. Никакого star-pro и 403.

## Альтернативы star-pro (пакетно)

1. **Официальные открытые данные ФНС (ЕГРЮЛ)** — бесплатно, без лимита по IP: скачиваете выгрузку, парсите XML/CSV, получаете пары ИНН+КПП. Минус — объём и свой парсер.
2. **Запуск `sync_org_kpp` с домашнего ПК** (не с VPS) — тот же cookie часто проходит; результат можно не в БД, а в CSV и залить на сервер.
3. **Платные API** (DaData «найти организацию», Контур и т.д.) — договор, лимиты, зато стабильный JSON по ИНН.
4. **Импорт готового CSV на сервер** (без HTTP к star-pro):

```bash
.venv/bin/python3 manage.py import_kpp_csv /path/kpp.csv --sync-certificates --dry-run
.venv/bin/python3 manage.py import_kpp_csv /path/kpp.csv --sync-certificates --ensure-organization
```

Формат CSV: заголовок `inn,kpp` (или `ИНН,КПП`), разделитель `,` или `;`.

## Связь с `sbis_fetch_kpp`

После `sync_org_kpp` КПП подхватится из **`Organization.kpp`** или **`Certificate.kpp`** (если заполнены).
