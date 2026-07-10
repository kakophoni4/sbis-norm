# API для 1С: отправка НДС и связанные методы

Базовый URL (прод): `http://<host>:8000/api/`  
Content-Type: `application/json`

Авторизация HTTP на эти эндпоинты сейчас не требуется (`permission_classes = []`).  
Подпись берётся **по ИНН** из БД CryptoPro (`Certificate` с `csptest_name` / private key).

**Критично:** `inn` в JSON, `ИННЮЛ` в XML и ЭЦП в CryptoPro должны совпадать. Иначе dry_run может пройти, а реальная отправка в СБИС/ФНС — нет или уйдёт «не тем» подписантом.

---

## 1. Отправка декларации НДС (основной метод для 1С)

`POST /api/sbis/send-nds-extra-1c/`

### Тело запроса

```json
{
  "inn": "9729337785",
  "main_xml_b64": "<base64 XML основного файла NO_NDS_...>",
  "book_xml_b64_list": [
    "<base64 XML книги покупок NO_NDS.8_...>",
    "<base64 XML книги продаж NO_NDS.9_...>"
  ],
  "dry_run": false
}
```

| Поле | Обязательно | Описание |
|------|-------------|----------|
| `inn` | да | ИНН организации (= ИНН в XML и ЭЦП) |
| `main_xml_b64` | да | Основной XML декларации в base64 (алиасы: `xml_b64`, `main_b64`) |
| `book_xml_b64_list` | нет | Список base64 книг; можно `books_b64` / `book_b64_list`; элементы — строки или `{ "b64": "..." }` |
| `dry_run` | нет | `true` — только разбор/проверка имён книг, **без** отправки в СБИС |

### Успех (HTTP 200)

```json
{
  "success": true,
  "result": { "...": "ответ СБИС.ВыполнитьДействие" },
  "send_meta": {
    "sbis_doc_id": "...",
    "sent_at": "...",
    "sent_date": "YYYY-MM-DD"
  }
}
```

При `dry_run: true` вместо `result`/`send_meta` приходит блок `parsed` (имена файлов, ожидаемые книги).

### Ошибки

| HTTP | Смысл |
|------|--------|
| 400 | Входные данные / имена книг не совпали с основным XML |
| 401 | У ИНН нет валидной подписи (`csptest_name`) |
| 403 | Нет сертификата по ИНН |
| 404 | Ошибка СБИС при отправке (тело в `error`) |

### Пример curl (dry_run)

```bash
curl -sS -X POST "http://127.0.0.1:8000/api/sbis/send-nds-extra-1c/" \
  -H "Content-Type: application/json" \
  -d '{
    "inn": "9729337785",
    "main_xml_b64": "'"$MAIN_B64"'",
    "book_xml_b64_list": ["'"$BOOK8_B64"'","'"$BOOK9_B64"'"],
    "dry_run": true
  }'
```

---

## 2. PDF квитанции из архива СБИС

`POST /api/sbis/get-receipt-pdf-1c/`

```json
{
  "inn": "9729337785",
  "sbis_doc_id": "<из send_meta после отправки>",
  "sent_date": "YYYY-MM-DD"
}
```

Ответ: `{ "success": true, "pdf_b64": "..." }` или ошибка.

Квитанция появляется не мгновенно: если сразу после отправки PDF ещё нет — повторить через несколько минут с теми же `sbis_doc_id` / `sent_date`.

---

## 3. Выписка книги продаж по контрагенту

`POST /api/sbis/get-sales-book-extract/`

```json
{
  "inn": "9707039440",
  "counterparty_id": "",
  "date_from": "2025-01-01",
  "date_to": "2025-12-31",
  "max_docs": 30
}
```

---

## 4. Загрузка организаций в 1С (обратный поток: мы → mole 1С)

Не HTTP API Django, а наш клиент к HTTP-сервису 1С `mole`:

- `GET {ONE_C_MOLE_BASE_URL}/health`
- `POST {ONE_C_MOLE_BASE_URL}/units` — массив организаций

Поля единицы (CSV/`collect_org_data`): `ИНН`, `КПП`, `ОГРН`, `Наименование`, `НаименованиеПолное`, `НаименованиеСокращенное`, …

Команда: `python manage.py upload_org_units_1c --from-csv ...`

---

## 5. Требования ФНС (получение / «подтверждение»)

Отдельного REST для 1С пока нет. Логика на стороне сервиса — **полный цикл по [доке Saby](https://saby.ru/help/integration/api/reporting/claim)**:

1. `СБИС.СписокСлужебныхЭтапов` — список входящих служебных (требования и т.п.)
2. `СБИС.ПодготовитьДействие` с действием **`Обработать служебное`** — вложения + ссылки
3. Скачать файлы по ссылке (часто зашифрованы) → `cryptcp -decr` → PDF/XML
4. `СБИС.ВыполнитьДействие` по тому же этапу (вложения/подписи после расшифровки)
5. Цикл служебных извещений: снова СписокСлужебныхЭтапов → prepare → sign → execute, пока список не пуст
6. Подтверждение получения: `СБИС.ПрочитатьДокумент` → действие **`Подтвердить получение`** (этап «Подтверждение»; в EDI иногда «Утверждение») → prepare → sign → execute
7. Сохранение в `RequirementDocument`; после save — хук `notify_requirement_saved` (пока лог, позже внешний сервис)

Флаги в логах/результате fetch: `executed`, `receipt_sent`, `receipt_skipped`, `service_stages_done`.

Операционно:

```bash
python manage.py probe_requirement_status --inn 9707039440 --days 10
python manage.py fetch_requirements_all_companies --days 10 --force
python manage.py list_requirement_documents --limit 20
```

Ежедневный сканер (Celery Beat): **17:00 Europe/Moscow** (`crontab` 14:00 UTC при `CELERY_TIMEZONE=UTC`) — задача `reports.tasks.fetch_requirements_daily_task` (`--days 10`, все ИНН с `has_private_key=True`).

Проверено на БАСТИОН `9707039440` (КПП `770701001`): полный цикл — после `Обработать служебное` подтверждение через **`Подтвердить получение`** (подпись содержимого `KV_*.xml`, не хеша) → `receipt_sent=True`.

---

## 6. Путь 1С (как должно работать автоматически)

```
1С                              Django API                         СБИС / CryptoPro
───                             ──────────                         ────────────────
собрать NO_NDS XML
(+ книги 8/9) base64
        │
        ▼
POST /api/sbis/send-nds-extra-1c/
  inn, main_xml_b64,
  book_xml_b64_list
  dry_run=false  ──────────►  выбрать Certificate(inn, pk)
                              export + uMy (если нужно)
                              cryptcp -sign XML/книги
                              auth СБИС
                              ЗаписатьКомплект
                              ПодготовитьДействие «Отправить»
                              ВыполнитьДействие
                     ◄──────  success + send_meta
                              { sbis_doc_id, sent_date, sent_at }

сохранить send_meta
        │
        │  (через N минут / по статусу в СБИС —
        │   квитанция ФНС появляется не сразу)
        ▼
POST /api/sbis/get-receipt-pdf-1c/
  inn, sbis_doc_id, sent_date
                     ──────────►  СписокДокументов → архив
                                  вытащить PDF справки
                     ◄──────  pdf_b64   или 400 «ещё нет справки»
```

**Проверено на БАСТИОН `9707039440` (2026-07-10):**  
`send-nds-extra-1c` → HTTP 200, `sbis_doc_id=73696d74-690b-4acd-82ff-176a37c16d7c`, ушло в ИФНС №7.  
`get-receipt-pdf-1c` сразу после отправки → 400: в архиве пока только PDF декларации/книг (`PDF/NO_NDS*`), справки ФНС ещё нет — **повторять позже** с тем же `send_meta`.

Требования ФНС — отдельный серверный цикл (`fetch_requirements_*`), не этот REST.

---

## 7. Полный цикл проверки на сервере (ops)

Всё на сервере (`/opt/sbis-norm`), HTTP как у 1С (`127.0.0.1:8000`).

```bash
cd /opt/sbis-norm
# при необходимости: bash scripts/ops/install_bastion_umy_and_test_sign.sh
docker compose exec -T web python /app/docs/make_bastion_nds_and_send_1c.py --dry-run
docker compose exec -T web python /app/docs/make_bastion_nds_and_send_1c.py --send
```

| Шаг | Ожидание |
|-----|----------|
| dry_run | HTTP 200, книги matched |
| --send | HTTP 200, `send_meta.sbis_doc_id` |
| receipt | `pdf_b64` **после** появления справки в архиве СБИС |

`--send` реально уходит в СБИС/ФНС.

---

## Замечания для интегратора

1. ИНН в JSON, в XML (`ИННЮЛ`) и ЭЦП в CryptoPro должны совпадать.
2. Имена файлов книг в основном XML (`КнигаПокуп` / `КнигаПрод`) должны совпасть с `ИдФайл` переданных book-XML (проверка при `validate_book_names`).
3. XML обычно в windows-1251; в base64 передаётся как есть.
4. Реальная отправка (`dry_run: false`) уходит в СБИС/ФНС — для проверки контракта сначала `dry_run: true`.
5. Ошибка СБИС «Регистрация клиента еще не завершилась» — статус кабинета в СБИС, не прокси и не формат запроса.
6. Для dry_run можно подставить чужой sample XML под другой `inn` (проверка парсера). Для шага C — только совпадающий ИНН.
