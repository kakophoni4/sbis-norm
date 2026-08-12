# Требования ФНС → CRM: полная интеграция

Документ для команды CRM.  
Сервис: **sbis-norm** (СБИС/ФНС шлюз).  
Прод: `http://146.19.125.77:8000`  
Базовый API: `http://<host>:8000/api/`

**Статус (проверено 2026-08-08):** получение требований, сроки, ответ комплектом документов — **готово и проверено** на тестовой компании ООО БАСТИОН (`9707039440`).

---

## 1. Что делает sbis-norm (и чего не делает CRM)

| Делает sbis-norm | Делает CRM |
|------------------|------------|
| Каждый день ~17:00 МСК скачивает требования из СБИС | Забирает список/файлы по HTTP |
| Подтверждает получение (квитанция в ФНС) | Показывает менеджеру, хранит у себя |
| Хранит PDF/файл + мета + сроки | Помечает «забрал» (`mark-synced`) |
| Принимает ответные файлы и отправляет в СБИС/ФНС | Собирает вложения и вызывает `/reply/` |

CRM **не** ходит в СБИС напрямую и **не** подписывает ЭЦП — это делает sbis-norm по ИНН компании.

---

## 2. Поток

```
СБИС / ФНС
    │  Celery ~17:00 МСК (whitelist ИНН, окно 10 дней)
    ▼
sbis-norm (RequirementDocument)
    │
    ├─ GET  /api/sbis/requirements/?unsynced=1     ← новые для CRM
    ├─ GET  /api/sbis/requirements/<id>/           ← мета
    ├─ GET  /api/sbis/requirements/<id>/file/      ← PDF (байты)
    ├─ POST /api/sbis/requirements/mark-synced/    ← «забрали»
    └─ POST /api/sbis/requirements/<id>/reply/     ← ответ в ФНС
    │
    ▼
CRM
```

Опционально: webhook при появлении нового требования (`REQUIREMENTS_WEBHOOK_URL`) — только мета, без файла.

---

## 3. Авторизация

Если на сервере задан `REQUIREMENTS_API_TOKEN`:

```http
X-API-Key: <token>
```

или

```http
Authorization: Bearer <token>
```

Если токен пустой — эндпоинты открыты (как сейчас на части прод-методов). Для CRM лучше работать с токеном, когда его включат.

---

## 4. Модель данных (поля ответа API)

Общий JSON объекта требования:

| Поле | Тип | Описание |
|------|-----|----------|
| `id` | int | ID в sbis-norm (ключ для CRM) |
| `inn` | string | ИНН организации |
| `document_date` | `YYYY-MM-DD` | дата требования |
| `sbis_doc_id` | string | ID документа в СБИС |
| `sbis_stage_id` | string\|null | ID этапа в СБИС |
| `doc_title` | string | название |
| `content_sha256` | string | хеш файла |
| `storage_file_name` | string | рекомендуемое имя файла |
| `created_at` | ISO datetime | когда сохранили у нас |
| `external_synced_at` | ISO datetime\|null | когда CRM пометила «забрано» |
| `response_due_date` | `YYYY-MM-DD`\|null | **срок ответа** из СБИС (`Срок`); часто `null` у старых/закрытых |
| `receipt_due_date` | `YYYY-MM-DD`\|null | срок квитанции о приёме (= дата док. + 6 раб. дней) |
| `knd` | string\|null | код формы (см. ниже) |
| `reply_status` | string | статус ответа (см. ниже) |
| `reply_sbis_doc_id` | string\|null | ID нашего ответа в СБИС |
| `replied_at` | ISO datetime\|null | когда отправили ответ через API |
| `reply_error` | string\|null | текст ошибки последней отправки |
| `file_size` | int | оценка размера файла, байты |
| `file_url` | string | путь к бинарнику |
| `reply_url` | string | путь для ответа |

### 4.1. `reply_status`

| Значение | Смысл для CRM |
|----------|----------------|
| `none` | ответа ещё нет |
| `sent` | ответ отправлен **через наш API** (`/reply/`) |
| `answered` | в СБИС уже видно, что по требованию ответили (в т.ч. **из ЛК СБИС**, не через CRM) |
| `error` | последняя попытка `/reply/` упала; смотри `reply_error` |

**Для CRM:** если `reply_status` = `answered` или `sent` — отвечать не нужно (можно закрыть задачу / не показывать как срочное).

Сканер при каждом проходе перечитывает карточку в СБИС для уже известных требований: обновляет `doc_title`, сроки и `answered`. Если статус стал `answered` (или обновились title/срок) — сбрасывается `external_synced_at`, запись снова попадёт в `unsynced=1`, чтобы CRM подтянула актуальные поля.

### 4.2. Сроки

- **`response_due_date`** — крайний срок ответа по существу (поле `Срок` из карточки СБИС). Может быть пустым, если СБИС не отдал дату.
- **`receipt_due_date`** — срок на квитанцию о получении (норма: 6 рабочих дней). Квитанцию шлёт **сканер sbis-norm**, не CRM.
- «Ответить за 6 дней» ≠ срок ответа документами. 6 дней — про квитанцию.

### 4.3. КНД

КНД у **требования** и у **ответа** разные — это нормально.

| Документ | Типичный КНД |
|----------|----------------|
| Требование «представить документы» | 1165013 (и др. виды) |
| Ответ (опись «представление документов») | **1184002** — так sbis-norm отправляет `/reply/` |

В поле `knd` у записи может оказаться код требования или связанный подтип — ориентируйтесь на него как на справочное; для ответа CRM код задавать не нужно.

---

## 5. API: чтение

### 5.1. Список

`GET /api/sbis/requirements/`

| Query | Описание |
|-------|----------|
| `unsynced=1` | только ещё не забранные CRM |
| `inn=` | фильтр по ИНН |
| `date_from` / `date_to` | `YYYY-MM-DD` |
| `since_id` | курсор: `id > since_id` |
| `limit` | 1…500, по умолчанию 50 |
| `include_file=1` | вложить base64 в list (**не использовать** в CRM — тяжело) |

Сортировка: `id` ASC.

```http
GET /api/sbis/requirements/?unsynced=1&limit=50
```

### 5.2. Мета одного

`GET /api/sbis/requirements/<id>/`

### 5.3. Файл (байты)

`GET /api/sbis/requirements/<id>/file/`

- Тело = сырой PDF/XML (не JSON, не base64)
- Заголовки: `Content-Type`, `Content-Disposition`, `X-Content-Sha256`

```bash
curl -sS -o /tmp/req.pdf "http://146.19.125.77:8000/api/sbis/requirements/138/file/"
```

---

## 6. API: пометить забранными

`POST /api/sbis/requirements/mark-synced/`

```json
{"ids": [12, 13, 14]}
```

Ответ:

```json
{"updated": 3, "synced_at": "2026-08-08T12:00:00+00:00"}
```

После этого id не попадут в `?unsynced=1`. Повторный вызов безопасен (идемпотентно).

---

## 7. API: ответить на требование

`POST /api/sbis/requirements/<id>/reply/`

Отправляет вложения в ФНС как формализованное **представление документов (КНД 1184002)**, привязанное к требованию.

### Тело

```json
{
  "attachments": [
    { "filename": "schet.pdf", "content_b64": "<base64>" },
    { "filename": "act.pdf", "content_b64": "<base64>" }
  ],
  "dry_run": false
}
```

| Поле | Обязательно | Описание |
|------|-------------|----------|
| `attachments` | да | массив файлов; алиасы полей: `files`, `b64` / `file_b64` |
| `dry_run` | нет | `true` — только валидация, **без** отправки в СБИС |

### Успех 200

```json
{
  "success": true,
  "send_meta": {
    "reply_sbis_doc_id": "b01ef712-...",
    "requirement_sbis_doc_id": "019f2229-...",
    "stage_name": "Отправить",
    "action_name": "Отправить",
    "sent_at": "2026-08-08T12:41:52",
    "sent_date": "2026-08-08",
    "filenames": ["test_empty.pdf"]
  },
  "parsed": {
    "inn": "9707039440",
    "kpp": "770701001",
    "kod_no": "7707",
    "knd": "1184002"
  }
}
```

В БД: `reply_status=sent`, `reply_sbis_doc_id`, `replied_at`.

### Ошибки

| HTTP | Смысл |
|------|--------|
| 400 | нет вложений / ошибка СБИС (текст в `error.message`) |
| 401 | нет валидной ЭЦП по ИНН |
| 403 | нет сертификата по ИНН |
| 404 | нет требования с таким `id` |
| 500 | неожиданная ошибка (в теле обычно JSON `error.message`) |

### Рекомендация CRM

1. Сначала `dry_run: true`.
2. При `success` — боевой вызов с теми же файлами.
3. Таймаут HTTP на reply: **не меньше 180 секунд** (подпись + СБИС + прокси).

### Пример curl

```bash
B64=$(base64 -w0 ./doc.pdf)   # Linux; на macOS: base64 < doc.pdf | tr -d '\n'

curl -sS -X POST "http://146.19.125.77:8000/api/sbis/requirements/12/reply/" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $REQUIREMENTS_API_TOKEN" \
  -d "{\"attachments\":[{\"filename\":\"doc.pdf\",\"content_b64\":\"$B64\"}],\"dry_run\":true}"
```

---

## 8. Рекомендуемый цикл CRM

### Pull новых

```
1. GET /api/sbis/requirements/?unsynced=1&limit=50
2. Для каждого:
     - сохранить мета (inn, dates, reply_status, response_due_date, …)
     - GET .../file/ → сохранить PDF
3. POST /api/sbis/requirements/mark-synced/ {"ids":[...успешные...]}
4. Если count == limit — повторить с шага 1
```

Фильтр «только PDF» по желанию: `storage_file_name` / Content-Type файла.

**Уведомления о блокировке счёта:** сканер сохраняет их как запись-маркер **без файла**
(`file` пустой / `storage_file_name` оканчивается на `.stub`, `reply_status` обычно `none`).
Это **не** «уже отвечено» — просто факт блокировки по компании. CRM должна:
сохранить карточку (по `doc_title` видно «блокировке счета»), **не показывать ответ**,
сделать `mark-synced` без PDF. `/reply/` на такие записи не вызывать.

### Ответ пользователем

```
1. Менеджер прикладывает файлы в CRM
2. CRM → POST .../requirements/<id>/reply/  (dry_run=true)
3. CRM → тот же запрос dry_run=false
4. Показать reply_status / reply_error из GET .../<id>/
```

### Дедуп у себя

Ключи: `id` sbis-norm **или** `(inn, sbis_doc_id)` **или** `content_sha256`.

---

## 9. Webhook (если включат)

После сохранения нового требования сканером:

```http
POST <REQUIREMENTS_WEBHOOK_URL>
Content-Type: application/json
```

Тело — мета (id, inn, dates, title, sha256, `file_url_hint`, `reply_url_hint`).  
**Файла нет** — забирать через `GET .../file/`.

---

## 10. Ограничения и ожидания

1. Сканер ходит только по whitelist ИНН (`docs/requirements_scan_inns.txt`), окно **10 дней**, раз в день ~17:00 МСК.
2. `response_due_date` бывает `null` — СБИС часто не отдаёт `Срок` на старых/закрытых карточках.
3. `/reply/` шлёт **формализованную опись 1184002** с вашими файлами. Отдельные виды формализованных XML-пояснений к НДС — вне текущего контракта (нужна доработка).
4. Повторный reply на то же требование возможен технически, но с точки зрения ФНС лучше один осмысленный комплект.
5. ЭЦП и прокси — на стороне sbis-norm; CRM передаёт только base64 файлов.

---

## 11. Проверено на проде

| Проверка | Результат |
|----------|-----------|
| List / detail / file | OK |
| mark-synced | OK |
| Backfill сроков/статусов | OK (где СБИС отдал данные) |
| `POST .../reply/` dry_run | OK (БАСТИОН) |
| `POST .../reply/` боевой | OK — `reply_status=sent`, получен `reply_sbis_doc_id` (БАСТИОН, 2026-08-08) |

Тестовая компания: **ООО БАСТИОН**, ИНН `9707039440`.

---

## 12. Быстрый smoke для CRM

```bash
BASE=http://146.19.125.77:8000

# новые
curl -sS "$BASE/api/sbis/requirements/?unsynced=1&limit=3"

# файл
curl -sS -o /tmp/r.pdf "$BASE/api/sbis/requirements/<ID>/file/"

# ответ (dry_run)
curl -sS -X POST "$BASE/api/sbis/requirements/<ID>/reply/" \
  -H "Content-Type: application/json" \
  -d '{"attachments":[{"filename":"a.pdf","content_b64":"<BASE64>"}],"dry_run":true}'
```

---

## 13. Контакты / ops (не CRM)

Ручной скан / отладка — команда инфраструктуры sbis-norm:

```bash
cd /opt/sbis-norm
docker compose exec -T web python manage.py fetch_requirements_all_companies --days 10
docker compose exec -T web python manage.py list_requirement_documents --limit 20
docker compose exec -T web python manage.py backfill_requirement_sbis_meta --limit 30
```

Краткая техдокументация API также: [`API_REQUIREMENTS_EXTERNAL.md`](API_REQUIREMENTS_EXTERNAL.md).
