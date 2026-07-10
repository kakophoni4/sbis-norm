# API: выгрузка требований ФНС во внешний сервис

Базовый URL: `http://<host>:8000/api/`  
Content-Type: `application/json`

Этот сервис **сам** забирает требования из СБИС (сканер 17:00 МСК), сохраняет в БД и отдаёт наружу по HTTP.  
Внешняя система только **читает** и помечает «забрано».

---

## Поток данных

```
СБИС / ФНС
    │
    ▼  Celery 17:00 МСК (whitelist лавки+новые, окно 10 дней)
sbis-norm: RequirementDocument (file_b64 + meta)
    │
    ├─ pull:  GET /api/sbis/requirements/ …
    ├─ file:  GET /api/sbis/requirements/<id>/
    └─ ack:   POST /api/sbis/requirements/mark-synced/
    │
    ▼
ваш сервис (CRM / архив / 1С / …)
```

Опционально push: после save → `POST REQUIREMENTS_WEBHOOK_URL` (только мета, без файла).

---

## Авторизация

| Env | Назначение |
|-----|------------|
| `REQUIREMENTS_API_TOKEN` | если задан — обязателен заголовок |
| `REQUIREMENTS_WEBHOOK_URL` | URL для push после сохранения |
| `REQUIREMENTS_WEBHOOK_TOKEN` | Bearer / X-API-Key на webhook |

Заголовок (если токен задан):

```http
X-API-Key: <REQUIREMENTS_API_TOKEN>
```

или

```http
Authorization: Bearer <REQUIREMENTS_API_TOKEN>
```

Если `REQUIREMENTS_API_TOKEN` пустой — эндпоинты открыты (как сейчас на проде для 1С-методов). Для продакшена токен рекомендуется.

---

## 1. Список требований

`GET /api/sbis/requirements/`

### Query-параметры

| Параметр | Тип | Описание |
|----------|-----|----------|
| `unsynced` | `1` / `true` | только ещё не забранные (`external_synced_at IS NULL`) |
| `inn` | string | фильтр по ИНН |
| `date_from` | `YYYY-MM-DD` | дата документа ≥ |
| `date_to` | `YYYY-MM-DD` | дата документа ≤ |
| `since_id` | int | `id > since_id` (курсор по возрастанию id) |
| `since_created_at` | ISO datetime / date | `created_at ≥` |
| `include_file` | `1` / `true` | сразу вложить `file_b64` в list (тяжело) |
| `limit` | int | 1…500, по умолчанию 50 |

Сортировка: по `id` ASC (удобно для курсора `since_id`).

### Пример

```http
GET /api/sbis/requirements/?unsynced=1&limit=50
```

### Ответ 200

```json
{
  "count": 2,
  "results": [
    {
      "id": 12,
      "inn": "9707039440",
      "document_date": "2026-07-06",
      "sbis_doc_id": "019f36c5-ceb0-79fe-934d-c5c1bfe5d256",
      "sbis_stage_id": "5b81ed01-bd93-5489-9c50-fc518816daa8",
      "doc_title": "Требование ФНС",
      "content_sha256": "a1b2c3…",
      "storage_file_name": "Требование ФНС (9707039440) (2026-07-06).pdf",
      "created_at": "2026-07-10T14:22:01.123456+00:00",
      "external_synced_at": null,
      "file_size": 184320
    }
  ]
}
```

`file_size` — оценка размера бинарника в байтах (из длины base64).  
В list по умолчанию **нет** `file_b64`.

---

## 2. Один документ (с файлом)

`GET /api/sbis/requirements/<id>/`

### Ответ 200

Те же поля + `file_b64` (строка base64 содержимого PDF/XML/ZIP).

Имя файла для сохранения: `storage_file_name` (или собрать из `inn` + `document_date` + расширение).

### Ошибки

| Код | Когда |
|-----|--------|
| 401 | неверный / отсутствующий API token |
| 404 | нет записи с таким id |

---

## 3. Пометить забранными

`POST /api/sbis/requirements/mark-synced/`

```json
{"ids": [12, 13, 14]}
```

### Ответ 200

```json
{
  "updated": 3,
  "synced_at": "2026-07-10T16:00:00.000000+00:00"
}
```

После этого эти id **не** попадут в `?unsynced=1`.

Идемпотентность: повторный mark на тех же id просто обновит `external_synced_at`.

---

## Рекомендуемый цикл интеграции (pull)

```
1. GET /api/sbis/requirements/?unsynced=1&limit=50
2. для каждого item:
     GET /api/sbis/requirements/{id}/
     сохранить file_b64 → диск / БД / очередь
3. POST /api/sbis/requirements/mark-synced/  {"ids": [...успешно сохранённые...]}
4. если count == limit — повторить с шага 1
```

Альтернатива курсором (если не используете unsynced):

```
since_id = 0
loop:
  GET ?since_id={since_id}&limit=50
  обработать results
  since_id = max(id)
  пока count > 0
```

---

## Webhook (опционально)

После успешного save сканером:

```http
POST <REQUIREMENTS_WEBHOOK_URL>
Content-Type: application/json
Authorization: Bearer <REQUIREMENTS_WEBHOOK_TOKEN>   # если задан
X-API-Key: <REQUIREMENTS_WEBHOOK_TOKEN>

{
  "id": 12,
  "inn": "9707039440",
  "document_date": "2026-07-06",
  "sbis_doc_id": "...",
  "sbis_stage_id": "...",
  "doc_title": "Требование ФНС",
  "content_sha256": "...",
  "storage_file_name": "...",
  "created_at": "...",
  "file_url_hint": "/api/sbis/requirements/12/"
}
```

Файла в webhook **нет** — забирайте через GET detail.

---

## Дедупликация на стороне sbis-norm

Уникальность: `(inn, sbis_doc_id)`.  
Дополнительно не плодим одинаковый контент за одну дату: `(inn, document_date, content_sha256)`.

Внешнему сервису достаточно опираться на `id` или пару `(inn, sbis_doc_id)` / `content_sha256`.

---

## Что сканер кладёт в БД

| Поле | Смысл |
|------|--------|
| `inn` | ИНН организации |
| `document_date` | дата требования |
| `sbis_doc_id` | id документа в СБИС |
| `doc_title` | название из СБИС |
| `file_b64` | содержимое (часто PDF после decrypt) |
| `storage_file_name` | рекомендуемое имя файла |
| `content_sha256` | хеш содержимого |
| `created_at` | когда сохранили у нас |
| `external_synced_at` | когда забрал внешний сервис |

Сканер: whitelist `docs/requirements_scan_inns.txt` (лавки + новые), окно **10 дней**, расписание **17:00 Europe/Moscow**.

---

## Проверка «всё работает» (на сервере)

```bash
cd /opt/sbis-norm
git pull origin main
docker compose exec -T web python manage.py migrate

# 1) есть ли записи
docker compose exec -T web python manage.py list_requirement_documents --limit 5

# 2) list API
curl -sS "http://127.0.0.1:8000/api/sbis/requirements/?unsynced=1&limit=3" | python3 -m json.tool | head -80

# 3) detail (подставь id из list)
ID=$(curl -sS "http://127.0.0.1:8000/api/sbis/requirements/?unsynced=1&limit=1" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['results'][0]['id'] if r.get('results') else '')")
echo "ID=$ID"
curl -sS "http://127.0.0.1:8000/api/sbis/requirements/${ID}/" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('inn', d.get('inn'), 'date', d.get('document_date'), 'file_b64_len', len(d.get('file_b64') or ''), 'name', d.get('storage_file_name'))
"

# 4) mark-synced + проверка что пропал из unsynced
curl -sS -X POST "http://127.0.0.1:8000/api/sbis/requirements/mark-synced/" \
  -H "Content-Type: application/json" \
  -d "{\"ids\": [${ID}]}"
curl -sS "http://127.0.0.1:8000/api/sbis/requirements/?unsynced=1&limit=5" | python3 -c "
import sys,json
r=json.load(sys.stdin)
ids=[x['id'] for x in r.get('results') or []]
print('still_unsynced_contains', ${ID} in ids, 'count', r.get('count'))
"
```

Если с токеном:

```bash
export TOK='your-token'
curl -sS -H "X-API-Key: $TOK" "http://127.0.0.1:8000/api/sbis/requirements/?unsynced=1&limit=3"
```

Снаружи (публичный хост), пример:

```bash
curl -sS "http://146.19.125.77:8000/api/sbis/requirements/?unsynced=1&limit=3"
```

---

## Типичные ошибки интеграции

| Симптом | Что сделать |
|---------|-------------|
| `count: 0` при unsynced | сканер ещё не сохранил / всё уже mark-synced / пустая БД |
| 401 | неверный `X-API-Key` |
| огромный list с `include_file=1` | не использовать; брать файл через detail |
| дубли у себя | ключ `(inn, sbis_doc_id)` или `content_sha256` |

---

## Связанные ops-команды (не для внешнего API)

```bash
# ручной прогон сканера
python manage.py fetch_requirements_all_companies --days 10 --workers 1

# список в консоли
python manage.py list_requirement_documents --limit 20
```
