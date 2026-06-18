# Цепочка: ключи СБИС на Linux → SESSION_ID в Django

Полная рабочая последовательность: от ZIP/RAR с ключами до `SESSION_ID` через `SbisSessionService`.

**Главное правило:** без **PrivateKey Link : Yes** в uMy (`certmgr -inst -store uMy -file ... -cont ...`) `cryptcp -decr -thumbprint` не находит ключ — авторизация в СБИС не работает.

---

## Схема

```
архив .zip/.rar
    → /var/opt/cprocsp/keys/root/{ИНН}/*.key
    → csptest видит \\.\HDIMAGE\...
    → certmgr -export -cont ... → .cer
    → certmgr -inst -store uMy -file ... -cont ...  (PrivateKey Link: Yes)
    → scan_certificates → таблица Certificate
    → SbisSessionService.authenticate() → SESSION_ID
```

---

## Вариант A — автоматически (массово, ~1000 подписей)

Проект: `/opt/sbis-norm`, архив `signatures_valid_latest.zip` лежит в git.

```bash
cd /opt/sbis-norm
git pull
docker compose up -d

# 1) Распаковка на хосте + certmgr/uMy в Docker + БД
sudo bash scripts/ops/install_signatures_from_bundle.sh

# 2) has_private_key=True для всех контейнеров
docker compose exec web python manage.py sync_has_private_key

# 3) Проверка одного ИНН
docker compose exec web python manage.py test_sbis_auth_one 9722082369
```

Скрипт `install_signatures_from_bundle.sh`:
1. Распаковывает bundle → `/root/mega_signatures_extracted/{ИНН}/...`
2. Кладёт `.key` в `/var/opt/cprocsp/keys/root/{ИНН}/`
3. В контейнере `web`: экспорт сертов + uMy (лучший действующий на ИНН)
4. `python manage.py scan_certificates --clear`

---

## Вариант B — вручную (3 организации, как эталон)

### 1. Распаковка контейнеров

Скопировать ZIP на сервер, например в `/root/keys/`.

```bash
mkdir -p /var/opt/cprocsp/keys/root/9715376022
mkdir -p /var/opt/cprocsp/keys/root/9722082369
mkdir -p /var/opt/cprocsp/keys/root/9715472576

unzip "ООО МОДЭМ-ПРОЭКТ 9715376022.zip" -d /var/opt/cprocsp/keys/root/9715376022
unzip "ООО МОЛТЕСТ 9722082369.zip"       -d /var/opt/cprocsp/keys/root/9722082369
unzip "ООО СТРОЙТЕХПЛЮС 9715472576.zip" -d /var/opt/cprocsp/keys/root/9715472576
```

Если внутри архива одна подпапка — поднять `.key` на уровень `{ИНН}/` (скрипт делает это сам).

Проверка:

```bash
/opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -fqcn
```

Ожидается, например:

```
\\.\HDIMAGE\ООО "МОДЭМ-ПРОЭКТ"
\\.\HDIMAGE\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297
\\.\HDIMAGE\286918236-b48c-96eb-238d-fb295c9c483
```

Linux-CSP подхватывает файловые контейнеры из `/var/opt/cprocsp/keys/root/`.

**Docker:** монтируется только `/var/opt/cprocsp/keys` — ключи на хосте видны в контейнере `web`.

---

### 2. Экспорт сертификатов из контейнеров

Имя контейнера — **точно** как в `csptest`. В bash экранирование: `"\\\\.\\HDIMAGE\\..."`.

```bash
# MOLTEST
/opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "\\\\.\\HDIMAGE\\286918236-b48c-96eb-238d-fb295c9c483" \
  -dest /tmp/moltest_from_container.cer

# СТРОЙТЕХПЛЮС
/opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "\\\\.\\HDIMAGE\\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297" \
  -dest /tmp/third_from_container.cer

# МОДЭМ-ПРОЭКТ (аналогично, контейнер из csptest)
/opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "\\\\.\\HDIMAGE\\ООО \"МОДЭМ-ПРОЭКТ\"" \
  -dest /tmp/modem_from_container.cer
```

`certmgr -export -cont` берёт X.509 из контейнера с привязкой к его ключу.

**В Docker** (от root внутри контейнера):

```bash
docker compose exec -u root web /opt/cprocsp/bin/amd64/certmgr \
  -export -cont '\\\\.\\HDIMAGE\\286918236-b48c-96eb-238d-fb295c9c483' \
  -dest /tmp/moltest.cer
```

---

### 3. Установка в uMy с привязкой к контейнеру

```bash
# СТРОЙТЕХПЛЮС
/opt/cprocsp/bin/amd64/certmgr \
  -inst -store uMy \
  -file /tmp/third_from_container.cer \
  -cont "\\\\.\\HDIMAGE\\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297"

# MOLTEST
/opt/cprocsp/bin/amd64/certmgr \
  -inst -store uMy \
  -file /tmp/moltest_from_container.cer \
  -cont "\\\\.\\HDIMAGE\\286918236-b48c-96eb-238d-fb295c9c483"

# МОДЭМ-ПРОЭКТ
/opt/cprocsp/bin/amd64/certmgr \
  -inst -store uMy \
  -file /tmp/modem_from_container.cer \
  -cont "\\\\.\\HDIMAGE\\ООО \"МОДЭМ-ПРОЭКТ\""
```

Проверка:

```bash
/opt/cprocsp/bin/amd64/certmgr -list -store uMy
```

Ожидаемое состояние:

| Организация | ИНН | PrivateKey Link | Container |
|-------------|-----|-----------------|-----------|
| СТРОЙТЕХПЛЮС | 9715472576 | Yes | HDIMAGE\\9715472576\\4698 |
| MOLTEST | 9722082369 | Yes | HDIMAGE\\9722082369\\06FC |
| МОДЭМ-ПРОЭКТ | 9715376022 | Yes | HDIMAGE\\9715376022\\6FF9 |

---

### 4. Запись в Django (таблица Certificate)

```bash
cd /opt/sbis-norm
docker compose exec web python manage.py scan_certificates
docker compose exec web python manage.py sync_has_private_key
```

Проверка в shell:

```python
from reports.models import Certificate
list(Certificate.objects.filter(inn="9722082369").values("inn", "csptest_name", "has_private_key"))
```

---

### 5. Авторизация в СБИС

HTTP-запрос (через NodeMaven RU-прокси, иначе с датацентра часто 500):

```http
POST https://online.sbis.ru/auth/service/
Content-Type: application/json-rpc;charset=utf-8

{
  "jsonrpc": "2.0",
  "method": "СБИС.АутентифицироватьПоСертификату",
  "params": {
    "Сертификат": {
      "ДвоичныеДанные": "<Base64 DER>",
      "ИНН": "9722082369",
      "ФИО": "..."
    }
  },
  "id": 1
}
```

Ответ — зашифрованная строка (Base64). Расшифровка:

```bash
/opt/cprocsp/bin/amd64/cryptcp \
  -decr -silent -nochain -norev \
  -thumbprint <SHA1_отпечаток> \
  /tmp/sbis_key.enc /tmp/sbis_key.dec
```

В Django всё это делает `SbisSessionService.authenticate()`:

```bash
docker compose exec web python manage.py test_sbis_auth_one 9722082369
```

Успех:

```
Session ID: 02684493-026d493b-0bce-f86a53d7e9374a59
```

В коде:

```python
from reports.models import Certificate
from reports.services.sbis_mail import SbisSessionService

cert = Certificate.objects.filter(inn="9722082369", has_private_key=True).first()
session_id = SbisSessionService(certificate=cert).authenticate()
```

`CertificateAuditLog` пишет шаги и ошибки.

---

## Вариант C — скрипт на папку с архивами

```bash
cd /opt/sbis-norm
sudo bash scripts/ops/sbis_keys_install_linux.sh --source ~/mega_signatures

# Только распаковка:
sudo bash scripts/ops/sbis_keys_install_linux.sh --source ~/mega_signatures --unpack-only

# Только uMy (ключи уже на диске):
docker compose exec -u root web bash /app/scripts/ops/sbis_keys_install_linux.sh --install-only

docker compose exec web python manage.py scan_certificates --clear
docker compose exec web python manage.py sync_has_private_key
```

Опции: `--recursive` (bundle вида `{ИНН}/архив.zip`), `--dry-run`.

---

## Массовая проверка: какие ИНН живые в СБИС

```bash
docker compose exec web python manage.py test_sbis_auth_all --quiet --limit 50
# полный прогон (долго):
docker compose exec web python manage.py test_sbis_auth_all --quiet --delay 1
```

Отчёты: `/app/media/sbis_auth_scan/`
- `valid_inns_*.txt` — авторизовались
- `sbis_auth_report_*.csv` — все ИНН + причина ошибки

Типичные ошибки СБИС (не баг сервера):
- `revoked_or_untrusted` — отозван / не доверенный
- `not_registered_in_sbis` — не зарегистрирован в СБИС

---

## Docker / окружение

| Параметр | Значение |
|----------|----------|
| Проект | `/opt/sbis-norm` |
| Ключи на хосте | `/var/opt/cprocsp/keys/root/{ИНН}/` |
| CryptoPro в контейнере | `/opt/cprocsp/bin/amd64/` |
| `CSP_USE_SUDO` | `False` (контейнер `web` от root) |
| `NODEMAVEN_API_KEY` | обязателен для запросов в СБИС |
| DNS в compose | `8.8.8.8`, `1.1.1.1` |

Проверка NodeMaven:

```bash
docker compose exec web python manage.py test_nodemaven
```

---

## Частые проблемы

| Симптом | Решение |
|---------|---------|
| `csptest` пустой | Проверить `.key` в `/var/opt/cprocsp/keys/root/{ИНН}/`, выровнять подпапки |
| `Keyset does not exist` | Нет PrivateKey Link — повторить шаг 3 (`certmgr -inst`) |
| `Failed to resolve online.sbis.ru` | `docker compose down && up -d` (DNS в compose) |
| `collected=0` прокси | `NODEMAVEN_API_KEY` + `NODEMAVEN_APIKEY` в `app.env` |
| Только 2 ИНН в скане | `sync_has_private_key --all` |
| Сертификат отозван | Другой контейнер на тот же ИНН или другой ИНН |

---

## Чеклист

- [ ] Архивы распакованы в `/var/opt/cprocsp/keys/root/{ИНН}/`
- [ ] `csptest -enum_cont` показывает контейнеры
- [ ] `certmgr -list -store uMy` → **PrivateKey Link : Yes**
- [ ] `scan_certificates` + `sync_has_private_key`
- [ ] `test_nodemaven` → OK
- [ ] `test_sbis_auth_one <ИНН>` → Session ID
