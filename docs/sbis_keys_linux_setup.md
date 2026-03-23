# Подключение ключей СБИС на Linux (ВЕЛЕС + ПАРТСКОРП)

Пошаговая последовательность команд для двух новых организаций. На сервере должен быть установлен Linux-CSP. Команды с CSP и записью в `/var/opt/cprocsp/` выполняются через `sudo`; скачивание можно делать из своей домашней папки (например, под `devuser`).

---

## Исходные данные

| Организация | ИНН       | Файл с ключами |
|-------------|-----------|----------------------------------------|
| СТРОИТЕЛЬНАЯ КОМПАНИЯ ВЕЛЕС | 7751224222 | [Mega RAR](https://mega.nz/file/6p5lVazC#XJEitEEOE0xM1oftY87XOdBp01pSdRT2CY79ExEvr0s) |
| ПАРТСКОРП   | 9721146348 | [Mega ZIP](https://mega.nz/file/ig5ASZiC#ojG7Zj4X8ZmSep31tV8Y8ThaIx-hvfvlrzQfBQV2WGY) |

---

## 0. Подготовка (один раз)

Установить утилиты, если ещё нет:

```bash
# Для распаковки RAR (ВЕЛЕС)
apt-get update && apt-get install -y unrar-free || (apt-get install -y unrar 2>/dev/null || true)

# Опционально: для скачивания с Mega с сервера (если не копируете архивы вручную)
# apt-get install -y megatools
```

Создать каталог для архивов и перейти в него. Если работаете не под root (например, под `devuser`), используйте домашний каталог:

```bash
mkdir -p ~/keys
cd ~/keys
```

Скачать архивы с Mega (один из способов):

- **Вариант А:** скачать на своём ПК по ссылкам выше, затем скопировать на сервер в `~/keys/` (scp, rsync, WinSCP и т.п.).
- **Вариант Б:** если установлен `megatools`, из любой папки (например, из `~`):
  ```bash
  megadl 'https://mega.nz/file/6p5lVazC#XJEitEEOE0xM1oftY87XOdBp01pSdRT2CY79ExEvr0s'
  megadl 'https://mega.nz/file/ig5ASZiC#ojG7Zj4X8ZmSep31tV8Y8ThaIx-hvfvlrzQfBQV2WGY'
  ```
  Файлы появятся в текущем каталоге. Перенести их в `~/keys`:  
  `mkdir -p ~/keys && mv *.rar *.zip ~/keys/ 2>/dev/null; cd ~/keys`

Проверить, что файлы на месте (имена могут отображаться «кракозябрами» из‑за кодировки — это нормально):

```bash
ls -la ~/keys/
# или по маске:
ls ~/keys/*.rar ~/keys/*.zip 2>/dev/null
# Должны быть: один RAR (ВЕЛЕС), один ZIP (ПАРТСКОРП)
```

---

## 1. Распаковка контейнеров

Архивы лежат в `~` (или в `~/keys`). Каталоги CSP создаём и заполняем через **sudo**.

Создать каталоги по ИНН (требуется sudo):

```bash
sudo mkdir -p /var/opt/cprocsp/keys/root/7751224222
sudo mkdir -p /var/opt/cprocsp/keys/root/9721146348
```

Перенести архивы в одну папку (если ещё не там) и перейти в неё:

```bash
mkdir -p ~/keys
mv ~/*.rar ~/*.zip ~/keys/ 2>/dev/null
cd ~/keys
```

Узнать точные имена файлов (если в `ls` отображаются знаки вопроса):

```bash
ls -1 *.rar *.zip 2>/dev/null
# Или: ls -b
```

Распаковать **ВЕЛЕС** (RAR). Подставьте вместо `ФАЙЛ.rar` имя из вывода предыдущей команды (можно подставить по табуляции):

```bash
# Если установлен unrar:
sudo unrar x "ФАЙЛ.rar" /var/opt/cprocsp/keys/root/7751224222/

# Если только unar (unrar-free):
sudo unar "ФАЙЛ.rar" -o /var/opt/cprocsp/keys/root/7751224222/
```

Распаковать **ПАРТСКОРП** (ZIP) — подставьте имя ZIP-файла:

```bash
sudo unzip "ФАЙЛ.zip" -d /var/opt/cprocsp/keys/root/9721146348
```

Проверить, что внутри каталогов есть файлы контейнеров (обычно несколько `.key` и т.п.):

```bash
sudo ls -la /var/opt/cprocsp/keys/root/7751224222/
sudo ls -la /var/opt/cprocsp/keys/root/9721146348/
```

---

## 2. Проверка, что CSP видит контейнеры

```bash
sudo /opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -fqcn
```

В выводе должны появиться две новые строки вида:

- `\\.\HDIMAGE\...` для ВЕЛЕС (7751224222)
- `\\.\HDIMAGE\...` для ПАРТСКОРП (9721146348)

Имена могут быть как читаемые (название организации), так и UUID. **Скопируйте эти две строки целиком** — они понадобятся ниже как `CONTAINER_VELES` и `CONTAINER_PARTSKORP`.

Пример (ваши значения будут другими):

```
\\.\HDIMAGE\ООО "ВЕЛЕС"
\\.\HDIMAGE\a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

## 3. Экспорт сертификатов из контейнеров

Подставьте вместо `CONTAINER_VELES` и `CONTAINER_PARTSKORP` **точные** строки из вывода шага 2. В командах контейнер задаётся с экранированием обратных слэшей: `\\\\\\.\\\\HDIMAGE\\\\...`

**ВЕЛЕС (7751224222):**

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "CONTAINER_VELES" \
  -dest /tmp/veles_7751224222.cer
```

Пример (если контейнер был `\\.\HDIMAGE\ООО "ВЕЛЕС"`):

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "\\\\.\\HDIMAGE\\ООО \"ВЕЛЕС\"" \
  -dest /tmp/veles_7751224222.cer
```

**ПАРТСКОРП (9721146348):**

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "CONTAINER_PARTSKORP" \
  -dest /tmp/partskorp_9721146348.cer
```

Пример (если контейнер был `\\.\HDIMAGE\a1b2c3d4-e5f6-7890-abcd-ef1234567890`):

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -export \
  -cont "\\\\.\\HDIMAGE\\a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -dest /tmp/partskorp_9721146348.cer
```

Проверка:

```bash
ls -la /tmp/veles_7751224222.cer /tmp/partskorp_9721146348.cer
```

---

## 4. Установка сертификатов в uMy с привязкой к контейнерам

Та же пара контейнеров: `CONTAINER_VELES` и `CONTAINER_PARTSKORP` — те же строки, что в шаге 3.

**ВЕЛЕС:**

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -inst \
  -store uMy \
  -file /tmp/veles_7751224222.cer \
  -cont "CONTAINER_VELES"
```

**ПАРТСКОРП:**

```bash
sudo /opt/cprocsp/bin/amd64/certmgr \
  -inst \
  -store uMy \
  -file /tmp/partskorp_9721146348.cer \
  -cont "CONTAINER_PARTSKORP"
```

---

## 5. Проверка uMy

```bash
sudo /opt/cprocsp/bin/amd64/certmgr -list -store uMy
```

У обоих сертификатов должно быть:

- **PrivateKey Link : Yes**
- **Container : HDIMAGE\\...** (путь к контейнеру)

ИНН в сертификатах: 7751224222 и 9721146348.

---

## 6. Запись в Django (Certificate)

Код ищет сертификат по полю `inn` и использует `csptest_name` для экспорта (certmgr -export -cont). Нужно создать две записи `Certificate` с правильным `csptest_name`.

**Вариант А — через management-команду (если есть scan_certificates):**

После шагов 1–5 выполнить на сервере в каталоге проекта:

```bash
cd /path/to/sbis_api_backend
source .venv/bin/activate   # или ваш способ активации venv
python manage.py scan_certificates
```

Команда может подхватить новые контейнеры из CSP и создать/обновить записи. Проверьте в админке или в БД, что у записей с `inn=7751224222` и `inn=9721146348` заполнены `csptest_name` и при необходимости `thumbprint`.

**Вариант Б — вручную через shell Django:**

```bash
cd /path/to/sbis_api_backend
source .venv/bin/activate
python manage.py shell
```

В shell (подставьте свои значения `csptest_name` из шага 2):

```python
from reports.models import Certificate

# ВЕЛЕС — замените на фактическое имя контейнера из csptest -enum_cont -fqcn
Certificate.objects.get_or_create(
    inn="7751224222",
    defaults={
        "csptest_name": r"\\.\HDIMAGE\ООО \"ВЕЛЕС\"",  # или UUID из шага 2
        "source": "LOCAL",
    },
)

# ПАРТСКОРП
Certificate.objects.get_or_create(
    inn="9721146348",
    defaults={
        "csptest_name": r"\\.\HDIMAGE\a1b2c3d4-e5f6-7890-abcd-ef1234567890",  # из шага 2
        "source": "LOCAL",
    },
)
```

Проверка авторизации в СБИС из Django:

```python
from reports.models import Certificate
from reports.sbis_service import auth_sbis_by_cert, get_thumbprint_from_cert, export_cert_der
import tempfile, os

for inn in ["7751224222", "9721146348"]:
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not cert.csptest_name:
        print(f"Нет сертификата для ИНН {inn}")
        continue
    path = f"/tmp/sbis_check_{inn}.cer"
    export_cert_der(cert.csptest_name, path)
    thumb = get_thumbprint_from_cert(path)
    session_id = auth_sbis_by_cert(path, thumb, inn=inn)
    print(f"ИНН {inn}: SESSION_ID = {session_id}")
    os.remove(path)
```

---

## Скрипт автоматической установки (папка с архивами)

В репозитории есть скрипт `scripts/sbis_keys_install_linux.sh`, который по папке с архивами (.zip / .rar) делает всё по шагам:

1. Находит в именах файлов ИНН (10 цифр), создаёт под каждым ИНН каталог в `/var/opt/cprocsp/keys/root/`.
2. Распаковывает архивы (unzip / unrar или unar).
3. **Выравнивает подпапки**: если внутри каталога ИНН одна подпапка (например `veles/` или `9721146348/`) и нет файлов `.key` в корне — поднимает содержимое на уровень выше, чтобы CSP увидел контейнер.
4. Получает список контейнеров через `csptest -keyset -enum_cont -fqcn`.
5. Для каждого контейнера: экспорт сертификата → установка в uMy с привязкой к контейнеру (`certmgr -inst -store uMy -file ... -cont ...`).
6. Выводит проверку `certmgr -list -store uMy` и готовые строки для создания записей `Certificate` в Django.

**Запуск (на сервере с Linux-CSP, с sudo):**

```bash
# Архивы в ~/mega_signatures (или укажите свою папку)
sudo ./scripts/sbis_keys_install_linux.sh --source ~/mega_signatures

# Только распаковать и показать контейнеры, без установки в uMy
sudo ./scripts/sbis_keys_install_linux.sh --source ~/mega_signatures --dry-run
```

Опции: `--source DIR` (папка с архивами), `--csp-root DIR` (по умолчанию `/var/opt/cprocsp/keys/root`), `--dry-run` (без установки в uMy).

---

## Краткий чеклист

1. Скачать/скопировать оба архива в `/root/keys/`.
2. Создать каталоги `7751224222` и `9721146348` в `/var/opt/cprocsp/keys/root/`.
3. Распаковать RAR в каталог ВЕЛЕС, ZIP — в каталог ПАРТСКОРП.
4. Выполнить `csptest -keyset -enum_cont -fqcn` и сохранить точные имена контейнеров.
5. Экспортировать сертификаты: `certmgr -export -cont "..." -dest /tmp/....cer`.
6. Установить в uMy с привязкой: `certmgr -inst -store uMy -file ... -cont "..."`.
7. Проверить: `certmgr -list -store uMy` (PrivateKey Link : Yes).
8. Создать/обновить записи `Certificate` в Django с правильным `csptest_name` и `inn`.

После этого подписи и авторизация в СБИС через `SbisSessionService` / `auth_sbis_by_cert` будут работать для ИНН 7751224222 и 9721146348.
