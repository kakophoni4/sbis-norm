# Цепочка: ключи СБИС на Linux → SESSION_ID в Django

От распаковки архивов с ключами до получения SESSION_ID через SbisSessionService.

## 1. Распаковка контейнеров на Linux

Скопировать ZIP‑архивы (например с Mega) на сервер, например в `~/mega_signatures` или `/root/keys/`.

Под root развернуть каждый архив с 6 .key:

```bash
mkdir -p /var/opt/cprocsp/keys/root/9715376022
mkdir -p /var/opt/cprocsp/keys/root/9722082369
mkdir -p /var/opt/cprocsp/keys/root/9715472576

unzip "ООО МОДЭМ-ПРОЭКТ 9715376022.zip" -d /var/opt/cprocsp/keys/root/9715376022
unzip "ООО МОЛТЕСТ 9722082369.zip"       -d /var/opt/cprocsp/keys/root/9722082369
unzip "ООО СТРОЙТЕХПЛЮС 9715472576.zip" -d /var/opt/cprocsp/keys/root/9715472576
```

Проверить, что контейнеры подхватились:

```bash
sudo /opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -fqcn
# Должно быть:
# \\.\HDIMAGE\ООО "МОДЭМ-ПРОЭКТ"
# \\.\HDIMAGE\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297
# \\.\HDIMAGE\286918236-b48c-96eb-238d-fb295c9c483
```

Linux‑CSP подхватывает файловые контейнеры по папкам HDIMAGE в `/var/opt/cprocsp/keys/root`.

## 2. Экспорт сертификатов из контейнеров на Linux

Под root извлечь сертификаты из HDIMAGE‑контейнеров. **certmgr при -export -cont берёт «родной» X.509 из контейнера с привязкой к его ключу.**

```bash
# Имя контейнера — как в выводе csptest, в кавычках с экранированием для shell:
sudo /opt/cprocsp/bin/amd64/certmgr -export -cont "\\\\.\\HDIMAGE\\76d8edb05-7c0d-6529-4e12-b6757cd0c1e" -dest /tmp/moltest.cer
sudo /opt/cprocsp/bin/amd64/certmgr -export -cont "\\\\.\\HDIMAGE\\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297" -dest /tmp/stroyteh.cer
```

## 3. Установка сертификатов в uMy с привязкой к контейнерам

Чтобы в uMy у каждого серта было **PrivateKey Link : Yes** и прописался нужный HDIMAGE‑контейнер:

```bash
sudo /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/moltest.cer -cont "\\\\.\\HDIMAGE\\76d8edb05-7c0d-6529-4e12-b6757cd0c1e"
sudo /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/stroyteh.cer -cont "\\\\.\\HDIMAGE\\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297"
```

Проверка:

```bash
sudo /opt/cprocsp/bin/amd64/certmgr -list -store uMy
```

Ожидается: **PrivateKey Link : Yes**, **Container : HDIMAGE\\ИНН\\...**

## 4. Авторизация в СБИС по сертификату на Linux

SbisSessionService.authenticate():

1. Берёт сертификат из uMy по SHA1‑отпечатку/ИНН.
2. JSON‑RPC к методу **СБИС.АутентифицироватьПоСертификату** (передаёт Base64 DER сертификата).
3. Расшифровывает ответ через **cryptcp -decr -thumbprint &lt;SHA1&gt; ...** (приватный ключ по сертификату из uMy).
4. Читает SESSION_ID из расшифрованного файла.

Без **PrivateKey Link : Yes** cryptcp по thumbprint не находит ключ — авторизация не работает.

## 5. Что важно помнить

Вся магия на Linux — **привязка PrivateKey Link к контейнеру** через:

`certmgr -inst -store uMy -file &lt;.cer&gt; -cont "\\\\.\\HDIMAGE\\&lt;имя_контейнера&gt;"`

Имя контейнера — точно как в выводе `csptest -keyset -enum_cont -fqcn` (один обратный слэш перед каждой частью в значении, в bash‑команде экранируют как `"\\\\.\\HDIMAGE\\..."`).

## 6. Django под пользователем (devuser) и «Keyset does not exist»

Ключи установлены под **root** (`sudo ./sbis_keys_install_linux.sh`), хранятся в `/var/opt/cprocsp/keys/root/`. Если Django (или celery) запущен от **devuser**, вызовы `certmgr`/`cryptcp` не видят эти контейнеры → «Failed to open container», «Keyset does not exist».

**Решение:** вызывать certmgr и cryptcp через **sudo**. В коде включено по умолчанию (`CSP_USE_SUDO = True` в настройках Django). Нужно разрешить devuser запускать эти утилиты без пароля:

```bash
sudo visudo
# Добавить строку (подставьте путь к certmgr/cryptcp при необходимости):
devuser ALL=(ALL) NOPASSWD: /opt/cprocsp/bin/amd64/certmgr, /opt/cprocsp/bin/amd64/cryptcp
```

Отключить sudo для CSP (если приложение крутится под root): в `settings.py` задать `CSP_USE_SUDO = False`.
