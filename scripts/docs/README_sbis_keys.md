# Установка ключей СБИС на Linux (скрипт)

Скрипт `sbis_keys_install_linux.sh` автоматизирует цепочку из инструкции: распаковка архивов с ключами → выравнивание подпапок → экспорт сертификатов → установка в uMy с привязкой к контейнеру → вывод команд для Django.

Полная цепочка до SESSION_ID в Django описана в [SBIS_KEYS_LINUX_CHAIN.md](SBIS_KEYS_LINUX_CHAIN.md).

## Требования

- Linux с установленным **Linux-CSP** (`/opt/cprocsp/bin/amd64/csptest`, `certmgr`)
- **unzip** для .zip
- **unrar** или **unar** для .rar
- Запуск с **sudo** (запись в `/var/opt/cprocsp/keys/root/` и вызов certmgr)

## Использование

```bash
# Все архивы в одной папке (например после megadl)
sudo ./sbis_keys_install_linux.sh --source ~/mega_signatures

# Только распаковать и вывести список контейнеров (не трогать uMy)
sudo ./sbis_keys_install_linux.sh --source ~/mega_signatures --dry-run

# Свой каталог CSP (по умолчанию /var/opt/cprocsp/keys/root)
sudo ./sbis_keys_install_linux.sh --source ~/keys --csp-root /var/opt/cprocsp/keys/root
```

## Что делает скрипт

1. **Поиск архивов** в `--source` (*.zip, *.rar) через `find` (подходит для тысяч файлов). Из имени файла извлекается ИНН (10 цифр подряд). При ошибке распаковки одного архива скрипт пишет «Ошибка unzip/unrar, пропуск» и продолжает остальные.
2. **Распаковка**: для каждого ИНН создаётся `$CSP_ROOT/$INN`, архив распаковывается туда.
3. **Выравнивание**: если внутри `$CSP_ROOT/$INN` одна подпапка и нет `.key` в корне — содержимое подпапки переносится на уровень выше (чтобы CSP подхватил контейнер).
4. **Контейнеры**: вызывается `csptest -keyset -enum_cont -fqcn`.
5. **Экспорт и uMy**: для каждого контейнера пробуют `certmgr -export -cont "<имя как в csptest>" -dest /tmp/...`; при успехе — `certmgr -inst -store uMy -file ... -cont "<то же имя>"` (так создаётся PrivateKey Link, нужный для СБИС). Если экспорт даёт 0x8010001c (в контейнере нет серта), скрипт ищет `.cer` в папке по ИНН из имени контейнера и ставит его с `-cont`; контейнеры без ИНН в имени пропускаются. Имя контейнера в certmgr передаётся как в выводе csptest (без лишнего экранирования).
6. В конце выводится `certmgr -list -store uMy` и примеры `Certificate.objects.get_or_create(...)` для Django.

## Подпапки в архивах

Если архив распаковывается в структуру вида `7751224222/veles/*.key` или `9721146348/9721146348/*.key`, скрипт автоматически поднимает файлы в `7751224222/*.key`, чтобы Linux-CSP увидел контейнер по пути `.../root/7751224222/`.

## Если на сервере «command not found»

Такое бывает из‑за переводов строк Windows (CRLF). На сервере выполните:

```bash
# убрать \r в конце строк
sed -i 's/\r$//' sbis_keys_install_linux.sh
# права на выполнение
chmod +x sbis_keys_install_linux.sh
# затем снова
sudo ./sbis_keys_install_linux.sh --source ~/keys --csp-root /var/opt/cprocsp/keys/root
```

Либо запуск через bash явно (без прав на выполнение):  
`sudo bash sbis_keys_install_linux.sh --source ~/keys --csp-root /var/opt/cprocsp/keys/root`
