#!/usr/bin/env bash
#
# Установка ключей СБИС на Linux по инструкции:
# распаковка архивов (ZIP/RAR) → выравнивание подпапок → экспорт сертов → установка в uMy с привязкой к контейнеру.
#
# Требования: Linux-CSP, unzip, unrar или unar. Запуск с sudo для шагов CSP.
#
# Использование:
#   sudo ./sbis_keys_install_linux.sh [--source DIR] [--csp-root DIR] [--dry-run]
#   --source   папка с архивами .zip/.rar (по умолчанию: текущая или ~/mega_signatures)
#   --csp-root каталог ключей CSP (по умолчанию: /var/opt/cprocsp/keys/root)
#   --dry-run  только распаковать и вывести список контейнеров, не ставить в uMy
#
set -euo pipefail

CSPTEST="${CSPTEST:-/opt/cprocsp/bin/amd64/csptest}"
CERTMGR="${CERTMGR:-/opt/cprocsp/bin/amd64/certmgr}"
SOURCE_DIR=""
CSP_ROOT="/var/opt/cprocsp/keys/root"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)   SOURCE_DIR="$2"; shift 2 ;;
    --csp-root) CSP_ROOT="$2";   shift 2 ;;
    --dry-run)  DRY_RUN=true;   shift 1 ;;
    *) echo "Неизвестный аргумент: $1"; exit 1 ;;
  esac
done

if [[ -z "$SOURCE_DIR" ]]; then
  if [[ -d "$HOME/mega_signatures" ]]; then
    SOURCE_DIR="$HOME/mega_signatures"
  else
    SOURCE_DIR="."
  fi
fi
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"

echo "Источник архивов: $SOURCE_DIR"
echo "Каталог CSP:      $CSP_ROOT"
echo ""

# Из имени файла достаём ИНН (10 цифр подряд). Без совпадения — пустая строка, без выхода по set -e.
get_inn_from_filename() {
  local name="$1"
  echo "$name" | grep -oE '[0-9]{10}' | head -1 || true
}

# Распаковка одного архива в каталог по ИНН
unpack_archive() {
  local archive="$1"
  local inn="$2"
  local dest="${CSP_ROOT}/${inn}"
  local base; base="$(basename "$archive")"
  local ext="${base##*.}"

  echo "  Распаковка: $base -> $dest"
  mkdir -p "$dest"
  case "${ext,,}" in
    zip)
      if ! unzip -o -q "$archive" -d "$dest" 2>/dev/null; then
        echo "  Ошибка unzip, пропуск архива." >&2
        return 1
      fi
      ;;
    rar)
      if command -v unrar &>/dev/null; then
        if ! unrar x -o+ "$archive" "$dest/" 2>/dev/null; then
          echo "  Ошибка unrar, пропуск архива." >&2
          return 1
        fi
      elif command -v unar &>/dev/null; then
        if ! unar -o "$dest" "$archive" 2>/dev/null; then
          echo "  Ошибка unar, пропуск архива." >&2
          return 1
        fi
      else
        echo "  Ошибка: нужен unrar или unar для RAR." >&2
        return 1
      fi
      ;;
    *)
      echo "  Пропуск (не zip/rar): $base" >&2
      return 0
      ;;
  esac
  # Выравнивание: если внутри одна подпапка и нет .key в корне — поднять содержимое
  local one sub
  one=""
  for sub in "$dest"/*/; do
    [[ -d "$sub" ]] || continue
    if [[ -n "$one" ]]; then
      one=""
      break
    fi
    one="$sub"
  done
  if [[ -n "$one" ]] && [[ ! -f "$dest"/*.key ]]; then
    echo "  Выравнивание подпапки: $(basename "$one")"
    shopt -s nullglob
    mv "$one"* "$dest/" 2>/dev/null || true
    rmdir "$one" 2>/dev/null || true
    shopt -u nullglob
  fi
  return 0
}

# Список контейнеров HDIMAGE из csptest (строки вида \\.\HDIMAGE\...)
list_containers() {
  "$CSPTEST" -keyset -enum_cont -fqcn 2>/dev/null | grep 'HDIMAGE' | grep -E '^\\' || true
}

# Имя контейнера в certmgr передаём как из csptest (один \ перед каждой частью).
# Удваивать слэши не нужно — иначе PrivateKey Link не создаётся.

# ИНН из сертификата (certmgr -list -file)
get_inn_from_cert() {
  local cert_path="$1"
  "$CERTMGR" -list -file "$cert_path" 2>/dev/null | grep -oE 'ИНН ЮЛ=[0-9]+' | head -1 | grep -oE '[0-9]+' || echo ""
}

# SHA1 Thumbprint из сертификата
get_thumbprint_from_cert() {
  local cert_path="$1"
  "$CERTMGR" -list -file "$cert_path" 2>/dev/null | grep -i "SHA1 Thumbprint" | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '\r\n' | tr '[:upper:]' '[:lower:]' || echo ""
}

# ИНН из имени контейнера (например "9718273748messa" -> 9718273748)
get_inn_from_cont_name() {
  local cont="$1"
  local name="${cont##*\\}"
  echo "$name" | grep -oE '[0-9]{10}' | head -1 || true
}

# Есть ли ИНН в списке распакованных
inn_in_seen() {
  local inn="$1"
  local s
  for s in "${seen_inns[@]}"; do
    [[ "$s" == "$inn" ]] && return 0
  done
  return 1
}

# Первый .cer в каталоге CSP_ROOT/INN (включая подпапки)
find_cer_for_inn() {
  local inn="$1"
  find "${CSP_ROOT}/${inn}" -maxdepth 3 -type f -iname '*.cer' 2>/dev/null | head -1
}

echo "=== 1. Поиск архивов и распаковка по ИНН ==="
seen_inns=()
# find избегает «argument list too long» при тысячах файлов
while IFS= read -r -d '' archive; do
  inn=$(get_inn_from_filename "$(basename "$archive")")
  if [[ -z "$inn" ]]; then
    echo "  Пропуск (ИНН не найден в имени): $(basename "$archive")"
    continue
  fi
  if unpack_archive "$archive" "$inn"; then
    seen_inns+=("$inn")
  else
    echo "  Пропуск из-за ошибки: $(basename "$archive")" >&2
  fi
done < <(find "$SOURCE_DIR" -maxdepth 1 -type f \( -iname '*.zip' -o -iname '*.rar' \) -print0 2>/dev/null)

echo ""
echo "=== 2. Список контейнеров (csptest) ==="
mapfile -t containers < <(list_containers)
for c in "${containers[@]}"; do
  echo "  $c"
done
if [[ ${#containers[@]} -eq 0 ]]; then
  echo "  Контейнеры не найдены. Проверьте пути и права (sudo)."
  exit 1
fi

if [[ "$DRY_RUN" == true ]]; then
  echo ""
  echo "Режим --dry-run: установка в uMy пропущена."
  echo "Запустите без --dry-run для экспорта сертификатов и установки в uMy."
  exit 0
fi

echo ""
echo "=== 3. Экспорт сертификатов и установка в uMy ==="
echo "(При 0x8010001c — в контейнере нет серта; ставим из .cer из папки ключей.)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
i=0
declare -a CONT_INN CONT_NAME CONT_THUMB
for cont in "${containers[@]}"; do
  [[ -z "$cont" ]] && continue
  cert_file="$tmpdir/cert_$i.cer"
  inst_ok=false
  cer_path=""
  if "$CERTMGR" -export -cont "$cont" -dest "$cert_file" 2>/dev/null; then
    inst_ok=true
  else
    # Экспорт не удался (0x8010001c): контейнер без серта. Пробуем поставить из .cer в папке по ИНН.
    cont_inn=$(get_inn_from_cont_name "$cont")
    if [[ -n "$cont_inn" ]] && inn_in_seen "$cont_inn"; then
      cer_path=$(find_cer_for_inn "$cont_inn")
      if [[ -n "$cer_path" ]] && [[ -f "$cer_path" ]]; then
        if "$CERTMGR" -inst -store uMy -file "$cer_path" -cont "$cont" 2>/dev/null; then
          cert_file="$cer_path"
          inst_ok=true
          echo "  Установка из .cer (контейнер без серта): $cont"
        fi
      fi
    fi
    if [[ "$inst_ok" != true ]]; then
      echo "  Пропуск контейнера (экспорт не удался, .cer не найден): $cont"
      ((i++)) || true
      continue
    fi
  fi
  inn=$(get_inn_from_cert "$cert_file")
  thumb=$(get_thumbprint_from_cert "$cert_file")
  echo "  Контейнер: $cont"
  echo "    ИНН: $inn, Thumbprint: $thumb"
  if [[ -z "$cer_path" ]]; then
    "$CERTMGR" -inst -store uMy -file "$cert_file" -cont "$cont" 2>/dev/null || {
      echo "    Ошибка установки в uMy (возможно уже установлен)."
    }
  fi
  CONT_INN[$i]="$inn"
  CONT_NAME[$i]="$cont"
  CONT_THUMB[$i]="$thumb"
  ((i++)) || true
done

echo ""
echo "=== 4. Проверка uMy ==="
"$CERTMGR" -list -store uMy 2>/dev/null | head -80

echo ""
echo "=== 5. Записи для Django (Certificate) ==="
echo "# В manage.py shell выполните (подставьте csptest_name по необходимости):"
echo ""
for j in $(seq 0 $((i-1))); do
  inn="${CONT_INN[$j]:-}"
  name="${CONT_NAME[$j]:-}"
  thumb="${CONT_THUMB[$j]:-}"
  [[ -z "$inn" ]] && continue
  # csptest_name как в выводе csptest (один \)
  echo "from reports.models import Certificate"
  echo "Certificate.objects.get_or_create(inn=\"$inn\", defaults={\"csptest_name\": r\"$name\", \"source\": \"LOCAL\"})  # thumb: $thumb"
  echo ""
done
echo "# Затем проверка: python manage.py shell -c \"from reports.models import Certificate; print(list(Certificate.objects.values_list('inn','csptest_name')))\""
