#!/usr/bin/env bash
#
# Установка ключей СБИС на Linux по инструкции:
# распаковка архивов (ZIP/RAR) → выравнивание подпапок → экспорт сертов → установка в uMy с привязкой к контейнеру.
#
# Требования: Linux-CSP, unzip, unrar или unar. Запуск с sudo для шагов CSP.
#
# Использование:
#   sudo ./sbis_keys_install_linux.sh [--source DIR] [--csp-root DIR] [--dry-run]
#   --source       папка с архивами .zip/.rar (по умолчанию: текущая или ~/mega_signatures)
#   --csp-root     каталог ключей CSP (по умолчанию: /var/opt/cprocsp/keys/root)
#   --dry-run      только распаковать и вывести список контейнеров, не ставить в uMy
#   --recursive    искать архивы во вложенных папках (ИНН = имя родительской папки)
#   --unpack-only  только распаковка ключей в CSP, без certmgr/uMy
#   --install-only только certmgr/uMy (ключи уже лежат в CSP_ROOT)
#
set -euo pipefail

CSPTEST="${CSPTEST:-/opt/cprocsp/bin/amd64/csptest}"
CERTMGR="${CERTMGR:-/opt/cprocsp/bin/amd64/certmgr}"
SOURCE_DIR=""
CSP_ROOT="/var/opt/cprocsp/keys/root"
DRY_RUN=false
RECURSIVE=false
UNPACK_ONLY=false
INSTALL_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)       SOURCE_DIR="$2"; shift 2 ;;
    --csp-root)     CSP_ROOT="$2";   shift 2 ;;
    --dry-run)      DRY_RUN=true;   shift 1 ;;
    --recursive)    RECURSIVE=true; shift 1 ;;
    --unpack-only)  UNPACK_ONLY=true; shift 1 ;;
    --install-only) INSTALL_ONLY=true; shift 1 ;;
    *) echo "Неизвестный аргумент: $1"; exit 1 ;;
  esac
done

if [[ "$UNPACK_ONLY" == true && "$INSTALL_ONLY" == true ]]; then
  echo "Нельзя одновременно --unpack-only и --install-only" >&2
  exit 1
fi

if [[ "$INSTALL_ONLY" != true ]]; then
  if [[ -z "$SOURCE_DIR" ]]; then
    if [[ -d "$HOME/mega_signatures" ]]; then
      SOURCE_DIR="$HOME/mega_signatures"
    else
      SOURCE_DIR="."
    fi
  fi
  SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
  echo "Источник архивов: $SOURCE_DIR"
fi
echo "Каталог CSP:      $CSP_ROOT"
echo ""

# Из имени файла достаём ИНН (10 цифр подряд). Без совпадения — пустая строка, без выхода по set -e.
get_inn_from_filename() {
  local name="$1"
  echo "$name" | grep -oE '[0-9]{12}' | head -1 || echo "$name" | grep -oE '[0-9]{10}' | head -1 || true
}

# ИНН для архива: при --recursive берём имя родительской папки (10–12 цифр), иначе из имени файла.
get_inn_for_archive() {
  local archive="$1"
  local parent_name
  if [[ "$RECURSIVE" == true ]]; then
    parent_name="$(basename "$(dirname "$archive")")"
    if [[ "$parent_name" =~ ^[0-9]{10,12}$ ]]; then
      echo "$parent_name"
      return
    fi
  fi
  get_inn_from_filename "$(basename "$archive")"
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
  local key_files=()
  one=""
  for sub in "$dest"/*/; do
    [[ -d "$sub" ]] || continue
    if [[ -n "$one" ]]; then
      one=""
      break
    fi
    one="$sub"
  done
  shopt -s nullglob
  key_files=("$dest"/*.key)
  shopt -u nullglob
  if [[ -n "$one" ]] && [[ ${#key_files[@]} -eq 0 ]]; then
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

# ИНН из Subject (не Issuer — у ФНС в Issuer всегда ИНН ЮЛ=7707329152)
get_inn_ul_from_cert() {
  local cert_path="$1"
  local subject
  subject="$("$CERTMGR" -list -file "$cert_path" 2>/dev/null | grep -E '^Subject[[:space:]]*:' | head -1)"
  [[ -z "$subject" ]] && { echo ""; return; }
  echo "$subject" | grep -oE 'ИНН ЮЛ=[0-9]+' | head -1 | grep -oE '[0-9]+' || echo ""
}

get_inn_other_from_cert() {
  local cert_path="$1"
  local subject
  subject="$("$CERTMGR" -list -file "$cert_path" 2>/dev/null | grep -E '^Subject[[:space:]]*:' | head -1)"
  [[ -z "$subject" ]] && { echo ""; return; }
  echo "$subject" | grep -oE 'ИНН ФЛ=[0-9]+' | head -1 | grep -oE '[0-9]+' || \
  echo "$subject" | grep -oE 'ИНН=[0-9]+' | head -1 | grep -oE '[0-9]+' || echo ""
}

# ИНН каталога ключей CSP_ROOT/{inn}/ по имени контейнера (UUID и т.п.)
get_inn_from_csp_folder_for_cont() {
  local cont="$1"
  local id inn_dir inn
  id="${cont##*\\}"
  id="${id%% копия}"
  id="${id%% *}"
  [[ -z "$id" ]] && { echo ""; return; }
  for inn_dir in "$CSP_ROOT"/*/; do
    [[ -d "$inn_dir" ]] || continue
    inn="$(basename "$inn_dir")"
    [[ "$inn" =~ ^[0-9]{10,12}$ ]] || continue
    if [[ -d "${inn_dir}${id}" ]] || find "$inn_dir" -maxdepth 2 -type d -name "$id" 2>/dev/null | grep -q .; then
      echo "$inn"
      return
    fi
  done
  echo ""
}

get_inn_from_cert() {
  local cert_path="$1" cont="$2"
  local inn_ul folder_inn
  inn_ul="$(get_inn_ul_from_cert "$cert_path")"
  [[ -n "$inn_ul" ]] && { echo "$inn_ul"; return; }
  if [[ -n "$cont" ]]; then
    folder_inn="$(get_inn_from_csp_folder_for_cont "$cont")"
    [[ -n "$folder_inn" ]] && { echo "$folder_inn"; return; }
  fi
  get_inn_other_from_cert "$cert_path"
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
  local s
  for s in "${seen_inns[@]}"; do
    [[ "$name" == *"$s"* ]] && { echo "$s"; return; }
  done
  echo "$name" | grep -oE '[0-9]{12}' | head -1 || echo "$name" | grep -oE '[0-9]{10}' | head -1 || true
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

# Epoch Not valid after из .cer (0 если не удалось). certmgr: DD/MM/YYYY HH:MM:SS UTC
cert_not_after_epoch_from_file() {
  local cert_path="$1"
  local raw normalized day month year time
  raw="$("$CERTMGR" -list -file "$cert_path" 2>/dev/null | grep -i "Not valid after" | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '\r')"
  [[ -z "$raw" ]] && { echo "0"; return; }
  normalized="${raw% UTC}"
  if [[ "$normalized" =~ ^([0-9]{2})/([0-9]{2})/([0-9]{4})\ ([0-9]{2}:[0-9]{2}:[0-9]{2})$ ]]; then
    day="${BASH_REMATCH[1]}"
    month="${BASH_REMATCH[2]}"
    year="${BASH_REMATCH[3]}"
    time="${BASH_REMATCH[4]}"
    date -u -d "${year}-${month}-${day} ${time}" +%s 2>/dev/null || echo "0"
    return
  fi
  date -u -d "$normalized" +%s 2>/dev/null || echo "0"
}

# Лучший .cer в каталоге CSP_ROOT/INN: только действующий с максимальным Not valid after
find_best_cer_for_inn() {
  local inn="$1"
  local now_epoch best_epoch best cert epoch
  now_epoch="$(date -u +%s)"
  best_epoch=0
  best=""
  while IFS= read -r cert; do
    [[ -f "$cert" ]] || continue
    epoch="$(cert_not_after_epoch_from_file "$cert")"
    [[ "$epoch" =~ ^[0-9]+$ ]] || epoch=0
    if (( epoch > now_epoch && epoch > best_epoch )); then
      best_epoch="$epoch"
      best="$cert"
    fi
  done < <(find "${CSP_ROOT}/${inn}" -maxdepth 3 -type f -iname '*.cer' 2>/dev/null)
  echo "$best"
}

seen_inns=()

collect_seen_inns_from_csp_root() {
  local d inn
  for d in "$CSP_ROOT"/*/; do
    [[ -d "$d" ]] || continue
    inn="$(basename "$d")"
    [[ "$inn" =~ ^[0-9]{10,12}$ ]] || continue
    seen_inns+=("$inn")
  done
}

if [[ "$INSTALL_ONLY" != true ]]; then
  echo "=== 1. Поиск архивов и распаковка по ИНН ==="
  # find избегает «argument list too long» при тысячах файлов
  find_depth=(-maxdepth 1)
  if [[ "$RECURSIVE" == true ]]; then
    find_depth=(-mindepth 2)
  fi
  while IFS= read -r -d '' archive; do
    archive="${archive#* }"
    inn=$(get_inn_for_archive "$archive")
    if [[ -z "$inn" ]]; then
      echo "  Пропуск (ИНН не найден): $(basename "$archive")"
      continue
    fi
    if unpack_archive "$archive" "$inn"; then
      seen_inns+=("$inn")
    else
      echo "  Пропуск из-за ошибки: $(basename "$archive")" >&2
    fi
  done < <(
    find "$SOURCE_DIR" "${find_depth[@]}" -type f \( -iname '*.zip' -o -iname '*.rar' \) -printf '%T@ %p\0' 2>/dev/null | sort -zr
  )
  echo ""
else
  echo "=== 1. Распаковка пропущена (--install-only) ==="
  collect_seen_inns_from_csp_root
  echo "  Каталогов по ИНН в CSP: ${#seen_inns[@]}"
  echo ""
fi

if [[ "$UNPACK_ONLY" == true ]]; then
  echo "Распаковано каталогов ИНН: ${#seen_inns[@]}"
  echo "Режим --unpack-only: csptest/certmgr пропущены."
  exit 0
fi

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
echo "(Далее выбираем ТОЛЬКО 1 лучший действующий сертификат на каждый ИНН.)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
i=0
declare -a CONT_INN CONT_NAME CONT_THUMB
declare -a CAND_INN CAND_NAME CAND_THUMB CAND_CERT CAND_EPOCH
declare -A BEST_IDX BEST_EPOCH
now_epoch="$(date -u +%s)"
for cont in "${containers[@]}"; do
  [[ -z "$cont" ]] && continue
  cert_file="$tmpdir/cert_$i.cer"
  inst_ok=false
  cer_path=""
  if "$CERTMGR" -export -cont "$cont" -dest "$cert_file" 2>/dev/null; then
    inst_ok=true
  else
    # Экспорт не удался (0x8010001c): контейнер без серта.
    # Пробуем поставить из лучшего действующего .cer в папке по ИНН.
    cont_inn=$(get_inn_from_cont_name "$cont")
    if [[ -n "$cont_inn" ]] && inn_in_seen "$cont_inn"; then
      cer_path=$(find_best_cer_for_inn "$cont_inn")
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
  inn=$(get_inn_from_cert "$cert_file" "$cont")
  thumb=$(get_thumbprint_from_cert "$cert_file")
  epoch="$(cert_not_after_epoch_from_file "$cert_file")"
  [[ "$epoch" =~ ^[0-9]+$ ]] || epoch=0
  echo "  Контейнер: $cont"
  echo "    ИНН: $inn, Thumbprint: $thumb, NotAfterEpoch: $epoch"
  if [[ -z "$inn" ]]; then
    echo "    Пропуск контейнера (не удалось определить ИНН из Subject/папки CSP)"
    ((i++)) || true
    continue
  fi
  if (( epoch > 0 && epoch <= now_epoch )); then
    echo "    Пропуск контейнера (сертификат просрочен)"
    ((i++)) || true
    continue
  fi
  CAND_INN[$i]="$inn"
  CAND_NAME[$i]="$cont"
  CAND_THUMB[$i]="$thumb"
  CAND_CERT[$i]="$cert_file"
  CAND_EPOCH[$i]="$epoch"
  if [[ -z "${BEST_EPOCH[$inn]:-}" ]] || (( epoch > BEST_EPOCH[$inn] )); then
    BEST_EPOCH[$inn]="$epoch"
    BEST_IDX[$inn]="$i"
  fi
  ((i++)) || true
done

echo ""
echo "=== 3.1 Выбор лучшего контейнера на ИНН ==="
k=0
for inn in "${!BEST_IDX[@]}"; do
  idx="${BEST_IDX[$inn]}"
  CONT_INN[$k]="${CAND_INN[$idx]}"
  CONT_NAME[$k]="${CAND_NAME[$idx]}"
  CONT_THUMB[$k]="${CAND_THUMB[$idx]}"
  cert_path="${CAND_CERT[$idx]}"
  cont_name="${CAND_NAME[$idx]}"
  echo "  Выбран: ИНН=$inn контейнер=$cont_name epoch=${CAND_EPOCH[$idx]}"
  "$CERTMGR" -inst -store uMy -file "$cert_path" -cont "$cont_name" 2>/dev/null || {
    echo "    Ошибка установки в uMy (возможно уже установлен)."
  }
  ((k++)) || true
done
i="$k"

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
  echo "Certificate.objects.update_or_create(inn=\"$inn\", defaults={\"csptest_name\": r\"$name\", \"source\": \"LOCAL\", \"thumbprint\": \"$thumb\", \"has_private_key\": True})  # thumb: $thumb"
  echo ""
done
echo "# Затем проверка: python manage.py shell -c \"from reports.models import Certificate; print(list(Certificate.objects.values_list('inn','csptest_name')))\""
