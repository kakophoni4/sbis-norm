#!/usr/bin/env bash
#
# Установка 10 новых ЭЦП (8 из реестра + АЗАРТ + РЫСЬ) в uMy и проверка СБИС.
#
# Запуск на сервере (хост, не внутри контейнера):
#   cd /opt/sbis-norm
#   sudo bash scripts/ops/install_new_10_signatures.sh
#
# Требования:
#   - ключи уже лежат плоско: /var/opt/cprocsp/keys/root/{ИНН}/*.key (6 файлов)
#   - АЗАРТ/РЫСЬ во временных .staging_azart / .staging_rys (по 6 ключей)
#   - docker compose web up
#
set -euo pipefail

cd /opt/sbis-norm

CSP_ROOT="${CSP_ROOT:-/var/opt/cprocsp/keys/root}"
CSPTEST="/opt/cprocsp/bin/amd64/csptest"
CERTMGR="/opt/cprocsp/bin/amd64/certmgr"
EXPORT_TIMEOUT=12
VERIFY_TIMEOUT=6
INST_TIMEOUT=20

# 8 ИНН из реестра gfg.zip
WANT_INNS=(
  9729355495  # ЗЕРО
  7751364195  # Диспут
  9722110190  # Зинтер
  7751364283  # Легем
  9729271407  # ПБС
  9709130493  # Принтера
  9729352582  # Роса
  7725354440  # Сервис-партнер монтаж
)

STAGING=(
  "azart:АЗАРТ"
  "rys:РЫСЬ"
)

declare -A INSTALLED_CONT INSTALLED_THUMB INSTALLED_SUBJECT
declare -A WANT_SET
for inn in "${WANT_INNS[@]}"; do
  WANT_SET["$inn"]=1
done

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

csp() {
  docker compose exec -T -u root web "$@"
}

container_has_key() {
  local cont="$1"
  csp timeout "$VERIFY_TIMEOUT" "$CSPTEST" -keyset -container "$cont" -verifycontext &>/dev/null
}

export_cert() {
  local cont="$1" dest="$2"
  csp timeout "$EXPORT_TIMEOUT" "$CERTMGR" -export -cont "$cont" -dest "$dest" &>/dev/null
}

inn_ul_from_cert() {
  local cert="$1"
  csp "$CERTMGR" -list -file "$cert" 2>/dev/null \
    | grep -E '^Subject[[:space:]]*:' \
    | head -1 \
    | grep -oE 'ИНН ЮЛ=[0-9]+' \
    | head -1 \
    | grep -oE '[0-9]+' || true
}

subject_from_cert() {
  local cert="$1"
  csp "$CERTMGR" -list -file "$cert" 2>/dev/null \
    | grep -E '^Subject[[:space:]]*:' \
    | head -1 \
    | sed 's/^Subject[[:space:]]*:[[:space:]]*//' || true
}

thumb_from_cert() {
  local cert="$1"
  csp "$CERTMGR" -list -file "$cert" 2>/dev/null \
    | grep -i 'SHA1 Thumbprint' \
    | head -1 \
    | sed 's/.*:[[:space:]]*//' \
    | tr '[:upper:]' '[:lower:]' \
    | tr -d '\r\n' || true
}

umy_has_link() {
  local thumb="$1"
  local thumb_lc
  thumb_lc="$(echo "$thumb" | tr '[:upper:]' '[:lower:]' | tr -d '\r\n')"
  csp "$CERTMGR" -list -store uMy 2>/dev/null | awk -v t="$thumb_lc" '
    BEGIN { block=0; haspk=0 }
    /^SHA1 Thumbprint/ {
      if (block && haspk) { found=1; exit }
      block=0; haspk=0
      sub(/^[^:]*:[[:space:]]*/, "")
      gsub(/[[:space:]]/, "", $0)
      if (tolower($0) == t) block=1
      next
    }
    block && /PrivateKey Link/ && /Yes/ { haspk=1 }
    END { exit (block && haspk) ? 0 : 1 }
  '
}

install_umy() {
  local cert="$1" cont="$2" thumb="$3"
  csp timeout "$INST_TIMEOUT" "$CERTMGR" -inst -store uMy -file "$cert" -cont "$cont" &>/dev/null \
    || return 1
  umy_has_link "$thumb"
}

keys_count() {
  local dir="$1"
  find "$dir" -maxdepth 1 -name '*.key' 2>/dev/null | wc -l | tr -d ' '
}

all_targets_done() {
  local inn entry tag
  for inn in "${WANT_INNS[@]}"; do
    [[ -n "${INSTALLED_CONT[$inn]:-}" ]] || return 1
  done
  for entry in "${STAGING[@]}"; do
    tag="${entry%%:*}"
    [[ -n "${INSTALLED_CONT[staging:$tag]:-}" ]] || return 1
  done
  return 0
}

relocate_staging() {
  local tag="$1" inn="$2"
  local src="${CSP_ROOT}/.staging_${tag}"
  local dst="${CSP_ROOT}/${inn}"
  [[ -d "$src" ]] || return 0
  local n
  n="$(keys_count "$src")"
  [[ "$n" -ge 4 ]] || return 0
  mkdir -p "$dst"
  mkdir -p "${dst}/.bak_staging_${tag}"
  mv "$dst"/*.key "${dst}/.bak_staging_${tag}/" 2>/dev/null || true
  mv "$src"/*.key "$dst/"
  rmdir "$src" 2>/dev/null || true
  log "ключи .staging_${tag} -> ${dst}/ ($n файлов)"
}

preflight() {
  log "=== preflight ==="
  docker compose ps web --status running &>/dev/null || die "контейнер web не запущен"
  csp test -x "$CSPTEST" || die "csptest недоступен в web"
  csp test -x "$CERTMGR" || die "certmgr недоступен в web"

  local inn n
  for inn in "${WANT_INNS[@]}"; do
    n="$(keys_count "${CSP_ROOT}/${inn}")"
    log "ИНН $inn: $n ключей в корне"
    [[ "$n" -ge 4 ]] || die "ИНН $inn — мало ключей (ожидается >=4 в ${CSP_ROOT}/${inn}/)"
  done
  for entry in "${STAGING[@]}"; do
    local tag="${entry%%:*}"
    n="$(keys_count "${CSP_ROOT}/.staging_${tag}")"
    log "staging .staging_${tag}: $n ключей"
    [[ "$n" -ge 4 ]] || die ".staging_${tag} — нет ключей (сначала unpack_flat)"
  done
  log "restart web (подхватить ключи)..."
  docker compose restart web &>/dev/null
  sleep 12
}

collect_containers() {
  mapfile -t ALL_CONTAINERS < <(
    csp "$CSPTEST" -keyset -enum_cont -fqcn 2>/dev/null \
      | grep 'HDIMAGE' \
      | grep -E '^\\' || true
  )
  local copy=() rest=()
  local c
  for c in "${ALL_CONTAINERS[@]}"; do
    if [[ "$c" == *" копия" ]]; then
      copy+=("$c")
    else
      rest+=("$c")
    fi
  done
  CONTAINERS=("${copy[@]}" "${rest[@]}")
  log "контейнеров HDIMAGE: ${#ALL_CONTAINERS[@]} (с «копия»: ${#copy[@]})"
}

scan_and_install() {
  log "=== сканирование контейнеров (сначала «копия») ==="
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  local total="${#CONTAINERS[@]}"
  local i=0
  local cont cert inn subj thumb tag kw entry

  for cont in "${CONTAINERS[@]}"; do
  i=$((i + 1))
  if (( i % 25 == 0 )); then
    log "  прогресс: $i / $total"
  fi
  all_targets_done && break

  container_has_key "$cont" || continue

  cert="${tmpdir}/c_${i}.cer"
  export_cert "$cont" "$cert" || continue
  [[ -s "$cert" ]] || continue

  inn="$(inn_ul_from_cert "$cert")"
  subj="$(subject_from_cert "$cert")"
  thumb="$(thumb_from_cert "$cert")"
  [[ -n "$thumb" ]] || continue

  # --- 8 целевых ИНН ---
  if [[ -n "$inn" && -n "${WANT_SET[$inn]:-}" && -z "${INSTALLED_CONT[$inn]:-}" ]]; then
    log "найден $inn -> ${cont##*\\}"
    if install_umy "$cert" "$cont" "$thumb"; then
      INSTALLED_CONT["$inn"]="$cont"
      INSTALLED_THUMB["$inn"]="$thumb"
      INSTALLED_SUBJECT["$inn"]="$subj"
      log "  OK uMy $inn"
    else
      log "  FAIL uMy $inn (нет PrivateKey Link)"
    fi
    continue
  fi

  # --- АЗАРТ / РЫСЬ по имени в Subject ---
  for entry in "${STAGING[@]}"; do
    tag="${entry%%:*}"
    kw="${entry#*:}"
    [[ -n "${INSTALLED_CONT[staging:$tag]:-}" ]] && continue
    [[ -z "$inn" ]] && continue
    [[ -n "${WANT_SET[$inn]:-}" ]] && continue
    if echo "$subj" | grep -qi "$kw"; then
      log "найден $tag -> ИНН $inn (${cont##*\\})"
      if install_umy "$cert" "$cont" "$thumb"; then
        INSTALLED_CONT["staging:$tag"]="$cont"
        INSTALLED_CONT["$inn"]="$cont"
        INSTALLED_THUMB["$inn"]="$thumb"
        INSTALLED_SUBJECT["$inn"]="$subj"
        relocate_staging "$tag" "$inn"
        log "  OK uMy $tag ($inn)"
      else
        log "  FAIL uMy $tag"
      fi
      break
    fi
  done
  done
}

retry_missing_want() {
  log "=== дожим оставшихся ИНН (точечный поиск) ==="
  local inn cont cert thumb subj
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  for inn in "${WANT_INNS[@]}"; do
    [[ -n "${INSTALLED_CONT[$inn]:-}" ]] && continue
    log "ищем $inn..."
    local n=0
    for cont in "${CONTAINERS[@]}"; do
      n=$((n + 1))
      container_has_key "$cont" || continue
      cert="${tmpdir}/r.cer"
      export_cert "$cont" "$cert" || continue
      [[ "$(inn_ul_from_cert "$cert")" == "$inn" ]] || continue
      thumb="$(thumb_from_cert "$cert")"
      subj="$(subject_from_cert "$cert")"
      log "  кандидат: ${cont##*\\}"
      if install_umy "$cert" "$cont" "$thumb"; then
        INSTALLED_CONT["$inn"]="$cont"
        INSTALLED_THUMB["$inn"]="$thumb"
        INSTALLED_SUBJECT["$inn"]="$subj"
        log "  OK uMy $inn"
        break
      fi
    done
    [[ -n "${INSTALLED_CONT[$inn]:-}" ]] || log "  WARN: $inn не установлен"
  done

  local entry tag kw
  for entry in "${STAGING[@]}"; do
    tag="${entry%%:*}"
    kw="${entry#*:}"
    [[ -n "${INSTALLED_CONT[staging:$tag]:-}" ]] && continue
    log "ищем $tag ($kw)..."
    for cont in "${CONTAINERS[@]}"; do
      container_has_key "$cont" || continue
      cert="${tmpdir}/r.cer"
      export_cert "$cont" "$cert" || continue
      subj="$(subject_from_cert "$cert")"
      inn="$(inn_ul_from_cert "$cert")"
      echo "$subj" | grep -qi "$kw" || continue
      [[ -z "$inn" ]] && continue
      thumb="$(thumb_from_cert "$cert")"
      if install_umy "$cert" "$cont" "$thumb"; then
        INSTALLED_CONT["staging:$tag"]="$cont"
        INSTALLED_CONT["$inn"]="$cont"
        INSTALLED_THUMB["$inn"]="$thumb"
        INSTALLED_SUBJECT["$inn"]="$subj"
        relocate_staging "$tag" "$inn"
        log "  OK uMy $tag -> $inn"
        break
      fi
    done
  done
}

update_database() {
  log "=== обновление БД Certificate ==="
  local py='from reports.models import Certificate
import sys
data = sys.stdin.read().strip().splitlines()
for line in data:
    if not line.strip():
        continue
    inn, cont, thumb = line.split("|", 2)
    Certificate.objects.update_or_create(
        inn=inn, csptest_name=cont,
        defaults={
            "thumbprint": thumb.lower(),
            "has_private_key": True,
            "source": "LOCAL",
            "is_active": True,
        },
    )
    print("DB", inn)
'
  local payload=""
  local inn
  for inn in "${!INSTALLED_CONT[@]}"; do
    [[ "$inn" == staging:* ]] && continue
    [[ -z "${INSTALLED_THUMB[$inn]:-}" ]] && continue
    payload+="${inn}|${INSTALLED_CONT[$inn]}|${INSTALLED_THUMB[$inn]}"$'\n'
  done
  if [[ -z "$payload" ]]; then
    log "WARN: нечего писать в БД"
    return
  fi
  printf '%s' "$payload" | docker compose exec -T web python manage.py shell -c "$py"
  docker compose exec -T web python manage.py sync_has_private_key &>/dev/null || true
}

verify_auth() {
  log "=== проверка СБИС (test_sbis_auth_one) ==="
  local inn ok=0 fail=0
  local all_inns=()
  for inn in "${WANT_INNS[@]}"; do
    all_inns+=("$inn")
  done
  for inn in "${!INSTALLED_CONT[@]}"; do
    [[ "$inn" == staging:* ]] && continue
    local found=0
    for w in "${all_inns[@]}"; do
      [[ "$w" == "$inn" ]] && { found=1; break; }
    done
    [[ $found -eq 0 ]] && all_inns+=("$inn")
  done

  for inn in "${all_inns[@]}"; do
    log "--- auth $inn ---"
    if docker compose exec -T web python manage.py test_sbis_auth_one "$inn" 2>&1 | tee "/tmp/auth_${inn}.log" | tail -3 | grep -q 'Session ID'; then
      log "AUTH OK $inn"
      ok=$((ok + 1))
    else
      log "AUTH FAIL $inn (см. /tmp/auth_${inn}.log)"
      fail=$((fail + 1))
    fi
  done
  log "=== итог auth: OK=$ok FAIL=$fail ==="
}

print_summary() {
  log "=== установлено в uMy ==="
  local inn
  for inn in "${WANT_INNS[@]}"; do
    if [[ -n "${INSTALLED_CONT[$inn]:-}" ]]; then
      echo "  OK  $inn  ${INSTALLED_CONT[$inn]##*\\}"
    else
      echo "  FAIL $inn"
    fi
  done
  local entry tag
  for entry in "${STAGING[@]}"; do
    tag="${entry%%:*}"
    if [[ -n "${INSTALLED_CONT[staging:$tag]:-}" ]]; then
      for inn in "${!INSTALLED_CONT[@]}"; do
        [[ "$inn" == staging:* ]] && continue
        [[ "${INSTALLED_CONT[$inn]}" == "${INSTALLED_CONT[staging:$tag]}" ]] && echo "  OK  $tag -> $inn"
      done
    else
      echo "  FAIL $tag"
    fi
  done
}

main() {
  [[ "$(id -u)" -eq 0 ]] || die "запускай от root: sudo bash $0"
  preflight
  collect_containers
  [[ ${#CONTAINERS[@]} -gt 0 ]] || die "csptest не видит контейнеры"
  scan_and_install
  retry_missing_want
  print_summary
  update_database
  verify_auth
  log "готово"
}

main "$@"
