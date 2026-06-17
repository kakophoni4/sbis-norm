#!/usr/bin/env bash
#
# Установка пакета signatures_valid_latest.zip (~1000 подписей):
#   1) распаковка bundle на хосте → ключи в /var/opt/cprocsp/keys/root/INN/
#   2) certmgr/uMy + scan_certificates внутри Docker (CryptoPro в контейнере)
#
# Использование на сервере:
#   sudo bash scripts/ops/install_signatures_from_bundle.sh /root/signatures_valid_latest.zip
#
set -euo pipefail

BUNDLE="${1:-}"
PROJECT_DIR="${PROJECT_DIR:-/opt/sbis-norm}"
if [[ -z "$BUNDLE" && -f "$PROJECT_DIR/signatures_valid_latest.zip" ]]; then
  BUNDLE="$PROJECT_DIR/signatures_valid_latest.zip"
fi
EXTRACT_DIR="${EXTRACT_DIR:-/root/mega_signatures_extracted}"
CSP_ROOT="/var/opt/cprocsp/keys/root"
INSTALL_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sbis_keys_install_linux.sh"

if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
  echo "Укажите путь к ZIP: sudo bash $0 /root/signatures_valid_latest.zip" >&2
  exit 1
fi

if [[ ! -f "$INSTALL_SCRIPT" ]]; then
  echo "Не найден $INSTALL_SCRIPT" >&2
  exit 1
fi

echo "=== Пакет: $BUNDLE ==="
echo "=== Проект: $PROJECT_DIR ==="
echo ""

echo "=== 0. Утилиты распаковки ==="
if ! command -v unzip &>/dev/null; then
  apt-get update -qq && apt-get install -y unzip
fi
if ! command -v unrar &>/dev/null && ! command -v unar &>/dev/null; then
  apt-get update -qq && (apt-get install -y unrar 2>/dev/null || apt-get install -y unar)
fi

echo "=== 1. Распаковка bundle ==="
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
unzip -o -q "$BUNDLE" -d "$EXTRACT_DIR"
archives_count="$(find "$EXTRACT_DIR" -mindepth 2 -type f \( -iname '*.zip' -o -iname '*.rar' \) | wc -l)"
echo "  Внутренних архивов: $archives_count"

echo ""
echo "=== 2. Распаковка ключей в CSP (на хосте) ==="
sed -i 's/\r$//' "$INSTALL_SCRIPT" 2>/dev/null || true
bash "$INSTALL_SCRIPT" \
  --source "$EXTRACT_DIR" \
  --recursive \
  --unpack-only \
  --csp-root "$CSP_ROOT"

echo ""
echo "=== 3. Docker: certmgr + uMy ==="
cd "$PROJECT_DIR"
if ! docker compose ps --status running 2>/dev/null | grep -q web; then
  echo "Контейнер web не запущен. Запускаю docker compose up -d ..."
  docker compose up -d
  sleep 5
fi

# Актуальные скрипты в контейнер (без пересборки образа)
docker compose cp "$INSTALL_SCRIPT" web:/app/scripts/ops/sbis_keys_install_linux.sh
if [[ -f "$PROJECT_DIR/reports/management/commands/scan_certificates.py" ]]; then
  docker compose cp "$PROJECT_DIR/reports/management/commands/scan_certificates.py" \
    web:/app/reports/management/commands/scan_certificates.py
fi

docker compose exec -T -u root web bash /app/scripts/ops/sbis_keys_install_linux.sh --install-only

echo ""
echo "=== 4. Django: scan_certificates → БД ==="
docker compose exec -T web python manage.py scan_certificates --clear

echo ""
echo "=== 5. Итог ==="
docker compose exec -T web python manage.py shell -c "
from reports.models import Certificate
total = Certificate.objects.count()
active = Certificate.objects.filter(is_active=True).count()
print(f'Certificate в БД: всего={total}, активных={active}')
"

echo ""
echo "Готово. Проверка одного ИНН:"
echo "  docker compose exec web python manage.py test_sbis_auth_one <INN>"
