#!/usr/bin/env bash
#
# Полный старт на сервере из git (без scp):
#   cd /opt/sbis-norm && git pull && sudo bash scripts/ops/bootstrap_server.sh
#
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$PROJECT_DIR"

TEMPLATE="$PROJECT_DIR/scripts/ops/app.env.example"
APP_ENV="$PROJECT_DIR/app.env"

echo "=== SBIS bootstrap: $PROJECT_DIR ==="

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Нет $TEMPLATE" >&2
  exit 1
fi

if [[ ! -f "$APP_ENV" ]]; then
  echo "=== Создаю app.env из старого проекта ==="
  SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
  PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
  sed \
    -e "s|SECRET_KEY=__GENERATE__|SECRET_KEY=${SECRET}|" \
    -e "s|POSTGRES_PASSWORD=__GENERATE__|POSTGRES_PASSWORD=${PASS}|" \
    -e "s|__POSTGRES_PASSWORD__|${PASS}|" \
    "$TEMPLATE" > "$APP_ENV"
  chmod 600 "$APP_ENV"
  echo "  app.env создан"
else
  echo "=== app.env уже есть — не перезаписываю ==="
fi

echo ""
echo "=== Утилиты для распаковки ключей ==="
if ! command -v unzip &>/dev/null; then
  apt-get update -qq && apt-get install -y unzip
fi
if ! command -v unrar &>/dev/null && ! command -v unar &>/dev/null; then
  apt-get update -qq && (apt-get install -y unrar 2>/dev/null || apt-get install -y unar)
fi

echo ""
echo "=== Docker build + up ==="
docker compose up --build -d

echo ""
echo "=== Ждём web ==="
for i in $(seq 1 60); do
  if docker compose exec -T web python manage.py check >/dev/null 2>&1; then
    echo "  Django OK"
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "  web не ответил за 5 мин — смотрите: docker compose logs web" >&2
    exit 1
  fi
  sleep 5
done

if [[ -f "$PROJECT_DIR/signatures_valid_latest.zip" ]]; then
  echo ""
  echo "=== Установка сертификатов из git-архива ==="
  sed -i 's/\r$//' "$PROJECT_DIR/scripts/ops/"*.sh 2>/dev/null || true
  bash "$PROJECT_DIR/scripts/ops/install_signatures_from_bundle.sh"
else
  echo ""
  echo "=== signatures_valid_latest.zip не найден — пропуск установки ключей ==="
fi

echo ""
echo "=== Готово ==="
docker compose ps
echo ""
docker compose exec -T web python manage.py shell -c "
from reports.models import Certificate
print('Certificate в БД:', Certificate.objects.count())
"
echo ""
echo "API: http://$(hostname -I | awk '{print $1}'):8000"
echo "Проверка СБИС: docker compose exec web python manage.py test_sbis_auth_one <INN>"
