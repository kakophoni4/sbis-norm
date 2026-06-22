#!/bin/bash
# Загрузка organizations_FINAL_670_v2.csv в продакшн 1С (/base/hs/mole).
# Перед запуском: ONE_C_MOLE_* в /opt/sbis-norm/app.env (см. README).
#
# Сразу:
#   bash /app/scripts/ops/upload_1c_prod.sh
#
# В рабочее время (пример: сегодня в 09:00 МСК = 06:00 UTC на сервере):
#   echo "bash /opt/sbis-norm/scripts/ops/upload_1c_prod.sh" | at 06:00

set -euo pipefail
cd "$(dirname "$0")/../.."

CSV="${1:-/app/media/org_export/organizations_FINAL_670_v2.csv}"
LOG="${2:-/app/media/org_export/upload_1c_prod_$(date +%Y%m%d_%H%M%S).log}"

echo "START $(date -Iseconds) csv=$CSV" | tee -a "$LOG"

docker compose exec -T web python manage.py upload_org_units_1c \
  --from-csv "$CSV" \
  --batch-size 25 \
  --delay 2 \
  2>&1 | tee -a "$LOG"

echo "DONE $(date -Iseconds)" | tee -a "$LOG"
