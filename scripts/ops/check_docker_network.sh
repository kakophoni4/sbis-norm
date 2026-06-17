#!/usr/bin/env bash
# Проверка сети/DNS внутри контейнера web
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "=== Host ==="
getent hosts online.sbis.ru || ping -c1 online.sbis.ru || true
echo "--- /etc/resolv.conf (host) ---"
head -5 /etc/resolv.conf 2>/dev/null || true

echo ""
echo "=== Container web ==="
docker compose exec -T web bash -lc '
echo "--- /etc/resolv.conf (container) ---"
cat /etc/resolv.conf
echo "--- resolve online.sbis.ru ---"
python3 -c "import socket; print(socket.gethostbyname(\"online.sbis.ru\"))" || echo "DNS FAIL"
echo "--- HTTPS probe ---"
python3 -c "import requests; r=requests.get(\"https://online.sbis.ru\", timeout=15); print(r.status_code)" || echo "HTTPS FAIL"
'
