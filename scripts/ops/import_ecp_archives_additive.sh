#!/usr/bin/env bash
#
# Безопасный импорт контейнеров CryptoPro из ZIP/RAR-архивов.
#
# Обёртка оставлена для совместимости с прежней командой. Логика находится в
# import_ecp_archives_additive.py: она восстанавливает имя контейнера из
# name.key, как старый рабочий install_crypto_containers.py.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/import_ecp_archives_additive.py" "$@"
