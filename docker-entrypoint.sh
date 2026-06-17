#!/bin/bash
set -e

mkdir -p /var/opt/cprocsp/keys/root
chmod 1777 /var/opt/cprocsp/keys
chmod 700 /var/opt/cprocsp/keys/root

/opt/cprocsp/sbin/amd64/cpconfig -license -set 00000-00000-00000-00000-00000 2>/dev/null || true
/opt/cprocsp/sbin/amd64/cpconfig -ini '\config\random' -add string '/dev/urandom' 2>/dev/null || true

if [ -f /app/scripts/ops/install_certificates.py ]; then
    python3 /app/scripts/ops/install_certificates.py
fi

/opt/cprocsp/bin/amd64/certmgr -list 2>&1 | head -50 || true

exec "$@"
