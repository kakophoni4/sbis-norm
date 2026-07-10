#!/usr/bin/env bash
# Установить серт БАСТИОН в uMy и проверить cryptcp -sign.
# Запуск НА СЕРВЕРЕ:
#   cd /opt/sbis-norm && bash scripts/ops/install_bastion_umy_and_test_sign.sh
set -euo pipefail
cd /opt/sbis-norm

INN="${INN:-9707039440}"
CONT="${CONT:-\\\\.\\HDIMAGE\\9707039440bastion}"
CER="/tmp/${INN}.cer"
TP_EXPECT="70040f6d3ce1687af5f0a6b782ef77e58bdc4033"
CERTMGR=/opt/cprocsp/bin/amd64/certmgr
CRYPTCP=/opt/cprocsp/bin/amd64/cryptcp

echo "=== 1) export from container ==="
docker compose exec -T -u root web "$CERTMGR" -export -cont "$CONT" -dest "$CER"

echo "=== 2) install into uMy with PrivateKey Link ==="
docker compose exec -T -u root web "$CERTMGR" -inst -store uMy -file "$CER" -cont "$CONT" || true
# альтернатива CryptoPro: взять серт прямо из контейнера
docker compose exec -T -u root web "$CRYPTCP" -instcert -cont "$CONT" || true

echo "=== 3) list uMy (must contain thumbprint) ==="
docker compose exec -T -u root web bash -c "$CERTMGR -list -store uMy" 2>&1 \
  | tee /tmp/umy_list.txt \
  | grep -A30 -i "$TP_EXPECT\|$INN\|БАСТИОН\|PrivateKey" | head -60 || true

if ! grep -qi "$TP_EXPECT" /tmp/umy_list.txt; then
  echo "FAIL: thumbprint $TP_EXPECT still NOT in uMy"
  echo "Full uMy count:"
  grep -c 'SHA1 Thumbprint' /tmp/umy_list.txt || true
  exit 2
fi
echo "OK: found in uMy"

echo "=== 4) cryptcp -sign tests ==="
docker compose exec -T -u root web bash -c "
set -e
printf '<a/>' > /tmp/t.xml
rm -f /tmp/t.xml.sgn /tmp/t2.xml.sgn /tmp/t3.xml.sgn
echo '--- A: -thumbprint ---'
$CRYPTCP -sign -detached -der -nochain -norev -thumbprint $TP_EXPECT /tmp/t.xml /tmp/t.xml.sgn && ls -la /tmp/t.xml.sgn
echo '--- B: -f cer ---'
$CRYPTCP -sign -detached -der -nochain -norev -f $CER /tmp/t.xml /tmp/t2.xml.sgn && ls -la /tmp/t2.xml.sgn
echo '--- C: -cont ---'
$CRYPTCP -sign -detached -der -nochain -norev -cont '$CONT' /tmp/t.xml /tmp/t3.xml.sgn && ls -la /tmp/t3.xml.sgn
"

echo "=== 5) same via Django sign_xml_if_needed ==="
docker compose exec -T web python manage.py shell << PY
from reports.services.sbis.crypto import export_cert_der, get_thumbprint_from_cert, sign_xml_if_needed
inn="$INN"
cont=r"$CONT"
export_cert_der(cont, f"/tmp/{inn}.cer")
tp=get_thumbprint_from_cert(f"/tmp/{inn}.cer")
open("/tmp/t_django.xml","wb").write(b"<a/>")
print("sgn", sign_xml_if_needed("/tmp/t_django.xml", None, tp, csptest_name=cont))
PY

echo "ALL OK — теперь: docker compose exec -T web python /app/docs/make_bastion_nds_and_send_1c.py --send"
