#!/usr/bin/env bash
# Диагностика VPN на сервере (рядом с /opt/sbis-norm).
# Запуск на сервере:
#   sudo bash /opt/sbis-norm/scripts/ops/diagnose_vpn.sh
#   sudo bash /opt/sbis-norm/scripts/ops/diagnose_vpn.sh > /tmp/vpn_diag.txt 2>&1

set -u

section() { echo ""; echo "========== $* =========="; }

section "HOST / TIME"
hostname -f 2>/dev/null || hostname
date
uptime

section "INTERFACES (tun/wg/ppp)"
ip -br link | grep -iE 'tun|wg|ppp|tailscale' || echo "(нет vpn-интерфейсов в ip link)"
ip -br addr | grep -iE 'tun|wg|ppp|tailscale' || true

section "WIREGUARD"
if command -v wg >/dev/null 2>&1; then
  wg show 2>&1 || true
else
  echo "wg не установлен"
fi
if [[ -d /etc/wireguard ]]; then
  ls -la /etc/wireguard/
else
  echo "/etc/wireguard нет"
fi
systemctl is-active wg-quick@* 2>/dev/null || systemctl list-units 'wg-quick@*' --all 2>/dev/null || true

section "OPENVPN"
systemctl is-active openvpn-server@* openvpn@* 2>/dev/null || true
systemctl list-units 'openvpn*' --all 2>/dev/null | head -20 || true
ls -la /etc/openvpn/ 2>/dev/null || echo "/etc/openvpn нет"

section "DOCKER VPN / PROXY"
docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}' 2>/dev/null | grep -iE 'vpn|wireguard|openvpn|xray|v2ray|shadow|outline|amnezia|wg|tailscale' || \
  docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}' 2>/dev/null | head -30

section "SYSTEMD vpn/wg/tailscale"
systemctl list-units --type=service --all 2>/dev/null | grep -iE 'vpn|wireguard|wg-|openvpn|xray|v2ray|tailscale|shadow' || echo "(нет подходящих unit)"

section "LISTEN PORTS (vpn-related)"
ss -tulpn 2>/dev/null | grep -iE '51820|1194|443|8388|1080|wireguard|openvpn|xray' || ss -tulpn 2>/dev/null | head -25

section "IPTABLES / NAT (кратко)"
iptables -t nat -L POSTROUTING -n -v 2>/dev/null | head -15 || echo "iptables nat недоступен"
iptables -L FORWARD -n -v 2>/dev/null | head -10 || true

section "IP FORWARD"
sysctl net.ipv4.ip_forward 2>/dev/null || true

section "RECENT VPN LOGS (journal, 50 lines)"
journalctl -u 'wg-quick@*' -u 'openvpn*' --no-pager -n 30 2>/dev/null || true
journalctl --no-pager -n 20 2>/dev/null | grep -iE 'wireguard|openvpn|vpn|wg0' || true

section "OPT /opt dirs (vpn?)"
ls -la /opt/ 2>/dev/null || true

section "FAILURES (failed units)"
systemctl --failed 2>/dev/null || true

echo ""
echo "=== DONE ==="
echo "Пришлите вывод целиком или /tmp/vpn_diag.txt"
