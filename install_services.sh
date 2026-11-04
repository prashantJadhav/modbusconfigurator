#!/usr/bin/env bash
# Install the gateway + configuration UI as systemd services.  Run AFTER setup_db.sh:  sudo bash install_services.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"; DEST=/opt/edge-gateway
[ -f /etc/edge-gateway/gateway.env ] || { echo "Run setup_db.sh first." >&2; exit 1; }

id gateway >/dev/null 2>&1 || useradd --system --home "$DEST" --shell /usr/sbin/nologin gateway
usermod -aG dialout gateway                         # access to /dev/ttyUSB* / ttyS* for RS485
install -d -o gateway -g gateway "$DEST"
cp -r "$HERE/gateway.py" "$HERE/ui" "$HERE/requirements.txt" "$DEST/"
python3 -m venv "$DEST/venv" && "$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"
chown -R gateway:gateway "$DEST"

cp "$HERE/edge-gateway.service" "$HERE/edge-gateway-ui.service" /etc/systemd/system/
sed -i 's/^Group=dialout/SupplementaryGroups=dialout/' /etc/systemd/system/edge-gateway.service
systemctl daemon-reload
systemctl enable --now edge-gateway-ui.service edge-gateway.service
sleep 3
echo; echo "UI first-start credentials (user 'admin'):"
journalctl -u edge-gateway-ui --no-pager | grep "created user" | tail -1 || true
echo "Open http://<this-device-ip>:8088"

#iptables-legacy -I SECURITY_LOCAL_ACCESS 3 -p tcp -s 192.168.3.0/24 --dport 8088 -j ACCEPT