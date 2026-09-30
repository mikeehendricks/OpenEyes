#!/usr/bin/env bash
# OpenEyes server — Ubuntu install script
# Usage: sudo bash install_ubuntu.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Please run as root (sudo bash install_ubuntu.sh)"; exit 1; fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR=/opt/openeyes
DATA_DIR=/var/lib/openeyes

echo "[1/6] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip >/dev/null

echo "[2/6] Creating service user..."
id -u openeyes &>/dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin openeyes

echo "[3/6] Installing application to $APP_DIR..."
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/openeyes" "$APP_DIR/"
cp "$SRC_DIR/requirements.txt" "$APP_DIR/"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "[4/6] Creating data directory $DATA_DIR..."
mkdir -p "$DATA_DIR"
chown -R openeyes:openeyes "$DATA_DIR" "$APP_DIR"

echo "[5/6] Installing systemd service..."
cp "$SRC_DIR/systemd/openeyes-server.service" /etc/systemd/system/openeyes-server.service
systemctl daemon-reload
systemctl enable --now openeyes-server

echo "[6/6] Waiting for first-run credentials..."
sleep 3
if [[ -f "$DATA_DIR/first_run.txt" ]]; then
  echo
  echo "=============================================================="
  echo " OpenEyes is running on port 8080"
  echo " Dashboard: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080/"
  echo
  sed 's/^/ /' "$DATA_DIR/first_run.txt"
  echo "=============================================================="
else
  echo "Service started; check 'journalctl -u openeyes-server' for credentials."
fi
