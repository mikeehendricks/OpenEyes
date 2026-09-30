#!/usr/bin/env bash
# ============================================================
# OpenEyes agent — zero-touch installer (Ubuntu/Debian, RHEL,
# and macOS incl. Apple Silicon)
#
# Installs the agent, enrolls it, and starts it as a managed
# service that survives reboots and failures. After this script
# finishes the agent runs autonomously — no user interaction is
# ever required again.
#
# Usage (as root / sudo):
#   sudo SERVER_URL=https://eyes.example.com:8080 \
#        ENROLL_TOKEN=<token-from-dashboard> \
#        [LABELS=branch-office,floor-2] \
#        [LAT=14.5995] [LNG=120.9842] \
#        bash install_agent.sh
# ============================================================
set -euo pipefail

SERVER_URL=${SERVER_URL:?Set SERVER_URL, e.g. https://eyes.example.com:8080}
ENROLL_TOKEN=${ENROLL_TOKEN:?Set ENROLL_TOKEN (Settings → enrollment token)}
LABELS=${LABELS:-}
LAT=${LAT:-}
LNG=${LNG:-}
INSECURE=${INSECURE:-false}

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo SERVER_URL=... ENROLL_TOKEN=... bash install_agent.sh" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR=/opt/openeyes-agent
CONF_DIR=/etc/openeyes
STATE_DIR=/var/lib/openeyes-agent
CONF=$CONF_DIR/agent.json
UNAME_S="$(uname -s)"

echo "[1/5] Prerequisites…"
if [[ "$UNAME_S" == "Linux" ]]; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y -qq python3 >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q python3 >/dev/null
  elif command -v yum >/dev/null; then
    yum install -y -q python3 >/dev/null
  fi
elif [[ "$UNAME_S" == "Darwin" ]]; then
  if ! command -v python3 >/dev/null; then
    echo "python3 not found. Install Xcode Command Line Tools: xcode-select --install" >&2
    exit 1
  fi
fi
PYTHON_BIN=$(command -v python3)

echo "[2/5] Installing agent to $APP_DIR…"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/openeyes_agent" "$APP_DIR/"

echo "[3/5] Writing configuration…"
mkdir -p "$CONF_DIR" "$STATE_DIR"
LABELS_JSON=$(python3 -c "import json,sys; print(json.dumps([x for x in sys.argv[1].split(',') if x]))" "$LABELS")
if [[ -n "$LAT" && -n "$LNG" ]]; then
  LOCATION_JSON="{\"lat\": $LAT, \"lng\": $LNG}"
else
  LOCATION_JSON="null"
fi
cat > "$CONF" <<EOF
{
  "server_url": "$SERVER_URL",
  "enrollment_token": "$ENROLL_TOKEN",
  "labels": $LABELS_JSON,
  "location": $LOCATION_JSON,
  "insecure_tls": $INSECURE,
  "state_path": "$STATE_DIR/state.json"
}
EOF
chmod 600 "$CONF"

echo "[4/5] Installing service…"
if [[ "$UNAME_S" == "Linux" ]]; then
  id -u openeyes-agent &>/dev/null || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin openeyes-agent
  chown -R openeyes-agent:openeyes-agent "$STATE_DIR" "$APP_DIR"
  cat > /etc/systemd/system/openeyes-agent.service <<EOF
[Unit]
Description=OpenEyes monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openeyes-agent
Environment=PYTHONPATH=$APP_DIR
ExecStart=$PYTHON_BIN -m openeyes_agent --config $CONF
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now openeyes-agent
  sleep 2
  systemctl --no-pager --lines=5 status openeyes-agent || true
elif [[ "$UNAME_S" == "Darwin" ]]; then
  chown -R root:wheel "$STATE_DIR"
  cat > /Library/LaunchDaemons/com.openeyes.agent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.openeyes.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>-m</string>
        <string>openeyes_agent</string>
        <string>--config</string>
        <string>$CONF</string>
    </array>
    <key>WorkingDirectory</key><string>$APP_DIR</string>
    <key>EnvironmentVariables</key>
    <dict><key>PYTHONPATH</key><string>$APP_DIR</string></dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/var/log/openeyes-agent.log</string>
    <key>StandardErrorPath</key><string>/var/log/openeyes-agent.err.log</string>
</dict>
</plist>
EOF
  launchctl unload /Library/LaunchDaemons/com.openeyes.agent.plist 2>/dev/null || true
  launchctl load -w /Library/LaunchDaemons/com.openeyes.agent.plist
fi

echo "[5/5] Verifying…"
sleep 3
if [[ "$UNAME_S" == "Linux" ]]; then
  if systemctl is-active --quiet openeyes-agent; then
    echo "✔ OpenEyes agent is running and will start automatically on boot."
  else
    echo "⚠ Service not active yet — it keeps retrying enrollment autonomously."
    echo "  Check: journalctl -u openeyes-agent -f"
  fi
else
  if launchctl list | grep -q com.openeyes.agent; then
    echo "✔ OpenEyes agent is loaded and will start automatically on boot."
    echo "  Logs: /var/log/openeyes-agent.log"
  else
    echo "⚠ launchd did not list the agent — check /var/log/openeyes-agent.err.log"
  fi
fi
