#!/bin/bash
# Generates a LaunchDaemon (macOS) or Systemd (Linux) service for Watchtower
DIR=$(pwd)
USER=$(whoami)

TARGET_SCRIPT="start.sh"
SERVICE_NAME="watchtower"
DESC="Watchtower Sovereign EDR Hub"

if [ "$1" == "--agent" ]; then
    # A19: start.sh reads NODE_TYPE from .env; there is no separate agent script.
    TARGET_SCRIPT="start.sh"
    SERVICE_NAME="watchtower-agent"
    DESC="Watchtower Sentinel Edge Node"
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[*] Generating macOS LaunchDaemon for $SERVICE_NAME..."
    mkdir -p "$HOME/Library/LaunchAgents"
    PLIST="$HOME/Library/LaunchAgents/com.vertex.$SERVICE_NAME.plist"
    cat << EOF2 > "$PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vertex.$SERVICE_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DIR/$TARGET_SCRIPT</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>WATCHTOWER_SUPERVISED</key>
        <string>1</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>$DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <!-- A24: restart on failure only (systemd Restart=on-failure parity) -->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <!-- A24: Umask 63 = 077, logs and data owner-only -->
    <key>Umask</key>
    <integer>63</integer>
    <key>StandardOutPath</key>
    <string>$DIR/data/${SERVICE_NAME}.log</string>
    <key>StandardErrorPath</key>
    <string>$DIR/data/${SERVICE_NAME}_error.log</string>
</dict>
</plist>
EOF2
    launchctl load "$PLIST" 2>/dev/null || echo "Run 'launchctl load $PLIST' to start."
    echo -e "\033[1;32m[+] macOS $SERVICE_NAME Service Installed.\033[0m"

elif grep -q "Ubuntu\|Debian" /etc/os-release > /dev/null 2>&1 || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[*] Generating Linux Systemd Service for $SERVICE_NAME..."
    SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
    sudo bash -c "cat << EOF2 > $SERVICE
[Unit]
Description=$DESC
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DIR
Environment=WATCHTOWER_SUPERVISED=1
ExecStart=$DIR/$TARGET_SCRIPT
Restart=on-failure
RestartSec=5
# A24 phase 1 hardening: only directives that break no Watchtower feature.
# NoNewPrivileges is NOT set here: isolate_network calls sudo. VETS decision A24b.
ProtectSystem=full
ReadWritePaths=$DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
UMask=0077

[Install]
WantedBy=multi-user.target
EOF2"
    sudo systemctl daemon-reload
    sudo systemctl enable $SERVICE_NAME
    sudo systemctl start $SERVICE_NAME
    echo -e "\033[1;32m[+] Linux Systemd $SERVICE_NAME Service Installed.\033[0m"
else
    echo "Unsupported OS for auto-service generation."
fi

