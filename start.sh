#!/bin/bash
echo "[Watchtower] Booting Command Center & Core Sensors..."

# Load environment variables
set -a
source .env 2>/dev/null
set +a

# A17: bind loopback unless .env names one interface (e.g. the Tailscale IP).
export WATCHTOWER_BIND_ADDRESS="${WATCHTOWER_BIND_ADDRESS:-127.0.0.1}"
export WATCHTOWER_UI_BIND_ADDRESS="${WATCHTOWER_UI_BIND_ADDRESS:-127.0.0.1}"
export WATCHTOWER_HONEYPOT_BIND="${WATCHTOWER_HONEYPOT_BIND:-127.0.0.1}"
# Quick pre-check for the two common spellings only. The authority is backend/bind_address.js, which
# backend/app.js and frontend/serve_ui.js run at startup on the parsed address bytes (A27).
for bind_var in WATCHTOWER_BIND_ADDRESS WATCHTOWER_UI_BIND_ADDRESS; do
    bind_val="${!bind_var}"
    if [ "$bind_val" = "0.0.0.0" ] || [ "$bind_val" = "::" ]; then
        echo "[!] REFUSED: $bind_var=$bind_val binds every interface. Set one IP." >&2
        exit 1
    fi
done

# Activate Python environment
source .venv/bin/activate
cd core
PIDS=""

if [ "$NODE_TYPE" == "HUB" ]; then
    echo "[Watchtower] Initiating Master Hub Boot Sequence..."

    # Start Backend API
    (cd ../backend && node app.js) &
    API_PID=$!

    # Start Frontend UI
    (cd ../frontend && node serve_ui.js) &
    UI_PID=$!

    sleep 2

    echo "[Watchtower] Starting C2 Beacon Listener & Hub Services..."
    python3 watchtower_beacon.py &
    PIDS="$PIDS $!"
elif [ "$NODE_TYPE" == "EDGE" ]; then
    echo "[Watchtower Sentinel] Initiating Edge Node Sequence..."
    echo "[Watchtower Sentinel] Starting Python Supervisor (Dynamic Node Orchestrator)..."
    python3 watchtower_beacon.py &
    PIDS="$PIDS $!"
else
    echo "[!] CRITICAL SEVERE: Internal Configuration missing NODE_TYPE."
    echo "[!] Re-run ./setup.sh to rebuild the .env correctly."
    exit 1
fi

# A20: one restart owner. Under systemd/launchd (install_service.sh sets
# WATCHTOWER_SUPERVISED=1) the service manager restarts; skip the respawn watchdog.
if [ "${WATCHTOWER_SUPERVISED:-0}" = "1" ]; then
    echo "[Watchtower] Supervised by the service manager: resurrection watchdog not started."
else
    echo "[Watchtower] Engaging Kernel-Level Resurrection Watchdog..."
    python3 watchtower_resurrection.py &
    PIDS="$PIDS $!"
fi

echo "[Watchtower] Booting Master Topography Scraper Engine natively..."
python3 watchtower_net_scraper.py &
PIDS="$PIDS $!"

echo "[Watchtower] Starting Crypto Guard DLP Monitor..."
python3 ../agent_skills/crypto_guard.py --monitor &
PIDS="$PIDS $!"

echo "[Watchtower] Deploying Local Network Honeypot on port 3306 (MySQL decoy)..."
python3 ../agent_skills/honeypot_spawner.py --port 3306 --monitor &
PIDS="$PIDS $!"

echo "[Watchtower] All systems operational. Press Ctrl+C to shutdown."
if [ "$NODE_TYPE" == "HUB" ]; then
    ALL_PIDS="$API_PID $UI_PID $PIDS"
else
    ALL_PIDS="$PIDS"
fi
trap "kill $ALL_PIDS 2>/dev/null; exit" INT TERM

# A25: under a service manager there is no resurrection watchdog (A20), so a
# single dead sensor would stay dead while `wait` blocks on the rest. Watch every
# child; if any exits, stop the group and exit 1 so systemd/launchd restarts it.
# Portable to macOS /bin/bash 3.2 (no `wait -n`).
if [ "${WATCHTOWER_SUPERVISED:-0}" = "1" ]; then
    while true; do
        for p in $ALL_PIDS; do
            if ! kill -0 "$p" 2>/dev/null; then
                echo "[Watchtower] Child $p exited under supervision; stopping group for a clean restart." >&2
                kill $ALL_PIDS 2>/dev/null
                exit 1
            fi
        done
        sleep 5 &
        wait $!
    done
fi
wait
