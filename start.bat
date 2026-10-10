@echo off
echo [Watchtower] Booting Command Center ^& Core Sensors...

if not exist .env (
    echo [ERROR] No .env file found. Please run setup.bat first.
    pause
    exit /b
)

for /f "delims=" %%A in (.env) do set %%A

REM A17: bind loopback unless .env names one interface (e.g. the Tailscale IP).
if "%WATCHTOWER_BIND_ADDRESS%"=="" set WATCHTOWER_BIND_ADDRESS=127.0.0.1
if "%WATCHTOWER_UI_BIND_ADDRESS%"=="" set WATCHTOWER_UI_BIND_ADDRESS=127.0.0.1
if "%WATCHTOWER_HONEYPOT_BIND%"=="" set WATCHTOWER_HONEYPOT_BIND=127.0.0.1
if "%WATCHTOWER_BIND_ADDRESS%"=="0.0.0.0" goto refuse_bind
if "%WATCHTOWER_BIND_ADDRESS%"=="::" goto refuse_bind
REM A27: same quick pre-check for the UI. The authority is backend\bind_address.js (parsed address bytes).
if "%WATCHTOWER_UI_BIND_ADDRESS%"=="0.0.0.0" goto refuse_ui_bind
if "%WATCHTOWER_UI_BIND_ADDRESS%"=="::" goto refuse_ui_bind
goto bind_ok
:refuse_bind
echo [!] REFUSED: WATCHTOWER_BIND_ADDRESS=%WATCHTOWER_BIND_ADDRESS% binds every interface. Set one IP.
exit /b 1
:refuse_ui_bind
echo [!] REFUSED: WATCHTOWER_UI_BIND_ADDRESS=%WATCHTOWER_UI_BIND_ADDRESS% binds every interface. Set one IP.
exit /b 1
:bind_ok

if not exist .venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment missing. Please run setup.bat first.
    pause
    exit /b
)
call .venv\Scripts\activate.bat
cd core

if "%NODE_TYPE%"=="HUB" (
    echo [Watchtower] Initiating Master Hub Boot Sequence...
    start /b cmd /c "cd ../backend && node app.js"
    start /b cmd /c "cd ../frontend && node serve_ui.js"
    timeout /t 2 /nobreak >nul
    echo [Watchtower] Starting C2 Beacon Listener ^& Hub Services...
    start /b python watchtower_beacon.py
) else if "%NODE_TYPE%"=="EDGE" (
    echo [Watchtower Sentinel] Initiating Edge Node Sequence...
    echo [Watchtower Sentinel] Starting Python Supervisor...
    start /b python watchtower_beacon.py
) else (
    echo [!] CRITICAL ERROR: NODE_TYPE is missing from .env. Please run setup.bat again.
    pause
    exit /b
)

echo [Watchtower] Engaging Kernel-Level Resurrection Watchdog...
start /b python watchtower_resurrection.py

echo [Watchtower] Booting Master Topography Scraper Engine natively...
start /b python watchtower_net_scraper.py

echo [Watchtower] Starting Crypto Guard DLP Monitor...
start /b python ../agent_skills/crypto_guard.py --monitor

echo [Watchtower] Deploying Local Network Honeypot on port 3306 (MySQL decoy)...
start /b python ../agent_skills/honeypot_spawner.py --port 3306 --monitor

echo [Watchtower] All enabled systems operational. Close this terminal to shutdown.
pause
