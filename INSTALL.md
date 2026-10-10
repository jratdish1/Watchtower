# Watchtower Installation Guide

Welcome to the definitive deployment guide for Watchtower. Because the system is engineered as a Sovereign Architecture, there are no binary installers (`.exe` or `.pkg`). You are in complete control of the source code.

## Path A: Standalone Deployment (Manual User Setup)

If you are a system administrator or power user looking to install Watchtower on your personal machine or server without using an Autonomous AI Agent, follow these native OS instructions.

### Windows Users
1. Clone or download this repository.
2. Ensure you have **Python 3.10+** installed on your system.
3. Double-click `setup.bat`. This will bypass execution policies locally and launch the setup loop natively in PowerShell.
4. Select `1` for Hub or `2` for Edge Sensor.
5. If you configured a Master Hub, run `npm ci --ignore-scripts` inside `/backend` and `/frontend`.
6. Double-click `start.bat` (it reads `NODE_TYPE` from `.env` for Hub or Edge).

### Mac & Linux Users
1. Open a terminal and navigate to this repository.
2. Ensure `python3`, `npm`, and `node` are installed recursively.
3. Execute the setup engine:
```bash
chmod +x setup.sh
./setup.sh
```
4. Follow the interactive CLI to generate your cryptographic `.env` topology.
5. To boot the system, execute `./start.sh` (it reads `NODE_TYPE` from `.env` for Hub or Edge).
6. Network: the API binds `WATCHTOWER_BIND_ADDRESS` and the Glass Pane UI binds `WATCHTOWER_UI_BIND_ADDRESS`, both default `127.0.0.1`. Each must be one IP address (use the Tailscale IP for a fleet hub); every-interface addresses (`0.0.0.0`, `::`, `::ffff:0.0.0.0` and other spellings) and hostnames are refused at startup with exit 1. The UI proxy reaches the API at `WATCHTOWER_API_HOST`, default = `WATCHTOWER_BIND_ADDRESS`. A busy port is retried up to `WATCHTOWER_LISTEN_RETRY_MAX` times (default 20, 3 s apart), then the process exits 1. The honeypot binds `WATCHTOWER_HONEYPOT_BIND` (default `127.0.0.1`).
7. Updates: `secure_update.sh` refuses to run (no real signature check yet). Update by checking out an exact reviewed SHA - see the header of that script.
8. Python dependencies are hash-locked (A26). Setup runs `pip install --require-hashes -r requirements.txt`. To change a pin, edit `requirements.in` and regenerate with the `uv pip compile` line at the top of that file.
9. Optional archiver (`core/watchtower_archiver.py`, not started by `start.sh`, needs Python 3.10+, pulls torch): `.venv/bin/pip install --require-hashes -r requirements-archiver.txt`.

---

## Path B: Agentic Deployment (Autonomous AI Orchestration)

Watchtower is built identically for AI consumption. If you are using OpenClaw, SWE-Agent, Hermes, or AutoGPT, you can simply point your Agent to this repository directory.

**Sample Prompt to your AI:**
> "Please navigate into the Watchtower directory. I need you to securely initialize the environment as a Master Hub node. Do not install Node dependencies yet, just configure the python virtual environment and ensure the cryptography secrets are successfully vaulted in the .env file. Use the native setup scripts provided in the dir."

Because the Agent has native bash execution capabilities, it will autonomously invoke `setup.sh`, negotiate the CLI parameters dynamically, and architect your system for you.
