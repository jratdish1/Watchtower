#!/usr/bin/env python3
import socket, sys, json, argparse, time, os, ipaddress

# A16: never bind every interface by default. Default is loopback.
# Set WATCHTOWER_HONEYPOT_BIND to one IP literal (e.g. the node's Tailscale IP)
# to expose the decoy on that interface only.
def honeypot_bind_address(raw=None):
    raw = os.environ.get("WATCHTOWER_HONEYPOT_BIND", "127.0.0.1") if raw is None else raw
    value = (raw or "").strip()
    if not value or any(c.isspace() for c in value):
        raise ValueError("WATCHTOWER_HONEYPOT_BIND must be one IP literal")
    ip = ipaddress.ip_address(value)  # raises on hostnames/CIDR
    if ip.version != 4:
        raise ValueError("WATCHTOWER_HONEYPOT_BIND must be IPv4 (AF_INET socket)")
    if ip.is_unspecified:
        raise ValueError("refusing 0.0.0.0: bind one interface, not all")
    return str(ip)

def deploy_honeypot(port, timeout=10, bind=None):
    s = None
    try:
        bind = honeypot_bind_address() if bind is None else bind
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port))
        s.listen(1)
        s.settimeout(timeout)

        conn, addr = s.accept()
        data = conn.recv(1024)
        conn.close()
        s.close()

        return {"status": "breach_detected", "port": port, "attacker_ip": addr[0], "payload_preview": str(data)[:100]}
    except socket.timeout:
        s.close()
        return {"status": "clean", "port": port}
    except Exception as e:
        if s is not None:
            s.close()
        return {"status": "error", "message": f"Could not bind port {port}. Error: {str(e)}"}

ERROR_BACKOFF_SECONDS = 60

def run_daemon(port):
    print(f"[*] Watchtower Honeypot listening indefinitely on port {port}...")
    while True:
        res = deploy_honeypot(port, timeout=86400)
        if res["status"] == "breach_detected":
            print(f"[!] HONEYPOT TRIPPED! Port: {port} | Attacker IP: {res['attacker_ip']}")
        elif res["status"] == "error":
            # A16: back off instead of spinning a CPU core when the port is taken.
            print(f"[!] Honeypot error: {res['message']} (retry in {ERROR_BACKOFF_SECONDS}s)", flush=True)
            time.sleep(ERROR_BACKOFF_SECONDS)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()

    if args.monitor: run_daemon(args.port)
    else: print(json.dumps(deploy_honeypot(args.port, args.timeout), indent=2))
