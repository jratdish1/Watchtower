# A26 live harness: proves the hash-locked paramiko works with
# core/watchtower_net_scraper.py. Real SSH server on 127.0.0.1 only.
# Prints one RESULT= JSON line. No network beyond loopback.
import json, os, socket, sys, threading
import paramiko

root, work = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(root, 'core'))
os.environ['WATCHTOWER_API_KEY'] = 'k' * 40
os.environ['WATCHTOWER_DATA_DIR'] = work

host_key = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, 'generate') else None
if host_key is None:
    host_key = paramiko.ECDSAKey.generate()
seen = {'auth': 0}

class Srv(paramiko.ServerInterface):
    def check_auth_password(self, u, p):
        seen['auth'] += 1
        return paramiko.AUTH_SUCCESSFUL if (u, p) == ('admin', 'pw') else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return 'password'
    def check_channel_request(self, kind, cid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self, ch, cmd):
        def reply():
            ch.send(b'0011.2233.4455 Gi1/0/1\n'); ch.send_exit_status(0); ch.close()
        threading.Timer(0.2, reply).start()
        return True

ls = socket.socket(); ls.bind(('127.0.0.1', 0)); ls.listen(5); port = ls.getsockname()[1]
def serve():
    while True:
        try: c, _ = ls.accept()
        except OSError: return
        t = paramiko.Transport(c); t.add_server_key(host_key)
        try: t.start_server(server=Srv())
        except Exception: pass
threading.Thread(target=serve, daemon=True).start()

orig = paramiko.SSHClient.connect
def connect(self, hostname, *a, **kw):
    kw['port'] = port; kw['look_for_keys'] = False; kw['allow_agent'] = False
    return orig(self, hostname, *a, **kw)
paramiko.SSHClient.connect = connect
os.environ['HOME'] = work  # empty system known_hosts

import watchtower_net_scraper as m
out = {'paramiko': paramiko.__version__}
os.environ.pop('WATCHTOWER_SSH_KNOWN_HOSTS', None)
out['unknown_key'] = m.scrape_switch('127.0.0.1', 'admin', 'pw')
out['auth_before_trust'] = seen['auth']
kh = os.path.join(work, 'kh'); hk = paramiko.HostKeys()
hk.add('[127.0.0.1]:%d' % port, host_key.get_name(), host_key); hk.save(kh)
os.environ['WATCHTOWER_SSH_KNOWN_HOSTS'] = kh
p = m.scrape_switch('127.0.0.1', 'admin', 'pw')
out['known_key_path'] = bool(p)
out['known_key_output'] = open(p).read() if p else None
ls.close()
print('RESULT=' + json.dumps(out))
