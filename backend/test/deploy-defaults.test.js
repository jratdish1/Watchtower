// A15/A16/A17: deploy-path defaults must fail closed.
// A15 secure_update.sh must refuse (no fake "Signature Verified").
// A16 honeypot binds loopback by default, refuses 0.0.0.0/hostnames/CIDR,
//     and backs off (no CPU spin) when the port is taken.
// A17 start.sh binds loopback by default and refuses all-interfaces binds.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..', '..');
let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`ok - ${name}`); }
  else { fail++; console.log(`not ok - ${name}${detail ? ' :: ' + detail : ''}`); }
}

// ---- A15 ----
const upd = spawnSync('bash', [path.join(ROOT, 'secure_update.sh')], {
  cwd: fs.mkdtempSync(path.join(require('os').tmpdir(), 'wt-upd-')), encoding: 'utf8', timeout: 20000,
});
const updOut = (upd.stdout || '') + (upd.stderr || '');
check('A15 secure_update.sh exits non-zero', upd.status !== 0, `status=${upd.status}`);
check('A15 no "Signature Verified" claim', !/Signature Verified/i.test(updOut));
check('A15 no "authentic" claim', !/authentic/i.test(updOut));
check('A15 no "Successfully Updated" claim', !/Successfully Updated/i.test(updOut));
check('A15 says REFUSED', /REFUSED/.test(updOut));

// ---- A17 ----
// start.sh (used by the systemd/launchd service) must default to loopback and
// refuse an all-interfaces bind. backend/app.js own default is tracked as A17b.
const startSh = path.join(ROOT, 'start.sh');
function startEnv(envLine) {
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'wt-start-'));
  fs.copyFileSync(startSh, path.join(tmp, 'start.sh'));
  fs.writeFileSync(path.join(tmp, '.env'), envLine + '\n');
  fs.mkdirSync(path.join(tmp, '.venv', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(tmp, '.venv', 'bin', 'activate'), 'true\n');
  fs.mkdirSync(path.join(tmp, 'core'));
  // NODE_TYPE is unset so start.sh stops at its own guard before launching anything.
  // start.sh exits early (no NODE_TYPE); an EXIT trap reports the exported values.
  const r = spawnSync('bash', ['-c', 'trap \'echo "BIND=$WATCHTOWER_BIND_ADDRESS HP=$WATCHTOWER_HONEYPOT_BIND"\' EXIT; source ./start.sh >/dev/null 2>&1'], { cwd: tmp, encoding: 'utf8', timeout: 20000 });
  const r2 = spawnSync('bash', ['./start.sh'], { cwd: tmp, encoding: 'utf8', timeout: 20000 });
  return { vars: (r.stdout || '').trim(), out: (r2.stdout || '') + (r2.stderr || ''), status: r2.status };
}
const s0 = startEnv('# no bind set');
check('A17 start.sh defaults API bind to 127.0.0.1', /BIND=127\.0\.0\.1\b/.test(s0.vars), s0.vars);
check('A17 start.sh defaults honeypot bind to 127.0.0.1', /HP=127\.0\.0\.1\b/.test(s0.vars), s0.vars);
const s1 = startEnv('WATCHTOWER_BIND_ADDRESS=0.0.0.0');
check('A17 start.sh refuses 0.0.0.0', s1.status !== 0 && /REFUSED/.test(s1.out), s1.out.slice(-200));
const s2 = startEnv('WATCHTOWER_BIND_ADDRESS=::');
check('A17 start.sh refuses ::', s2.status !== 0 && /REFUSED/.test(s2.out), s2.out.slice(-200));
const s3 = startEnv('WATCHTOWER_BIND_ADDRESS=100.86.203.66');
check('A17 start.sh keeps an operator-set tailnet IP', /BIND=100\.86\.203\.66\b/.test(s3.vars), s3.vars);
check('A17 start.sh with tailnet IP is not refused', !/REFUSED/.test(s3.out), s3.out.slice(-200));
const envEx = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
check('A17 .env.example bind is not 0.0.0.0', !/^WATCHTOWER_BIND_ADDRESS=0\.0\.0\.0\s*$/m.test(envEx));
check('A16 .env.example documents honeypot bind', /^WATCHTOWER_HONEYPOT_BIND=127\.0\.0\.1\s*$/m.test(envEx));

// ---- A16 (runtime, python) ----
const py = process.env.PYTHON_BIN || 'python3';
const probe = `
import importlib.util, json, os, socket, sys, time
spec = importlib.util.spec_from_file_location("hp", os.path.join(sys.argv[1], "agent_skills", "honeypot_spawner.py"))
hp = importlib.util.module_from_spec(spec); spec.loader.exec_module(hp)
out = {}
os.environ.pop("WATCHTOWER_HONEYPOT_BIND", None)
try: out["default"] = hp.honeypot_bind_address()
except Exception as e: out["default"] = "ERR"
bad = ["0.0.0.0", "", " ", "localhost", "10.0.0.0/8", "127.0.0.1\\n0.0.0.0", "127.0.0.1 0.0.0.0", " 0.0.0.0 ", "::1", "999.1.1.1", "evil.example"]
out["bad"] = {}
for b in bad:
    try: hp.honeypot_bind_address(b); out["bad"][b] = "ACCEPTED"
    except Exception: out["bad"][b] = "refused"
try: out["trimmed"] = hp.honeypot_bind_address(" 127.0.0.1 \\n")
except Exception: out["trimmed"] = "ERR"
try: out["tailnet"] = hp.honeypot_bind_address("100.86.203.66")
except Exception: out["tailnet"] = "ERR"
# deploy_honeypot binds loopback by default
r = hp.deploy_honeypot(0, timeout=1)
out["clean"] = r.get("status")
# env 0.0.0.0 must not bind
os.environ["WATCHTOWER_HONEYPOT_BIND"] = "0.0.0.0"
out["env_any"] = hp.deploy_honeypot(0, timeout=1).get("status")
os.environ.pop("WATCHTOWER_HONEYPOT_BIND", None)
# backoff: occupy a port, run daemon loop with sleep patched, count retries
blk = socket.socket(); blk.bind(("127.0.0.1", 0)); blk.listen(1); port = blk.getsockname()[1]
calls = {"n": 0}
def fake_sleep(sec):
    calls["n"] += 1; calls["sec"] = sec
    if calls["n"] >= 3: raise KeyboardInterrupt
hp.time.sleep = fake_sleep
try: hp.run_daemon(port)
except KeyboardInterrupt: pass
out["backoff_calls"] = calls["n"]; out["backoff_sec"] = calls.get("sec")
blk.close()
print(json.dumps(out))
`;
const r = spawnSync(py, ['-c', probe, ROOT], { encoding: 'utf8', timeout: 30000 });
let res = null;
try { res = JSON.parse((r.stdout || '').trim().split('\n').pop()); } catch (e) { /* ignore */ }
check('A16 python probe ran', !!res, (r.stderr || '').slice(-300));
if (res) {
  check('A16 default bind is 127.0.0.1', res.default === '127.0.0.1', res.default);
  for (const [k, v] of Object.entries(res.bad || {})) {
    check(`A16 refuses bind ${JSON.stringify(k)}`, v === 'refused', v);
  }
  check('A16 outer whitespace trimmed to one IP', res.trimmed === '127.0.0.1', res.trimmed);
  check('A16 accepts a single tailnet IPv4', res.tailnet === '100.86.203.66', res.tailnet);
  check('A16 loopback probe returns clean', res.clean === 'clean', res.clean);
  check('A16 env 0.0.0.0 does not bind', res.env_any === 'error', res.env_any);
  check('A16 daemon backs off on bind error (sleep called)', res.backoff_calls >= 3, String(res.backoff_calls));
  check('A16 backoff is >= 30s per retry', Number(res.backoff_sec) >= 30, String(res.backoff_sec));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
