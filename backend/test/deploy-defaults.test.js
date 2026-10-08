// A15/A16/A17: deploy-path defaults must fail closed.
// A15 secure_update.sh must refuse (no fake "Signature Verified").
// A16 honeypot binds loopback by default, refuses 0.0.0.0/hostnames/CIDR,
//     and backs off (no CPU spin) when the port is taken.
// A17 start.sh binds loopback by default and refuses all-interfaces binds.
// A18 sensors observe only (audit) unless policy explicitly sets AUDIT_MODE false;
//     an edge that cannot reach the hub must never kill processes or quarantine files.
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

// ---- A18 (runtime, python) ----
const a18 = `
import importlib.util, json, os, sys, tempfile, re
root = sys.argv[1]
os.environ["WATCHTOWER_API_KEY"] = "a18-test-only-key-not-a-secret-0123456789abcdef"
os.environ["WATCHTOWER_API_URL"] = "http://127.0.0.1:9"
os.environ["WATCHTOWER_DATA_DIR"] = tempfile.mkdtemp()
os.environ.pop("WATCHTOWER_AUDIT_MODE", None)
spec = importlib.util.spec_from_file_location("bc", os.path.join(root, "core", "watchtower_beacon.py"))
bc = importlib.util.module_from_spec(spec); spec.loader.exec_module(bc)
out = {}
out["fallback"] = bc.sync_policy().get("WATCHTOWER_AUDIT_MODE")
cases = {"missing": {}, "bool_false": {"WATCHTOWER_AUDIT_MODE": False}, "str_false": {"WATCHTOWER_AUDIT_MODE": "false"},
         "str_False_pad": {"WATCHTOWER_AUDIT_MODE": " False "}, "bool_true": {"WATCHTOWER_AUDIT_MODE": True},
         "str_yes": {"WATCHTOWER_AUDIT_MODE": "yes"}, "str_0": {"WATCHTOWER_AUDIT_MODE": "0"},
         "none": {"WATCHTOWER_AUDIT_MODE": None}, "empty": {"WATCHTOWER_AUDIT_MODE": ""}}
if hasattr(bc, "audit_mode_env"):
    out["env"] = {k: bc.audit_mode_env(v) for k, v in cases.items()}
    out["env"]["not_dict"] = bc.audit_mode_env(["x"])
else:
    out["env"] = {k: "MISSING" for k in list(cases) + ["not_dict"]}
captured = []
class FakeP:
    def poll(self): return None
def fake_popen(args, env=None, **kw):
    captured.append(env.get("WATCHTOWER_AUDIT_MODE")); return FakeP()
bc.subprocess.Popen = fake_popen
os.environ["WATCHTOWER_AUDIT_MODE"] = "false"   # hostile outer env must not leak through
bc.RUNNING_SENSORS.clear(); bc.manage_sensors({"ENABLE_FIM": True})
out["popen_missing_key"] = captured[-1] if captured else None
bc.RUNNING_SENSORS.clear(); bc.manage_sensors({"ENABLE_FIM": True, "WATCHTOWER_AUDIT_MODE": False})
out["popen_explicit_false"] = captured[-1] if captured else None
os.environ.pop("WATCHTOWER_AUDIT_MODE", None)
out["sensors"] = {}
for name in ("watchtower_fim.py", "watchtower_behavioral.py"):
    src = open(os.path.join(root, "core", name)).read()
    line = [l for l in src.splitlines() if l.startswith("AUDIT_MODE =")]
    res = {}
    for label, val in (("unset", None), ("false", "false"), ("FALSE", "FALSE"), ("true", "true"), ("empty", ""), ("junk", "maybe")):
        if val is None: os.environ.pop("WATCHTOWER_AUDIT_MODE", None)
        else: os.environ["WATCHTOWER_AUDIT_MODE"] = val
        ns = {"os": os}
        exec(line[0], ns) if line else None
        res[label] = ns.get("AUDIT_MODE")
    out["sensors"][name] = res
print(json.dumps(out))
`;
const ra = spawnSync(py, ['-c', a18, ROOT], { encoding: 'utf8', timeout: 30000, cwd: path.join(ROOT, 'core') });
let a = null;
try { a = JSON.parse((ra.stdout || '').trim().split('\n').pop()); } catch (e) { /* ignore */ }
check('A18 python probe ran', !!a, (ra.stderr || '').slice(-300));
if (a) {
  check('A18 hub-unreachable fallback policy is audit', a.fallback === true, String(a.fallback));
  const expectFalse = new Set(['bool_false', 'str_false', 'str_False_pad']);
  for (const [k, v] of Object.entries(a.env)) {
    const want = expectFalse.has(k) ? 'false' : 'true';
    check(`A18 audit_mode_env(${k}) = ${want}`, v === want, v);
  }
  check('A18 sensor env is audit when policy omits the key (outer env ignored)', a.popen_missing_key === 'true', String(a.popen_missing_key));
  check('A18 sensor env honors explicit false', a.popen_explicit_false === 'false', String(a.popen_explicit_false));
  for (const [name, r] of Object.entries(a.sensors)) {
    check(`A18 ${name} unset env -> audit`, r.unset === true, String(r.unset));
    check(`A18 ${name} "false" -> active`, r.false === false, String(r.false));
    check(`A18 ${name} "FALSE" -> active`, r.FALSE === false, String(r.FALSE));
    check(`A18 ${name} "true" -> audit`, r.true === true, String(r.true));
    check(`A18 ${name} "" -> audit`, r.empty === true, String(r.empty));
    check(`A18 ${name} junk -> audit`, r.junk === true, String(r.junk));
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
