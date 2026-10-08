// A23: AI bridge must return a verdict dict (never crash) when the inference
//      server is offline or returns junk. Only SAFE/SUSPICIOUS/MALICIOUS trusted.
// A24: generated systemd unit carries phase-1 hardening, keeps $DIR writable,
//      and does NOT set NoNewPrivileges (isolate_network needs sudo; VETS A24b).
// A25: under supervision start.sh exits 1 when any child dies (service manager
//      restarts the group); SIGTERM still stops cleanly; manual runs unchanged.
// Nothing real is installed; the fake LLM listens on 127.0.0.1 only.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..', '..');
let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`ok - ${name}`); }
  else { fail++; console.log(`not ok - ${name}${detail ? ' :: ' + detail : ''}`); }
}
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));

// ---- A23 runtime ----
const PY = String.raw`
import json, os, sys, threading, http.server, socket
sys.path.insert(0, os.path.join(sys.argv[1], 'core'))
mode = {'v': None}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200)
        self.send_header('Content-Type','application/json'); self.send_header('Content-Length', str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self): self._send({'data': [{'id': 'fake'}]})
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self._send({'choices': [{'message': {'content': mode['v']}}]})
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
s = socket.socket(); s.bind(('127.0.0.1', 0)); dead = s.getsockname()[1]; s.close()
f = os.path.join(sys.argv[2], 'probe.txt'); open(f, 'w').write('echo hello\n')
import importlib
out = {}
os.environ['AI_INFERENCE_URL'] = 'http://127.0.0.1:%d/v1/chat/completions' % dead
import watchtower_ai_bridge as b
try: out['offline'] = b.analyze_file('FILE_CREATED', f)
except Exception as e: out['offline'] = {'crash': type(e).__name__}
b.LM_STUDIO_URL = 'http://127.0.0.1:%d/v1/chat/completions' % srv.server_address[1]
cases = {
  'safe': '{"verdict": "SAFE", "reason": "benign"}',
  'think_fence': '<think>hmm\nlong</think>` + '```' + String.raw`json\n{"verdict": "MALICIOUS", "reason": "x"}\n` + '```' + String.raw`',
  'list': '[1,2,3]',
  'bad_verdict': '{"verdict": "OK", "reason": "y"}',
  'no_verdict': '{"reason": "z"}',
  'garbage': 'not json at all',
  'long_reason': json.dumps({'verdict': 'SUSPICIOUS', 'reason': 'A' * 5000}),
}
for k, v in cases.items():
    mode['v'] = v
    try: out[k] = b.analyze_file('FILE_CREATED', f)
    except Exception as e: out[k] = {'crash': type(e).__name__}
print('RESULT=' + json.dumps(out))
`;
const work = tmp('wt-a23-');
const r = spawnSync('python3', ['-c', PY, ROOT, work], { encoding: 'utf8', timeout: 60000,
  env: { PATH: process.env.PATH, HOME: work, PYTHONDONTWRITEBYTECODE: '1' } });
const line = (r.stdout || '').split('\n').find((l) => l.startsWith('RESULT='));
let res = {};
try { res = JSON.parse(line.slice(7)); } catch (e) { /* reported below */ }
check('A23 harness produced a result', !!line, (r.stderr || '').slice(-400));
const v = (k) => (res[k] || {}).verdict;
check('A23 offline LLM: no crash', res.offline && !res.offline.crash, JSON.stringify(res.offline));
check('A23 offline LLM: verdict ERROR', v('offline') === 'ERROR', JSON.stringify(res.offline));
check('A23 valid SAFE passes through', v('safe') === 'SAFE', JSON.stringify(res.safe));
check('A23 think block + json fence parsed', v('think_fence') === 'MALICIOUS', JSON.stringify(res.think_fence));
for (const k of ['list', 'bad_verdict', 'no_verdict']) {
  check(`A23 ${k}: not trusted -> UNKNOWN`, v(k) === 'UNKNOWN', JSON.stringify(res[k]));
}
check('A23 garbage: no crash, verdict ERROR', v('garbage') === 'ERROR', JSON.stringify(res.garbage));
check('A23 reason capped at 500 chars', v('long_reason') === 'SUSPICIOUS' && res.long_reason.reason.length <= 500,
  res.long_reason ? String(res.long_reason.reason.length) : 'missing');
for (const [k, o] of Object.entries(res)) {
  check(`A23 ${k}: no crash key`, !o.crash, JSON.stringify(o));
}

// ---- A24 runtime: generate the systemd unit with shims ----
function shim(dir, name, body) {
  fs.writeFileSync(path.join(dir, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
}
for (const [label, args, svc] of [['hub', [], 'watchtower.service'], ['agent', ['--agent'], 'watchtower-agent.service']]) {
  const out = tmp('wt-unit-'); const bin = tmp('wt-bin-');
  shim(bin, 'sudo', `exec "\${@//\\/etc\\/systemd\\/system\\//${out}/}"`);
  shim(bin, 'systemctl', 'exit 0'); shim(bin, 'launchctl', 'exit 0');
  const g = spawnSync('bash', [path.join(ROOT, 'install_service.sh'), ...args], { cwd: ROOT, encoding: 'utf8', timeout: 20000,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, OSTYPE: 'linux-gnu' } });
  const p = path.join(out, svc);
  const unit = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
  check(`A24 ${label}: unit written`, unit.length > 0, (g.stderr || '').slice(-200));
  for (const d of ['ProtectSystem=full', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectKernelLogs=yes',
    'ProtectControlGroups=yes', 'ProtectClock=yes', 'ProtectHostname=yes', 'RestrictSUIDSGID=yes',
    'RestrictRealtime=yes', 'LockPersonality=yes', 'UMask=0077']) {
    check(`A24 ${label}: ${d}`, new RegExp('^' + d + '$', 'm').test(unit));
  }
  check(`A24 ${label}: ReadWritePaths is the install dir`, new RegExp('^ReadWritePaths=' + ROOT.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&') + '$', 'm').test(unit));
  check(`A24 ${label}: NoNewPrivileges not set (sudo for isolate_network)`, !/^NoNewPrivileges=/m.test(unit));
  check(`A24 ${label}: hardening sits in [Service]`, unit.indexOf('ProtectSystem=') > unit.indexOf('[Service]') && unit.indexOf('ProtectSystem=') < unit.indexOf('[Install]'));
  const sa = spawnSync('systemd-analyze', ['--version'], { encoding: 'utf8' });
  if (sa.status === 0) {
    const vr = spawnSync('systemd-analyze', ['verify', p], { encoding: 'utf8' });
    check(`A24 ${label}: systemd-analyze verify clean of unknown keys`, !/Unknown key|Unknown section/i.test(vr.stderr || ''), (vr.stderr || '').slice(-300));
  }
}

// ---- A24 launchd (macOS canary target): generate the plist with HOME redirected ----
{
  const home = tmp('wt-home-'); const bin = tmp('wt-bin-');
  shim(bin, 'launchctl', 'exit 0');
  for (const [label, args, name] of [['hub', [], 'com.vertex.watchtower.plist'], ['agent', ['--agent'], 'com.vertex.watchtower-agent.plist']]) {
    spawnSync('bash', [path.join(ROOT, 'install_service.sh'), ...args], { cwd: ROOT, encoding: 'utf8', timeout: 20000,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, OSTYPE: 'darwin23', HOME: home } });
    const pp = path.join(home, 'Library', 'LaunchAgents', name);
    const pl = fs.existsSync(pp) ? fs.readFileSync(pp, 'utf8') : '';
    check(`A24 launchd ${label}: plist written`, pl.length > 0);
    check(`A24 launchd ${label}: KeepAlive restarts on failure only`, /<key>KeepAlive<\/key>\s*<dict>\s*<key>SuccessfulExit<\/key>\s*<false\/>\s*<\/dict>/.test(pl));
    check(`A24 launchd ${label}: ThrottleInterval 10`, /<key>ThrottleInterval<\/key>\s*<integer>10<\/integer>/.test(pl));
    check(`A24 launchd ${label}: Umask 63 (077)`, /<key>Umask<\/key>\s*<integer>63<\/integer>/.test(pl));
    check(`A24 launchd ${label}: still supervised (A20)`, /<key>WATCHTOWER_SUPERVISED<\/key>\s*<string>1<\/string>/.test(pl));
    const lint = spawnSync('python3', ['-c', 'import plistlib,sys; plistlib.load(open(sys.argv[1],"rb")); print("ok")', pp], { encoding: 'utf8' });
    check(`A24 launchd ${label}: plist parses (plistlib)`, (lint.stdout || '').trim() === 'ok', (lint.stderr || '').slice(-200));
  }
}

// ---- A25 runtime: supervised child watch ----
function startRig(supervised) {
  const d = tmp('wt-a25-'); const bin = tmp('wt-bin-'); const pids = path.join(d, 'pids');
  fs.mkdirSync(pids);
  fs.copyFileSync(path.join(ROOT, 'start.sh'), path.join(d, 'start.sh'));
  fs.writeFileSync(path.join(d, '.env'), 'NODE_TYPE=EDGE\n');
  fs.mkdirSync(path.join(d, '.venv', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(d, '.venv', 'bin', 'activate'), 'true\n');
  fs.mkdirSync(path.join(d, 'core'));
  // beacon dies after 1 s; every other sensor runs until killed.
  shim(bin, 'python3', `echo $$ > ${pids}/$$; case "$*" in *watchtower_beacon*) sleep 1; exit 0;; esac; exec sleep 60`);
  shim(bin, 'node', 'exec sleep 60');
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
  delete env.WATCHTOWER_SUPERVISED;
  if (supervised) env.WATCHTOWER_SUPERVISED = '1';
  return { d, pids, env };
}
// Zombie-aware: a reaped-late child (state Z) is dead, even though kill -0 succeeds.
const alive = (pid) => {
  try {
    const st = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    return st.slice(st.lastIndexOf(')') + 2, st.lastIndexOf(')') + 3) !== 'Z';
  } catch (e) {
    if (fs.existsSync('/proc/self/stat')) return false;
    try { process.kill(pid, 0); return true; } catch (e2) { return false; }
  }
};
const waitDead = (pid, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (!alive(pid)) return true; spawnSync('sleep', ['0.2']); } return !alive(pid); };
const pidList = (dir) => fs.readdirSync(dir).map(Number).filter(Boolean);
{
  const g = startRig(true); const t0 = Date.now();
  const r = spawnSync('bash', ['./start.sh'], { cwd: g.d, encoding: 'utf8', timeout: 30000, env: g.env });
  const secs = (Date.now() - t0) / 1000;
  check('A25 supervised: start.sh exits 1 when a sensor dies', r.status === 1, `status=${r.status} signal=${r.signal}`);
  check('A25 supervised: exit within 12 s', secs < 12, String(secs));
  check('A25 supervised: logs which child exited', /exited under supervision/.test(r.stderr || ''), (r.stderr || '').slice(-200));
  pidList(g.pids).forEach((p) => waitDead(p, 2000));
  const left = pidList(g.pids).filter(alive);
  check('A25 supervised: siblings killed (no orphans)', left.length === 0, left.join(','));
  left.forEach((p) => { try { process.kill(p, 'SIGKILL'); } catch (e) { /* gone */ } });
}
for (const supervised of [true, false]) {
  const label = supervised ? 'supervised' : 'manual';
  const g = startRig(supervised);
  // beacon must not die in this run: make it a long sleeper too.
  fs.writeFileSync(path.join(path.dirname(g.env.PATH.split(':')[0]), path.basename(g.env.PATH.split(':')[0]), 'python3'),
    `#!/bin/bash\necho $$ > ${g.pids}/$$\nexec sleep 60\n`, { mode: 0o755 });
  const child = require('child_process').spawn('bash', ['./start.sh'], { cwd: g.d, env: g.env, stdio: 'ignore' });
  spawnSync('sleep', ['3']);
  check(`A25 ${label}: still running after 3 s with healthy sensors`, child.exitCode === null && alive(child.pid));
  const t0 = Date.now();
  child.kill('SIGTERM');
  check(`A25 ${label}: SIGTERM stops start.sh within 6 s`, waitDead(child.pid, 6000), String((Date.now() - t0) / 1000));
  spawnSync('sleep', ['0.5']);
  const left = pidList(g.pids).filter(alive);
  check(`A25 ${label}: SIGTERM kills all sensors`, left.length === 0, left.join(','));
  left.forEach((p) => { try { process.kill(p, 'SIGKILL'); } catch (e) { /* gone */ } });
}
const startSrc = fs.readFileSync(path.join(ROOT, 'start.sh'), 'utf8');
const codeLines = startSrc.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
check('A25 start.sh avoids bash>=4.3 `wait -n` (macOS bash 3.2)', !/wait\s+-n/.test(codeLines));

console.log(`\n# bridge-hardening: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
