'use strict';
// A13: isolate_network must accept only a single hub IP. A newline in the
// target injected extra pf rules on macOS; 0.0.0.0/0 or a hostname turned
// iptables/netsh isolation into allow-all. Runs the real Python module with
// psutil stubbed and subprocess/platform patched (no command ever runs).
// Also refuses IPv6 zone ids (free text after %), any/unspecified,
// multicast, broadcast/reserved, and leading-zero or non-ASCII digits.
const { spawnSync } = require('child_process');
const path = require('path');

const repo = path.join(__dirname, '..', '..');
const PY = process.env.PYTHON_BIN || 'python3';
let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name + (detail ? ' :: ' + detail : '')); }
}

const harness = `
import sys, json, types
sys.modules['psutil'] = types.ModuleType('psutil')
sys.path.insert(0, ${JSON.stringify(path.join(repo, 'core'))})
import watchtower_quarantine as q
cases = json.loads(sys.argv[1])
out = []
for os_name, target in cases:
    calls = []
    class P:
        returncode = 0
        def __init__(self, cmd, **kw): calls.append({'cmd': cmd})
        def communicate(self, data=None):
            calls[-1]['stdin'] = data
            return ('', '')
    def run(cmd, **kw):
        calls.append({'cmd': cmd})
    q.subprocess.Popen = P
    q.subprocess.run = run
    q.platform.system = lambda n=os_name: n
    msg = q.isolate_network(target)
    out.append({'os': os_name, 'target': target, 'msg': msg, 'calls': calls})
print(json.dumps(out))
`;

const GOOD = [
  ['100.64.0.1', '100.64.0.1'],
  ['http://100.64.0.1:4040', '100.64.0.1'],
  ['https://100.64.0.1', '100.64.0.1'],
  ['  100.64.0.1  ', '100.64.0.1'],
  ['http://[fd7a:115c:a1e0::1]:4040', 'fd7a:115c:a1e0::1'],
  ['::ffff:100.64.0.1', '100.64.0.1'],
  ['127.0.0.1', '127.0.0.1'],
  ['::1', '::1'],
];
const BAD = [
  '100.64.0.1\npass out all',
  '100.64.0.1\rpass out all',
  'http://100.64.0.1\npass',
  '0.0.0.0/0',
  '100.64.0.0/10',
  'evil.example.com',
  'http://evil.example.com:4040',
  '100.64.0.1 any',
  '-j ACCEPT',
  '',
  'remoteip=any',
  'fe80::1%#',
  'fe80::1%en0',
  'http://[fe80::1%25en0]:4040',
  '0.0.0.0',
  '::',
  '::ffff:0.0.0.0',
  '255.255.255.255',
  '224.0.0.1',
  'ff02::1',
  '100.64.0.01',
  '\uff11\uff10\uff10.64.0.1',
];
const OSES = ['Darwin', 'Linux', 'Windows'];
const cases = [];
for (const os of OSES) {
  for (const [t] of GOOD) cases.push([os, t]);
  for (const t of BAD) cases.push([os, t]);
}

const r = spawnSync(PY, ['-c', harness, JSON.stringify(cases)], { encoding: 'utf8' });
if (r.status !== 0) {
  console.log(r.stderr);
  check('python harness runs', false, 'exit ' + r.status);
} else {
  const results = JSON.parse(r.stdout);
  let i = 0;
  for (const os of OSES) {
    for (const [t, ip] of GOOD) {
      const res = results[i++];
      const flat = JSON.stringify(res.calls);
      const hasIp = res.calls.length > 0 && flat.includes(ip);
      let pfOk = true;
      if (os === 'Darwin') {
        const rules = (res.calls[0] && res.calls[0].stdin) || '';
        pfOk = rules.split('\n').filter(Boolean).length === 3;
      }
      check(`${os} accepts ${JSON.stringify(t)} as ${ip}`, hasIp && pfOk && res.msg.startsWith('[+]'), res.msg);
    }
    for (const t of BAD) {
      const res = results[i++];
      check(`${os} refuses ${JSON.stringify(t)} with no command run`,
        res.calls.length === 0 && res.msg.startsWith('[-] Refused'),
        `calls=${JSON.stringify(res.calls)} msg=${res.msg}`);
    }
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
