// A22: sensors must reach the hub out of the box.
// - .env.example carries WATCHTOWER_API_URL and its port equals WATCHTOWER_API_PORT.
// - every Python sensor default URL uses that same port.
// - setup.sh edge rewrite actually lands the operator's hub URL in .env (replayed).
// - setup.sh / setup.ps1 hub mode do not rewrite the URL to a LAN/public IP
//   (the API binds loopback, so the hub's own beacon must stay on 127.0.0.1).
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
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const envEx = read('.env.example');
const portM = envEx.match(/^WATCHTOWER_API_PORT=(\d+)\s*$/m);
const urlM = envEx.match(/^WATCHTOWER_API_URL=(\S+)\s*$/m);
const port = portM ? portM[1] : '';
check('A22 .env.example sets WATCHTOWER_API_PORT', !!port);
check('A22 .env.example sets WATCHTOWER_API_URL', !!urlM);
let u = null;
try { u = new URL(urlM ? urlM[1] : ''); } catch (e) { /* invalid */ }
check('A22 .env.example API URL host is 127.0.0.1', !!u && u.hostname === '127.0.0.1', urlM && urlM[1]);
check('A22 .env.example API URL port equals API port', !!u && u.port === port, `${u && u.port} vs ${port}`);

// Sensor defaults: every core/*.py the deploy path launches (beacon sensor list +
// start.sh). Standalone tools (archiver, overseer, threat_intel) are tracked as A22c.
const core = path.join(ROOT, 'core');
const beaconSrc = fs.readFileSync(path.join(core, 'watchtower_beacon.py'), 'utf8');
const startSrc = read('start.sh');
const launched = new Set(['watchtower_beacon.py']);
for (const m of beaconSrc.matchAll(/target_sensors\.append\("([\w.]+\.py)"\)/g)) launched.add(m[1]);
for (const m of startSrc.matchAll(/python3 ([\w]+\.py)\b/g)) launched.add(m[1]);
check('A22 deploy path sensor list parsed', launched.size >= 8, [...launched].join(','));
const files = [...launched].filter((f) => fs.existsSync(path.join(core, f)));
let seen = 0;
for (const f of files) {
  const src = fs.readFileSync(path.join(core, f), 'utf8');
  const re = /os\.environ\.get\(\s*["']WATCHTOWER_API_URL["']\s*,\s*["']http:\/\/127\.0\.0\.1:(\d+)["']\s*\)/g;
  let m;
  while ((m = re.exec(src))) {
    seen++;
    check(`A22 ${f} default API port ${m[1]} equals ${port}`, m[1] === port, m[1]);
  }
}
check('A22 found sensor API URL defaults to check', seen >= 5, String(seen));

// setup.sh edge rewrite, replayed on a copy of .env.example
const setupSh = read('setup.sh');
const edge = setupSh.split('elif [ "$NODE_TYPE" == "2" ]')[1] || '';
const hub = (setupSh.split('if [ "$NODE_TYPE" == "1" ]')[1] || '').split('elif [ "$NODE_TYPE" == "2" ]')[0];
const sedLine = (edge.match(/^\s*sed -i\.bak "s\|[^"]*\|\$HUB_IP\|g" \.env\s*$/m) || [''])[0].trim();
check('A22 setup.sh edge has a HUB_IP rewrite line', !!sedLine, sedLine);
if (sedLine) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a22-'));
  fs.copyFileSync(path.join(ROOT, '.env.example'), path.join(d, '.env'));
  const hubUrl = 'http://100.64.0.9:4040';
  const r = spawnSync('bash', ['-c', `HUB_IP='${hubUrl}'; ${sedLine}`], { cwd: d, encoding: 'utf8' });
  const out = fs.readFileSync(path.join(d, '.env'), 'utf8');
  check('A22 edge rewrite runs', r.status === 0, r.stderr);
  check('A22 edge .env carries the operator hub URL', new RegExp(`^WATCHTOWER_API_URL=${hubUrl.replace(/[.]/g, '\\.')}$`, 'm').test(out),
    (out.match(/^WATCHTOWER_API_URL=.*$/m) || ['(missing)'])[0]);
}
check('A22 setup.sh hub mode does not rewrite the API URL', !/127\.0\.0\.1:4040/.test(hub) && !/LOCAL_IP/.test(hub));

const ps1 = read('setup.ps1');
const psHub = (ps1.split('if ($NodeType -eq "1")')[1] || '').split('elseif ($NodeType -eq "2")')[0];
const psEdge = ps1.split('elseif ($NodeType -eq "2")')[1] || '';
check('A22 setup.ps1 hub mode does not rewrite the API URL', !/127\.0\.0\.1:4040/.test(psHub) && !/LocalIp/.test(psHub));
check('A22 setup.ps1 edge mode rewrites the URL to the hub', /-replace "http:\/\/127\.0\.0\.1:4040", \$HubIp/.test(psEdge));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
