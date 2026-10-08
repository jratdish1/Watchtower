// A19: edge service install must point at a script that exists (no start-agent.*).
// A20: under systemd/launchd, start.sh must not also run the resurrection respawner
//      (one restart owner). Unsupervised manual runs keep it.
// A17 (Windows): start.bat binds loopback by default and refuses all-interfaces.
// Nothing real is installed: sudo/systemctl/launchctl/python3/node are shims.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..', '..');
let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`ok - ${name}`); }
  else { fail++; console.log(`not ok - ${name}${detail ? ' :: ' + detail : ''}`); }
}
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
function shim(dir, name, body) {
  fs.writeFileSync(path.join(dir, name), '#!/bin/bash\n' + body + '\n', { mode: 0o755 });
}

// ---- A19 static: no tracked file references start-agent ----
let tracked = [];
try { tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean); } catch (e) { /* not a git checkout */ }
check('A19 git ls-files available', tracked.length > 0);
const refs = tracked.filter((f) => !f.endsWith('service-owner.test.js') && !f.startsWith('node_modules') &&
  fs.existsSync(path.join(ROOT, f)) && fs.statSync(path.join(ROOT, f)).size < 2e6 &&
  /start-agent/.test(fs.readFileSync(path.join(ROOT, f), 'latin1')));
check('A19 no tracked file references start-agent', refs.length === 0, refs.join(','));

// ---- A19/A20 runtime: generate the systemd unit with shims ----
function genUnit(args) {
  const out = tmp('wt-unit-');
  const bin = tmp('wt-bin-');
  shim(bin, 'sudo', `exec "\${@//\\/etc\\/systemd\\/system\\//${out}/}"`);
  shim(bin, 'systemctl', 'exit 0');
  shim(bin, 'launchctl', 'exit 0');
  const r = spawnSync('bash', [path.join(ROOT, 'install_service.sh'), ...args], {
    cwd: ROOT, encoding: 'utf8', timeout: 20000,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, OSTYPE: 'linux-gnu' },
  });
  const files = fs.readdirSync(out);
  const unit = files.length ? fs.readFileSync(path.join(out, files[0]), 'utf8') : '';
  return { r, files, unit };
}
for (const [label, args, svc] of [['hub', [], 'watchtower.service'], ['agent', ['--agent'], 'watchtower-agent.service']]) {
  const g = genUnit(args);
  check(`A19 ${label}: unit file ${svc} written`, g.files.includes(svc), g.files.join(',') + ' ' + (g.r.stderr || '').slice(-200));
  const m = g.unit.match(/^ExecStart=(.+)$/m);
  const target = m ? m[1].trim() : '';
  check(`A19 ${label}: ExecStart target exists`, !!target && fs.existsSync(target), target);
  check(`A19 ${label}: ExecStart is start.sh`, path.basename(target) === 'start.sh', target);
  check(`A20 ${label}: unit sets WATCHTOWER_SUPERVISED=1`, /^Environment=WATCHTOWER_SUPERVISED=1$/m.test(g.unit));
}
const inst = fs.readFileSync(path.join(ROOT, 'install_service.sh'), 'utf8');
check('A20 launchd plist sets WATCHTOWER_SUPERVISED', /<key>WATCHTOWER_SUPERVISED<\/key>\s*<string>1<\/string>/.test(inst));

// ---- A20 runtime: start.sh skips resurrection only when supervised ----
function runStart(supervised) {
  const d = tmp('wt-start-');
  const bin = tmp('wt-bin-');
  const log = path.join(d, 'launched.log');
  fs.copyFileSync(path.join(ROOT, 'start.sh'), path.join(d, 'start.sh'));
  fs.writeFileSync(path.join(d, '.env'), 'NODE_TYPE=EDGE\n');
  fs.mkdirSync(path.join(d, '.venv', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(d, '.venv', 'bin', 'activate'), 'true\n');
  fs.mkdirSync(path.join(d, 'core'));
  shim(bin, 'python3', `echo "$*" >> ${log}`);
  shim(bin, 'node', `echo "node $*" >> ${log}`);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
  delete env.WATCHTOWER_SUPERVISED;
  if (supervised) env.WATCHTOWER_SUPERVISED = '1';
  const r = spawnSync('bash', ['./start.sh'], { cwd: d, encoding: 'utf8', timeout: 20000, env });
  return { r, launched: fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '' };
}
const sup = runStart(true);
check('A20 supervised: beacon launched', /watchtower_beacon\.py/.test(sup.launched), sup.launched);
check('A20 supervised: resurrection NOT launched', !/watchtower_resurrection\.py/.test(sup.launched), sup.launched);
// A25: shims exit at once; under supervision a dead child must end start.sh non-zero (service manager restarts).
check('A20/A25 supervised: dead children -> start.sh exits 1', sup.r.status === 1, String(sup.r.status));
const man = runStart(false);
check('A20 manual run: beacon launched', /watchtower_beacon\.py/.test(man.launched), man.launched);
check('A20 manual run: resurrection still launched', /watchtower_resurrection\.py/.test(man.launched), man.launched);

// ---- A17 Windows (static) ----
const bat = fs.readFileSync(path.join(ROOT, 'start.bat'), 'utf8');
const envAt = bat.indexOf('in (.env) do set');
const defAt = bat.indexOf('if "%WATCHTOWER_BIND_ADDRESS%"=="" set WATCHTOWER_BIND_ADDRESS=127.0.0.1');
const launchAt = bat.indexOf('node app.js');
check('A17 start.bat defaults API bind to 127.0.0.1', defAt > -1);
check('A17 start.bat default comes after .env load and before launch', envAt > -1 && defAt > envAt && defAt < launchAt, `${envAt}/${defAt}/${launchAt}`);
check('A17 start.bat defaults honeypot bind to 127.0.0.1', bat.includes('if "%WATCHTOWER_HONEYPOT_BIND%"=="" set WATCHTOWER_HONEYPOT_BIND=127.0.0.1'));
check('A17 start.bat refuses 0.0.0.0', /if "%WATCHTOWER_BIND_ADDRESS%"=="0\.0\.0\.0" goto refuse_bind/.test(bat));
check('A17 start.bat refuses ::', /if "%WATCHTOWER_BIND_ADDRESS%"=="::" goto refuse_bind/.test(bat));
check('A17 start.bat refuse path exits non-zero', /:refuse_bind\r?\n[^\n]*REFUSED[^\n]*\r?\nexit \/b 1/.test(bat));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
