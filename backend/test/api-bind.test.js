// A27: backend/app.js binds loopback by default and refuses every-interface or non-IP binds,
// even when started directly (not through start.sh). Spawns the real app; nothing listens on 0.0.0.0.
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
let pass = 0, fail = 0;
function check(name, ok, info) { if (ok) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, info || ''); } }
const KEY = require('crypto').randomBytes(32).toString('hex');
let port = 44100;
function run(bind) {
  return new Promise((resolve) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a27-'));
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_API_PORT: String(port++), WATCHTOWER_DATA_DIR: tmp, WATCHTOWER_UPDATES_DIR: tmp,
      WATCHTOWER_DB_PATH: path.join(tmp, 'wt.db'), AUTO_REMEDIATE: 'false' };
    if (bind !== undefined) env.WATCHTOWER_BIND_ADDRESS = bind;
    const p = spawn(process.execPath, ['app.js'], { cwd: path.join(__dirname, '..'), env });
    let out = '';
    const done = (r) => { clearTimeout(t); try { p.kill('SIGKILL'); } catch (e) {} fs.rmSync(tmp, { recursive: true, force: true }); resolve(r); };
    p.stdout.on('data', (d) => { out += d; const m = /Server listening on http:\/\/(\S+):\d+/.exec(out); if (m) done({ listened: m[1], out }); });
    p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => done({ code, out }));
    const t = setTimeout(() => done({ timeout: true, out }), 8000);
  });
}
(async () => {
  let r = await run(undefined);
  check('unset -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  r = await run('');
  check('empty -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  r = await run('127.0.0.1');
  check('127.0.0.1 -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  r = await run('192.0.2.1');  // TEST-NET-1, never assigned to this host
  check('unbindable IP -> exit 1 + FATAL, not a silent exit 0', r.code === 1 && /\[FATAL\] API cannot listen/.test(r.out) && !r.listened, JSON.stringify(r).slice(0, 200));
  for (const bad of ['0.0.0.0', '::', '::0', '0:0:0:0:0:0:0:0', '00.0.0.0', '::ffff:0.0.0.0', 'localhost', 'evil.example', '10.0.0.0/8', '127.0.0.1 0.0.0.0', '999.1.1.1']) {
    r = await run(bad);
    check(`refuses ${JSON.stringify(bad)}`, r.code === 1 && /\[FATAL\] WATCHTOWER_BIND_ADDRESS/.test(r.out) && !r.listened, JSON.stringify(r).slice(0, 200));
  }
  const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  check("no '0.0.0.0' default left in app.js", !/WATCHTOWER_BIND_ADDRESS\s*\|\|\s*['"]0\.0\.0\.0['"]/.test(src));
  check('no pre-listen "Listening on" claim', !/API Gateway\] Listening on/.test(src));
  console.log(`# api-bind: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
