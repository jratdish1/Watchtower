// A27: one bind-address and listen-error rule (backend/bind_address.js) for the API and the UI.
// Covers: the rule itself on the parsed bytes, the real UI process refusing every-interface binds, the bounded
// busy-port retry on both real processes, the UI proxy reaching an API bound to a non-loopback/IPv6 address with a
// valid Host header, both listeners using the one shared module (no private copies), and start.sh/start.bat parity.
const { spawn, spawnSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const ROOT = path.join(__dirname, '..', '..');
const B = require('../bind_address');
let pass = 0, fail = 0;
function check(name, ok, info) { if (ok) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, info || ''); } }

// Every-interface spellings (IPv6 wildcard, IPv4 wildcard, IPv4-mapped IPv4 wildcard, zone, case, padding).
const EVERY = ['0.0.0.0', '::', '::0', '0::0', '::0:0', '0:0:0:0:0:0:0:0', '::%lo', '::%eth0',
  '::ffff:0.0.0.0', '::ffff:0:0', '0:0:0:0:0:ffff:0:0', '::ffff:0000:0000', '::FFFF:0:0', '0000:0000:0000:0000:0000:ffff:0000:0000'];
// Not an IP literal at all.
const NOT_IP = ['localhost', 'evil.example', '10.0.0.0/8', '127.0.0.1 0.0.0.0', '999.1.1.1', '00.0.0.0', '1.2.3', '0', '::%', '::1%../x'];
// One specific interface.
const ONE = ['127.0.0.1', '127.0.0.2', '100.86.203.66', '::1', 'fe80::1%en0', '64:ff9b::0.0.0.0', '::ffff:127.0.0.1', '::0.0.0.1', '2001:db8::1'];

for (const v of EVERY) check(`rule: every-interface ${JSON.stringify(v)} refused`, B.checkBindAddress(v).ok === false);
for (const v of NOT_IP) check(`rule: non-IP ${JSON.stringify(v)} refused`, B.checkBindAddress(v).ok === false);
for (const v of ONE) check(`rule: one interface ${JSON.stringify(v)} accepted`, B.checkBindAddress(v).ok === true);
for (const v of [undefined, null, '', '   ']) {
  const r = B.checkBindAddress(v);
  check(`rule: ${JSON.stringify(v)} -> default 127.0.0.1`, r.ok === true && r.address === '127.0.0.1', JSON.stringify(r));
}
check('rule: input is trimmed', B.checkBindAddress('  127.0.0.1\n').address === '127.0.0.1');
check('urlHost brackets IPv6, zone written %25 (RFC 6874)', B.urlHost('::1') === '[::1]' && B.urlHost('fe80::1%en0') === '[fe80::1%25en0]');
check('hostHeader: IPv4 / IPv6 bracketed / zone dropped', B.hostHeader('127.0.0.1', 3000) === '127.0.0.1:3000'
  && B.hostHeader('::1', '3000') === '[::1]:3000' && B.hostHeader('fe80::1%en0', 3000) === '[fe80::1]:3000');
// UI -> API target: explicit WATCHTOWER_API_HOST wins; otherwise the API bind address; otherwise loopback.
for (const [env, want, why] of [
  [{}, '127.0.0.1', 'nothing set -> loopback'],
  [{ WATCHTOWER_BIND_ADDRESS: '100.86.203.66' }, '100.86.203.66', 'API bound to tailnet IP -> proxy follows it'],
  [{ WATCHTOWER_BIND_ADDRESS: ' ::1 ' }, '::1', 'API bound to ::1 (trimmed) -> proxy follows it'],
  [{ WATCHTOWER_BIND_ADDRESS: '0.0.0.0' }, '127.0.0.1', 'refused API bind -> loopback, never a wildcard target'],
  [{ WATCHTOWER_BIND_ADDRESS: 'localhost' }, '127.0.0.1', 'non-IP API bind -> loopback'],
  [{ WATCHTOWER_API_HOST: 'hub.tailnet.ts.net', WATCHTOWER_BIND_ADDRESS: '100.86.203.66' }, 'hub.tailnet.ts.net', 'explicit host wins'],
  [{ WATCHTOWER_API_HOST: ' [::1] ' }, '::1', 'explicit bracketed IPv6 -> bare address'],
  [{ WATCHTOWER_API_HOST: '   ', WATCHTOWER_BIND_ADDRESS: '::1' }, '::1', 'blank explicit host ignored'],
]) check(`apiTargetHost: ${why}`, B.apiTargetHost(env) === want, JSON.stringify({ env, got: B.apiTargetHost(env) }));
check('apiTargetHost(undefined) -> loopback', B.apiTargetHost(undefined) === '127.0.0.1');
// Busy-port retry count: digits only, 0..1000, else the default (20).
for (const [raw, want] of [[undefined, 20], ['', 20], ['0', 0], ['1', 1], [' 5 ', 5], ['1000', 1000], ['1001', 20],
  ['-1', 20], ['3.5', 20], ['1e3', 20], ['abc', 20], ['99999', 20]]) {
  check(`listenRetryMax(${JSON.stringify(raw)}) -> ${want}`, B.listenRetryMax(raw) === want, String(B.listenRetryMax(raw)));
}
check('urlHost leaves IPv4 alone', B.urlHost('127.0.0.1') === '127.0.0.1');

// Starts the real UI server on port 0 (the OS picks a free port atomically; no probe-then-close race).
// Resolves on its listen line or on close (stdout/stderr fully drained).
function runUi(bind) {
  return new Promise((resolve) => {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME,
      WATCHTOWER_API_KEY: require('crypto').randomBytes(32).toString('hex'),
      WATCHTOWER_UI_PORT: '0', WATCHTOWER_API_PORT: '9' };
    if (bind !== undefined) env.WATCHTOWER_UI_BIND_ADDRESS = bind;
    const p = spawn(process.execPath, [path.join(ROOT, 'frontend', 'serve_ui.js')], { cwd: ROOT, env });
    let out = '';
    const done = (r) => { clearTimeout(t); try { p.kill('SIGKILL'); } catch (e) {} resolve(r); };
    p.stdout.on('data', (d) => { out += d; const m = /UI Server listening on http:\/\/(\S+):(\d+)/.exec(out); if (m) done({ listened: m[1], port: Number(m[2]), out }); });
    p.stderr.on('data', (d) => { out += d; });
    p.on('close', (code) => done({ code, out }));
    const t = setTimeout(() => done({ timeout: true, out }), 8000);
  });
}

(async () => {
  // Real UI process: default and explicit loopback listen.
  let r = await runUi(undefined);
  check('UI unset -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 240));
  check('UI listen line reports the real OS-chosen port (port 0 -> not ":0")', Number.isInteger(r.port) && r.port > 0, JSON.stringify(r).slice(0, 240));
  r = await runUi('127.0.0.1');
  check('UI 127.0.0.1 -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 240));
  // Real UI process: every-interface and non-IP binds stop before listening, exit 1, one FATAL line.
  for (const bad of ['0.0.0.0', '::', '::ffff:0:0', '0:0:0:0:0:ffff:0:0', '::FFFF:0:0', '::%lo', 'localhost']) {
    r = await runUi(bad);
    check(`UI refuses ${JSON.stringify(bad)}`, r.code === 1 && /\[FATAL\] WATCHTOWER_UI_BIND_ADDRESS/.test(r.out) && !r.listened && !/listening on/i.test(r.out), JSON.stringify(r).slice(0, 240));
  }

  // Listen failure is one [FATAL] line + exit 1, never an unhandled 'error' stack trace.
  r = await runUi('192.0.2.1'); // TEST-NET-1, never assigned to this host
  check('UI unbindable IP -> exit 1 + FATAL, no stack trace', r.code === 1 && /\[FATAL\] UI cannot listen/.test(r.out) && !/Unhandled 'error'/.test(r.out) && !r.listened, JSON.stringify(r).slice(0, 240));
  r = await runUi('::1');
  check('UI ::1 -> listens as [::1] or exits with the FATAL line (host without IPv6)',
    r.listened === '[::1]' || (r.code === 1 && /\[FATAL\] UI cannot listen on \[::1\]/.test(r.out) && !/Unhandled 'error'/.test(r.out)), JSON.stringify(r).slice(0, 240));
  // Busy port, both real processes: retried a bounded number of times, then exit 1 with one FATAL line.
  async function holdPort() {
    const hold = require('net').createServer();
    await new Promise((ok) => hold.listen(0, '127.0.0.1', ok));
    return hold;
  }
  // Runs a real listener on a held port. freeAfterMs: release the port after that delay (null = keep it held).
  async function busyRun(which, retryMax, freeAfterMs) {
    const hold = await holdPort();
    const busy = hold.address().port;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a27-busy2-'));
    const key = require('crypto').randomBytes(32).toString('hex');
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: key };
    if (retryMax !== undefined) env.WATCHTOWER_LISTEN_RETRY_MAX = retryMax;
    let script;
    if (which === 'UI') {
      Object.assign(env, { WATCHTOWER_UI_PORT: String(busy), WATCHTOWER_API_PORT: '9', WATCHTOWER_UI_BIND_ADDRESS: '127.0.0.1' });
      script = path.join(ROOT, 'frontend', 'serve_ui.js');
    } else {
      Object.assign(env, { WATCHTOWER_API_PORT: String(busy), WATCHTOWER_BIND_ADDRESS: '127.0.0.1', WATCHTOWER_DATA_DIR: tmp,
        WATCHTOWER_UPDATES_DIR: tmp, WATCHTOWER_DB_PATH: path.join(tmp, 'wt.db'), AUTO_REMEDIATE: 'false' });
      script = path.join(ROOT, 'backend', 'app.js');
    }
    const t0 = Date.now();
    const res = await new Promise((resolve) => {
      const p = spawn(process.execPath, [script], { cwd: path.dirname(script), env });
      let o = '';
      const listenRe = which === 'UI' ? /UI Server listening on/ : /Server listening on/;
      const fin = (r) => { clearTimeout(t); try { p.kill('SIGKILL'); } catch (e) {} resolve(r); };
      p.stdout.on('data', (d) => { o += d; if (listenRe.test(o)) fin({ listened: true, out: o, ms: Date.now() - t0 }); });
      p.stderr.on('data', (d) => { o += d; });
      p.on('close', (code, signal) => fin({ code: code !== null ? code : signal, out: o, ms: Date.now() - t0 }));
      if (freeAfterMs !== null) setTimeout(() => hold.close(), freeAfterMs);
      const t = setTimeout(() => fin({ timeout: true, out: o }), 15000);
    });
    try { hold.close(); } catch (e) {}
    fs.rmSync(tmp, { recursive: true, force: true });
    return res;
  }
  for (const which of ['UI', 'API']) {
    const fatalRe = new RegExp(`\\[FATAL\\] ${which} cannot listen on 127\\.0\\.0\\.1:\\d+: EADDRINUSE`);
    let b = await busyRun(which, '0', null);
    check(`${which} busy port, retry max 0 -> exit 1 + FATAL EADDRINUSE at once, no retry, no listening claim`,
      b.code === 1 && fatalRe.test(b.out) && !/Retry \d/.test(b.out) && !/listening on/i.test(b.out) && b.ms < 2500, JSON.stringify(b).slice(0, 300));
    b = await busyRun(which, '1', null);
    check(`${which} busy port, retry max 1 -> one WARN retry, then exit 1 + FATAL (bounded, no endless loop)`,
      b.code === 1 && /\[WARN\] \w+: Port \d+ is occupied\. Retry 1\/1 in 3 seconds/.test(b.out) && !/Retry 2\//.test(b.out)
        && fatalRe.test(b.out) && !/listening on/i.test(b.out) && b.ms >= 2500, JSON.stringify(b).slice(0, 300));
    b = await busyRun(which, undefined, 1000);
    check(`${which} busy port freed after 1 s -> default retry binds by itself`, b.listened === true && /Retry 1\/20/.test(b.out),
      JSON.stringify(b).slice(0, 300));
  }

  // A runtime 'error' after a successful bind is reported as a server error (not "cannot listen") and still exits 1.
  {
    const r = spawnSync(process.execPath, ['-e', `
      const B = require(${JSON.stringify(path.join(ROOT, 'backend', 'bind_address.js'))});
      const s = require('http').createServer();
      B.handleListenErrors(s, 0, '127.0.0.1', 'UNIT', {});
      s.listen(0, '127.0.0.1', () => { const e = new Error('boom'); e.code = 'EMFILE'; s.emit('error', e); });
    `], { encoding: 'utf8', timeout: 10000 });
    check('runtime server error after bind -> exit 1 + "[FATAL] UNIT server error on 127.0.0.1:0: EMFILE"',
      r.status === 1 && /\[FATAL\] UNIT server error on 127\.0\.0\.1:0: EMFILE/.test(r.stderr), JSON.stringify({ s: r.status, e: r.stderr }).slice(0, 240));
  }

  // UI proxy reaches an API bound to a non-default address with no WATCHTOWER_API_HOST: the target follows
  // WATCHTOWER_BIND_ADDRESS (a fleet hub binds the API to its Tailscale IP) and the Host header is valid HTTP
  // ("[::1]:port" for IPv6, never a bare "::1:port"). A mock API records what arrives. Each address runs only where
  // the host can bind it (127.0.0.2 on Linux, ::1 where IPv6 loopback exists); an unbindable one is a printed SKIP,
  // never counted as a pass. At least one must run so the proxy path is always exercised.
  async function proxyRun(apiBind) {
    const http = require('http');
    const seen = [];
    const mock = http.createServer((req, res) => { seen.push({ host: req.headers.host, key: req.headers['x-api-key'], url: req.url });
      res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); });
    const bound = await new Promise((ok) => { mock.once('error', () => ok(false)); mock.listen(0, apiBind, () => ok(true)); });
    if (!bound) return { skipped: true };
    const apiPort = mock.address().port;
    const key = require('crypto').randomBytes(32).toString('hex');
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: key, WATCHTOWER_UI_PORT: '0',
      WATCHTOWER_UI_BIND_ADDRESS: '127.0.0.1', WATCHTOWER_API_PORT: String(apiPort), WATCHTOWER_BIND_ADDRESS: apiBind };
    const ui = spawn(process.execPath, [path.join(ROOT, 'frontend', 'serve_ui.js')], { cwd: ROOT, env });
    let o = ''; ui.stdout.on('data', (d) => { o += d; }); ui.stderr.on('data', (d) => { o += d; });
    for (let t = Date.now(); !/UI Server listening on/.test(o) && Date.now() - t < 8000;) await new Promise((r) => setTimeout(r, 50));
    const um = /UI Server listening on http:\/\/\S+:(\d+)/.exec(o);
    if (!um) { try { ui.kill('SIGKILL'); } catch (e) {} await new Promise((r) => mock.close(r)); return { uiFailed: true, o: o.slice(0, 300) }; }
    const uiPort = Number(um[1]);
    const req = (method, p, headers, body) => new Promise((resolve) => {
      const r = http.request({ hostname: '127.0.0.1', port: uiPort, path: p, method, headers }, (res) => {
        let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d })); });
      r.on('error', (e) => resolve({ status: 0, headers: {}, body: String(e.code || e.message) })); if (body) r.write(body); r.end();
    });
    const host = `127.0.0.1:${uiPort}`;
    const login = await req('POST', '/login', { 'content-type': 'application/json', origin: `http://${host}`, host }, JSON.stringify({ key }));
    const cookie = String((login.headers['set-cookie'] || [''])[0]).split(';')[0];
    const got = await req('GET', '/api/status', { cookie, host });
    try { ui.kill('SIGKILL'); } catch (e) {}
    await new Promise((r) => mock.close(r));
    return { apiPort, key, login: login.status, got: got.status, hit: seen.find((x) => x.url === '/api/status'), seen, o: o.slice(0, 200) };
  }
  let proxyRan = 0;
  for (const [apiBind, wantHost] of [['127.0.0.2', (p) => `127.0.0.2:${p}`], ['::1', (p) => `[::1]:${p}`]]) {
    const pr = await proxyRun(apiBind);
    if (pr.skipped) { console.log(`SKIP UI proxy -> API bound to ${apiBind}: this host cannot bind it (not counted)`); continue; }
    proxyRan++;
    if (pr.uiFailed) { check(`UI proxy -> API bound to ${apiBind}: UI started`, false, JSON.stringify(pr)); continue; }
    check(`UI proxy -> API bound to ${apiBind}: login ok, request reaches the API (target follows WATCHTOWER_BIND_ADDRESS)`,
      pr.login === 200 && pr.got === 200 && !!pr.hit, JSON.stringify(pr).slice(0, 300));
    check(`UI proxy -> API bound to ${apiBind}: Host header "${wantHost('<port>')}", operator key added by the UI`,
      !!pr.hit && pr.hit.host === wantHost(pr.apiPort) && pr.hit.key === pr.key, JSON.stringify(pr.hit));
  }
  check('UI proxy path exercised on at least one non-default API address', proxyRan >= 1, `ran=${proxyRan}`);

  // Single source: both listeners use the shared module; neither keeps a private copy or a raw env default.
  const app = fs.readFileSync(path.join(ROOT, 'backend', 'app.js'), 'utf8');
  const ui = fs.readFileSync(path.join(ROOT, 'frontend', 'serve_ui.js'), 'utf8');
  check('app.js uses ./bind_address', /require\(['"]\.\/bind_address['"]\)/.test(app) && /requireBindAddress\(process\.env\.WATCHTOWER_BIND_ADDRESS,/.test(app));
  check('serve_ui.js uses ../backend/bind_address', /require\(['"]\.\.\/backend\/bind_address['"]\)/.test(ui) && /requireBindAddress\(process\.env\.WATCHTOWER_UI_BIND_ADDRESS,/.test(ui));
  for (const [name, src] of [['app.js', app], ['serve_ui.js', ui]]) {
    check(`${name} has no private ipBytes/isEveryInterface copy`, !/function\s+(ipBytes|isEveryInterface)\b/.test(src));
    check(`${name} has no raw "|| address" bind default`, !/BIND_ADDRESS\s*\|\|\s*['"]/.test(src));
    check(`${name} uses the shared listen-error rule and keeps no own server.on('error') handler`,
      /handleListenErrors\(server,/.test(src) && !/server\.on\(\s*['"]error['"]/.test(src));
  }
  check('serve_ui.js: API target from apiTargetHost, Host header from hostHeader, no raw "host + \':\' + port"',
    /apiTargetHost\(process\.env\)/.test(ui) && (ui.match(/hostHeader\(apiHost, apiPort\)/g) || []).length === 2
      && !/apiHost\s*\+\s*['"]:['"]/.test(ui) && !/WATCHTOWER_API_HOST\s*\|\|/.test(ui));

  // start.sh: UI bind defaults to loopback and its quick pre-check refuses the two common wildcards.
  function startSh(envLine) {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-uibind-'));
    fs.copyFileSync(path.join(ROOT, 'start.sh'), path.join(d, 'start.sh'));
    fs.writeFileSync(path.join(d, '.env'), envLine + '\n');
    fs.mkdirSync(path.join(d, '.venv', 'bin'), { recursive: true });
    fs.writeFileSync(path.join(d, '.venv', 'bin', 'activate'), 'true\n');
    fs.mkdirSync(path.join(d, 'core'));
    // NODE_TYPE is unset, so start.sh stops at its own guard before launching anything.
    const vars = spawnSync('bash', ['-c', 'trap \'echo "UI=$WATCHTOWER_UI_BIND_ADDRESS"\' EXIT; source ./start.sh >/dev/null 2>&1'], { cwd: d, encoding: 'utf8', timeout: 20000 });
    const run = spawnSync('bash', ['./start.sh'], { cwd: d, encoding: 'utf8', timeout: 20000 });
    fs.rmSync(d, { recursive: true, force: true });
    return { vars: (vars.stdout || '').trim(), out: (run.stdout || '') + (run.stderr || ''), status: run.status };
  }
  let s = startSh('# no bind set');
  check('start.sh defaults UI bind to 127.0.0.1', /UI=127\.0\.0\.1\b/.test(s.vars), s.vars);
  for (const bad of ['0.0.0.0', '::']) {
    s = startSh(`WATCHTOWER_UI_BIND_ADDRESS=${bad}`);
    check(`start.sh refuses UI ${bad}`, s.status === 1 && /REFUSED: WATCHTOWER_UI_BIND_ADDRESS/.test(s.out), s.out.slice(-200));
  }
  s = startSh('WATCHTOWER_UI_BIND_ADDRESS=100.86.203.66');
  check('start.sh keeps an operator-set UI tailnet IP (no refusal)', /UI=100\.86\.203\.66\b/.test(s.vars) && !/REFUSED/.test(s.out), s.vars + ' | ' + s.out.slice(-200));

  // start.bat parity (Windows): UI default + the same quick pre-check. Static check (no cmd.exe in CI).
  const bat = fs.readFileSync(path.join(ROOT, 'start.bat'), 'utf8');
  check('start.bat defaults UI bind to 127.0.0.1', /if "%WATCHTOWER_UI_BIND_ADDRESS%"=="" set WATCHTOWER_UI_BIND_ADDRESS=127\.0\.0\.1/.test(bat));
  check('start.bat refuses UI 0.0.0.0 and :: before launching node',
    /"%WATCHTOWER_UI_BIND_ADDRESS%"=="0\.0\.0\.0" goto refuse_ui_bind/.test(bat) && /"%WATCHTOWER_UI_BIND_ADDRESS%"=="::" goto refuse_ui_bind/.test(bat)
      && /:refuse_ui_bind\r?\necho \[!\] REFUSED: WATCHTOWER_UI_BIND_ADDRESS[^\r\n]*\r?\nexit \/b 1/.test(bat)
      && bat.indexOf('goto refuse_ui_bind') < bat.indexOf('node serve_ui.js'));

  console.log(`# bind-address: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  // A harness error is one counted FAIL and exit 1, never an unhandled rejection.
  console.log('FAIL harness error', e && e.stack ? e.stack : e);
  console.log(`# bind-address: ${pass} passed, ${fail + 1} failed`);
  process.exit(1);
});
