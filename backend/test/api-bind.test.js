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
  check('unbindable IP -> exit 1 + FATAL, not a silent exit 0', r.code === 1 && /\[FATAL\] API cannot listen/.test(r.out) && !r.listened && !/listening on/i.test(r.out), JSON.stringify(r).slice(0, 200));
  for (const bad of ['0.0.0.0', '::', '::0', '0:0:0:0:0:0:0:0', '00.0.0.0', '::ffff:0.0.0.0', 'localhost', 'evil.example', '10.0.0.0/8', '127.0.0.1 0.0.0.0', '999.1.1.1']) {
    r = await run(bad);
    check(`refuses ${JSON.stringify(bad)}`, r.code === 1 && /\[FATAL\] WATCHTOWER_BIND_ADDRESS/.test(r.out) && !r.listened && !/listening on/i.test(r.out), JSON.stringify(r).slice(0, 200));
  }
  // P2-1 (Codex CLI G2 seat): EADDRINUSE path. Port held by another socket -> no listening claim, retry logged,
  // then the app binds by itself once the port is free (retry loop works, no crash, no silent exit).
  {
    const net = require('net');
    const busyPort = port++;
    const blocker = net.createServer();
    await new Promise((ok) => blocker.listen(busyPort, '127.0.0.1', ok));
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a27-busy-'));
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_API_PORT: String(busyPort), WATCHTOWER_DATA_DIR: tmp, WATCHTOWER_UPDATES_DIR: tmp,
      WATCHTOWER_DB_PATH: path.join(tmp, 'wt.db'), AUTO_REMEDIATE: 'false', WATCHTOWER_BIND_ADDRESS: '127.0.0.1' };
    const p = spawn(process.execPath, ['app.js'], { cwd: path.join(__dirname, '..'), env });
    let out = '', exited = null, freedAt = 0;
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => { exited = code; });
    const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
    // Event-driven, not fixed sleeps: wait (max 8 s) until the app reports the busy port, then free it.
    const busyRe = new RegExp(`Port ${busyPort} is occupied`);
    for (let t = Date.now(); !busyRe.test(out) && exited === null && Date.now() - t < 8000;) await wait(100);
    const claimedWhileBusy = /listening on/i.test(out);
    const retryLogged = busyRe.test(out);
    await new Promise((ok) => blocker.close(ok)); freedAt = out.length;
    // Recovery log comes from the ORIGINAL server.listen(port, addr, cb) callback: Node registers cb as a
    // once('listening') handler; a failed bind never fires it, so it fires on the retry's successful bind.
    // (Verified 2026-10-10: occupied +152ms, freed +1502ms, "Server listening on" +3159ms.) Retry is 3 s; allow 12 s.
    const upRe = /Server listening on http:\/\/127\.0\.0\.1:\d+/;
    for (let t = Date.now(); !upRe.test(out.slice(freedAt)) && exited === null && Date.now() - t < 12000;) await wait(100);
    const recovered = upRe.test(out.slice(freedAt));
    try { p.kill('SIGKILL'); } catch (e) {}
    fs.rmSync(tmp, { recursive: true, force: true });
    check('EADDRINUSE -> no listening claim while the port is held', !claimedWhileBusy, out.slice(0, 200));
    check('EADDRINUSE -> retry is logged, process stays up', retryLogged && exited === null, JSON.stringify({ exited, out: out.slice(0, 200) }));
    check('EADDRINUSE -> binds by itself once the port is free', recovered, out.slice(-200));
  }
  const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  check("no '0.0.0.0' default left in app.js", !/WATCHTOWER_BIND_ADDRESS\s*\|\|\s*['"]0\.0\.0\.0['"]/.test(src));
  check('no pre-listen "Listening on" claim', !/API Gateway\] Listening on/.test(src));
  {
    // P2-2 (Codex CLI G2 seat): not one string. Every "listening on" claim in app.js (any case) must sit inside the
    // server.listen(..., () => { ... }) callback, i.e. it is printed only after the socket is really bound.
    // Formatting-tolerant: find any server.listen(<args>, () => { / function () { callback and brace-match its end.
    const claims = [...src.matchAll(/listening on/gi)].map((m) => m.index);
    const m = /server\.listen\s*\([^)]*?,\s*(?:\(\s*\)\s*=>|function\s*\(\s*\))\s*\{/.exec(src);
    let cb = -1, cbEnd = -1;
    if (m) {
      cb = m.index;
      for (let i = m.index + m[0].length, depth = 1; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) { cbEnd = i; break; }
      }
    }
    check('every "listening on" claim is inside the listen callback', claims.length >= 1 && cb !== -1 && cbEnd !== -1 && claims.every((i) => i > cb && i < cbEnd), JSON.stringify({ claims, cb, cbEnd }));
  }
  console.log(`# api-bind: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
