// A27: backend/app.js binds loopback by default and refuses every-interface or non-IP binds,
// even when started directly (not through start.sh). Spawns the real app; nothing listens on 0.0.0.0.
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
let pass = 0, fail = 0;
function check(name, ok, info) { if (ok) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, info || ''); } }
const KEY = require('crypto').randomBytes(32).toString('hex');
// G2 (Copilot WT #31): port 0, so the child asks the OS for a free port atomically. A probe-then-close port
// could be taken by another process in between and send a valid case down the busy-port retry path.
function run(bind) {
  return new Promise((resolve) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a27-'));
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_API_PORT: '0', WATCHTOWER_DATA_DIR: tmp, WATCHTOWER_UPDATES_DIR: tmp,
      WATCHTOWER_DB_PATH: path.join(tmp, 'wt.db'), AUTO_REMEDIATE: 'false' };
    if (bind !== undefined) env.WATCHTOWER_BIND_ADDRESS = bind;
    const p = spawn(process.execPath, ['app.js'], { cwd: path.join(__dirname, '..'), env });
    let out = '';
    const done = (r) => { clearTimeout(t); try { p.kill('SIGKILL'); } catch (e) {} fs.rmSync(tmp, { recursive: true, force: true }); resolve(r); };
    p.stdout.on('data', (d) => { out += d; const m = /Server listening on http:\/\/(\S+):(\d+)/.exec(out); if (m) done({ listened: m[1], port: Number(m[2]), out }); });
    p.stderr.on('data', (d) => { out += d; });
    // G2 P2 fix: 'close' fires after stdout/stderr are fully drained; 'exit' can fire first and lose the FATAL line.
    p.on('close', (code) => done({ code, out }));
    const t = setTimeout(() => done({ timeout: true, out }), 8000);
  });
}
(async () => {
  let r = await run(undefined);
  check('unset -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  check('listen line reports the real OS-chosen port (port 0 -> not ":0")', Number.isInteger(r.port) && r.port > 0, JSON.stringify(r).slice(0, 200));
  r = await run('');
  check('empty -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  r = await run('127.0.0.1');
  check('127.0.0.1 -> listens on 127.0.0.1', r.listened === '127.0.0.1', JSON.stringify(r).slice(0, 200));
  r = await run('192.0.2.1');  // TEST-NET-1, never assigned to this host
  check('unbindable IP -> exit 1 + FATAL, not a silent exit 0', r.code === 1 && /\[FATAL\] API cannot listen/.test(r.out) && !r.listened && !/listening on/i.test(r.out), JSON.stringify(r).slice(0, 200));
  for (const bad of ['0.0.0.0', '::', '::0', '0:0:0:0:0:0:0:0', '00.0.0.0', '::ffff:0.0.0.0', 'localhost', 'evil.example', '10.0.0.0/8', '127.0.0.1 0.0.0.0', '999.1.1.1',
    // G2 P1 (Copilot, WT #30): wildcard spellings the old text check let through.
    '::ffff:0:0', '0:0:0:0:0:ffff:0:0', '::ffff:0000:0000', '::FFFF:0:0', '::%lo', '::0:0', '0::0']) {
    r = await run(bad);
    check(`refuses ${JSON.stringify(bad)}`, r.code === 1 && /\[FATAL\] WATCHTOWER_BIND_ADDRESS/.test(r.out) && !r.listened && !/listening on/i.test(r.out), JSON.stringify(r).slice(0, 200));
  }
  // G2 P1 side effect fixed: a real, specific IPv6 address that merely ends in 0.0.0.0 is not "every interface".
  // It may not exist on this host (then the app exits with the normal "cannot listen" FATAL), but it must never be
  // refused by the bind-address rule.
  for (const ok of ['64:ff9b::0.0.0.0', '::1']) {
    r = await run(ok);
    check(`accepts specific ${JSON.stringify(ok)} (no bind-address refusal)`, !/\[FATAL\] WATCHTOWER_BIND_ADDRESS/.test(r.out), JSON.stringify(r).slice(0, 200));
  }
  // P2-1 (Codex CLI G2 seat): EADDRINUSE path. Port held by another socket -> no listening claim, retry logged,
  // then the app binds by itself once the port is free (retry loop works, no crash, no silent exit).
  {
    const net = require('net');
    // Round 3 (Copilot finding): never a hard-coded port. Let the OS pick a free one (port 0) and reject on
    // a bind error instead of hanging or crashing the whole test run.
    const blocker = net.createServer();
    const busyPort = await new Promise((ok, bad) => {
      blocker.once('error', bad);
      blocker.listen(0, '127.0.0.1', () => { blocker.removeListener('error', bad); ok(blocker.address().port); });
    });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-a27-busy-'));
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_API_PORT: String(busyPort), WATCHTOWER_DATA_DIR: tmp, WATCHTOWER_UPDATES_DIR: tmp,
      WATCHTOWER_DB_PATH: path.join(tmp, 'wt.db'), AUTO_REMEDIATE: 'false', WATCHTOWER_BIND_ADDRESS: '127.0.0.1' };
    const p = spawn(process.execPath, ['app.js'], { cwd: path.join(__dirname, '..'), env });
    let out = '', exited = null, freedAt = 0;
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    // Round 3 (Copilot finding): a signal kill reports code === null, which looked like "still running".
    // Record the signal name instead so a crash by signal is never mistaken for "process stays up".
    p.on('exit', (code, signal) => { exited = code !== null ? code : (signal || 'SIGNAL'); });
    const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
    // Event-driven, not fixed sleeps: wait (max 8 s) until the app reports the busy port, then free it.
    const busyRe = new RegExp(`Port ${busyPort} is occupied`);
    for (let t = Date.now(); !busyRe.test(out) && exited === null && Date.now() - t < 8000;) await wait(100);
    // Codex CLI 28C P2: read while the port is STILL held (blocker not closed yet), so a later recovery line
    // can never be counted here. busyOut is the frozen snapshot.
    const busyOut = out;
    const claimedWhileBusy = /listening on/i.test(busyOut);
    const retryLogged = busyRe.test(busyOut);
    await new Promise((ok) => blocker.close(ok)); freedAt = out.length;
    // Recovery log comes from the ORIGINAL server.listen(port, addr, cb) callback: Node registers cb as a
    // once('listening') handler; a failed bind never fires it, so it fires on the retry's successful bind.
    // (Verified 2026-10-10: occupied +152ms, freed +1502ms, "Server listening on" +3159ms.) Retry is 3 s; allow 12 s.
    const upRe = /Server listening on http:\/\/127\.0\.0\.1:\d+/;
    for (let t = Date.now(); !upRe.test(out.slice(freedAt)) && exited === null && Date.now() - t < 12000;) await wait(100);
    const recovered = upRe.test(out.slice(freedAt));
    // Codex CLI 28C P2: record "still running" BEFORE the cleanup kill, never after it.
    const stillUp = exited === null;
    try { p.kill('SIGKILL'); } catch (e) {}
    fs.rmSync(tmp, { recursive: true, force: true });
    check('EADDRINUSE -> no listening claim while the port is held', !claimedWhileBusy, busyOut.slice(0, 200));
    check('EADDRINUSE -> retry is logged, process stays up', retryLogged && stillUp, JSON.stringify({ exited, stillUp, out: out.slice(0, 200) }));
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
      // Round 3 (Copilot finding): the lower bound is the callback's opening brace, not the start of
      // server.listen(...), so a "listening on" inside the listen arguments is NOT counted as inside the callback.
      cb = m.index + m[0].length - 1;
      for (let i = m.index + m[0].length, depth = 1; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) { cbEnd = i; break; }
      }
    }
    check('every "listening on" claim is inside the listen callback', claims.length >= 1 && cb !== -1 && cbEnd !== -1 && claims.every((i) => i > cb && i < cbEnd), JSON.stringify({ claims, cb, cbEnd }));
  }
  console.log(`# api-bind: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  // Codex CLI 28C P2: a harness error is one counted FAIL and exit 1, never an unhandled rejection.
  console.log('FAIL harness error', e && e.stack ? e.stack : e);
  console.log(`# api-bind: ${pass} passed, ${fail + 1} failed`);
  process.exit(1);
});
