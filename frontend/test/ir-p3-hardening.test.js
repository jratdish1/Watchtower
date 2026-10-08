/**
 * IR P3 backlog from Watchtower PR #6 (tracked in KB receipt
 * ops/vao-torch/receipts/RECEIPT-20261006-WATCHTOWER-6-MERGE-STEP5.md):
 *   P3-1  percent-encoding in the request target was forwarded as-is
 *   P3-2  allowlist action matching was case-sensitive
 *   P3-3  WATCHTOWER_UI_COOKIE_SECURE=0 is an intentional opt-out; make it visible
 *
 * Run: node frontend/test/ir-p3-hardening.test.js
 * No secrets: uses the placeholder test key from backend/test/spawn_api.js.
 */
'use strict';

const http = require('http');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const { TEST_OPERATOR_KEY, startApi } = require('../../backend/test/spawn_api');
const allowlist = require('../../backend/allowlist');

let passed = 0;
let failed = 0;

function check(name, cond, info) {
  if (cond) {
    passed++;
    console.log('  ok  - ' + name);
  } else {
    failed++;
    console.log('  FAIL- ' + name + (info ? '\n        ' + info : ''));
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
    server.on('error', reject);
  });
}

function rawRequest(port, method, urlPath, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: urlPath, method, headers: headers || {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch (_) { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function rawUpgrade(port, urlPath) {
  return new Promise((resolve) => {
    let data = '';
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write('GET ' + urlPath + ' HTTP/1.1\r\nHost: 127.0.0.1:' + port
        + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
        + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
    });
    sock.on('data', (c) => { data += c.toString(); });
    sock.on('close', () => resolve(data.split('\r\n')[0] || ''));
    sock.on('error', () => resolve(data.split('\r\n')[0] || 'error'));
    setTimeout(() => sock.destroy(), 3000);
  });
}

function spawnUi(port, apiPort, extra) {
  const env = Object.assign({}, process.env, {
    WATCHTOWER_UI_PORT: String(port),
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
    WATCHTOWER_API_PORT: String(apiPort),
  });
  delete env.WATCHTOWER_UI_BIND_ADDRESS;
  delete env.WATCHTOWER_UI_COOKIE_SECURE;
  delete env.WATCHTOWER_UI_ORIGIN;
  Object.assign(env, extra || {});
  const child = spawn(process.execPath, [path.join(__dirname, '../serve_ui.js')], {
    cwd: path.join(__dirname, '../..'),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('UI did not listen\n' + log)), 8000);
    const take = (chunk) => {
      log += chunk.toString();
      if (log.includes('UI Server listening')) {
        clearTimeout(timer);
        // give the post-listen warning line a tick to flush
        setTimeout(resolve, 50);
      }
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error('UI exited ' + code + '\n' + log)); });
  });
  return { child, ready, log: () => log };
}

function cookieOf(res) {
  const sc = res.headers['set-cookie'];
  return Array.isArray(sc) ? sc[0] : (sc || '');
}

(async () => {
  console.log('IR P3 hardening tests\n');

  // ---------- P3-2: case-insensitive action matching (unit) ----------
  allowlist.setConfigForTests({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['kill', 'lock_dir', 'quarantine', 'disable_user'], audit_blocked_actions: ['kill'] },
    profile_capabilities: {},
  });
  for (const a of ['KILL', 'Kill', ' kill ', 'LOCK_DIR', 'Quarantine', 'DISABLE_USER', 'PURGE', ' Purge_All', 'WIPE', 'Destroy', 'CLEAR']) {
    check('destructive: ' + JSON.stringify(a), allowlist.isPurgeOrDestructiveAction(a) === true);
  }
  for (const a of ['update_policy', 'UPDATE_CORE', 'rollback', '', '   ', 123, null, undefined, {}]) {
    check('not destructive: ' + JSON.stringify(a), allowlist.isPurgeOrDestructiveAction(a) === false);
  }
  const hasNormalize = typeof allowlist.normalizeAction === 'function';
  check('normalizeAction trims and lowercases', hasNormalize && allowlist.normalizeAction('  KiLL ') === 'kill');
  check('normalizeAction non-string -> empty', hasNormalize && allowlist.normalizeAction(42) === '');

  const devices = { 'ops-1': 'Ops-Fleet' };
  const auditGroups = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: true } };
  for (const a of ['kill', 'KILL', ' Kill ']) {
    const d = allowlist.assertC2Command({ host: 'ops-1', action: a }, devices, auditGroups, 'GitHub vets-ops');
    check('audit mode blocks ' + JSON.stringify(a), d && d.rule === 'DENY_C2_ACTION_NOT_ALLOWED' && d.detail.reason === 'WATCHTOWER_AUDIT_MODE', JSON.stringify(d));
  }
  const noRollback = { 'Ops-Fleet': { ENABLE_ROLLBACK: false } };
  for (const a of ['rollback', 'ROLLBACK', ' Rollback ']) {
    const d = allowlist.assertC2Command({ host: 'ops-1', action: a }, devices, noRollback, 'GitHub vets-ops');
    check('ENABLE_ROLLBACK=false blocks ' + JSON.stringify(a), d && d.rule === 'DENY_C2_ACTION_NOT_ALLOWED' && d.detail.reason === 'ENABLE_ROLLBACK=false', JSON.stringify(d));
  }
  for (const a of ['KILL', 'Purge']) {
    const d = allowlist.assertC2Command({ host: 'ops-1', action: a }, devices, {}, 'GitHub vets-ops');
    check('purge cap required for ' + JSON.stringify(a), d && d.rule === 'DENY_PURGE_WITHOUT_CAP', JSON.stringify(d));
  }
  const ok = allowlist.assertC2Command({ host: 'ops-1', action: 'update_policy' }, devices, {}, 'GitHub vets-ops');
  check('non-destructive action still allowed for mapped profile', ok === null, JSON.stringify(ok));
  const caseGroup = allowlist.assertProfileAllowed('ops-fleet', 'GitHub vets-ops');
  check('host group names stay exact-match (fail closed)', caseGroup && caseGroup.rule === 'DENY_UNMAPPED_GROUP', JSON.stringify(caseGroup));
  allowlist.resetForTests();

  // ---------- P3-1: canonical percent-encoding at the UI proxy ----------
  const api = await startApi();
  const uiPort = await freePort();
  const ui = spawnUi(uiPort, api.port);
  try {
    await ui.ready;
    const login = await rawRequest(uiPort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const cookie = cookieOf(login).split(';')[0];
    check('login ok', login.status === 200 && cookie.startsWith('wt_session='), login.status + ' ' + login.body);
    const H = { Cookie: cookie };

    const baseline = await rawRequest(uiPort, 'GET', '/api/agents', H);
    check('baseline /api/agents is 200', baseline.status === 200, String(baseline.status));

    const rejected = [
      ['/api/%61gents', 'encoded letter'],
      ['/api/%41GENTS', 'encoded upper letter'],
      ['/api/%76%32/c2/beacon', 'encoded v2 segment'],
      ['/api/v2/%74opology', 'encoded letter under /api/v2'],
      ['/api/agent%73', 'encoded trailing letter'],
      ['/api/agents%2D', 'encoded hyphen'],
      ['/api/agents%5F', 'encoded underscore'],
      ['/api/agents%7e', 'encoded tilde'],
      ['/api/agents%30', 'encoded digit'],
      ['/api/agents%', 'bare percent'],
      ['/api/agents%4', 'truncated escape'],
      ['/api/agents%zz', 'non-hex escape'],
    ];
    for (const [p, label] of rejected) {
      const r = await rawRequest(uiPort, 'GET', p, H);
      check('reject ' + label + ' (' + p + ')', r.status === 403 && r.json && r.json.error === 'Forbidden', r.status + ' ' + r.body.slice(0, 80));
    }

    const prefix = await rawRequest(uiPort, 'GET', '/%61pi/agents', H);
    check('encoded /api prefix is never proxied (UI 404, nothing forwarded)', prefix.status === 404 && prefix.json && prefix.json.error === 'Not found', prefix.status + ' ' + prefix.body.slice(0, 60));

    const space = await rawRequest(uiPort, 'GET', '/api/alerts%20', H);
    check('reserved escape %20 still forwarded as-is (backend 404, not 403)', space.status === 404, space.status + ' ' + space.body.slice(0, 60));
    const query = await rawRequest(uiPort, 'GET', '/api/agents?x=%61%zz', H);
    check('query string encodings are not checked (200)', query.status === 200, String(query.status));

    const up1 = await rawUpgrade(uiPort, '/socket.io/%3F');
    check('upgrade with reserved escape passes the path check (auth decides: 401)', /^HTTP\/1\.1 401/.test(up1), up1);
    const up2 = await rawUpgrade(uiPort, '/socket.io/%73ocket');
    check('upgrade with encoded letter is 403', /^HTTP\/1\.1 403/.test(up2), up2);
    const up3 = await rawUpgrade(uiPort, '/socket.io/%');
    check('upgrade with bare percent is 403', /^HTTP\/1\.1 403/.test(up3), up3);
  } finally {
    ui.child.kill('SIGTERM');
    api.stop();
  }

  // ---------- P3-3: COOKIE_SECURE=0 opt-out is visible ----------
  const cases = [
    [{ WATCHTOWER_UI_COOKIE_SECURE: '0', WATCHTOWER_UI_ORIGIN: 'https://wt.example.test' }, 'WARNING', false, 'flag 0 over https origin warns'],
    [{ WATCHTOWER_UI_COOKIE_SECURE: 'false', WATCHTOWER_UI_ORIGIN: 'https://wt.example.test' }, 'WARNING', false, 'flag false over https origin warns'],
    [{ WATCHTOWER_UI_COOKIE_SECURE: '0' }, 'NOTICE', false, 'flag 0 without https origin gives notice'],
    [{ WATCHTOWER_UI_ORIGIN: 'https://wt.example.test' }, null, true, 'https origin alone: Secure, no warning'],
    [{}, null, false, 'defaults: no Secure, no warning'],
    [{ WATCHTOWER_UI_COOKIE_SECURE: '1' }, null, true, 'flag 1: Secure, no warning'],
  ];
  for (const [env, needle, secure, label] of cases) {
    const p = await freePort();
    const u = spawnUi(p, 9, env);
    try {
      await u.ready;
      const log = u.log();
      if (needle) {
        check(label + ' (log)', log.includes(needle) && log.includes('WATCHTOWER_UI_COOKIE_SECURE'), log);
      } else {
        check(label + ' (log)', !/WARNING|NOTICE/.test(log), log);
      }
      check(label + ' (log never prints the key)', !log.includes(TEST_OPERATOR_KEY));
      const s = await rawRequest(p, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
      const hasSecure = /;\s*Secure/i.test(cookieOf(s));
      check(label + ' (cookie Secure=' + secure + ')', hasSecure === secure, cookieOf(s));
    } finally {
      u.child.kill('SIGTERM');
    }
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
