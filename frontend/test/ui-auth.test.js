/**
 * Glass Pane operator session: no key in HTML, unauthenticated UI refused,
 * startup refused for a missing or placeholder key, UI bound to loopback
 * unless WATCHTOWER_UI_BIND_ADDRESS is set.
 *
 * Run: node frontend/test/ui-auth.test.js
 */
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const { TEST_OPERATOR_KEY, startApi } = require('../../backend/test/spawn_api');

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
  });
}

function rawRequest(port, method, urlPath, headers, body, hostname) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: hostname || '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: headers || {},
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        let json = null;
        try { json = raw.length ? JSON.parse(raw.toString('utf8')) : null; } catch (_) { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, body: raw.toString('utf8'), raw, json });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function spawnUi(port, extra, hostnameWait) {
  const env = Object.assign({}, process.env, {
    WATCHTOWER_UI_PORT: String(port),
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
    WATCHTOWER_API_PORT: '9',
  }, extra || {});
  if (!extra || !Object.prototype.hasOwnProperty.call(extra, 'WATCHTOWER_UI_BIND_ADDRESS')) {
    delete env.WATCHTOWER_UI_BIND_ADDRESS;
  }
  const child = spawn(process.execPath, [path.join(__dirname, '../serve_ui.js')], {
    cwd: path.join(__dirname, '../..'),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('UI server did not listen\n' + log)), 8000);
    const take = (chunk) => {
      log += chunk.toString();
      if (log.includes('UI Server listening')) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error('UI server exited ' + code + '\n' + log));
    });
  });
  return { child, log: () => log, ready, hostname: hostnameWait || '127.0.0.1' };
}

async function expectRefuse(label, key, needle) {
  const env = Object.assign({}, process.env, {
    WATCHTOWER_UI_PORT: '9',
    WATCHTOWER_UI_BIND_ADDRESS: '127.0.0.1',
  });
  if (key === undefined) delete env.WATCHTOWER_API_KEY;
  else env.WATCHTOWER_API_KEY = key;
  const child = spawn(process.execPath, [path.join(__dirname, '../serve_ui.js')], {
    cwd: path.join(__dirname, '../..'),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill('SIGTERM'); resolve('timeout'); }, 4000);
    child.stdout.on('data', (chunk) => { log += chunk.toString(); });
    child.stderr.on('data', (chunk) => { log += chunk.toString(); });
    child.on('exit', (exitCode) => { clearTimeout(timer); resolve(exitCode); });
  });
  check(label + ' exits non-zero', code !== 0 && code !== 'timeout', String(code) + ' ' + log);
  check(label + ' log refuses startup', log.includes('Refusing to start'));
  check(label + ' log does not contain the key', !needle || !log.includes(needle), log);
}

function cookiePair(res) {
  const setCookie = res.headers['set-cookie'];
  const raw = Array.isArray(setCookie) ? setCookie[0] : (setCookie || '');
  return raw;
}

(async () => {
  console.log('UI operator session tests\n');

  await expectRefuse('unset key', undefined, 'WATCHTOWER_DEFAULT_KEY');
  await expectRefuse('empty key', '', '');
  await expectRefuse('placeholder key', 'WATCHTOWER_DEFAULT_KEY', 'WATCHTOWER_DEFAULT_KEY');
  await expectRefuse('html placeholder', 'YOUR_SECRET_API_KEY_HERE', 'YOUR_SECRET_API_KEY_HERE');
  await expectRefuse('short key', 'short-key-value', 'short-key-value');

  const port = await freePort();
  const ui = spawnUi(port);
  try {
    await ui.ready;
    const log = ui.log();
    check('default bind is 127.0.0.1', log.includes('http://127.0.0.1:' + port), log);
    check('default bind is not all interfaces', !log.includes('0.0.0.0'), log);
    check('startup log does not contain the key', !log.includes(TEST_OPERATOR_KEY), log);

    const page = await rawRequest(port, 'GET', '/watchtower.html');
    check('GET /watchtower.html without a session → 401', page.status === 401, String(page.status));
    const root = await rawRequest(port, 'GET', '/');
    check('GET / without a session → 401', root.status === 401, String(root.status));
    const api = await rawRequest(port, 'GET', '/api/alerts');
    check('GET /api/alerts on the UI without a session → 401', api.status === 401, String(api.status));
    const source = await rawRequest(port, 'GET', '/serve_ui.js');
    check('GET /serve_ui.js without a session → 401', source.status === 401, String(source.status));
    const pkg = await rawRequest(port, 'GET', '/package.json');
    check('GET /package.json without a session → 401', pkg.status === 401, String(pkg.status));

    const loginPage = await rawRequest(port, 'GET', '/login');
    check('GET /login is the credential form', loginPage.status === 200, String(loginPage.status));
    check(
      'login form contains no operator key',
      !loginPage.body.includes(TEST_OPERATOR_KEY)
        && !loginPage.body.includes('WATCHTOWER_DEFAULT_KEY')
        && !loginPage.body.includes('YOUR_SECRET_API_KEY_HERE')
    );

    const bad = await rawRequest(port, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('POST /login wrong key → 401', bad.status === 401, String(bad.status));
    check('wrong login does not set a session', !String(bad.headers['set-cookie'] || '').includes('wt_session='));

    const good = await rawRequest(port, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const setCookie = cookiePair(good);
    check('POST /login valid key → 200', good.status === 200, String(good.status));
    check('session cookie is HttpOnly', /HttpOnly/i.test(setCookie), setCookie);
    check('session cookie is SameSite=Strict', /SameSite=Strict/i.test(setCookie), setCookie);
    check('login response does not contain the key', !good.body.includes(TEST_OPERATOR_KEY));
    const cookie = setCookie.split(';')[0];

    const html = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie });
    check('authenticated Glass Pane → 200', html.status === 200, String(html.status));
    check(
      'served HTML contains no operator key',
      !html.body.includes(TEST_OPERATOR_KEY)
        && !html.body.includes('WATCHTOWER_DEFAULT_KEY')
        && !html.body.includes('YOUR_SECRET_API_KEY_HERE')
        && !html.body.includes('x-api-key')
    );
    const hidden = await rawRequest(port, 'GET', '/serve_ui.js', { Cookie: cookie });
    check('authenticated /serve_ui.js is not served', hidden.status === 404, String(hidden.status));
    const hiddenPkg = await rawRequest(port, 'GET', '/package.json', { Cookie: cookie });
    check('authenticated /package.json is not served', hiddenPkg.status === 404, String(hiddenPkg.status));
    const logo = await rawRequest(port, 'GET', '/assets/watchtower_logo.png', { Cookie: cookie });
    const logoFile = fs.readFileSync(path.join(__dirname, '../../assets/watchtower_logo.png'));
    check(
      'allowlisted logo is served',
      logo.status === 200 && logo.raw.length === logoFile.length && logo.raw.slice(0, 3).toString('hex') === logoFile.slice(0, 3).toString('hex'),
      String(logo.status) + ' len ' + logo.raw.length
    );
    const logoAnon = await rawRequest(port, 'GET', '/assets/watchtower_logo.png');
    check('logo without a session → 401', logoAnon.status === 401, String(logoAnon.status));
  } finally {
    ui.child.kill('SIGTERM');
  }

  const optPort = await freePort();
  const opted = spawnUi(optPort, { WATCHTOWER_UI_BIND_ADDRESS: '127.0.0.2' }, '127.0.0.2');
  try {
    await opted.ready;
    check('explicit bind address is honored', opted.log().includes('http://127.0.0.2:' + optPort), opted.log());
    let refused = false;
    try {
      await rawRequest(optPort, 'GET', '/login', {}, null, '127.0.0.1');
    } catch (err) {
      refused = true;
    }
    check('opt-in bind is not 127.0.0.1', refused);
    const onOpt = await rawRequest(optPort, 'GET', '/login', {}, null, '127.0.0.2');
    check('opt-in bind serves /login', onOpt.status === 200, String(onOpt.status));
  } finally {
    opted.child.kill('SIGTERM');
  }

  const api = await startApi({ WATCHTOWER_API_KEY: TEST_OPERATOR_KEY });
  const uiPort = await freePort();
  const proxied = spawnUi(uiPort, { WATCHTOWER_API_PORT: String(api.port), WATCHTOWER_API_KEY: TEST_OPERATOR_KEY });
  try {
    await proxied.ready;
    const anon = await rawRequest(uiPort, 'GET', '/api/alerts');
    check('proxied alerts without a session → 401', anon.status === 401, String(anon.status));
    const session = await rawRequest(uiPort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const cookie = cookiePair(session).split(';')[0];
    const alerts = await rawRequest(uiPort, 'GET', '/api/alerts', { Cookie: cookie });
    check('proxied alerts with a session and no browser key → 200', alerts.status === 200 && Array.isArray(alerts.json), JSON.stringify(alerts.json));
    check('proxied body does not echo the key', !alerts.body.includes(TEST_OPERATOR_KEY));

    const io = require(path.join(__dirname, '../node_modules/socket.io-client'));
    const denied = await new Promise((resolve) => {
      const socket = io('http://127.0.0.1:' + uiPort, {
        transports: ['websocket'],
        reconnection: false,
        timeout: 3000,
        forceNew: true,
      });
      const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3500);
      socket.on('connect', () => { clearTimeout(timer); socket.close(); resolve('connected'); });
      socket.on('connect_error', () => { clearTimeout(timer); socket.close(); resolve('error'); });
    });
    check('socket without a session is refused', denied !== 'connected', denied);

    const allowed = await new Promise((resolve) => {
      const socket = io('http://127.0.0.1:' + uiPort, {
        transports: ['websocket'],
        reconnection: false,
        timeout: 3000,
        forceNew: true,
        extraHeaders: { Cookie: cookie },
      });
      const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3500);
      socket.on('connect', () => { clearTimeout(timer); socket.close(); resolve('connected'); });
      socket.on('connect_error', (err) => { clearTimeout(timer); socket.close(); resolve('error:' + (err && err.message)); });
    });
    check('socket with a session connects', allowed === 'connected', allowed);
  } finally {
    proxied.child.kill('SIGTERM');
    api.stop();
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
