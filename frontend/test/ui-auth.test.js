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
const net = require('net');
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
  await expectRefuse('template example key', 'generate_a_secure_random_key_here', 'generate_a_secure_random_key_here');
  await expectRefuse('short key', 'short-key-value', 'short-key-value');

  const uiSrc = fs.readFileSync(path.join(__dirname, '../serve_ui.js'), 'utf8');
  check('UI proxy default port matches the API default', /WATCHTOWER_API_PORT \|\| '3000'/.test(uiSrc));

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
    check(
      'GET / without a session redirects to /login',
      root.status === 302 && root.headers.location === '/login',
      String(root.status) + ' ' + root.headers.location
    );
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

    const loggedOut = await rawRequest(port, 'POST', '/logout', { Cookie: cookie });
    check('POST /logout clears the session', loggedOut.status === 200 && /Max-Age=0/i.test(cookiePair(loggedOut)), cookiePair(loggedOut));
    const afterLogout = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie });
    check('logged-out cookie no longer opens the UI', afterLogout.status === 401, String(afterLogout.status));

    function leaks(body) {
      return /at\s+\S+\.js:\d+/.test(body) || body.includes('node:internal') || body.includes('serve_ui.js') || body.includes('URIError');
    }
    const badCookie = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: 'wt_session=%E0%A4%A' });
    check('malformed cookie is 400', badCookie.status === 400, String(badCookie.status) + ' ' + badCookie.body);
    check('malformed cookie body is generic', badCookie.json && badCookie.json.error === 'Bad request' && !leaks(badCookie.body), badCookie.body);
    const badLogin = await rawRequest(port, 'GET', '/login', { Cookie: 'x=%' });
    check('malformed cookie on /login is 400', badLogin.status === 400 && !leaks(badLogin.body), badLogin.body);
    const stillUp = await rawRequest(port, 'GET', '/login');
    check('UI still serves /login after a malformed cookie', stillUp.status === 200, String(stillUp.status));
    const badJson = await rawRequest(port, 'POST', '/login', { 'Content-Type': 'application/json' }, '{');
    check('invalid JSON does not return a stack', (badJson.status === 400 || badJson.status === 500) && !leaks(badJson.body), badJson.status + ' ' + badJson.body);

    const wsBad = await new Promise((resolve) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write(
          'GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n'
          + 'Host: 127.0.0.1:' + port + '\r\n'
          + 'Upgrade: websocket\r\n'
          + 'Connection: Upgrade\r\n'
          + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
          + 'Sec-WebSocket-Version: 13\r\n'
          + 'Cookie: wt_session=%E0%A4%A\r\n'
          + '\r\n'
        );
      });
      let data = '';
      const timer = setTimeout(() => { sock.destroy(); resolve({ data, closed: false }); }, 2000);
      sock.on('data', (chunk) => { data += chunk.toString('utf8'); });
      sock.on('error', () => {});
      sock.on('close', () => { clearTimeout(timer); resolve({ data, closed: true }); });
    });
    check(
      'malformed cookie on the WebSocket upgrade is refused',
      wsBad.data.includes('400') && !leaks(wsBad.data),
      JSON.stringify(wsBad)
    );
    const afterWs = await rawRequest(port, 'GET', '/login');
    check('UI process survived the malformed WebSocket cookie', afterWs.status === 200, String(afterWs.status));
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

    const noOrigin = await rawRequest(uiPort, 'POST', '/api/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
    }, JSON.stringify({ ip: '203.0.113.10', name: 'fixture' }));
    check('proxied POST without Origin is forbidden', noOrigin.status === 403 && noOrigin.json && noOrigin.json.error === 'Forbidden', noOrigin.body);
    const withOrigin = await rawRequest(uiPort, 'POST', '/api/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
      Origin: 'http://127.0.0.1:' + uiPort,
    }, JSON.stringify({ ip: '203.0.113.10', name: 'fixture' }));
    check('proxied POST with a matching Origin succeeds', withOrigin.status === 200, withOrigin.status + ' ' + withOrigin.body);
  } finally {
    proxied.child.kill('SIGTERM');
    api.stop();
  }

  const throttlePort = await freePort();
  const throttled = spawnUi(throttlePort);
  try {
    await throttled.ready;
    for (let i = 0; i < 5; i++) {
      const miss = await rawRequest(throttlePort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('login failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    const blocked = await rawRequest(throttlePort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('sixth login failure is throttled', blocked.status === 429 && blocked.json && blocked.json.error === 'Too many requests', blocked.body);
  } finally {
    throttled.child.kill('SIGTERM');
  }

  const shortPort = await freePort();
  const shortLived = spawnUi(shortPort, { WATCHTOWER_UI_SESSION_MS: '80' });
  try {
    await shortLived.ready;
    const session = await rawRequest(shortPort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const cookie = cookiePair(session).split(';')[0];
    await new Promise((resolve) => setTimeout(resolve, 120));
    const expired = await rawRequest(shortPort, 'GET', '/watchtower.html', { Cookie: cookie });
    check('expired session is rejected', expired.status === 401, String(expired.status));
  } finally {
    shortLived.child.kill('SIGTERM');
  }

  const securePort = await freePort();
  const secureUi = spawnUi(securePort, { WATCHTOWER_UI_COOKIE_SECURE: '1' });
  try {
    await secureUi.ready;
    const session = await rawRequest(securePort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('Secure flag is set when configured', /;\s*Secure/i.test(cookiePair(session)), cookiePair(session));
  } finally {
    secureUi.child.kill('SIGTERM');
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
