/**
 * Glass Pane operator session: no key in HTML, unauthenticated UI refused,
 * startup refused for a missing or placeholder key, UI bound to loopback
 * unless WATCHTOWER_UI_BIND_ADDRESS is set.
 *
 * Run: node frontend/test/ui-auth.test.js
 */
'use strict';

const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const { TEST_OPERATOR_KEY, startApi } = require('../../backend/test/spawn_api');
const io = require(path.join(__dirname, '../node_modules/socket.io-client'));

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
    check('session cookie Max-Age matches the default TTL', /Max-Age=28800/.test(setCookie), setCookie);
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
    check(
      'Glass Pane has a logout control',
      html.body.includes('id="fe-logout-btn"') && html.body.includes("fetch('/logout'") && !/id="fe-logout-btn"[^>]*data-mutate/.test(html.body)
    );
    check(
      'logout redirects only after a successful response',
      html.body.includes("if (res.ok) location.assign('/login')") && html.body.includes("showToast('error', 'Log out failed')") && !html.body.includes(".finally(() => { location.assign('/login')")
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

    const noOriginLogout = await rawRequest(port, 'POST', '/logout', { Cookie: cookie });
    check('logout without Origin is forbidden', noOriginLogout.status === 403 && noOriginLogout.json && noOriginLogout.json.error === 'Forbidden', noOriginLogout.body);
    const stillIn = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie });
    check('logout without Origin keeps the session', stillIn.status === 200, String(stillIn.status));
    const twin = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie + '; ' + cookie });
    check('duplicate identical wt_session cookies keep the session', twin.status === 200, String(twin.status));
    const clash = await rawRequest(port, 'GET', '/', { Cookie: cookie + '; wt_session=other-token' });
    check(
      'disagreeing wt_session cookies redirect / to /login',
      clash.status === 302 && clash.headers.location === '/login',
      String(clash.status) + ' ' + clash.body
    );
    const clashPage = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie + '; wt_session=other-token' });
    check('disagreeing wt_session cookies do not open the UI', clashPage.status === 401, String(clashPage.status));
    const loggedOut = await rawRequest(port, 'POST', '/logout', { Cookie: cookie, Origin: 'http://127.0.0.1:' + port });
    check('POST /logout clears the session', loggedOut.status === 200 && /Max-Age=0/i.test(cookiePair(loggedOut)), cookiePair(loggedOut));
    const afterLogout = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: cookie });
    check('logged-out cookie no longer opens the UI', afterLogout.status === 401, String(afterLogout.status));

    function leaks(body) {
      return /at\s+\S+\.js:\d+/.test(body) || body.includes('node:internal') || body.includes('serve_ui.js') || body.includes('URIError');
    }
    const badCookie = await rawRequest(port, 'GET', '/watchtower.html', { Cookie: 'wt_session=%E0%A4%A' });
    check('malformed cookie is 400', badCookie.status === 400, String(badCookie.status) + ' ' + badCookie.body);
    check('malformed cookie body is generic', badCookie.json && badCookie.json.error === 'Bad request' && !leaks(badCookie.body), badCookie.body);
    const badLogin = await rawRequest(port, 'GET', '/login', { Cookie: 'wt_session=%E0%A4%A' });
    check('malformed session cookie on /login is treated as absent', badLogin.status === 200 && badLogin.body.includes('Operator key') && !leaks(badLogin.body), String(badLogin.status) + ' ' + badLogin.body.slice(0, 180));
    const badLoginPost = await rawRequest(port, 'POST', '/login', {
      'Content-Type': 'application/json',
      Cookie: 'wt_session=%E0%A4%A',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('POST /login with a malformed session cookie still succeeds', badLoginPost.status === 200 && /Max-Age=28800/.test(cookiePair(badLoginPost)), String(badLoginPost.status) + ' ' + badLoginPost.body);
    const otherCookie = await rawRequest(port, 'GET', '/login', { Cookie: 'prefs=%E0%A4%A' });
    check('unrelated malformed cookie still serves /login', otherCookie.status === 200, String(otherCookie.status) + ' ' + otherCookie.body);
    const badRoot = await rawRequest(port, 'GET', '/', { Cookie: 'wt_session=%E0%A4%A' });
    check(
      'malformed wt_session on / redirects to /login',
      badRoot.status === 302 && badRoot.headers.location === '/login' && !leaks(badRoot.body),
      String(badRoot.status) + ' ' + badRoot.body
    );
    const otherRoot = await rawRequest(port, 'GET', '/', { Cookie: 'theme=%' });
    check(
      'unrelated malformed cookie still redirects /',
      otherRoot.status === 302 && otherRoot.headers.location === '/login',
      String(otherRoot.status)
    );
    const stillUp = await rawRequest(port, 'GET', '/login');
    check('UI still serves /login after a malformed cookie', stillUp.status === 200, String(stillUp.status));
    const badJson = await rawRequest(port, 'POST', '/login', { 'Content-Type': 'application/json' }, '{');
    check('invalid JSON is 400 without a stack', badJson.status === 400 && badJson.json && badJson.json.error === 'Bad request' && !leaks(badJson.body), badJson.status + ' ' + badJson.body);

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
    const beaconProxy = await rawRequest(uiPort, 'GET', '/api/v2/c2/beacon?host=ops-1', { Cookie: cookie });
    check('UI proxy refuses beacon GET', beaconProxy.status === 403 && beaconProxy.json && beaconProxy.json.error === 'Forbidden', beaconProxy.body);
    const syncProxy = await rawRequest(uiPort, 'GET', '/api/v2/policies/sync?host=ghost-fixture', { Cookie: cookie });
    check('UI proxy refuses policy sync GET', syncProxy.status === 403 && syncProxy.json && syncProxy.json.error === 'Forbidden', syncProxy.body);
    const shapedWrite = await rawRequest(uiPort, 'POST', '/API/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
    }, '{}');
    check('state-changing proxy variant without Origin is forbidden', shapedWrite.status === 403 && shapedWrite.json && shapedWrite.json.error === 'Forbidden', shapedWrite.body);

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
        extraHeaders: { Cookie: cookie, Origin: 'http://127.0.0.1:' + uiPort },
      });
      const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3500);
      socket.on('connect', () => { clearTimeout(timer); socket.close(); resolve('connected'); });
      socket.on('connect_error', (err) => { clearTimeout(timer); socket.close(); resolve('error:' + (err && err.message)); });
    });
    check('socket with a session connects', allowed === 'connected', allowed);

    const polled = await new Promise((resolve) => {
      const socket = io('http://127.0.0.1:' + uiPort, {
        reconnection: false,
        timeout: 5000,
        forceNew: true,
        extraHeaders: { Cookie: cookie, Origin: 'http://127.0.0.1:' + uiPort },
      });
      let firstTransport = '';
      let gotEvent = false;
      let upgraded = false;
      const finish = (result) => { clearTimeout(timer); socket.close(); resolve(result); };
      const timer = setTimeout(() => finish('timeout:' + firstTransport + ':' + gotEvent + ':' + upgraded), 6000);
      const maybeDone = () => { if (gotEvent && upgraded && firstTransport === 'polling') finish('event'); };
      socket.io.on('open', () => {
        firstTransport = socket.io.engine && socket.io.engine.transport ? socket.io.engine.transport.name : '';
        if (socket.io.engine) socket.io.engine.on('upgrade', () => { upgraded = true; maybeDone(); });
      });
      socket.on('sync_state', (payload) => {
        if (payload && Array.isArray(payload.alerts)) gotEvent = true;
        maybeDone();
      });
      socket.on('connect_error', (err) => finish('error:' + (err && err.message)));
    });
    check('default-transport socket.io through the proxy receives sync_state', polled === 'event', polled);

    const encodedSpace = await rawRequest(uiPort, 'GET', '/api/alerts%20', { Cookie: cookie });
    check(
      'percent-encoded space is forwarded raw and is not a 500',
      encodedSpace.status === 404 && encodedSpace.body.includes('Cannot GET /api/alerts%20') && !/at\s+\S+\.js:\d+/.test(encodedSpace.body),
      encodedSpace.status + ' ' + encodedSpace.body
    );

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
    const nullOrigin = await rawRequest(uiPort, 'POST', '/api/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
      Origin: 'null',
    }, JSON.stringify({ ip: '203.0.113.10', name: 'fixture' }));
    check('Origin null is forbidden on a state-changing proxy request', nullOrigin.status === 403 && nullOrigin.json && nullOrigin.json.error === 'Forbidden', nullOrigin.body);
    const opaqueSite = await rawRequest(uiPort, 'POST', '/api/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
      Origin: 'null',
      'Sec-Fetch-Site': 'same-origin',
    }, JSON.stringify({ ip: '203.0.113.13', name: 'fixture' }));
    check(
      'Origin null stays forbidden when Sec-Fetch-Site is same-origin',
      opaqueSite.status === 403 && opaqueSite.json && opaqueSite.json.error === 'Forbidden',
      opaqueSite.body
    );
    const pane = await rawRequest(uiPort, 'GET', '/watchtower.html', { Cookie: cookie });
    check(
      'Glass Pane sets Referrer-Policy strict-origin-when-cross-origin',
      pane.status === 200 && pane.headers['referrer-policy'] === 'strict-origin-when-cross-origin',
      String(pane.headers['referrer-policy'])
    );
    const sameOriginNoReferer = await rawRequest(uiPort, 'POST', '/api/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
      Origin: 'http://127.0.0.1:' + uiPort,
    }, JSON.stringify({ ip: '203.0.113.11', name: 'fixture' }));
    check(
      'same-origin POST without Referer still succeeds',
      sameOriginNoReferer.status === 200,
      sameOriginNoReferer.status + ' ' + sameOriginNoReferer.body
    );
    const cased = await rawRequest(uiPort, 'POST', '/API/v2/infrastructure', {
      Cookie: cookie,
      'Content-Type': 'application/json',
      Origin: 'http://127.0.0.1:' + uiPort,
    }, JSON.stringify({ ip: '203.0.113.12', name: 'fixture' }));
    check('case-variant allowlisted path is forwarded as received', cased.status === 200, cased.status + ' ' + cased.body);

    const crossOrigin = await new Promise((resolve) => {
      const sock = net.connect(uiPort, '127.0.0.1', () => {
        sock.write(
          'GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n'
          + 'Host: 127.0.0.1:' + uiPort + '\r\n'
          + 'Upgrade: websocket\r\n'
          + 'Connection: Upgrade\r\n'
          + 'Origin: https://evil.example\r\n'
          + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
          + 'Sec-WebSocket-Version: 13\r\n'
          + 'Cookie: ' + cookie + '\r\n'
          + '\r\n'
        );
      });
      let data = '';
      const timer = setTimeout(() => { sock.destroy(); resolve(data); }, 2000);
      sock.on('data', (chunk) => { data += chunk.toString('utf8'); });
      sock.on('error', () => {});
      sock.on('close', () => { clearTimeout(timer); resolve(data); });
    });
    check(
      'cross-origin WebSocket upgrade is refused before 101',
      crossOrigin.includes('403') && !crossOrigin.includes('101'),
      crossOrigin
    );
    const missingOrigin = await new Promise((resolve) => {
      const sock = net.connect(uiPort, '127.0.0.1', () => {
        sock.write(
          'GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n'
          + 'Host: 127.0.0.1:' + uiPort + '\r\n'
          + 'Upgrade: websocket\r\n'
          + 'Connection: Upgrade\r\n'
          + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
          + 'Sec-WebSocket-Version: 13\r\n'
          + 'Cookie: ' + cookie + '\r\n'
          + '\r\n'
        );
      });
      let data = '';
      const timer = setTimeout(() => { sock.destroy(); resolve(data); }, 2000);
      sock.on('data', (chunk) => { data += chunk.toString('utf8'); });
      sock.on('error', () => {});
      sock.on('close', () => { clearTimeout(timer); resolve(data); });
    });
    check(
      'WebSocket upgrade without Origin is refused before 101',
      missingOrigin.includes('403') && !missingOrigin.includes('101'),
      missingOrigin
    );
    const upgradePaths = [
      ['/api/v2/c2/beacon', 'beacon', '403'],
      ['/API/v2/c2/beacon', 'beacon case', '403'],
      ['/api/v2/c2/beacon/', 'beacon trailing slash', '403'],
      ['/api//v2//c2//beacon', 'beacon double slash', '400'],
      ['/socket.io/../api/v2/c2/beacon', 'beacon dot-segment', '400'],
      ['/api/v2/policies/sync', 'policy sync', '403'],
    ];
    for (const [urlPath, label, status] of upgradePaths) {
      const refused = await new Promise((resolve) => {
        const sock = net.connect(uiPort, '127.0.0.1', () => {
          sock.write(
            'GET ' + urlPath + ' HTTP/1.1\r\n'
            + 'Host: 127.0.0.1:' + uiPort + '\r\n'
            + 'Upgrade: websocket\r\n'
            + 'Connection: Upgrade\r\n'
            + 'Origin: http://127.0.0.1:' + uiPort + '\r\n'
            + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
            + 'Sec-WebSocket-Version: 13\r\n'
            + 'Cookie: ' + cookie + '\r\n'
            + '\r\n'
          );
        });
        let data = '';
        const timer = setTimeout(() => { sock.destroy(); resolve(data); }, 2000);
        sock.on('data', (chunk) => { data += chunk.toString('utf8'); });
        sock.on('error', () => {});
        sock.on('close', () => { clearTimeout(timer); resolve(data); });
      });
      check(
        'upgrade of ' + label + ' is refused',
        refused.includes(status) && !refused.includes('101'),
        refused
      );
    }

    const live = await new Promise((resolve) => {
      const socket = io('http://127.0.0.1:' + uiPort, {
        transports: ['websocket'],
        reconnection: false,
        timeout: 3000,
        forceNew: true,
        extraHeaders: { Cookie: cookie, Origin: 'http://127.0.0.1:' + uiPort },
      });
      const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3500);
      socket.on('connect', () => { clearTimeout(timer); resolve(socket); });
      socket.on('connect_error', (err) => { clearTimeout(timer); socket.close(); resolve('error:' + (err && err.message)); });
    });
    check('socket stays up before logout', live && live.connected === true, String(live));
    if (live && live.connected) {
      const gone = new Promise((resolve) => {
        const timer = setTimeout(() => resolve('timeout'), 2000);
        live.on('disconnect', () => { clearTimeout(timer); resolve('disconnected'); });
      });
      const loggedOut = await rawRequest(uiPort, 'POST', '/logout', { Cookie: cookie, Origin: 'http://127.0.0.1:' + uiPort });
      const closed = await gone;
      check('logout returns ok', loggedOut.status === 200, String(loggedOut.status));
      check('logout closes the open WebSocket', closed === 'disconnected', closed);
      live.close();
    } else {
      check('logout returns ok', false, 'socket was not connected');
      check('logout closes the open WebSocket', false, 'socket was not connected');
    }
  } finally {
    proxied.child.kill('SIGTERM');
    api.stop();
  }

  const variantAllow = path.join(os.tmpdir(), 'wt-ui-variant-' + process.pid + '.json');
  const variantDb = path.join(os.tmpdir(), 'wt-ui-variant-db-' + process.pid + '.json');
  fs.writeFileSync(variantAllow, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  }));
  fs.writeFileSync(variantDb, JSON.stringify({
    alerts: [],
    threats: [],
    assets: {},
    groups: { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false } },
    deviceGroups: { 'ops-1': 'Ops-Fleet' },
  }));
  const variantApi = await startApi({
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
    WATCHTOWER_ALLOWLIST_PATH: variantAllow,
    WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
    WATCHTOWER_DB_PATH: variantDb,
    AUTO_REMEDIATE: 'true',
  });
  const variantUiPort = await freePort();
  const variantUi = spawnUi(variantUiPort, {
    WATCHTOWER_API_PORT: String(variantApi.port),
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
  });
  try {
    await variantUi.ready;
    const ingested = await rawRequest(variantApi.port, 'POST', '/api/v2/ingest/threat', {
      'Content-Type': 'application/json',
      'x-api-key': TEST_OPERATOR_KEY,
    }, JSON.stringify({ source: 'ops-1', ai_verdict: 'MALICIOUS', file_path: '/tmp/fixture', event_type: 'FILE' }));
    check('variant fixture queued a command', ingested.status === 201, String(ingested.status) + ' ' + ingested.body);
    const variantSession = await rawRequest(variantUiPort, 'POST', '/login', {
      'Content-Type': 'application/json',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const variantCookie = cookiePair(variantSession).split(';')[0];
    const variants = [
      ['/api/v2/c2/beacon/', 'trailing slash', 403],
      ['/API/v2/c2/beacon', 'uppercase', 403],
      ['/api/V2/C2/BEACON', 'mixed case', 403],
      ['/api//v2//c2//beacon', 'double slash', 400],
      ['/api/v2/c2/%62eacon', 'percent-encoded', 403],
      ['/api/foo/../v2/c2/beacon', 'dot-segment', 400],
      ['/api/v2/policies/sync/', 'policy sync trailing slash', 403],
    ];
    for (const [urlPath, label, status] of variants) {
      const blocked = await rawRequest(variantUiPort, 'GET', urlPath + '?host=ops-1', {
        Cookie: variantCookie,
        Origin: 'http://127.0.0.1:9',
      });
      const error = status === 400 ? 'Bad request' : 'Forbidden';
      check(
        'proxy ' + label + ' is forbidden',
        blocked.status === status && blocked.json && blocked.json.error === error,
        blocked.status + ' ' + blocked.body
      );
    }
    const agentRoutes = [
      '/api/v2/c2/beacon',
      '/api/v2/policies/sync',
      '/api/v2/ingest/inventory',
      '/api/v2/ingest/threat',
    ];
    function nonCanonical(base) {
      return [
        [base + '#/../../infrastructure', 'hash'],
        [base + '%23/../../infrastructure', 'encoded hash'],
        [base.replace('/api/', '/api\\'), 'backslash'],
        [base.replace('/v2/', '/v2%2f'), 'encoded slash'],
        [base.replace('/v2/', '/v2/../v2/'), 'dot-segment'],
        [base.replace('/v2/', '//v2/'), 'double slash'],
      ];
    }
    for (const base of agentRoutes) {
      for (const [urlPath, label] of nonCanonical(base)) {
        const blocked = await rawRequest(variantUiPort, 'POST', urlPath, {
          Cookie: variantCookie,
          Origin: 'http://127.0.0.1:' + variantUiPort,
          'Content-Type': 'application/json',
        }, '{}');
        check(
          'POST ' + base + ' ' + label + ' is rejected',
          blocked.status === 400 && blocked.json && blocked.json.error === 'Bad request',
          blocked.status + ' ' + blocked.body
        );
        const upgraded = await new Promise((resolve) => {
          const sock = net.connect(variantUiPort, '127.0.0.1', () => {
            sock.write(
              'GET ' + urlPath + ' HTTP/1.1\r\n'
              + 'Host: 127.0.0.1:' + variantUiPort + '\r\n'
              + 'Upgrade: websocket\r\n'
              + 'Connection: Upgrade\r\n'
              + 'Origin: http://127.0.0.1:' + variantUiPort + '\r\n'
              + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
              + 'Sec-WebSocket-Version: 13\r\n'
              + 'Cookie: ' + variantCookie + '\r\n'
              + '\r\n'
            );
          });
          let data = '';
          const timer = setTimeout(() => { sock.destroy(); resolve(data); }, 1500);
          sock.on('data', (chunk) => { data += chunk.toString('utf8'); });
          sock.on('error', () => {});
          sock.on('close', () => { clearTimeout(timer); resolve(data); });
        });
        check(
          'upgrade ' + base + ' ' + label + ' is rejected',
          upgraded.includes('400') && !upgraded.includes('101'),
          upgraded
        );
      }
    }
    const posted = await rawRequest(variantUiPort, 'POST', '/api/v2/c2/beacon/?host=ops-1', {
      Cookie: variantCookie,
      Origin: 'http://127.0.0.1:' + variantUiPort,
      'Content-Type': 'application/json',
    }, '{}');
    check('proxy beacon POST with a trailing slash is forbidden', posted.status === 403, posted.status + ' ' + posted.body);
    const still = await rawRequest(variantApi.port, 'GET', '/api/v2/c2/beacon?host=ops-1', {
      'x-api-key': TEST_OPERATOR_KEY,
    });
    check(
      'path variants left the beacon queue intact',
      still.status === 200 && still.json && still.json.commands && still.json.commands.some((c) => c.action === 'quarantine'),
      JSON.stringify(still.json)
    );
  } finally {
    variantUi.child.kill('SIGTERM');
    variantApi.stop();
    try { fs.unlinkSync(variantAllow); } catch (_) {}
    try { fs.unlinkSync(variantDb); } catch (_) {}
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
    const spoofed = await rawRequest(throttlePort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.50',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('untrusted X-Forwarded-For does not bypass the socket throttle', spoofed.status === 429, spoofed.body);
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

  const trustPort = await freePort();
  const trusted = spawnUi(trustPort, { WATCHTOWER_TRUSTED_PROXY: '127.0.0.1' });
  try {
    await trusted.ready;
    for (let i = 0; i < 5; i++) {
      const miss = await rawRequest(trustPort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.8',
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('trusted-proxy failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    const locked = await rawRequest(trustPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.8',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('forwarded client stays throttled', locked.status === 429, locked.body);
    const other = await rawRequest(trustPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.9',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('a different forwarded client can still log in', other.status === 200, other.body);
  } finally {
    trusted.child.kill('SIGTERM');
  }

  const rightPort = await freePort();
  const rightmost = spawnUi(rightPort, { WATCHTOWER_TRUSTED_PROXY: '127.0.0.1' });
  try {
    await rightmost.ready;
    for (let i = 0; i < 5; i++) {
      const miss = await rawRequest(rightPort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.50, 203.0.113.8',
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('rightmost-hop failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    const rotated = await rawRequest(rightPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '198.51.100.77, 203.0.113.8',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('rotating the leftmost X-Forwarded-For hop does not bypass the throttle', rotated.status === 429, rotated.body);
    const spoofLeft = await rawRequest(rightPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.9, 203.0.113.8',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('a spoofed operator address on the left does not move the throttle bucket', spoofLeft.status === 429, spoofLeft.body);
    const operator = await rawRequest(rightPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.8, 203.0.113.9',
    }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    check('the rightmost hop is the throttle bucket', operator.status === 200, operator.body);
  } finally {
    rightmost.child.kill('SIGTERM');
  }

  const prunePort = await freePort();
  const pruned = spawnUi(prunePort, { WATCHTOWER_TRUSTED_PROXY: '127.0.0.1' });
  try {
    await pruned.ready;
    for (let i = 0; i < 4; i++) {
      const miss = await rawRequest(prunePort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.21',
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('inactive-row failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    let fillerOk = true;
    for (let i = 0; i < 60; i++) {
      const miss = await rawRequest(prunePort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.' + (i + 1),
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      if (miss.status !== 401) fillerOk = false;
    }
    check('filler login failures stay 401', fillerOk);
    for (let i = 0; i < 5; i++) {
      const miss = await rawRequest(prunePort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.20',
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('active-lock failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    const locked = await rawRequest(prunePort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.20',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('active lock is throttled before eviction', locked.status === 429, locked.body);
    for (let i = 60; i < 63; i++) {
      await rawRequest(prunePort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.' + (i + 1),
      }, JSON.stringify({ key: 'z'.repeat(32) }));
    }
    const stillLocked = await rawRequest(prunePort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.20',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('an active lockout survives the failure-map cap', stillLocked.status === 429, stillLocked.body);
    const dropped = await rawRequest(prunePort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.21',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    const droppedAgain = await rawRequest(prunePort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.21',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check(
      'the cap evicts an inactive row before an active lock',
      dropped.status === 401 && droppedAgain.status === 401,
      dropped.status + ' ' + droppedAgain.status
    );
  } finally {
    pruned.child.kill('SIGTERM');
  }

  const hardPort = await freePort();
  const hard = spawnUi(hardPort, {
    WATCHTOWER_UI_LOGIN_FAILURE_CAP: '2',
    WATCHTOWER_TRUSTED_PROXY: '127.0.0.1',
  });
  try {
    await hard.ready;
    for (const ip of ['203.0.113.40', '203.0.113.41']) {
      for (let i = 0; i < 5; i++) {
        const miss = await rawRequest(hardPort, 'POST', '/login', {
          'Content-Type': 'application/json',
          'X-Forwarded-For': ip,
        }, JSON.stringify({ key: 'z'.repeat(32) }));
        check('hard-cap failure ' + ip + ' ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
      }
      const lockedIp = await rawRequest(hardPort, 'POST', '/login', {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('hard-cap address ' + ip + ' is locked', lockedIp.status === 429, lockedIp.body);
    }
    const fresh = await rawRequest(hardPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.42',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('a new bucket is refused when every slot is an active lock', fresh.status === 429, fresh.body);
    const kept = await rawRequest(hardPort, 'POST', '/login', {
      'Content-Type': 'application/json',
      'X-Forwarded-For': '203.0.113.40',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('a full map of active lockouts does not evict one', kept.status === 429, kept.body);
  } finally {
    hard.child.kill('SIGTERM');
  }

  const againPort = await freePort();
  const again = spawnUi(againPort);
  try {
    await again.ready;
    for (let i = 0; i < 5; i++) {
      const miss = await rawRequest(againPort, 'POST', '/login', {
        'Content-Type': 'application/json',
      }, JSON.stringify({ key: 'z'.repeat(32) }));
      check('backoff failure ' + (i + 1) + ' is 401', miss.status === 401, String(miss.status));
    }
    const firstLock = await rawRequest(againPort, 'POST', '/login', {
      'Content-Type': 'application/json',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('first lockout is 429', firstLock.status === 429, firstLock.body);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const afterExpiry = await rawRequest(againPort, 'POST', '/login', {
      'Content-Type': 'application/json',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('a failure after expiry is counted again', afterExpiry.status === 401, afterExpiry.body);
    const escalated = await rawRequest(againPort, 'POST', '/login', {
      'Content-Type': 'application/json',
    }, JSON.stringify({ key: 'z'.repeat(32) }));
    check('expiry keeps the failure history and escalates the next lock', escalated.status === 429, escalated.body);
  } finally {
    again.child.kill('SIGTERM');
  }

  const hugePort = await freePort();
  const huge = spawnUi(hugePort, { WATCHTOWER_UI_SESSION_MS: '999999999999' });
  try {
    await huge.ready;
    const session = await rawRequest(hugePort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const hugeCookie = cookiePair(session);
    check(
      'session TTL is clamped below the setTimeout overflow',
      session.status === 200 && /Max-Age=2147483/.test(hugeCookie) && !/Max-Age=999999999/.test(hugeCookie),
      hugeCookie
    );
    const page = await rawRequest(hugePort, 'GET', '/watchtower.html', { Cookie: hugeCookie.split(';')[0] });
    check('clamped session is still valid immediately', page.status === 200, String(page.status));
  } finally {
    huge.child.kill('SIGTERM');
  }

  const shortWsPort = await freePort();
  const shortApi = await startApi({ WATCHTOWER_API_KEY: TEST_OPERATOR_KEY });
  const shortWs = spawnUi(shortWsPort, {
    WATCHTOWER_UI_SESSION_MS: '400',
    WATCHTOWER_API_PORT: String(shortApi.port),
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
  });
  try {
    await shortWs.ready;
    const session = await rawRequest(shortWsPort, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify({ key: TEST_OPERATOR_KEY }));
    const shortCookie = cookiePair(session).split(';')[0];
    const closed = await new Promise((resolve) => {
      const socket = io('http://127.0.0.1:' + shortWsPort, {
        transports: ['websocket'],
        reconnection: false,
        timeout: 3000,
        forceNew: true,
        extraHeaders: { Cookie: shortCookie, Origin: 'http://127.0.0.1:' + shortWsPort },
      });
      const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3000);
      socket.on('connect', () => {
        setTimeout(() => {
          if (!socket.connected) {
            clearTimeout(timer);
            resolve('disconnected');
          }
        }, 700);
      });
      socket.on('disconnect', () => { clearTimeout(timer); resolve('disconnected'); });
      socket.on('connect_error', (err) => { clearTimeout(timer); socket.close(); resolve('error:' + (err && err.message)); });
    });
    check('expired session closes the open WebSocket', closed === 'disconnected', closed);
  } finally {
    shortWs.child.kill('SIGTERM');
    shortApi.stop();
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
