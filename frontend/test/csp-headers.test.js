/**
 * CSP and baseline security headers on serve_ui.js responses.
 *
 * Run: node frontend/test/csp-headers.test.js
 */
'use strict';

const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const {
  securityHeaders,
  contentSecurityPolicy,
  SOCKET_IO_SCRIPT,
  FONT_STYLESHEET_ORIGIN,
  FONT_FILE_ORIGIN,
} = require('../security_headers');
const { TEST_OPERATOR_KEY } = require('../../backend/test/spawn_api');

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

function directives(csp) {
  const out = {};
  String(csp || '').split(';').forEach((part) => {
    const bits = part.trim().split(/\s+/).filter(Boolean);
    if (!bits.length) return;
    out[bits[0]] = bits.slice(1);
  });
  return out;
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

function get(port, urlPath, headers) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path: urlPath, headers: headers || {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    }).on('error', reject);
  });
}

(async () => {
  console.log('CSP header tests\n');

  const sample = contentSecurityPolicy('testNonceValue');
  const dirs = directives(sample);
  check("default-src 'self'", dirs['default-src'] && dirs['default-src'].join(' ') === "'self'");
  check("frame-ancestors 'none'", dirs['frame-ancestors'] && dirs['frame-ancestors'].join(' ') === "'none'");
  check("object-src 'none'", dirs['object-src'] && dirs['object-src'].join(' ') === "'none'");
  check("base-uri 'self'", dirs['base-uri'] && dirs['base-uri'].join(' ') === "'self'");
  check("connect-src 'self'", dirs['connect-src'] && dirs['connect-src'].includes("'self'"));
  check('script-src allows the socket.io script', dirs['script-src'] && dirs['script-src'].includes(SOCKET_IO_SCRIPT));
  check('script-src has a nonce', dirs['script-src'] && dirs['script-src'].includes("'nonce-testNonceValue'"));
  check('script-src has no unsafe-inline', dirs['script-src'] && !dirs['script-src'].includes("'unsafe-inline'"));
  check('style-src-elem has a nonce', dirs['style-src-elem'] && dirs['style-src-elem'].includes("'nonce-testNonceValue'"));
  check('style-src-elem allows the font stylesheet origin', dirs['style-src-elem'] && dirs['style-src-elem'].includes(FONT_STYLESHEET_ORIGIN));
  check('style-src-elem has no unsafe-inline', dirs['style-src-elem'] && !dirs['style-src-elem'].includes("'unsafe-inline'"));
  check(
    "style-src-attr unsafe-inline is the attribute allowance",
    dirs['style-src-attr'] && dirs['style-src-attr'].includes("'unsafe-inline'")
  );
  check('font-src allows gstatic', dirs['font-src'] && dirs['font-src'].includes(FONT_FILE_ORIGIN));

  const headers = securityHeaders('abc');
  check('X-Content-Type-Options nosniff', headers['X-Content-Type-Options'] === 'nosniff');
  check('Referrer-Policy no-referrer', headers['Referrer-Policy'] === 'no-referrer');

  const port = await freePort();
  const uiEnv = Object.assign({}, process.env, {
    WATCHTOWER_UI_PORT: String(port),
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
    WATCHTOWER_API_PORT: '9',
  });
  delete uiEnv.WATCHTOWER_UI_BIND_ADDRESS;
  const child = spawn(process.execPath, [path.join(__dirname, '../serve_ui.js')], {
    cwd: path.join(__dirname, '../..'),
    env: uiEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  try {
    await new Promise((resolve, reject) => {
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

    const login = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      });
      req.on('error', reject);
      req.end(JSON.stringify({ key: TEST_OPERATOR_KEY }));
    });
    const setCookie = login.headers['set-cookie'];
    const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie || '').split(';')[0];
    check('operator login sets a session cookie', login.status === 200 && cookie.indexOf('wt_session=') === 0, String(login.status));
    const page = await get(port, '/watchtower.html', { Cookie: cookie });
    check('GET /watchtower.html → 200', page.status === 200, String(page.status));
    const csp = page.headers['content-security-policy'];
    const live = directives(csp);
    check('response CSP default-src self', live['default-src'] && live['default-src'].includes("'self'"));
    check('response CSP frame-ancestors none', live['frame-ancestors'] && live['frame-ancestors'].includes("'none'"));
    check('response CSP object-src none', live['object-src'] && live['object-src'].includes("'none'"));
    check('response CSP base-uri self', live['base-uri'] && live['base-uri'].includes("'self'"));
    check('response CSP connect-src self', live['connect-src'] && live['connect-src'].includes("'self'"));
    check('response script-src pins socket.io', live['script-src'] && live['script-src'].includes(SOCKET_IO_SCRIPT));
    check('response script-src has no unsafe-inline', live['script-src'] && !live['script-src'].includes("'unsafe-inline'"));
    check('response X-Content-Type-Options nosniff', page.headers['x-content-type-options'] === 'nosniff');
    check('response Referrer-Policy no-referrer', page.headers['referrer-policy'] === 'no-referrer');

    const scriptNonce = page.body.match(/<script nonce="([^"]+)">/);
    const styleNonce = page.body.match(/<style nonce="([^"]+)">/);
    check('inline script carries a nonce', !!(scriptNonce && scriptNonce[1]));
    check('style block carries a nonce', !!(styleNonce && styleNonce[1]));
    check(
      'script and style nonces match',
      !!(scriptNonce && styleNonce && scriptNonce[1] === styleNonce[1])
    );
    check(
      'CSP nonce matches the HTML nonce',
      !!(scriptNonce && csp && csp.includes("'nonce-" + scriptNonce[1] + "'"))
    );
    check('served HTML has no onclick attributes', !/\son[a-z]+=/i.test(page.body));
    const page2 = await get(port, '/watchtower.html', { Cookie: cookie });
    const nonce2 = page2.body.match(/<script nonce="([^"]+)">/);
    check('nonces differ across responses', !!(scriptNonce && nonce2 && scriptNonce[1] !== nonce2[1]));

    const root = await get(port, '/', { Cookie: cookie });
    check('GET / carries nosniff', root.headers['x-content-type-options'] === 'nosniff');
    check('GET / carries a CSP', typeof root.headers['content-security-policy'] === 'string' && root.headers['content-security-policy'].includes("frame-ancestors 'none'"));
  } finally {
    child.kill('SIGTERM');
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
