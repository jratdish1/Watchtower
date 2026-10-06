/**
 * Spawn backend/app.js on 127.0.0.1 for zero-dependency HTTP/socket tests.
 * No secrets: the caller passes a placeholder key.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');

const REPO = path.join(__dirname, '../..');
const TEST_OPERATOR_KEY = 'wt-test-operator-key-0123456789abcd';

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
    server.on('error', reject);
  });
}

function request(port, method, urlPath, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method,
        headers: headers || {},
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = raw ? JSON.parse(raw) : null;
          } catch (_) {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: raw, json });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function startApi(extraEnv) {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-api-'));
  const env = Object.assign({}, process.env, {
    WATCHTOWER_API_KEY: TEST_OPERATOR_KEY,
    WATCHTOWER_API_PORT: String(port),
    WATCHTOWER_BIND_ADDRESS: '127.0.0.1',
    WATCHTOWER_DB_PATH: path.join(tmp, 'db.json'),
    WATCHTOWER_DATA_DIR: tmp,
    WATCHTOWER_ALLOWLIST: '1',
    WATCHTOWER_OPERATOR_PROFILE_ID: '',
    WATCHTOWER_UI_ORIGIN: 'http://127.0.0.1:8080',
  });
  delete env.WATCHTOWER_ALLOWLIST_PATH;
  delete env.WATCHTOWER_OTA_ALLOW_ALL;
  if (extraEnv) Object.assign(env, extraEnv);

  const child = spawn(process.execPath, [path.join(REPO, 'backend/app.js')], {
    cwd: REPO,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let log = '';
  let settled = false;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      reject(new Error('server did not listen\n' + log));
    }, 8000);
    const take = (chunk) => {
      log += chunk.toString();
      if (!settled && log.includes('Server listening')) {
        settled = true;
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error('server exited ' + code + '\n' + log));
    });
  });

  return {
    port,
    tmp,
    key: env.WATCHTOWER_API_KEY,
    log: () => log,
    stop() {
      child.kill('SIGTERM');
      try {
        fs.rmSync(tmp, { recursive: true, force: true });
      } catch (_) {}
    },
  };
}

module.exports = { REPO, TEST_OPERATOR_KEY, freePort, request, startApi };
