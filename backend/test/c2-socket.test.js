/**
 * Socket c2_command: non-string action is rejected, destructive C2 without
 * a purge capability is a coded deny. Placeholder key only.
 *
 * Run: node backend/test/c2-socket.test.js
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const io = require(path.join(__dirname, '../../frontend/node_modules/socket.io-client'));
const { request, startApi, TEST_OPERATOR_KEY } = require('./spawn_api');

const KEY = TEST_OPERATOR_KEY;
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

function connect(port, token) {
  return new Promise((resolve, reject) => {
    const socket = io('http://127.0.0.1:' + port, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
      timeout: 4000,
      forceNew: true,
    });
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('socket timeout'));
    }, 5000);
    socket.on('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.on('connect_error', (err) => {
      clearTimeout(timer);
      socket.close();
      reject(err);
    });
  });
}

function once(socket, event) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for ' + event)), 4000);
    socket.once(event, (payload) => {
      clearTimeout(timer);
      resolve(payload);
    });
  });
}

(async () => {
  console.log('c2 socket tests\n');

  const allowPath = path.join(os.tmpdir(), 'wt-c2-allow-' + process.pid + '.json');
  const dbPath = path.join(os.tmpdir(), 'wt-c2-db-' + process.pid + '.json');
  fs.writeFileSync(
    allowPath,
    JSON.stringify({
      host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
      ota: { allow_all: false },
      c2: {
        destructive_actions: ['kill', 'lock_dir', 'quarantine', 'disable_user'],
        audit_blocked_actions: ['kill'],
      },
      profile_capabilities: {},
    })
  );
  fs.writeFileSync(
    dbPath,
    JSON.stringify({
      alerts: [],
      threats: [],
      assets: {},
      groups: { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false, ENABLE_ROLLBACK: true } },
      deviceGroups: { 'ops-1': 'Ops-Fleet' },
    })
  );

  let api;
  let socket;
  try {
    api = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: allowPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      WATCHTOWER_DB_PATH: dbPath,
    });

    let rejected = false;
    try {
      await connect(api.port, 'wrong-key');
    } catch (err) {
      rejected = true;
      check('invalid socket key rejected', /Authentication error/i.test(String(err && err.message)));
    }
    check('invalid socket key did not connect', rejected);
    let paddedRejected = false;
    try {
      await connect(api.port, '  generate_a_secure_random_key_here  ');
    } catch (err) {
      paddedRejected = true;
      check('padded placeholder socket key is rejected', /Authentication error/i.test(String(err && err.message)));
    }
    check('padded placeholder socket key did not connect', paddedRejected);

    socket = await connect(api.port, KEY);
    check('valid socket key connects', socket.connected === true);

    const cases = [null, 1, { not: 'string' }, ['kill']];
    for (const action of cases) {
      const wait = once(socket, 'c2_result');
      socket.emit('c2_command', { action, target: '/tmp/x', host: 'ops-1' });
      const payload = await wait;
      const label = action === null ? 'null' : Array.isArray(action) ? 'array' : typeof action;
      check(
        'non-string action (' + label + ') → invalid_c2_action',
        payload && payload.ok === false && payload.error === 'invalid_c2_action',
        JSON.stringify(payload)
      );
    }

    const nullWait = once(socket, 'c2_result');
    socket.emit('c2_command', null);
    const nullCmd = await nullWait;
    check(
      'null command object → invalid_c2_action',
      nullCmd && nullCmd.error === 'invalid_c2_action',
      JSON.stringify(nullCmd)
    );

    const purgeWait = once(socket, 'c2_result');
    socket.emit('c2_command', { action: 'quarantine', target: '/tmp/x', host: 'ops-1' });
    const purge = await purgeWait;
    check(
      'quarantine without purge cap → allowlist_purge_denied',
      purge && purge.allowlist_denied === true && purge.result && purge.result.error === 'allowlist_purge_denied' && purge.result.rule === 'DENY_PURGE_WITHOUT_CAP',
      JSON.stringify(purge)
    );

    const rollbackWait = once(socket, 'c2_result');
    socket.emit('c2_command', { action: 'rollback', target: '/tmp/x', host: 'ops-1' });
    const rollback = await rollbackWait;
    check(
      'rollback is not accepted over the socket',
      rollback && rollback.ok === false && rollback.error === 'invalid_c2_action' && !rollback.allowlist_denied,
      JSON.stringify(rollback)
    );

    for (const action of ['UPDATE_CORE', 'UPDATE_POLICY']) {
      const reservedWait = once(socket, 'c2_result');
      socket.emit('c2_command', { action, target: 'http://evil.example/update_core.zip', host: 'ops-1', hmac: 'abc' });
      const reserved = await reservedWait;
      check(
        action + ' is reserved for the server',
        reserved && reserved.ok === false && reserved.error === 'invalid_c2_action' && !reserved.allowlist_denied,
        JSON.stringify(reserved)
      );
    }
    const queued = await request(api.port, 'GET', '/api/v2/c2/beacon?host=ops-1', { 'x-api-key': KEY });
    check(
      'reserved socket actions did not queue a command',
      queued.status === 200 && queued.json && Array.isArray(queued.json.commands) && queued.json.commands.length === 0,
      JSON.stringify(queued.json)
    );

    const again = once(socket, 'c2_result');
    socket.emit('c2_command', { action: { bad: true }, target: 't', host: 'ops-1' });
    const still = await again;
    check('handler still alive after rejects', still && still.error === 'invalid_c2_action');
    check('socket still connected', socket.connected === true);
  } finally {
    if (socket) socket.close();
    if (api) api.stop();
    try { fs.unlinkSync(allowPath); } catch (_) {}
    try { fs.unlinkSync(dbPath); } catch (_) {}
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
