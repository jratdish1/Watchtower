/**
 * Operator API-key auth for the previously open GETs, plus purge-cap HTTP denies.
 * Placeholder key only. No live hosts.
 *
 * Run: node backend/test/auth.test.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { keysEqual, operatorKeyProblem, MIN_OPERATOR_KEY_LENGTH } = require('../auth');
const { ipAllowed } = require('../ip_allow');
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

function auth(key) {
  return key === undefined ? {} : { 'x-api-key': key };
}

(async () => {
  console.log('auth + purge HTTP tests\n');

  const authSrc = fs.readFileSync(path.join(__dirname, '../auth.js'), 'utf8');
  check('keysEqual uses timingSafeEqual', authSrc.includes('crypto.timingSafeEqual'));
  check('equal placeholder keys match', keysEqual(KEY, KEY) === true);
  check('same-length mismatch fails', keysEqual(KEY.slice(0, -1) + 'X', KEY) === false);
  check('shorter prefix fails and does not throw', keysEqual(KEY.slice(0, 4), KEY) === false);
  check('longer key fails', keysEqual(KEY + '-extra', KEY) === false);
  check('empty provided fails', keysEqual('', KEY) === false);
  check('missing provided fails', keysEqual(undefined, KEY) === false);
  check('empty expected fails closed', keysEqual(KEY, '') === false);
  check('unset key is rejected', operatorKeyProblem(undefined) === 'unset');
  check('empty key is rejected', operatorKeyProblem('') === 'empty' && operatorKeyProblem('   ') === 'empty');
  check('default literal is rejected', operatorKeyProblem('WATCHTOWER_DEFAULT_KEY') === 'placeholder');
  check('html placeholder is rejected', operatorKeyProblem('YOUR_SECRET_API_KEY_HERE') === 'placeholder');
  check('short key is rejected', operatorKeyProblem('a'.repeat(MIN_OPERATOR_KEY_LENGTH - 1)) === 'too_short');
  check('32 character private key is accepted', operatorKeyProblem('b'.repeat(MIN_OPERATOR_KEY_LENGTH)) === null);
  check('loopback is allowed', ipAllowed('127.0.0.1') && ipAllowed('::1') && ipAllowed('::ffff:127.0.0.1'));
  check('CGNAT 100.64.0.0/10 is allowed', ipAllowed('100.64.0.0') && ipAllowed('100.127.255.255') && ipAllowed('::ffff:100.100.1.1'));
  check('substring 100. does not match', !ipAllowed('100.1.2.3') && !ipAllowed('100.128.0.0') && !ipAllowed('100.63.255.255') && !ipAllowed('10.0.0.100'));

  const appSrc = fs.readFileSync(path.join(__dirname, '../app.js'), 'utf8');
  const ipAt = appSrc.indexOf('ipAllowed(');
  const updatesAt = appSrc.indexOf("app.use('/updates'");
  const assetsAt = appSrc.indexOf("app.use('/assets'");
  check('updates static is mounted after the IP allowlist', ipAt !== -1 && updatesAt > ipAt);
  check('assets static is mounted after the IP allowlist', assetsAt > ipAt);
  check('CORS is not wildcard', !/origin:\s*["']\*["']/.test(appSrc));
  check('search errors are generic', appSrc.includes("error: 'index unavailable'") && !appSrc.includes('details: stderr'));
  check('local c2 success sets ok', /io\.emit\('c2_result', \{ ok: true, status: 'ok'/.test(appSrc));

  const allowPath = path.join(os.tmpdir(), 'wt-auth-allow-' + process.pid + '.json');
  fs.writeFileSync(
    allowPath,
    JSON.stringify({
      host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
      ota: { allow_all: false },
      c2: { destructive_actions: ['quarantine', 'kill'], audit_blocked_actions: ['kill'] },
      profile_capabilities: {},
    })
  );

  const infraPath = path.join(__dirname, '../../data/infrastructure.json');
  const topoPath = path.join(__dirname, '../../data/detailed_network_topology.csv');
  fs.mkdirSync(path.dirname(infraPath), { recursive: true });
  const infraBefore = fs.existsSync(infraPath) ? fs.readFileSync(infraPath) : null;
  const topoBefore = fs.existsSync(topoPath) ? fs.readFileSync(topoPath) : null;
  fs.writeFileSync(infraPath, '{"ip":"203.0.113.10"}\n');
  fs.writeFileSync(topoPath, 'Switch_IP,Port_Topology\n203.0.113.10,clean\n');

  let api;
  let capped;
  try {
    api = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: allowPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
    });

    const alertsMissing = await request(api.port, 'GET', '/api/alerts');
    check('GET /api/alerts missing key → 401', alertsMissing.status === 401, String(alertsMissing.status));
    check(
      'GET /api/alerts missing key body',
      alertsMissing.json && alertsMissing.json.error === 'Unauthorized: Invalid or missing API Key'
    );

    const alertsBad = await request(api.port, 'GET', '/api/alerts', auth(KEY.slice(0, -1) + 'Z'));
    check('GET /api/alerts wrong key → 401', alertsBad.status === 401, String(alertsBad.status));

    const alertsPrefix = await request(api.port, 'GET', '/api/alerts', auth(KEY.slice(0, 4)));
    check('GET /api/alerts prefix key → 401', alertsPrefix.status === 401, String(alertsPrefix.status));

    const alertsOk = await request(api.port, 'GET', '/api/alerts', auth(KEY));
    check('GET /api/alerts valid key → 200', alertsOk.status === 200, String(alertsOk.status));
    check('GET /api/alerts returns an array', Array.isArray(alertsOk.json));

    const agentsMissing = await request(api.port, 'GET', '/api/agents');
    check('GET /api/agents missing key → 401', agentsMissing.status === 401, String(agentsMissing.status));

    const agentsBad = await request(api.port, 'GET', '/api/agents', auth('not-the-key'));
    check('GET /api/agents wrong key → 401', agentsBad.status === 401, String(agentsBad.status));

    const agentsOk = await request(api.port, 'GET', '/api/agents', auth(KEY));
    check('GET /api/agents valid key → 200', agentsOk.status === 200, String(agentsOk.status));
    check('GET /api/agents returns an array', Array.isArray(agentsOk.json));

    const memoryMissing = await request(api.port, 'GET', '/api/memory/search?q=fixture');
    check('GET /api/memory/search missing key → 401', memoryMissing.status === 401, String(memoryMissing.status));
    check(
      'GET /api/memory/search missing key body',
      memoryMissing.json && memoryMissing.json.error === 'Unauthorized: Invalid or missing API Key'
    );

    const memoryBad = await request(api.port, 'GET', '/api/memory/search?q=fixture', auth(KEY.slice(0, -1) + 'Z'));
    check('GET /api/memory/search wrong key → 401', memoryBad.status === 401, String(memoryBad.status));

    const memoryPrefix = await request(api.port, 'GET', '/api/memory/search?q=fixture', auth(KEY.slice(0, 4)));
    check('GET /api/memory/search prefix key → 401', memoryPrefix.status === 401, String(memoryPrefix.status));

    const memoryNoQuery = await request(api.port, 'GET', '/api/memory/search', auth(KEY));
    check('GET /api/memory/search valid key without q → 400', memoryNoQuery.status === 400, String(memoryNoQuery.status));

    const memoryMissingIndex = await request(api.port, 'GET', '/api/memory/search?q=fixture', auth(KEY));
    check('GET /api/memory/search missing index → 503', memoryMissingIndex.status === 503, String(memoryMissingIndex.status));
    check(
      'GET /api/memory/search 503 body is generic',
      memoryMissingIndex.json && memoryMissingIndex.json.error === 'index unavailable' && !memoryMissingIndex.json.details,
      JSON.stringify(memoryMissingIndex.json)
    );

    const corsEvil = await request(api.port, 'GET', '/api/v1/heartbeat', { Origin: 'https://evil.example' });
    check(
      'CORS does not reflect an arbitrary origin',
      corsEvil.headers['access-control-allow-origin'] !== '*' && corsEvil.headers['access-control-allow-origin'] !== 'https://evil.example',
      String(corsEvil.headers['access-control-allow-origin'])
    );
    const corsUi = await request(api.port, 'GET', '/api/v1/heartbeat', { Origin: 'http://127.0.0.1:8080' });
    check(
      'CORS allows the default UI origin',
      corsUi.headers['access-control-allow-origin'] === 'http://127.0.0.1:8080',
      String(corsUi.headers['access-control-allow-origin'])
    );

    const heartbeat = await request(api.port, 'GET', '/api/v1/heartbeat');
    check(
      'GET /api/v1/heartbeat stays open and is not fleet data',
      heartbeat.status === 200 && heartbeat.json && heartbeat.json.status === 'ok' && !heartbeat.json.alerts && !heartbeat.json.agents,
      JSON.stringify(heartbeat.json)
    );

    const purgeInfra = await request(api.port, 'DELETE', '/api/v2/infrastructure', auth(KEY));
    check('DELETE infrastructure without purge cap → 403', purgeInfra.status === 403, JSON.stringify(purgeInfra.json));
    check(
      'DELETE infrastructure code allowlist_purge_denied',
      purgeInfra.json && purgeInfra.json.error === 'allowlist_purge_denied' && purgeInfra.json.rule === 'DENY_PURGE_WITHOUT_CAP'
    );
    check('DELETE infrastructure did not remove the file', fs.existsSync(infraPath));

    const purgeTopo = await request(api.port, 'DELETE', '/api/v2/topology', auth(KEY));
    check('DELETE topology without purge cap → 403', purgeTopo.status === 403, JSON.stringify(purgeTopo.json));
    check(
      'DELETE topology code allowlist_purge_denied',
      purgeTopo.json && purgeTopo.json.error === 'allowlist_purge_denied'
    );
    check('DELETE topology did not remove the file', fs.existsSync(topoPath));

    const purgeNoKey = await request(api.port, 'DELETE', '/api/v2/infrastructure');
    check('DELETE infrastructure missing key → 401', purgeNoKey.status === 401, String(purgeNoKey.status));
  } finally {
    if (api) api.stop();
  }

  const capPath = path.join(os.tmpdir(), 'wt-auth-cap-' + process.pid + '.json');
  fs.writeFileSync(
    capPath,
    JSON.stringify({
      host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
      ota: { allow_all: false },
      c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
      profile_capabilities: { 'GitHub vets-ops': ['purge'] },
    })
  );
  try {
    capped = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: capPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
    });
    const okInfra = await request(capped.port, 'DELETE', '/api/v2/infrastructure', auth(KEY));
    check('DELETE infrastructure with purge cap → 200', okInfra.status === 200, JSON.stringify(okInfra.json));
    check('purge cap removed infrastructure file', !fs.existsSync(infraPath));
    const okTopo = await request(capped.port, 'DELETE', '/api/v2/topology', auth(KEY));
    check('DELETE topology with purge cap → 200', okTopo.status === 200, JSON.stringify(okTopo.json));
  } finally {
    if (capped) capped.stop();
    if (infraBefore === null) {
      try { fs.unlinkSync(infraPath); } catch (_) {}
    } else {
      fs.writeFileSync(infraPath, infraBefore);
    }
    if (topoBefore === null) {
      try { fs.unlinkSync(topoPath); } catch (_) {}
    } else {
      fs.writeFileSync(topoPath, topoBefore);
    }
    try { fs.unlinkSync(allowPath); } catch (_) {}
    try { fs.unlinkSync(capPath); } catch (_) {}
  }

  let flagOff;
  try {
    flagOff = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST: '0',
      WATCHTOWER_ALLOWLIST_PATH: allowPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
    });
    fs.writeFileSync(infraPath, '{"ip":"203.0.113.10"}\n');
    const stillDenied = await request(flagOff.port, 'DELETE', '/api/v2/infrastructure', auth(KEY));
    check('ALLOWLIST=0 still denies purge', stillDenied.status === 403, JSON.stringify(stillDenied.json));
    check('ALLOWLIST=0 left the infrastructure file', fs.existsSync(infraPath));
  } finally {
    if (flagOff) flagOff.stop();
    try { fs.unlinkSync(infraPath); } catch (_) {}
  }

  const autoPath = path.join(os.tmpdir(), 'wt-auth-auto-' + process.pid + '.json');
  fs.writeFileSync(autoPath, JSON.stringify({
    host_group_to_profiles: { Default: ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: [], audit_blocked_actions: [] },
    profile_capabilities: {},
  }));
  let autoOff;
  let autoOn;
  try {
    autoOff = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: autoPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      AUTO_REMEDIATE: 'true',
    });
    const ingested = await request(autoOff.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), JSON.stringify({
      source: 'remote-fixture',
      ai_verdict: 'MALICIOUS',
      file_path: '/tmp/fixture',
      event_type: 'FILE',
    }));
    check('threat ingest without purge cap → 201', ingested.status === 201, String(ingested.status));
    const beacon = await request(autoOff.port, 'GET', '/api/v2/c2/beacon?host=remote-fixture', auth(KEY));
    check(
      'AUTO_REMEDIATE does not queue quarantine without purge cap',
      beacon.status === 200 && beacon.json && Array.isArray(beacon.json.commands) && beacon.json.commands.length === 0,
      JSON.stringify(beacon.json)
    );
  } finally {
    if (autoOff) autoOff.stop();
  }

  fs.writeFileSync(autoPath, JSON.stringify({
    host_group_to_profiles: { Default: ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  }));
  try {
    autoOn = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: autoPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      AUTO_REMEDIATE: 'true',
    });
    const ingested = await request(autoOn.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), JSON.stringify({
      source: 'remote-fixture',
      ai_verdict: 'MALICIOUS',
      file_path: '/tmp/fixture',
      event_type: 'FILE',
    }));
    check('threat ingest with purge cap → 201', ingested.status === 201, String(ingested.status));
    const beacon = await request(autoOn.port, 'GET', '/api/v2/c2/beacon?host=remote-fixture', auth(KEY));
    check(
      'AUTO_REMEDIATE queues quarantine when the profile has purge',
      beacon.status === 200 && beacon.json && beacon.json.commands && beacon.json.commands.some((c) => c.action === 'quarantine'),
      JSON.stringify(beacon.json)
    );
  } finally {
    if (autoOn) autoOn.stop();
    try { fs.unlinkSync(autoPath); } catch (_) {}
  }

  async function expectRefuse(label, envOverlay, secretNeedles) {
    const env = Object.assign({}, process.env);
    delete env.WATCHTOWER_API_KEY;
    if (envOverlay) Object.assign(env, envOverlay);
    if (envOverlay && Object.prototype.hasOwnProperty.call(envOverlay, 'WATCHTOWER_API_KEY') && envOverlay.WATCHTOWER_API_KEY === undefined) {
      delete env.WATCHTOWER_API_KEY;
    }
    const child = spawn(process.execPath, [path.join(__dirname, '../app.js')], {
      cwd: path.join(__dirname, '../..'),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    const code = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        resolve('timeout');
      }, 4000);
      child.stdout.on('data', (chunk) => { log += chunk.toString(); });
      child.stderr.on('data', (chunk) => { log += chunk.toString(); });
      child.on('exit', (exitCode) => {
        clearTimeout(timer);
        resolve(exitCode);
      });
    });
    check(label + ' exits non-zero', code !== 0 && code !== 'timeout', String(code) + ' ' + log);
    check(label + ' log refuses startup', log.includes('Refusing to start'));
    check(label + ' log does not contain the key', secretNeedles.every((needle) => needle === '' || !log.includes(needle)), log);
  }

  await expectRefuse('unset key', { WATCHTOWER_API_KEY: undefined }, ['WATCHTOWER_DEFAULT_KEY']);
  await expectRefuse('empty key', { WATCHTOWER_API_KEY: '' }, []);
  await expectRefuse('placeholder key', { WATCHTOWER_API_KEY: 'WATCHTOWER_DEFAULT_KEY' }, ['WATCHTOWER_DEFAULT_KEY']);
  await expectRefuse('short key', { WATCHTOWER_API_KEY: 'short-key-value' }, ['short-key-value']);

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
