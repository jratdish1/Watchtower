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
const { keysEqual } = require('../auth');
const { request, startApi } = require('./spawn_api');

const KEY = 'wt-test-operator-key';
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

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
