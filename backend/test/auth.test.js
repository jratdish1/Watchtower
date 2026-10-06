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
const { spawn, spawnSync } = require('child_process');
const { keysEqual, operatorKeyProblem, MIN_OPERATOR_KEY_LENGTH } = require('../auth');
const { ipAllowed } = require('../ip_allow');
const { request, startApi, freePort, TEST_OPERATOR_KEY } = require('./spawn_api');

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
  check(
    '31 character key plus two spaces is rejected',
    operatorKeyProblem('d'.repeat(31) + '  ') === 'too_short' && operatorKeyProblem('  ' + 'd'.repeat(31)) === 'too_short'
  );
  check('32 character private key is accepted', operatorKeyProblem('b'.repeat(MIN_OPERATOR_KEY_LENGTH)) === null);
  check('template example key is rejected', operatorKeyProblem('generate_a_secure_random_key_here') === 'placeholder');
  check(
    'placeholder padded with whitespace is rejected',
    operatorKeyProblem('  generate_a_secure_random_key_here  ') === 'placeholder'
      && operatorKeyProblem('WATCHTOWER_DEFAULT_KEY' + ' '.repeat(16)) === 'placeholder'
  );
  check(
    'a non-placeholder key keeps surrounding whitespace',
    operatorKeyProblem('  ' + 'c'.repeat(32)) === null
  );
  const exampleSrc = fs.readFileSync(path.join(__dirname, '../../.env.example'), 'utf8');
  const exampleUrl = (exampleSrc.match(/^AI_INFERENCE_URL=(.*)$/m) || [])[1];
  check(
    'literal from an example file is rejected',
    !!exampleUrl && exampleUrl.trim().length >= MIN_OPERATOR_KEY_LENGTH && operatorKeyProblem(exampleUrl.trim()) === 'placeholder'
  );
  const repoData = path.resolve(__dirname, '../../data');
  const repoDataNames = ['infrastructure.json', 'detailed_network_topology.csv', 'historical_topology.json'];
  function repoSnap() {
    const snap = {};
    repoDataNames.forEach((name) => {
      const file = path.join(repoData, name);
      snap[name] = fs.existsSync(file) ? fs.readFileSync(file) : null;
    });
    return snap;
  }
  function snapEqual(left, right) {
    return repoDataNames.every((name) => {
      if (left[name] === null || right[name] === null) return left[name] === right[name];
      return left[name].equals(right[name]);
    });
  }
  const repoBefore = repoSnap();
  const testSrc = fs.readFileSync(__filename, 'utf8');
  check(
    'auth test source does not write the repo data directory',
    !/writeFileSync\(\s*path\.join\(\s*repoData/.test(testSrc) && !testSrc.includes(path.join('data', 'infrastructure.json'))
  );
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

  let api;
  let capped;
  let infraPath;
  let topoPath;
  try {
    api = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: allowPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
    });
    infraPath = path.join(api.tmp, 'infrastructure.json');
    topoPath = path.join(api.tmp, 'detailed_network_topology.csv');
    fs.writeFileSync(infraPath, '{"ip":"203.0.113.10"}\n');
    fs.writeFileSync(topoPath, 'Switch_IP,Port_Topology\n203.0.113.10,clean\n');

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

    const badJson = await request(api.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{');
    check('malformed JSON is 400', badJson.status === 400 && badJson.json && badJson.json.error === 'Bad request', badJson.status + ' ' + badJson.body);
    check('malformed JSON body has no stack', !/at\s+\S+\.js:\d+/.test(badJson.body) && !badJson.body.includes('SyntaxError'));
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
    const cappedInfra = path.join(capped.tmp, 'infrastructure.json');
    const cappedTopo = path.join(capped.tmp, 'detailed_network_topology.csv');
    fs.writeFileSync(cappedInfra, '{"ip":"203.0.113.10"}\n');
    fs.writeFileSync(cappedTopo, 'Switch_IP,Port_Topology\n203.0.113.10,clean\n');
    const okInfra = await request(capped.port, 'DELETE', '/api/v2/infrastructure', auth(KEY));
    check('DELETE infrastructure with purge cap → 200', okInfra.status === 200, JSON.stringify(okInfra.json));
    check('purge cap removed infrastructure file', !fs.existsSync(cappedInfra));
    const okTopo = await request(capped.port, 'DELETE', '/api/v2/topology', auth(KEY));
    check('DELETE topology with purge cap → 200', okTopo.status === 200, JSON.stringify(okTopo.json));
    check('purge cap removed topology file', !fs.existsSync(cappedTopo));
  } finally {
    if (capped) capped.stop();
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
    const flagInfra = path.join(flagOff.tmp, 'infrastructure.json');
    fs.writeFileSync(flagInfra, '{"ip":"203.0.113.10"}\n');
    const stillDenied = await request(flagOff.port, 'DELETE', '/api/v2/infrastructure', auth(KEY));
    check('ALLOWLIST=0 still denies purge', stillDenied.status === 403, JSON.stringify(stillDenied.json));
    check(
      'ALLOWLIST=0 deny is the purge rule on a loaded map',
      stillDenied.json && stillDenied.json.error === 'allowlist_purge_denied' && stillDenied.json.rule === 'DENY_PURGE_WITHOUT_CAP'
    );
    check('ALLOWLIST=0 left the infrastructure file', fs.existsSync(flagInfra));
    check(
      'ALLOWLIST=0 did not fall closed to an empty map',
      !flagOff.log().includes('fail-closed empty map'),
      flagOff.log()
    );
  } finally {
    if (flagOff) flagOff.stop();
    try { fs.unlinkSync(allowPath); } catch (_) {}
  }

  const autoPath = path.join(os.tmpdir(), 'wt-auth-auto-' + process.pid + '.json');
  const enrolledDb = path.join(os.tmpdir(), 'wt-auth-enrolled-' + process.pid + '.json');
  fs.writeFileSync(enrolledDb, JSON.stringify({
    alerts: [],
    threats: [],
    assets: {},
    groups: { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false } },
    deviceGroups: { 'ops-1': 'Ops-Fleet' },
  }));
  function threatBody(source) {
    return JSON.stringify({
      source,
      ai_verdict: 'MALICIOUS',
      file_path: '/tmp/fixture',
      event_type: 'FILE',
    });
  }
  fs.writeFileSync(autoPath, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
    profile_capabilities: {},
  }));
  let autoOff;
  let autoOn;
  try {
    autoOff = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: autoPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      WATCHTOWER_DB_PATH: enrolledDb,
      AUTO_REMEDIATE: 'true',
    });
    const ingested = await request(autoOff.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), threatBody('ops-1'));
    check('threat ingest without purge cap → 201', ingested.status === 201, String(ingested.status));
    const beacon = await request(autoOff.port, 'GET', '/api/v2/c2/beacon?host=ops-1', auth(KEY));
    check(
      'AUTO_REMEDIATE does not queue quarantine without purge cap',
      beacon.status === 200 && beacon.json && Array.isArray(beacon.json.commands) && beacon.json.commands.length === 0,
      JSON.stringify(beacon.json)
    );
  } finally {
    if (autoOff) autoOff.stop();
  }

  fs.writeFileSync(autoPath, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  }));
  fs.writeFileSync(enrolledDb, JSON.stringify({
    alerts: [],
    threats: [],
    assets: {},
    groups: { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false } },
    deviceGroups: { 'ops-1': 'Ops-Fleet' },
  }));
  try {
    autoOn = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: autoPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      WATCHTOWER_DB_PATH: enrolledDb,
      AUTO_REMEDIATE: 'true',
    });
    const unknown = await request(autoOn.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), threatBody('remote-fixture'));
    check('threat ingest for an unknown host → 201', unknown.status === 201, String(unknown.status));
    const unknownBeacon = await request(autoOn.port, 'GET', '/api/v2/c2/beacon?host=remote-fixture', auth(KEY));
    check(
      'AUTO_REMEDIATE does not queue an unknown host',
      unknownBeacon.status === 200 && unknownBeacon.json && Array.isArray(unknownBeacon.json.commands) && unknownBeacon.json.commands.length === 0,
      JSON.stringify(unknownBeacon.json)
    );
    const ingested = await request(autoOn.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), threatBody('ops-1'));
    check('threat ingest for an allowlisted host → 201', ingested.status === 201, String(ingested.status));
    const beacon = await request(autoOn.port, 'GET', '/api/v2/c2/beacon?host=ops-1', auth(KEY));
    const firstCmd = beacon.json && beacon.json.commands && beacon.json.commands.find((c) => c.action === 'quarantine');
    check(
      'AUTO_REMEDIATE queues quarantine for an allowlisted host with purge',
      beacon.status === 200 && !!firstCmd && typeof firstCmd.id === 'string' && firstCmd.id.length > 0,
      JSON.stringify(beacon.json)
    );
    const beaconAgain = await request(autoOn.port, 'GET', '/api/v2/c2/beacon?host=ops-1', auth(KEY));
    check(
      'GET beacon delivers a command id at most once',
      beaconAgain.status === 200 && beaconAgain.json && Array.isArray(beaconAgain.json.commands) && beaconAgain.json.commands.length === 0,
      JSON.stringify(beaconAgain.json)
    );
    const pulled = await request(autoOn.port, 'POST', '/api/v2/c2/beacon?host=ops-1', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    check(
      'POST beacon does not return a command already delivered by GET',
      pulled.status === 200 && pulled.json && Array.isArray(pulled.json.commands) && pulled.json.commands.length === 0,
      JSON.stringify(pulled.json)
    );
    const ingestedAgain = await request(autoOn.port, 'POST', '/api/v2/ingest/threat', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), threatBody('ops-1'));
    check('second threat ingest for the same host → 201', ingestedAgain.status === 201, String(ingestedAgain.status));
    const posted = await request(autoOn.port, 'POST', '/api/v2/c2/beacon?host=ops-1', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    const postedCmd = posted.json && posted.json.commands && posted.json.commands.find((c) => c.action === 'quarantine');
    check(
      'POST beacon returns a command that GET has not delivered',
      posted.status === 200 && !!postedCmd && typeof postedCmd.id === 'string' && postedCmd.id !== firstCmd.id,
      JSON.stringify(posted.json)
    );
    const afterPull = await request(autoOn.port, 'GET', '/api/v2/c2/beacon?host=ops-1', auth(KEY));
    check(
      'POST beacon clears the queue',
      afterPull.status === 200 && afterPull.json && Array.isArray(afterPull.json.commands) && afterPull.json.commands.length === 0,
      JSON.stringify(afterPull.json)
    );
  } finally {
    if (autoOn) autoOn.stop();
    try { fs.unlinkSync(autoPath); } catch (_) {}
    try { fs.unlinkSync(enrolledDb); } catch (_) {}
  }

  const enrollApi = await startApi({ WATCHTOWER_API_KEY: KEY });
  try {
    function enrollDb() {
      const file = path.join(enrollApi.tmp, 'db.json');
      if (!fs.existsSync(file)) return { deviceGroups: {} };
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    const ghost = await request(enrollApi.port, 'GET', '/api/v2/policies/sync?host=ghost-fixture', auth(KEY));
    check(
      'GET policies/sync does not enroll an unknown host',
      ghost.status === 200 && ghost.json && ghost.json.group === 'Default' && !Object.prototype.hasOwnProperty.call(enrollDb().deviceGroups || {}, 'ghost-fixture'),
      JSON.stringify(ghost.json) + ' ' + JSON.stringify(enrollDb().deviceGroups)
    );
    const longHost = 'h'.repeat(254);
    const longSync = await request(enrollApi.port, 'GET', '/api/v2/policies/sync?host=' + longHost, auth(KEY));
    check(
      'GET policies/sync rejects a host longer than 253',
      longSync.status === 400 && !Object.prototype.hasOwnProperty.call(enrollDb().deviceGroups || {}, longHost),
      String(longSync.status) + ' ' + longSync.body
    );
    const longBeacon = await request(enrollApi.port, 'GET', '/api/v2/c2/beacon?host=' + longHost, auth(KEY));
    check('GET beacon rejects a host longer than 253', longBeacon.status === 400, String(longBeacon.status));
    const peek = await request(enrollApi.port, 'GET', '/api/v2/c2/beacon?host=beacon-only', auth(KEY));
    check(
      'GET beacon does not enroll an unknown host',
      peek.status === 200 && !Object.prototype.hasOwnProperty.call(enrollDb().deviceGroups || {}, 'beacon-only'),
      JSON.stringify(enrollDb().deviceGroups)
    );
    const longPost = await request(enrollApi.port, 'POST', '/api/v2/c2/beacon?host=' + longHost, Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    check(
      'POST beacon rejects a host longer than 253',
      longPost.status === 400 && !Object.prototype.hasOwnProperty.call(enrollDb().deviceGroups || {}, longHost),
      String(longPost.status) + ' ' + longPost.body
    );
    const longAssign = await request(enrollApi.port, 'POST', '/api/v2/policies/update', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), JSON.stringify({ host: longHost, newGroup: 'Default' }));
    check('policy reassign rejects a host longer than 253', longAssign.status === 400, String(longAssign.status) + ' ' + longAssign.body);
    const joined = await request(enrollApi.port, 'POST', '/api/v2/c2/beacon?host=short-host', Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    check(
      'POST beacon enrolls a host',
      joined.status === 200 && enrollDb().deviceGroups && enrollDb().deviceGroups['short-host'] === 'Default',
      JSON.stringify(enrollDb().deviceGroups)
    );
    const maxHost = 'a'.repeat(253);
    const maxJoin = await request(enrollApi.port, 'POST', '/api/v2/c2/beacon?host=' + maxHost, Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    check(
      'POST beacon accepts a 253 character host',
      maxJoin.status === 200 && enrollDb().deviceGroups && enrollDb().deviceGroups[maxHost] === 'Default',
      String(maxJoin.status)
    );
    const paddedHost = await request(enrollApi.port, 'POST', '/api/v2/c2/beacon?host=' + encodeURIComponent(' short-host '), Object.assign({
      'Content-Type': 'application/json',
    }, auth(KEY)), '{}');
    check(
      'POST beacon rejects a padded host',
      paddedHost.status === 400 && !Object.prototype.hasOwnProperty.call(enrollDb().deviceGroups || {}, ' short-host ') && enrollDb().deviceGroups['short-host'] === 'Default',
      String(paddedHost.status) + ' ' + paddedHost.body + ' ' + JSON.stringify(enrollDb().deviceGroups)
    );
    for (const reserved of ['__proto__', 'constructor', 'toString']) {
      const blocked = await request(enrollApi.port, 'POST', '/api/v2/c2/beacon?host=' + reserved, Object.assign({
        'Content-Type': 'application/json',
      }, auth(KEY)), '{}');
      const groups = enrollDb().deviceGroups || {};
      check(
        'POST beacon rejects reserved host ' + reserved,
        blocked.status === 400 && !Object.prototype.hasOwnProperty.call(groups, reserved),
        String(blocked.status) + ' ' + blocked.body
      );
    }
  } finally {
    enrollApi.stop();
  }

  fs.writeFileSync(capPath, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['quarantine'], audit_blocked_actions: [] },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  }));
  const otaDb = path.join(os.tmpdir(), 'wt-auth-ota-' + process.pid + '.json');
  const updatesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-ota-zip-'));
  const zipPath = path.join(__dirname, '../updates/update_core.zip');
  const zipBefore = fs.existsSync(zipPath) ? fs.readFileSync(zipPath) : null;
  fs.writeFileSync(otaDb, JSON.stringify({
    alerts: [],
    threats: [],
    assets: {},
    groups: { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false } },
    deviceGroups: { 'ops-1': 'Ops-Fleet' },
  }));
  let otaApi;
  try {
    otaApi = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: capPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      WATCHTOWER_DB_PATH: otaDb,
      WATCHTOWER_PUBLIC_BASE_URL: 'http://hub.example:3000',
      WATCHTOWER_UPDATES_DIR: updatesDir,
    });
    const uploaded = await request(otaApi.port, 'POST', '/api/v2/ota/upload?group=Ops-Fleet', Object.assign({
      'Content-Type': 'application/zip',
      Host: 'evil.example',
    }, auth(KEY)), Buffer.from('PK\x03\x04fixture'));
    check('OTA upload ignores a hostile Host header', uploaded.status === 200, JSON.stringify(uploaded.json));
    const otaBeacon = await request(otaApi.port, 'GET', '/api/v2/c2/beacon?host=ops-1', auth(KEY));
    const otaCmd = otaBeacon.json && otaBeacon.json.commands && otaBeacon.json.commands.find((c) => c.action === 'UPDATE_CORE');
    check(
      'OTA target uses the configured public base',
      !!(otaCmd && otaCmd.target === 'http://hub.example:3000/updates/update_core.zip'),
      JSON.stringify(otaBeacon.json)
    );
    check('OTA target does not copy the request Host', !(otaCmd && String(otaCmd.target).includes('evil.example')));
    check('OTA zip was written under the temp updates dir', fs.existsSync(path.join(updatesDir, 'update_core.zip')));
    const zipAfter = fs.existsSync(zipPath) ? fs.readFileSync(zipPath) : null;
    const zipUntouched = (zipBefore === null && zipAfter === null)
      || (zipBefore && zipAfter && zipBefore.equals(zipAfter));
    check('OTA test did not write backend/updates/update_core.zip', zipUntouched);
  } finally {
    if (otaApi) otaApi.stop();
    try { fs.unlinkSync(otaDb); } catch (_) {}
    try { fs.rmSync(updatesDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.unlinkSync(capPath); } catch (_) {}
  }

  fs.writeFileSync(capPath, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: [], audit_blocked_actions: [] },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  }));
  const otaDbPlain = path.join(os.tmpdir(), 'wt-auth-ota-plain-' + process.pid + '.json');
  const plainUpdates = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-ota-plain-'));
  fs.writeFileSync(otaDbPlain, JSON.stringify({
    alerts: [],
    threats: [],
    assets: {},
    groups: { 'Ops-Fleet': {} },
    deviceGroups: { 'ops-1': 'Ops-Fleet' },
  }));
  let otaPlain;
  try {
    otaPlain = await startApi({
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_ALLOWLIST_PATH: capPath,
      WATCHTOWER_OPERATOR_PROFILE_ID: 'GitHub vets-ops',
      WATCHTOWER_DB_PATH: otaDbPlain,
      WATCHTOWER_UPDATES_DIR: plainUpdates,
      WATCHTOWER_PUBLIC_BASE_URL: '',
    });
    const refused = await request(otaPlain.port, 'POST', '/api/v2/ota/upload?group=Ops-Fleet', Object.assign({
      'Content-Type': 'application/zip',
    }, auth(KEY)), Buffer.from('PK\x03\x04fixture'));
    check('OTA upload without a public base is refused', refused.status === 503 && refused.json && refused.json.error === 'OTA unavailable', JSON.stringify(refused.json));
    check('refused OTA body has no loopback URL', !refused.body.includes('127.0.0.1'));
    check('refused OTA did not write a zip', !fs.existsSync(path.join(plainUpdates, 'update_core.zip')));
    check('startup warns when the public base is unset', otaPlain.log().includes('WATCHTOWER_PUBLIC_BASE_URL is unset'));
  } finally {
    if (otaPlain) otaPlain.stop();
    try { fs.unlinkSync(otaDbPlain); } catch (_) {}
    try { fs.rmSync(plainUpdates, { recursive: true, force: true }); } catch (_) {}
    try { fs.unlinkSync(capPath); } catch (_) {}
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

  const repoRoot = path.join(__dirname, '../..');
  const backendDir = path.join(__dirname, '..');
  const expectedData = path.resolve(repoRoot, 'data');
  const cwdData = path.resolve(backendDir, 'data');
  const cwdDataBefore = fs.existsSync(cwdData);
  const dataPort = await freePort();
  const dataChild = spawn(process.execPath, [path.join(backendDir, 'app.js')], {
    cwd: backendDir,
    env: Object.assign({}, process.env, {
      WATCHTOWER_API_KEY: KEY,
      WATCHTOWER_API_PORT: String(dataPort),
      WATCHTOWER_BIND_ADDRESS: '127.0.0.1',
      WATCHTOWER_DATA_DIR: './data',
      WATCHTOWER_DB_PATH: path.join(os.tmpdir(), 'wt-cwd-db-' + process.pid + '.json'),
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let dataLog = '';
  const dataCode = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      dataChild.kill('SIGTERM');
      resolve('listening');
    }, 4000);
    const take = (chunk) => {
      dataLog += chunk.toString();
      if (dataLog.includes('Server listening')) {
        clearTimeout(timer);
        dataChild.kill('SIGTERM');
        resolve('listening');
      }
    };
    dataChild.stdout.on('data', take);
    dataChild.stderr.on('data', take);
    dataChild.on('exit', (code) => {
      clearTimeout(timer);
      if (!dataLog.includes('Server listening')) resolve(code);
    });
  });
  check('server started from backend/ with ./data', dataCode === 'listening', dataLog);
  check(
    'WATCHTOWER_DATA_DIR=./data from backend/ is repo data/',
    dataLog.includes('[Watchtower DB] Data directory ' + expectedData),
    dataLog
  );
  check('that start did not select backend/data', !dataLog.includes(cwdData), dataLog);
  if (!cwdDataBefore) check('that start did not create backend/data', !fs.existsSync(cwdData));
  try { fs.unlinkSync(path.join(os.tmpdir(), 'wt-cwd-db-' + process.pid + '.json')); } catch (_) {}

  await expectRefuse('unset key', { WATCHTOWER_API_KEY: undefined }, ['WATCHTOWER_DEFAULT_KEY']);
  await expectRefuse('empty key', { WATCHTOWER_API_KEY: '' }, []);
  await expectRefuse('placeholder key', { WATCHTOWER_API_KEY: 'WATCHTOWER_DEFAULT_KEY' }, ['WATCHTOWER_DEFAULT_KEY']);
  await expectRefuse('template example key', { WATCHTOWER_API_KEY: 'generate_a_secure_random_key_here' }, ['generate_a_secure_random_key_here']);
  await expectRefuse('padded placeholder key', { WATCHTOWER_API_KEY: '  generate_a_secure_random_key_here  ' }, ['generate_a_secure_random_key_here']);
  await expectRefuse('short key', { WATCHTOWER_API_KEY: 'short-key-value' }, ['short-key-value']);
  await expectRefuse('31 character key plus two spaces', { WATCHTOWER_API_KEY: 'e'.repeat(31) + '  ' }, ['e'.repeat(31)]);

  const coreDir = path.join(__dirname, '../../core');
  const fallback = /environ\.get\(\s*["']WATCHTOWER_API_KEY["']\s*,|=\s*["']WATCHTOWER_DEFAULT_KEY["']|=\s*["']YOUR_SECRET_API_KEY_HERE["']/;
  fs.readdirSync(coreDir).filter((name) => name.endsWith('.py') || name.endsWith('.ps1')).forEach((name) => {
    const src = fs.readFileSync(path.join(coreDir, name), 'utf8');
    const sendsKey = src.includes('x-api-key') || src.includes('$ApiKey');
    check(name + ' does not fall back to a public key', !fallback.test(src));
    if (sendsKey) {
      check(
        name + ' fail-starts without a private key',
        src.includes('require_operator_key') || src.includes('exit 1')
      );
    }
  });
  const ps1 = fs.readFileSync(path.join(coreDir, 'watchtower_ad_sensor.ps1'), 'utf8');
  check('ad sensor fails start instead of using a public key', ps1.includes('exit 1') && ps1.includes('$env:WATCHTOWER_API_KEY') && !ps1.includes('os.environ.get'));
  const beaconEnv = Object.assign({}, process.env);
  delete beaconEnv.WATCHTOWER_API_KEY;
  const beacon = spawnSync('python3', [path.join(coreDir, 'watchtower_beacon.py')], {
    env: beaconEnv,
    encoding: 'utf8',
    timeout: 5000,
  });
  const beaconLog = (beacon.stderr || '') + (beacon.stdout || '');
  check('beacon without a key exits 1', beacon.status === 1, String(beacon.status) + ' ' + beaconLog);
  check('beacon refusal does not print a key', beaconLog.includes('Refusing to start') && !beaconLog.includes('WATCHTOWER_DEFAULT_KEY'));
  const paddedPy = spawnSync('python3', ['-c', 'from operator_key import require_operator_key\nrequire_operator_key()'], {
    cwd: coreDir,
    env: Object.assign({}, process.env, { WATCHTOWER_API_KEY: '  generate_a_secure_random_key_here  ' }),
    encoding: 'utf8',
    timeout: 5000,
  });
  const paddedPyLog = (paddedPy.stderr || '') + (paddedPy.stdout || '');
  check(
    'python client rejects a padded placeholder',
    paddedPy.status === 1 && paddedPyLog.includes('Refusing to start') && !paddedPyLog.includes('generate_a_secure_random_key_here'),
    String(paddedPy.status) + ' ' + paddedPyLog
  );
  const shortPad = 'f'.repeat(31) + '  ';
  const shortPy = spawnSync('python3', ['-c', 'from operator_key import require_operator_key\nrequire_operator_key()'], {
    cwd: coreDir,
    env: Object.assign({}, process.env, { WATCHTOWER_API_KEY: shortPad }),
    encoding: 'utf8',
    timeout: 5000,
  });
  const shortPyLog = (shortPy.stderr || '') + (shortPy.stdout || '');
  check(
    'python client rejects a 31 character key plus two spaces',
    shortPy.status === 1 && shortPyLog.includes('Refusing to start') && !shortPyLog.includes(shortPad.trim()),
    String(shortPy.status) + ' ' + shortPyLog
  );
  const otaZip = path.join(os.tmpdir(), 'wt-ota-probe-' + process.pid + '.zip');
  const otaProbe = spawnSync('python3', ['-c', [
    'import os, hmac, hashlib, zipfile, pathlib, sys',
    'sys.path.insert(0, os.environ["WT_CORE"])',
    'import watchtower_beacon as beacon',
    'marker = "wt-ota-must-not-land.txt"',
    'zip_path = os.environ["WT_ZIP"]',
    'with zipfile.ZipFile(zip_path, "w") as zf:',
    '    zf.writestr(marker, b"no")',
    'url = pathlib.Path(zip_path).as_uri()',
    'landed = os.path.join(os.environ["WT_CORE"], marker)',
    'beacon.execute_local_quarantine("UPDATE_CORE", url, None)',
    'missing = os.path.exists(landed)',
    'beacon.execute_local_quarantine("UPDATE_CORE", url, "00")',
    'short = os.path.exists(landed)',
    'beacon.execute_local_quarantine("UPDATE_CORE", url, "0" * 64)',
    'bad = os.path.exists(landed)',
    'good = hmac.new(os.environ["WATCHTOWER_API_KEY"].encode(), b"abc", hashlib.sha256).hexdigest()',
    'print("MISSING", int(missing))',
    'print("SHORT", int(short))',
    'print("BAD", int(bad))',
    'print("NONE", int(beacon.ota_signature_ok(b"abc", None)))',
    'print("EMPTY", int(beacon.ota_signature_ok(b"abc", "")))',
    'print("GOOD", int(beacon.ota_signature_ok(b"abc", good)))',
    'print("WRONG", int(beacon.ota_signature_ok(b"abc", "f" * 64)))',
  ].join('\n')], {
    cwd: coreDir,
    env: Object.assign({}, process.env, {
      WATCHTOWER_API_KEY: KEY,
      WT_CORE: coreDir,
      WT_ZIP: otaZip,
    }),
    encoding: 'utf8',
    timeout: 8000,
  });
  const otaOut = (otaProbe.stdout || '') + (otaProbe.stderr || '');
  check(
    'OTA apply requires a valid signature',
    otaProbe.status === 0
      && otaOut.includes('MISSING 0')
      && otaOut.includes('SHORT 0')
      && otaOut.includes('BAD 0')
      && otaOut.includes('NONE 0')
      && otaOut.includes('EMPTY 0')
      && otaOut.includes('GOOD 1')
      && otaOut.includes('WRONG 0')
      && !otaOut.includes(KEY),
    otaOut
  );
  try { fs.unlinkSync(otaZip); } catch (_) {}
  try { fs.unlinkSync(path.join(coreDir, 'wt-ota-must-not-land.txt')); } catch (_) {}
  check('ad sensor trims before the placeholder list', ps1.includes('$ApiKeyTrimmed') && ps1.includes('$ApiKeyTrimmed -in'));
  check('ad sensor length check uses the trimmed key', ps1.includes('$ApiKeyTrimmed.Length -lt 32'));
  check('repo data files are unchanged', snapEqual(repoBefore, repoSnap()));

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
