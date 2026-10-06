/**
 * Unit tests — Host-Group → profile_id allowlist adapter
 * No live keys; test doubles only.
 *
 * Run: node --test backend/test/allowlist.test.js
 *   or: node backend/test/allowlist.test.js
 */
'use strict';

const path = require('path');
const assert = require('assert');

// Ensure module resolves from backend/
const allowlist = require('../allowlist');

const PASS = [];
const FAIL = [];

function test(name, fn) {
  try {
    allowlist.resetForTests();
    // Default ON for tests
    process.env.WATCHTOWER_ALLOWLIST = '1';
    delete process.env.WATCHTOWER_OPERATOR_PROFILE_ID;
    delete process.env.WATCHTOWER_OTA_ALLOW_ALL;
    allowlist.loadConfig(true);
    fn();
    PASS.push(name);
    console.log(`  ok  - ${name}`);
  } catch (e) {
    FAIL.push({ name, err: e });
    console.error(`  FAIL - ${name}`);
    console.error(`        ${e.message}`);
  }
}

console.log('allowlist adapter tests\n');

test('unmapped Default deny (DENY_UNMAPPED_GROUP)', () => {
  const d = allowlist.assertMappedGroup('Default');
  assert.ok(d, 'expected deny');
  assert.strictEqual(d.rule, 'DENY_UNMAPPED_GROUP');
  assert.strictEqual(d.error, 'allowlist_unmapped_group');
  assert.strictEqual(d.status, 403);

  const d2 = allowlist.assertPolicyGroupWrite('Default', { Default: {} }, 'GitHub vets-ops');
  assert.ok(d2);
  assert.strictEqual(d2.rule, 'DENY_UNMAPPED_GROUP');
});

test('missing host deny (DENY_MISSING_HOST_GROUP)', () => {
  const deviceGroups = { 'known-host': 'Ops-Fleet' };
  const d = allowlist.assertHostPresent('ghost-host', deviceGroups);
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_MISSING_HOST_GROUP');
  assert.strictEqual(d.error, 'allowlist_missing_host_group');

  const d2 = allowlist.assertC2Command(
    { action: 'quarantine', target: '/tmp/x', host: 'ghost-host' },
    deviceGroups,
    {},
    'GitHub vets-ops'
  );
  assert.ok(d2);
  assert.strictEqual(d2.rule, 'DENY_MISSING_HOST_GROUP');
});

test('OTA ALL deny by default (DENY_OTA_ALL_DEFAULT)', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const d = allowlist.assertOtaGroup('ALL');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_OTA_ALL_DEFAULT');
  assert.strictEqual(d.error, 'allowlist_ota_all_forbidden');
});

test('wrong-profile deny (DENY_WRONG_PROFILE)', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  // Builder-Lab maps to builder/developer — not ops
  const d = allowlist.assertProfileAllowed('Builder-Lab', 'GitHub vets-ops');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_WRONG_PROFILE');
  assert.strictEqual(d.error, 'allowlist_wrong_profile');

  // Fixture: profile A cannot C2 host in group mapped only to B
  const deviceGroups = { 'lab-host': 'Builder-Lab' };
  const groupDB = {
    'Builder-Lab': { ENABLE_ROLLBACK: true, WATCHTOWER_AUDIT_MODE: false },
  };
  const d2 = allowlist.assertC2Command(
    { action: 'quarantine', target: '/tmp/x', host: 'lab-host' },
    deviceGroups,
    groupDB,
    'GitHub vets-ops'
  );
  assert.ok(d2);
  assert.strictEqual(d2.rule, 'DENY_WRONG_PROFILE');
});

test('operator profile unset → fail-closed DENY_WRONG_PROFILE on mapped group', () => {
  delete process.env.WATCHTOWER_OPERATOR_PROFILE_ID;
  const d = allowlist.assertProfileAllowed('Ops-Fleet');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_WRONG_PROFILE');
  assert.ok(d.detail && d.detail.reason === 'operator_profile_unset');
});

test('mapped group + matching profile allows', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const d = allowlist.assertProfileAllowed('Ops-Fleet');
  assert.strictEqual(d, null);

  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const d2 = allowlist.assertReassign('ops-1', 'Ops-Fleet', deviceGroups, 'GitHub vets-ops');
  // reassign to same mapped group with matching profile — ok (both current+new mapped)
  // Wait: Ops-Fleet → Ops-Fleet is fine. But Builder-Lab needs different profile.
  assert.strictEqual(d2, null);

  const ota = allowlist.assertOtaGroup('Ops-Fleet', 'GitHub vets-ops');
  assert.strictEqual(ota, null);
});

test('reassign to Default (UNMAPPED) → DENY_REASSIGN_TO_UNMAPPED', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const d = allowlist.assertReassign('ops-1', 'Default', deviceGroups);
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_REASSIGN_TO_UNMAPPED');
  assert.strictEqual(d.error, 'allowlist_reassign_unmapped');
});

test('C2 audit mode blocks kill (DENY_C2_ACTION_NOT_ALLOWED)', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const groupDB = {
    'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: true, ENABLE_ROLLBACK: true },
  };
  const d = allowlist.assertC2Command(
    { action: 'kill', target: 'pid:1', host: 'ops-1' },
    deviceGroups,
    groupDB
  );
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_C2_ACTION_NOT_ALLOWED');
  assert.strictEqual(d.error, 'allowlist_c2_denied');
});

test('resolveHostGroup returns missing for unknown host', () => {
  const r = allowlist.resolveHostGroup('nope', {});
  assert.strictEqual(r.missing, true);
  assert.strictEqual(r.group, null);
  const r2 = allowlist.resolveHostGroup('h1', { h1: 'Default' });
  assert.strictEqual(r2.missing, false);
  assert.strictEqual(r2.group, 'Default');
});

test('WATCHTOWER_ALLOWLIST=0 stays enforced (fail closed)', () => {
  process.env.WATCHTOWER_ALLOWLIST = '0';
  assert.strictEqual(allowlist.isEnabled(), true);
});

test('OTA ALL allowed only with Exact-GO flag', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  process.env.WATCHTOWER_OTA_ALLOW_ALL = '1';
  const d = allowlist.assertOtaGroup('ALL');
  assert.strictEqual(d, null);
});


test('omit group from override revokes (no DEFAULT_SEED retain)', () => {
  // Simulate production override that only maps Default — Ops-Fleet must NOT fall open
  allowlist.setConfigForTests({
    host_group_to_profiles: { Default: ['UNMAPPED'] },
    ota: { allow_all: false },
    c2: { destructive_actions: [], audit_blocked_actions: ['kill'] },
  });
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const d = allowlist.assertMappedGroup('Ops-Fleet');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_UNMAPPED_GROUP');
  const d2 = allowlist.assertProfileAllowed('Builder-Lab', 'Hermes vets-developer');
  assert.ok(d2);
  assert.strictEqual(d2.rule, 'DENY_UNMAPPED_GROUP');
});

test('path miss fail-closed empty map (no illustrative fall-open)', () => {
  const fs = require('fs');
  const os = require('os');
  const p = path.join(os.tmpdir(), 'watchtower-allowlist-missing-' + process.pid + '.json');
  try { fs.unlinkSync(p); } catch (_) {}
  process.env.WATCHTOWER_ALLOWLIST_PATH = p;
  allowlist.resetForTests();
  const cfg = allowlist.loadConfig(true);
  assert.deepStrictEqual(cfg.host_group_to_profiles, {});
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const d = allowlist.assertMappedGroup('Ops-Fleet');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_UNMAPPED_GROUP');
  delete process.env.WATCHTOWER_ALLOWLIST_PATH;
  allowlist.resetForTests();
});

test('bad profile shape fail-closed (no throw on assert)', () => {
  const fs = require('fs');
  const os = require('os');
  const p = path.join(os.tmpdir(), 'watchtower-allowlist-badshape-' + process.pid + '.json');
  fs.writeFileSync(p, JSON.stringify({ host_group_to_profiles: { 'Ops-Fleet': 'GitHub vets-ops' } }));
  process.env.WATCHTOWER_ALLOWLIST_PATH = p;
  allowlist.resetForTests();
  const cfg = allowlist.loadConfig(true);
  assert.deepStrictEqual(cfg.host_group_to_profiles, {});
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  // Must not throw — deny instead of 500
  const d = allowlist.assertProfileAllowed('Ops-Fleet', 'GitHub vets-ops');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_UNMAPPED_GROUP');
  fs.unlinkSync(p);
  delete process.env.WATCHTOWER_ALLOWLIST_PATH;
  allowlist.resetForTests();
});

test('destructive C2 without purge cap → DENY_PURGE_WITHOUT_CAP', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const groupDB = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false, ENABLE_ROLLBACK: true } };
  const d = allowlist.assertC2Command(
    { action: 'quarantine', target: '/tmp/x', host: 'ops-1' },
    deviceGroups,
    groupDB
  );
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_PURGE_WITHOUT_CAP');
  assert.strictEqual(d.error, 'allowlist_purge_denied');
  assert.strictEqual(d.status, 403);

  const kill = allowlist.assertC2Command(
    { action: 'kill', target: 'pid:9', host: 'ops-1' },
    deviceGroups,
    groupDB
  );
  assert.ok(kill);
  assert.strictEqual(kill.rule, 'DENY_PURGE_WITHOUT_CAP');

  const http = allowlist.assertPurgeCapability('GitHub vets-ops');
  assert.ok(http);
  assert.strictEqual(http.error, 'allowlist_purge_denied');
});

test('explicit purge capability allows destructive C2 and purge', () => {
  allowlist.setConfigForTests({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: {
      destructive_actions: ['kill', 'lock_dir', 'quarantine', 'disable_user'],
      audit_blocked_actions: ['kill'],
    },
    profile_capabilities: { 'GitHub vets-ops': ['purge'] },
  });
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const groupDB = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false, ENABLE_ROLLBACK: true } };
  assert.strictEqual(
    allowlist.assertC2Command(
      { action: 'quarantine', target: '/tmp/x', host: 'ops-1' },
      deviceGroups,
      groupDB
    ),
    null
  );
  assert.strictEqual(allowlist.assertPurgeCapability(), null);
  // Non-destructive action does not require the cap (profile match is enough).
  allowlist.setConfigForTests({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    ota: { allow_all: false },
    c2: { destructive_actions: ['kill', 'quarantine'], audit_blocked_actions: [] },
    profile_capabilities: {},
  });
  assert.strictEqual(
    allowlist.assertC2Command(
      { action: 'refresh', target: 'noop', host: 'ops-1' },
      deviceGroups,
      groupDB
    ),
    null
  );
});

test('purge capability unset profile fails closed', () => {
  delete process.env.WATCHTOWER_OPERATOR_PROFILE_ID;
  const d = allowlist.assertPurgeCapability();
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_PURGE_WITHOUT_CAP');
  assert.strictEqual(d.detail.reason, 'operator_profile_unset');
});

test('non-string C2 action does not throw in assertC2Command', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const deviceGroups = { 'ops-1': 'Ops-Fleet' };
  const groupDB = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false } };
  let d;
  assert.doesNotThrow(() => {
    d = allowlist.assertC2Command(
      { action: { not: 'a string' }, target: '/tmp/x', host: 'ops-1' },
      deviceGroups,
      groupDB
    );
  });
  assert.strictEqual(d, null);
  assert.strictEqual(allowlist.isPurgeOrDestructiveAction(null), false);
  assert.strictEqual(allowlist.isPurgeOrDestructiveAction(1), false);
});

test('bad profile_capabilities shape fail-closed (no throw)', () => {
  const fs = require('fs');
  const os = require('os');
  const p = path.join(os.tmpdir(), 'watchtower-allowlist-badcaps-' + process.pid + '.json');
  fs.writeFileSync(p, JSON.stringify({
    host_group_to_profiles: { 'Ops-Fleet': ['GitHub vets-ops'] },
    profile_capabilities: { 'GitHub vets-ops': 'purge' },
  }));
  process.env.WATCHTOWER_ALLOWLIST_PATH = p;
  allowlist.resetForTests();
  const cfg = allowlist.loadConfig(true);
  assert.deepStrictEqual(cfg.host_group_to_profiles, {});
  assert.deepStrictEqual(cfg.profile_capabilities, {});
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  const d = allowlist.assertPurgeCapability('GitHub vets-ops');
  assert.ok(d);
  assert.strictEqual(d.rule, 'DENY_PURGE_WITHOUT_CAP');
  fs.unlinkSync(p);
  delete process.env.WATCHTOWER_ALLOWLIST_PATH;
  allowlist.resetForTests();
});

console.log(`\n${PASS.length} passed, ${FAIL.length} failed`);
if (FAIL.length) {
  process.exitCode = 1;
}
