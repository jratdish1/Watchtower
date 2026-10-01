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

test('feature flag OFF skips enforcement posture (isEnabled false)', () => {
  process.env.WATCHTOWER_ALLOWLIST = '0';
  assert.strictEqual(allowlist.isEnabled(), false);
});

test('OTA ALL allowed only with Exact-GO flag', () => {
  process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
  process.env.WATCHTOWER_OTA_ALLOW_ALL = '1';
  const d = allowlist.assertOtaGroup('ALL');
  assert.strictEqual(d, null);
});

console.log(`\n${PASS.length} passed, ${FAIL.length} failed`);
if (FAIL.length) {
  process.exitCode = 1;
}
