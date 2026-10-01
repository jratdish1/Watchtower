/**
 * Watchtower BE Host-Group → profile_id ALLOWLIST ADAPTER
 * Escalation CALL (A) — adapter/bridge only (do NOT rename Host Groups).
 *
 * Paper SoT: WATCHTOWER_BE_ALLOWLIST-20261001.md sha256 da9a84075cf7d249…
 * Base main: ac8cdf2c8d22d51739007edd9a90a8537e13b92a
 *
 * Env:
 *   WATCHTOWER_ALLOWLIST=1|0   feature gate (default ON / fail-closed deny-unmapped)
 *   WATCHTOWER_OPERATOR_PROFILE_ID  optional; when unset → operator has NO mapped
 *                                   profiles → all mapped-group mutates DENY until
 *                                   Escalation binds + sets env (fail-closed)
 *   WATCHTOWER_OTA_ALLOW_ALL=1  Exact-GO override for group=ALL OTA (default off)
 *   WATCHTOWER_ALLOWLIST_PATH   optional path to allowlist.json seed
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ERRORS = {
  DENY_UNMAPPED_GROUP: { status: 403, error: 'allowlist_unmapped_group', rule: 'DENY_UNMAPPED_GROUP' },
  DENY_MISSING_HOST_GROUP: { status: 403, error: 'allowlist_missing_host_group', rule: 'DENY_MISSING_HOST_GROUP' },
  DENY_WRONG_PROFILE: { status: 403, error: 'allowlist_wrong_profile', rule: 'DENY_WRONG_PROFILE' },
  DENY_UNKNOWN_GROUP_NAME: { status: 403, error: 'allowlist_unknown_group', rule: 'DENY_UNKNOWN_GROUP_NAME' },
  DENY_OTA_ALL_DEFAULT: { status: 403, error: 'allowlist_ota_all_forbidden', rule: 'DENY_OTA_ALL_DEFAULT' },
  DENY_C2_ACTION_NOT_ALLOWED: { status: 403, error: 'allowlist_c2_denied', rule: 'DENY_C2_ACTION_NOT_ALLOWED' },
  DENY_CROSS_GROUP_C2: { status: 403, error: 'allowlist_wrong_group', rule: 'DENY_CROSS_GROUP_C2' },
  DENY_REASSIGN_TO_UNMAPPED: { status: 403, error: 'allowlist_reassign_unmapped', rule: 'DENY_REASSIGN_TO_UNMAPPED' },
  DENY_PURGE_WITHOUT_CAP: { status: 403, error: 'allowlist_purge_denied', rule: 'DENY_PURGE_WITHOUT_CAP' },
  DENY_ORPHAN_GROUP_CREATE: { status: 403, error: 'allowlist_orphan_group', rule: 'DENY_ORPHAN_GROUP_CREATE' },
};

const UNMAPPED = 'UNMAPPED';
const DEFAULT_SEED = {
  host_group_to_profiles: {
    Default: [UNMAPPED],
    'Ops-Fleet': ['GitHub vets-ops'],
    'Builder-Lab': ['GitHub vets-builder', 'Hermes vets-developer'],
  },
  ota: { allow_all: false },
  c2: {
    destructive_actions: ['kill', 'lock_dir', 'quarantine', 'disable_user'],
    audit_blocked_actions: ['kill'],
  },
};

let _config = null;

function _envTruthy(name) {
  const v = process.env[name];
  if (v === undefined || v === null || v === '') return null;
  const s = String(v).trim().toLowerCase();
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true;
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false;
  return null;
}

/** Feature enabled by default (prod deny-unmapped ON). Disable with WATCHTOWER_ALLOWLIST=0. */
function isEnabled() {
  const e = _envTruthy('WATCHTOWER_ALLOWLIST');
  if (e === null) return true;
  return e;
}

function loadConfig(forceReload) {
  if (_config && !forceReload) return _config;
  const cfgPath =
    process.env.WATCHTOWER_ALLOWLIST_PATH || path.join(__dirname, 'allowlist.json');
  try {
    if (fs.existsSync(cfgPath)) {
      const raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
      _config = {
        host_group_to_profiles: {
          ...DEFAULT_SEED.host_group_to_profiles,
          ...(raw.host_group_to_profiles || {}),
        },
        ota: { ...DEFAULT_SEED.ota, ...(raw.ota || {}) },
        c2: { ...DEFAULT_SEED.c2, ...(raw.c2 || {}) },
      };
    } else {
      _config = JSON.parse(JSON.stringify(DEFAULT_SEED));
    }
  } catch (e) {
    console.warn('[allowlist] Failed to load seed; using embedded DEFAULT_SEED:', e.message);
    _config = JSON.parse(JSON.stringify(DEFAULT_SEED));
  }
  return _config;
}

/** Test helper: replace in-memory map without touching disk. */
function setConfigForTests(cfg) {
  _config = cfg ? JSON.parse(JSON.stringify(cfg)) : null;
}

function resetForTests() {
  _config = null;
}

function getProfilesForGroup(hostGroup) {
  const cfg = loadConfig();
  if (!hostGroup || !Object.prototype.hasOwnProperty.call(cfg.host_group_to_profiles, hostGroup)) {
    return null;
  }
  return cfg.host_group_to_profiles[hostGroup];
}

function isMappedGroup(hostGroup) {
  const profiles = getProfilesForGroup(hostGroup);
  if (!profiles || profiles.length === 0) return false;
  if (profiles.length === 1 && profiles[0] === UNMAPPED) return false;
  if (profiles.every((p) => p === UNMAPPED)) return false;
  return true;
}

/**
 * Resolve host → Host Group via deviceGroups map.
 * Does NOT invent Default on mutate paths (caller decides enroll vs deny).
 * @returns {{ group: string|null, missing: boolean }}
 */
function resolveHostGroup(host, deviceGroups) {
  if (!host || !deviceGroups || !Object.prototype.hasOwnProperty.call(deviceGroups, host)) {
    return { group: null, missing: true };
  }
  return { group: deviceGroups[host], missing: false };
}

function getOperatorProfileId() {
  const v = process.env.WATCHTOWER_OPERATOR_PROFILE_ID;
  if (v === undefined || v === null || String(v).trim() === '') return null;
  return String(v).trim();
}

function makeDeny(ruleKey, detail) {
  const base = ERRORS[ruleKey];
  if (!base) {
    return { status: 403, error: 'allowlist_denied', rule: ruleKey, detail };
  }
  return { ...base, detail };
}

/** Group absent from map OR maps to UNMAPPED → DENY_UNMAPPED_GROUP */
function assertMappedGroup(hostGroup) {
  if (!hostGroup) {
    return makeDeny('DENY_UNKNOWN_GROUP_NAME', { hostGroup });
  }
  const profiles = getProfilesForGroup(hostGroup);
  if (profiles === null) {
    return makeDeny('DENY_UNMAPPED_GROUP', { hostGroup, reason: 'absent_from_map' });
  }
  if (!isMappedGroup(hostGroup)) {
    return makeDeny('DENY_UNMAPPED_GROUP', { hostGroup, reason: 'maps_to_UNMAPPED' });
  }
  return null;
}

/**
 * Caller profile must be in ALLOWLIST_MAP[host_group].
 * When operator profile unset → no mapped profiles → DENY_WRONG_PROFILE (fail-closed).
 */
function assertProfileAllowed(hostGroup, profileId) {
  const mappedDeny = assertMappedGroup(hostGroup);
  if (mappedDeny) return mappedDeny;
  const profiles = getProfilesForGroup(hostGroup).filter((p) => p !== UNMAPPED);
  const pid = profileId === undefined ? getOperatorProfileId() : profileId;
  if (!pid) {
    return makeDeny('DENY_WRONG_PROFILE', {
      hostGroup,
      reason: 'operator_profile_unset',
      note: 'Set WATCHTOWER_OPERATOR_PROFILE_ID after Escalation bind',
    });
  }
  if (!profiles.includes(pid)) {
    return makeDeny('DENY_WRONG_PROFILE', { hostGroup, profileId: pid, allowed: profiles });
  }
  return null;
}

function assertHostPresent(host, deviceGroups) {
  const { missing } = resolveHostGroup(host, deviceGroups);
  if (missing) {
    return makeDeny('DENY_MISSING_HOST_GROUP', { host });
  }
  return null;
}

function assertHostGroupAllowed(host, deviceGroups, profileId) {
  const miss = assertHostPresent(host, deviceGroups);
  if (miss) return miss;
  const { group } = resolveHostGroup(host, deviceGroups);
  return assertProfileAllowed(group, profileId);
}

function assertOtaGroup(groupName, profileId) {
  if (!groupName) {
    return makeDeny('DENY_UNKNOWN_GROUP_NAME', { hostGroup: groupName });
  }
  if (groupName === 'ALL') {
    const cfg = loadConfig();
    const envAll = _envTruthy('WATCHTOWER_OTA_ALLOW_ALL');
    const allowAll = envAll === true || (envAll === null && cfg.ota && cfg.ota.allow_all === true);
    if (!allowAll) {
      return makeDeny('DENY_OTA_ALL_DEFAULT', { group: 'ALL' });
    }
    // ALL still requires operator profile to be set (no group scope to check)
    const pid = profileId === undefined ? getOperatorProfileId() : profileId;
    if (!pid) {
      return makeDeny('DENY_WRONG_PROFILE', { reason: 'operator_profile_unset_for_ota_all' });
    }
    return null;
  }
  return assertProfileAllowed(groupName, profileId);
}

function assertReassign(host, newGroup, deviceGroups, profileId) {
  const miss = assertHostPresent(host, deviceGroups);
  if (miss) return miss;
  if (!isMappedGroup(newGroup)) {
    // newGroup absent or UNMAPPED
    const profiles = getProfilesForGroup(newGroup);
    if (profiles === null || !isMappedGroup(newGroup)) {
      return makeDeny('DENY_REASSIGN_TO_UNMAPPED', { host, newGroup });
    }
  }
  const { group: currentGroup } = resolveHostGroup(host, deviceGroups);
  const curDeny = assertProfileAllowed(currentGroup, profileId);
  if (curDeny) return curDeny;
  return assertProfileAllowed(newGroup, profileId);
}

/**
 * Policy update for named group (create or update).
 * Unknown/unmapped group → deny (orphan create blocked).
 */
function assertPolicyGroupWrite(group, groupDB, profileId) {
  if (!group) {
    return makeDeny('DENY_UNKNOWN_GROUP_NAME', { hostGroup: group });
  }
  const profiles = getProfilesForGroup(group);
  if (profiles === null) {
    // Not in adapter map → orphan if creating, unmapped if somehow referenced
    if (!groupDB || !Object.prototype.hasOwnProperty.call(groupDB, group)) {
      return makeDeny('DENY_ORPHAN_GROUP_CREATE', { group });
    }
    return makeDeny('DENY_UNMAPPED_GROUP', { hostGroup: group, reason: 'absent_from_map' });
  }
  if (!isMappedGroup(group)) {
    return makeDeny('DENY_UNMAPPED_GROUP', { hostGroup: group, reason: 'maps_to_UNMAPPED' });
  }
  return assertProfileAllowed(group, profileId);
}

function assertC2Command(cmd, deviceGroups, groupDB, profileId) {
  if (!cmd || !cmd.host) {
    return makeDeny('DENY_MISSING_HOST_GROUP', { host: cmd && cmd.host });
  }
  const hostDeny = assertHostGroupAllowed(cmd.host, deviceGroups, profileId);
  if (hostDeny) return hostDeny;

  const { group } = resolveHostGroup(cmd.host, deviceGroups);
  const policy = (groupDB && groupDB[group]) || {};
  const cfg = loadConfig();
  const action = (cmd.action || '').toLowerCase();

  if (policy.WATCHTOWER_AUDIT_MODE === true) {
    const blocked = (cfg.c2 && cfg.c2.audit_blocked_actions) || ['kill'];
    if (blocked.map((a) => String(a).toLowerCase()).includes(action)) {
      return makeDeny('DENY_C2_ACTION_NOT_ALLOWED', {
        action,
        reason: 'WATCHTOWER_AUDIT_MODE',
      });
    }
  }

  // ENABLE_ROLLBACK gate for rollback-class actions
  if (action === 'rollback' && policy.ENABLE_ROLLBACK === false) {
    return makeDeny('DENY_C2_ACTION_NOT_ALLOWED', { action, reason: 'ENABLE_ROLLBACK=false' });
  }

  return null;
}

function sendHttpDeny(res, deny) {
  if (!deny) return false;
  res.status(deny.status || 403).json({
    error: deny.error,
    rule: deny.rule,
    detail: deny.detail || undefined,
  });
  return true;
}

function socketDenyPayload(deny) {
  return {
    ok: false,
    error: deny.error,
    rule: deny.rule,
    detail: deny.detail || undefined,
  };
}

module.exports = {
  ERRORS,
  UNMAPPED,
  isEnabled,
  loadConfig,
  setConfigForTests,
  resetForTests,
  getProfilesForGroup,
  isMappedGroup,
  resolveHostGroup,
  getOperatorProfileId,
  makeDeny,
  assertMappedGroup,
  assertProfileAllowed,
  assertHostPresent,
  assertHostGroupAllowed,
  assertOtaGroup,
  assertReassign,
  assertPolicyGroupWrite,
  assertC2Command,
  sendHttpDeny,
  socketDenyPayload,
};
