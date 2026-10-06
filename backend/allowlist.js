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
 *   WATCHTOWER_ALLOWLIST_PATH   optional override path; missing/bad → fail-closed empty map\n *                               (omit group from file = revoke; no DEFAULT_SEED merge)
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
  // Fail closed: no profile has purge until the file lists it explicitly.
  profile_capabilities: {},
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

/** Fail-closed empty map — omit groups stay denied; no illustrative fall-open. */
function denyAllConfig(reason) {
  return {
    host_group_to_profiles: {},
    ota: { allow_all: false },
    c2: { destructive_actions: [], audit_blocked_actions: [] },
    profile_capabilities: {},
    _loadError: reason || 'deny_all',
  };
}

/**
 * Validate allowlist shapes. Returns {ok, cfg} or {ok:false, reason}.
 * Profiles must be string arrays; C2 lists must be arrays.
 */
function validateAndNormalize(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'root_not_object' };
  }
  const mapIn = raw.host_group_to_profiles;
  if (mapIn === undefined || mapIn === null) {
    // Empty map is valid (deny all groups). Capabilities still parse; bad shape fail-closes.
    const capsResult = normalizeProfileCapabilities(raw.profile_capabilities);
    if (!capsResult.ok) return capsResult;
    return {
      ok: true,
      cfg: {
        host_group_to_profiles: {},
        ota: { allow_all: false, ...(raw.ota && typeof raw.ota === 'object' ? { allow_all: !!raw.ota.allow_all } : {}) },
        c2: {
          destructive_actions: [],
          audit_blocked_actions: [],
          ...(raw.c2 && typeof raw.c2 === 'object' ? {} : {}),
        },
        profile_capabilities: capsResult.profile_capabilities,
      },
    };
  }
  if (typeof mapIn !== 'object' || Array.isArray(mapIn)) {
    return { ok: false, reason: 'host_group_to_profiles_not_object' };
  }
  const host_group_to_profiles = {};
  for (const [group, profiles] of Object.entries(mapIn)) {
    if (!Array.isArray(profiles)) {
      return { ok: false, reason: `profiles_not_array:${group}` };
    }
    if (!profiles.every((p) => typeof p === 'string')) {
      return { ok: false, reason: `profiles_not_strings:${group}` };
    }
    host_group_to_profiles[group] = profiles.slice();
  }
  const otaRaw = raw.ota && typeof raw.ota === 'object' && !Array.isArray(raw.ota) ? raw.ota : {};
  const c2Raw = raw.c2 && typeof raw.c2 === 'object' && !Array.isArray(raw.c2) ? raw.c2 : {};
  if (c2Raw.destructive_actions !== undefined && !Array.isArray(c2Raw.destructive_actions)) {
    return { ok: false, reason: 'c2.destructive_actions_not_array' };
  }
  if (c2Raw.audit_blocked_actions !== undefined && !Array.isArray(c2Raw.audit_blocked_actions)) {
    return { ok: false, reason: 'c2.audit_blocked_actions_not_array' };
  }
  const capsResult = normalizeProfileCapabilities(raw.profile_capabilities);
  if (!capsResult.ok) return capsResult;
  return {
    ok: true,
    cfg: {
      host_group_to_profiles,
      ota: { allow_all: false, ...otaRaw, allow_all: otaRaw.allow_all === true },
      c2: {
        destructive_actions: Array.isArray(c2Raw.destructive_actions)
          ? c2Raw.destructive_actions.slice()
          : DEFAULT_SEED.c2.destructive_actions.slice(),
        audit_blocked_actions: Array.isArray(c2Raw.audit_blocked_actions)
          ? c2Raw.audit_blocked_actions.slice()
          : DEFAULT_SEED.c2.audit_blocked_actions.slice(),
      },
      profile_capabilities: capsResult.profile_capabilities,
    },
  };
}

/**
 * profile_capabilities: { "<profile_id>": ["purge", ...] }
 * Absent → {} (nobody can purge). Bad shape → caller fail-closes the whole file.
 */
function normalizeProfileCapabilities(raw) {
  if (raw === undefined || raw === null) {
    return { ok: true, profile_capabilities: {} };
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'profile_capabilities_not_object' };
  }
  const profile_capabilities = {};
  for (const [profileId, caps] of Object.entries(raw)) {
    if (!Array.isArray(caps) || !caps.every((c) => typeof c === 'string')) {
      return { ok: false, reason: `profile_capabilities_not_string_array:${profileId}` };
    }
    profile_capabilities[profileId] = caps.slice();
  }
  return { ok: true, profile_capabilities };
}

/**
 * Load allowlist.
 * - Bundled allowlist.json (default path, exists): sole source of truth — omit group = revoke
 *   (NO merge with DEFAULT_SEED illustrative entries).
 * - WATCHTOWER_ALLOWLIST_PATH set: must exist + parse + validate; else fail-closed empty map
 *   (NO Ops-Fleet/Builder-Lab fall-open).
 * - No file at default path: embedded DEFAULT_SEED (dev bootstrap only).
 */
function loadConfig(forceReload) {
  if (_config && !forceReload) return _config;
  const explicitPath = process.env.WATCHTOWER_ALLOWLIST_PATH;
  const cfgPath = explicitPath || path.join(__dirname, 'allowlist.json');
  const pathWasExplicit = Boolean(explicitPath && String(explicitPath).trim());

  try {
    if (!fs.existsSync(cfgPath)) {
      if (pathWasExplicit) {
        console.warn('[allowlist] WATCHTOWER_ALLOWLIST_PATH missing — fail-closed empty map:', cfgPath);
        _config = denyAllConfig('path_missing');
        return _config;
      }
      // No bundled file: bootstrap seed only
      _config = JSON.parse(JSON.stringify(DEFAULT_SEED));
      return _config;
    }
    const raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    const validated = validateAndNormalize(raw);
    if (!validated.ok) {
      console.warn('[allowlist] Invalid shape — fail-closed empty map:', validated.reason);
      _config = denyAllConfig(validated.reason);
      return _config;
    }
    // File is sole SoT for host_group_to_profiles — do NOT merge DEFAULT_SEED
    // (omitted Ops-Fleet/Builder-Lab must revoke, not retain).
    _config = validated.cfg;
    return _config;
  } catch (e) {
    console.warn('[allowlist] Load/parse failed — fail-closed empty map:', e.message);
    _config = denyAllConfig('load_parse_error:' + e.message);
    return _config;
  }
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
  if (!Array.isArray(profiles) || profiles.length === 0) return false;
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

/** Explicit allowlist capability. Unset profile or missing list → false (fail closed). */
function profileHasCapability(cap, profileId) {
  const cfg = loadConfig();
  const pid = profileId === undefined ? getOperatorProfileId() : profileId;
  if (!pid || !cap) return false;
  const list = cfg.profile_capabilities && cfg.profile_capabilities[pid];
  if (!Array.isArray(list)) return false;
  const want = String(cap).toLowerCase();
  return list.some((c) => String(c).toLowerCase() === want);
}

/**
 * Purge verbs plus the configured destructive C2 list.
 * Non-strings are not destructive (caller rejects them before execution).
 */
function isPurgeOrDestructiveAction(action) {
  if (typeof action !== 'string' || action.length === 0) return false;
  const a = action.toLowerCase();
  const cfg = loadConfig();
  const list = (cfg.c2 && cfg.c2.destructive_actions) || [];
  if (list.some((x) => String(x).toLowerCase() === a)) return true;
  return a === 'purge' || a.startsWith('purge_') || a === 'wipe' || a === 'destroy' || a === 'clear';
}

/**
 * Paper §5 rule 9. Deny unless this operator profile lists capability "purge".
 * Unset profile denies (fail closed) — does not fall open.
 */
function assertPurgeCapability(profileId) {
  const pid = profileId === undefined ? getOperatorProfileId() : profileId;
  if (!profileHasCapability('purge', pid)) {
    return makeDeny('DENY_PURGE_WITHOUT_CAP', {
      profileId: pid || null,
      reason: pid ? 'purge_capability_absent' : 'operator_profile_unset',
    });
  }
  return null;
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
  const action = typeof cmd.action === 'string' ? cmd.action.toLowerCase() : '';

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

  // §5 rule 9: destructive / purge C2 requires an explicit purge capability.
  if (isPurgeOrDestructiveAction(typeof cmd.action === 'string' ? cmd.action : '')) {
    const purgeDeny = assertPurgeCapability(profileId);
    if (purgeDeny) return purgeDeny;
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
  profileHasCapability,
  isPurgeOrDestructiveAction,
  assertPurgeCapability,
  sendHttpDeny,
  socketDenyPayload,
};
