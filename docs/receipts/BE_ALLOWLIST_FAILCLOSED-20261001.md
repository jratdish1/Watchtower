# BE ALLOWLIST FAIL-CLOSED FIX — 2026-10-01

**Authority:** Escalation Exact GO FIX PR (IR NOT_GRADE_A FIX_LIST P1×3 post WT#2 merge)  
**Base:** main `56b57f4c300a9fce3c7d5c4a0c30ddcfb640aca6`  
**Paper:** `da9a8407…`  
**HOLD:** AUTH-01 · Contabo deploy · secret dumps

## Fixes
1. **Omit = revoke:** loaded file is sole SoT for `host_group_to_profiles` — no merge with DEFAULT_SEED illustrative Ops-Fleet/Builder-Lab.
2. **Path/parse miss:** `WATCHTOWER_ALLOWLIST_PATH` missing or unreadable → fail-closed **empty map** (not DEFAULT_SEED fall-open).
3. **Shape validation:** profiles must be string arrays; bad C2 lists rejected → deny-all path (no throw → 500/socket crash).

## Tests
`node backend/test/allowlist.test.js` → 14 passed (adds omit-revoke, path-miss, bad-shape).

Semper Fi.
