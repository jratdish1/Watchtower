# BE ALLOWLIST ADAPTER — CODE PR1 Receipt

**Stamp:** 2026-10-01 ~2:20 PM PT (Builder Fleet Ops executor)  
**Branch:** `builder/be-allowlist-adapter-20261001`  
**Base main:** `ac8cdf2c8d22d51739007edd9a90a8537e13b92a` (PR0 Contabo disk FE merge)  
**Paper SoT:** `/workspace/builder-receipts/WATCHTOWER_BE_ALLOWLIST-20261001.md`  
**Paper sha256:** `da9a84075cf7d249667e1d27a99ff8954c558e15390b84dda6c3547218f0dd22`  
**Escalation:** CALL (A) ADAPTER/BRIDGE — Host Groups remain native names; adapter maps → `profile_id[]` only.

---

## Dual SoT cites

| Layer | Cite |
|-------|------|
| Paper allowlist matrix | `WATCHTOWER_BE_ALLOWLIST-20261001.md` sha `da9a8407…` |
| Code base | `main` @ `ac8cdf2c…` (PR#1 tip was `13ae7768…`; FE tip sha `8edb9c24…`) |
| FE disk baseline (reference; not patched here) | Contabo `watchtower.html` `cb019399…` |

---

## What landed

1. **`backend/allowlist.js`** — Host Group → `profile_id[]` adapter module:
   - `resolveHostGroup`, `assertMappedGroup`, `assertProfileAllowed`
   - Deny helpers with stable §5 codes: `DENY_UNMAPPED_GROUP`, `DENY_MISSING_HOST_GROUP`, `DENY_WRONG_PROFILE`, `DENY_OTA_ALL_DEFAULT`, `DENY_C2_ACTION_NOT_ALLOWED`, `DENY_REASSIGN_TO_UNMAPPED` (+ orphan/unknown/audit)
2. **`backend/allowlist.json`** — paper §3 seed only:
   - `Default` → `UNMAPPED`
   - Illustrative: `Ops-Fleet` → `GitHub vets-ops`; `Builder-Lab` → `GitHub vets-builder`, `Hermes vets-developer`
   - **No** live Hermes/GitHub production binds invented
3. **`backend/app.js` wiring** (fail-closed when `WATCHTOWER_ALLOWLIST` enabled; **default ON**):
   - `POST /api/v2/policies/update` — group policy + host reassign
   - `POST /api/v2/ota/upload` — deny `group=ALL` by default
   - socket `c2_command` — host-scoped deny for unmapped/missing/wrong-profile/audit kill
4. **Operator profile (shared-key era):** `WATCHTOWER_OPERATOR_PROFILE_ID` optional. When **unset**, operator has **no** mapped profiles → mapped-group mutates **DENY** until Escalation binds + sets env.
5. **Unit tests:** `backend/test/allowlist.test.js` (node harness; no live keys).

---

## HOLD (honored)

- AUTH-01 / M1 live enroll **HOLD**
- NO Contabo mutate / deploy / DNS / secret dumps / PAT scrub
- NO Host Group rename to `profile_id`
- **FE `savePolicy` bug NOT patched** this PR (paper §6 slice “do not patch”; code acceptance #7 deferred to FE follow-up PR — document below)

---

## FE follow-up (OPEN — not this PR)

Disk FE / upstream: `onclick="savePolicy()"` but only `savePolicyConfig()` defined → Deploy Policy / Create Group UI path dead until alias or rename.  
**Prefer BE-only this PR.** Suggested later FE one-liner (disk-true base `cb019399…`):

```js
function savePolicy(){ return savePolicyConfig.apply(this, arguments); }
```

Also OPEN: Contabo BE `app.js` disk hash vs upstream (paper §7) — **OPEN**.

---

## Env (prod default deny-unmapped ON)

| Var | Default | Meaning |
|-----|---------|---------|
| `WATCHTOWER_ALLOWLIST` | ON (`1`; unset ⇒ enabled) | Feature gate; `0` disables |
| `WATCHTOWER_OPERATOR_PROFILE_ID` | unset | Fail-closed until Escalation bind |
| `WATCHTOWER_OTA_ALLOW_ALL` | `0` | Exact-GO for OTA `ALL` |
| `WATCHTOWER_ALLOWLIST_PATH` | `backend/allowlist.json` | Seed override |

---

## Test command

```bash
node backend/test/allowlist.test.js
```

---

## Non-actions

- Did not squash/merge, Contabo SSH, force-push main, invent live secrets
- Did not patch FE `savePolicy` / socket syntax
- Did not bind live production profiles beyond paper §3 examples

Semper Fi.
