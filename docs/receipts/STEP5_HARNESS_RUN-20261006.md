# Step 5 harness run — 2026-10-06

**Stamp:** 2026-10-05 10:56 PM PDT (2026-10-06 05:56:37 UTC). Memory-search auth re-run: 2026-10-05 11:03 PM PDT (2026-10-06 06:03:33 UTC). Operator-key close re-run: 2026-10-05 11:23 PM PDT (2026-10-06 06:23:20 UTC).
**Runner:** isolated CI/VM (this workspace). No live hosts.
**Node:** `v22.14.0`
**Paper:** `jratdish1/knowledge-base` `ops/vao-torch/tasks/VAO-TASK-20261002-STEP5-HARNESS-PAPER.md` (blob `0940f85c3d297b3ce9f9744e87795e3075d902ad`). `gh api repos/jratdish1/knowledge-base/contents/...` returned HTTP 404; the file was read through the authenticated contents API. Paper score at plant: 16 specified, 0 executed. This receipt is the run.

**HOLD:** AUTH-01 HOLD · no deploy · no Contabo

## SHAs

| | SHA |
|--|-----|
| base (`main` at branch point) | `383964e7851330ebe3d66ad1eb0fd0371f9b984f` |
| prior tip (before operator-key close) | `8ca0cd8e99bae5d1d9335a02115701279ba00340` |
| memory-search auth commit | `b2198712693630ced6674150aeb60b5819a39a6c` |
| head (operator-key auth commit) | `HEAD_SHA_PLACEHOLDER` |

`head` is `HEAD_SHA_PLACEHOLDER`, the commit that refuses a missing or placeholder operator key and removes that key from the Glass Pane HTML. This line records that id. The pull request description repeats `git rev-parse HEAD` after the final push. A commit object cannot contain its own id.

Working directory for every command: repository root.

## Commands

| Command | Exit | Passed | Failed | Skipped |
|---------|------|--------|--------|---------|
| `node backend/test/allowlist.test.js` | 0 | 19 | 0 | 0 |
| `node backend/test/auth.test.js` | 0 | 70 | 0 | 0 |
| `node backend/test/c2-socket.test.js` | 0 | 11 | 0 | 0 |
| `node frontend/test/xss-static.test.js` | 0 | 11 | 0 | 0 |
| `node frontend/test/csp-headers.test.js` | 0 | 34 | 0 | 0 |
| `node frontend/test/ui-auth.test.js` | 0 | 45 | 0 | 0 |
| `node frontend/test/step5-harness.test.js` | 0 | 61 | 0 | 0 |

Harness line: `STEP5_SUMMARY executed=16 blocked=0 passed=61 failed=0 skipped=0`

Combined checks: **251 passed, 0 failed, 0 skipped.** Auth is 70 (startup refusal, CGNAT, CORS, index 503, allowlist-off purge, auto-remediate). CSP is 34 (session plus distinct nonces). `ui-auth.test.js` is 45. Step 5 is 61. Allowlist 19, socket 11, XSS 11.

## Step 5 matrix (16)

Paper rows are the isolated FE+BE harness. None of them call the VIC Hermes SSH path, live enrollment (AUTH-01), Contabo, or a real fleet host. All 16 executed here. **Blocked: 0.**

| # | Paper case | Status | Pass | Fail | Skip | Evidence |
|---|------------|--------|------|------|------|----------|
| 1 | Unmapped `Default` group → `allowlist_unmapped_group`; FE blocked | executed | 3 | 0 | 0 | `assertMappedGroup('Default')`; HTTP + socket `c2_result` set `conn.blocked` and the toast includes the code |
| 2 | Missing host → `allowlist_missing_host_group`; FE blocked | executed | 2 | 0 | 0 | `assertC2Command` on `ghost-host`; socket deny shape blocks the FE |
| 3 | OTA group `ALL`, flag unset → `allowlist_ota_all_forbidden`; FE blocked | executed | 2 | 0 | 0 | `assertOtaGroup('ALL')`; `handleAllowlistResponse` 403 |
| 4 | Operator profile not in the group map → `allowlist_wrong_profile`; FE blocked | executed | 3 | 0 | 0 | ops profile against `Builder-Lab` host; HTTP + socket |
| 5 | Operator profile unset on a mapped group → fail-closed deny; FE blocked | executed | 2 | 0 | 0 | `DENY_WRONG_PROFILE` / `operator_profile_unset`; FE blocked |
| 6 | Reassign onto unmapped `Default` → `allowlist_reassign_unmapped`; FE blocked | executed | 2 | 0 | 0 | `assertReassign`; HTTP 403 shape |
| 7 | Audit mode `kill` → `allowlist_c2_denied`; FE blocked | executed | 2 | 0 | 0 | `DENY_C2_ACTION_NOT_ALLOWED` before the purge cap; socket |
| 8 | Omit group from override → revoke; no seed fall-open | executed | 2 | 0 | 0 | in-memory map with only `Default`; `Ops-Fleet` and `Builder-Lab` deny |
| 9 | Allowlist path missing → empty map; deny; no illustrative fall-open | executed | 2 | 0 | 0 | missing `WATCHTOWER_ALLOWLIST_PATH`; `DENY_UNMAPPED_GROUP` |
| 10 | Bad profile shape → deny; assertion does not throw | executed | 2 | 0 | 0 | profiles value is a string; load fail-closes; assert returns a deny |
| 11 | Hostile markup in agent/API text fields → text, no executable sink | executed | 7 | 0 | 0 | vm Glass Pane: matrix, stream, mesh, inventory, policy host, topology; raw `<img` / `<script` / `<svg` absent |
| 12 | Partial `escHtml(` wrap → static guard rejects | executed | 3 | 0 | 0 | matching `)` must be the final token; `xss-static.test.js` carries the same rule |
| 13 | Data-built inline `on*` absent; C2 target/host byte-exact | executed | 6 | 0 | 0 | no `on*=` attributes in the HTML; `issueCommand` emits the raw target and host |
| 14 | `escHtml` edges (markup, quotes, empty, numbers) | executed | 4 | 0 | 0 | real `escHtml` from the Glass Pane script |
| 15 | Missing event time → `TIME UNKNOWN` | executed | 7 | 0 | 0 | `formatStamp` null/empty/unparseable; card render; local `c2_result` `{ ok, status, action, target, result }` and the string-`result` shape both toast `C2 OK`, not `C2 FAIL` |
| 16 | Offline and paused → mutating controls stay disabled | executed | 12 | 0 | 0 | `[data-mutate="1"]` buttons disable on offline and pause, enable on online and resume. Click, keyup, and change listeners are retained and dispatched (`fe-pause-btn`, `mesh-search`, `ota-file-input`, `fe-open-ota`) |

**Counts:** executed 16 · blocked 0.

## BLOCKED rows

None. The 16 paper rows are specified as an isolated harness (in-process doubles, no production traffic).

These paths were not required by any row and were not used:

| Path | Missing evidence, if a future row required it |
|------|-----------------------------------------------|
| VIC Hermes SSH | No Hermes host, SSH endpoint, or key material is available in this VM. AUTH-01 HOLD forbids using one. |
| Live enrollment (AUTH-01) | No Exact GO. No enrollment token, no Machine ACK. |
| Contabo | No Contabo host, disk, or credentials. Deploy is out of scope. |
| Real fleet host | No enrolled beacon. C2 against a remote host is not executed; destructive actions are denied or queued in memory only. |

## Independent review close (tip 8ca0cd8 NOT_GRADE_A)

Each item below is fixed in `HEAD_SHA_PLACEHOLDER`. None are left as documentation-only.

| Item | Status | What changed |
|------|--------|----------------|
| P1 fail-open `WATCHTOWER_DEFAULT_KEY` | fixed | `backend/app.js` and `frontend/serve_ui.js` call `requireOperatorKey`. Unset, empty, placeholder (`WATCHTOWER_DEFAULT_KEY`, `YOUR_SECRET_API_KEY_HERE`), or shorter than 32 characters: process exits non-zero. The log names the reason and does not print the key. |
| P1 key in `/watchtower.html` | fixed | The HTML no longer contains a key. `POST /login` checks the key with `keysEqual` and sets an `HttpOnly; SameSite=Strict` session cookie. The Glass Pane, logo, `/api`, and `/socket.io` require that cookie. The UI process holds the key and adds `x-api-key` on the proxy. Default bind is `127.0.0.1`. Another address requires `WATCHTOWER_UI_BIND_ADDRESS`. |
| P2 `ip.includes("100.")` | fixed | `backend/ip_allow.js` allows `100.64.0.0/10` only. `100.1.2.3` and `100.128.0.0` are denied. |
| P2 `WATCHTOWER_ALLOWLIST=0` | fixed | `isEnabled()` stays true. The setting is ignored. Purge, C2, policy, and OTA checks are not wrapped in that flag. |
| P2 `AUTO_REMEDIATE` | fixed | `quarantine` and `disable_user` always count as purge-gated. `queueHostCommand` refuses them without `profile_capabilities`. |
| P2 UI serves its folder | fixed | Explicit files only: `/login`, `/watchtower.html`, `/assets/watchtower_logo.png`. `serve_ui.js` and `package.json` return 404 after login and 401 before it. |
| P2 raw script errors | fixed | Search, OTA, and local C2 failures return a generic error. Details stay in the server log. |
| P2 missing `core/search_vector_index.py` | fixed | Authenticated `GET /api/memory/search?q=` returns 503 `{ error: 'index unavailable' }`. No stub was added. Missing or invalid key is still 401. |
| P2 CORS `*` | fixed | HTTP and socket.io allow only `WATCHTOWER_UI_ORIGIN`, default `http://127.0.0.1:8080`. |
| P2 `/updates` before the IP allowlist | fixed | `/updates` and `/assets` are mounted after `ipAllowed`. `trust proxy` is false, so the socket address is the one checked. |
| P2 local C2 success renders `C2 FAIL` | fixed | Local success emits `{ ok: true, status: 'ok', action, target, result }`. The Glass Pane treats that envelope, and a string `result` with no error, as `C2 OK`. Listeners stay registered in the harness. |
| P2 distinct nonces | fixed | `csp-headers.test.js` compares two authenticated responses. |

`GET /login` is the only unauthenticated UI page. It is the operator key form. It contains no key and no fleet data. Everything else on the UI returns 401 without the session cookie.

Client scripts under `core/` still default their own outbound key to the public literal when `WATCHTOWER_API_KEY` is unset. Those processes are not the API or the UI. The API now refuses that literal, so the fallback cannot authenticate. They were not changed in this pass.

## Fleet-data GET and WebSocket auth

Audit of `backend/app.js` after the memory-search close. Operator check is `keysEqual` (`crypto.timingSafeEqual`). Missing or invalid key: HTTP 401, or WebSocket `Authentication error`.

### Closed in this change

| Route | Was | Now |
|-------|-----|-----|
| `GET /api/memory/search` | `authenticate` skipped every GET on this path, then ran the cognitive search | Same operator key. Missing, wrong, and prefix keys → 401. Valid key with no `q` → 400 (handler reached, no search). |

### Already gated (fleet data, no change this pass)

| Route | Fleet data | Gate |
|-------|------------|------|
| `GET /api/alerts` | Alert store | `authenticate` |
| `GET /api/agents` | Agent list | `authenticate` |
| `GET /api/v2/topology` | Topology rows | `authenticate` |
| `GET /api/v2/c2/beacon` | Queued C2 for a host | `authenticate` |
| `GET /api/v2/policies/sync` | Host group policy | `authenticate` |
| WebSocket `/socket.io/` | `sync_state` sends alerts, threats, assets, inventory, groups, deviceGroups. Later events (`c2_command`, inventory, threats) ride the same connection | `io.use` + `keysEqual` before `connection`. Invalid key does not connect (`c2-socket.test.js`) |

No other unauthenticated GET or WebSocket route returns fleet data.

### Inspected and left open (not fleet data)

| Route | Returns | Why it stays open |
|-------|---------|-------------------|
| `GET /api/v1/heartbeat` | `{ status: 'ok', timestamp }` | Liveness only. Test asserts it has no alerts or agents. It is behind the IP allowlist. |
| `GET /assets/*` on the API | Brand images | Not fleet records. Now behind the IP allowlist. The Glass Pane logo is a separate UI route and requires the session cookie. |
| `GET /updates/*` | Static update blobs under `backend/updates` | Not a host, alert, inventory, or policy listing. Now behind the IP allowlist. |

## What else this run covers

Not paper rows. Same VM, same node, exit 0:

- `GET /api/alerts`, `GET /api/agents`, and `GET /api/memory/search`: missing, wrong, and prefix keys return 401. Alerts and agents with the test key return 200. Memory search with that key and no `q` returns 400. With `q` and no index script, the response is 503 `index unavailable` and has no script output. Compare is `crypto.timingSafeEqual` over equal-length buffers (`backend/auth.js`). The server does not start when the key is unset, empty, a built-in placeholder, or shorter than 32 characters.
- `DELETE /api/v2/infrastructure` and `DELETE /api/v2/topology`: 403 `allowlist_purge_denied` / `DENY_PURGE_WITHOUT_CAP` without the purge capability (files left in place); 200 when the operator profile lists `purge`.
- Socket `c2_command`: non-string `action`, null command, and array action emit `invalid_c2_action` and the process stays up. `quarantine` without the cap emits `allowlist_purge_denied`.
- `serve_ui.js` responses: CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `connect-src 'self'`, pinned socket.io script, per-response nonce), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

## CSP allowances (unavoidable)

- `style-src-attr 'unsafe-inline'`: the Glass Pane still uses `style=""` attributes. A nonce does not apply to attributes; moving them would rebuild the UI.
- `style-src 'unsafe-inline'`: fallback for user agents that ignore `style-src-elem` / `style-src-attr`. Browsers that implement those directives take the nonce on `<style>` (`style-src-elem` has no `'unsafe-inline'`) and the attribute directive for `style=""`.
- `script-src` has no `'unsafe-inline'`. The inline program and the style block get a per-response nonce. Static controls are bound from that script; the HTML has no `on*=` attributes.
- `https://cdn.socket.io/4.7.4/socket.io.min.js` is the script tag already on the page.
- `connect-src 'self'`: same-origin `/api` and socket.io (`window.location.origin`). The `Host` header is not copied into the policy.
- `https://fonts.googleapis.com` and `https://fonts.gstatic.com`: the existing Inter / Fira Code stylesheet.

## Secrets / bidi

No live key, token, or credential is printed. Tests use a 35-character placeholder that is not a built-in literal and is not written in this receipt. Hidden/bidi Unicode scan of source: 0 hits. `watchtower.html` no longer contains `YOUR_SECRET_API_KEY_HERE`. `serve_ui.js` does not substitute a key into HTML.

AUTH-01 HOLD · no deploy · no Contabo.
