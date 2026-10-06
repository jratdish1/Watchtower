# Step 5 harness run — 2026-10-06

**Stamp:** 2026-10-05 10:56 PM PDT (2026-10-06 05:56:37 UTC). Memory-search auth re-run: 2026-10-05 11:03 PM PDT (2026-10-06 06:03:33 UTC). Operator-key close re-run: 2026-10-05 11:23 PM PDT (2026-10-06 06:23:20 UTC). Cookie and template-key close re-run: 2026-10-05 11:46 PM PDT (2026-10-06 06:46:18 UTC). Data-dir close re-run: 2026-10-06 02:14 AM PDT (2026-10-06 09:14:13 UTC). Beacon and login close re-run: 2026-10-06 02:34 AM PDT (2026-10-06 09:34:17 UTC). Proxy-path close re-run: 2026-10-06 02:47 AM PDT (2026-10-06 09:47:55 UTC). Proxy-forward close re-run: 2026-10-06 03:05 AM PDT (2026-10-06 10:05:21 UTC). Canonical-target close re-run: 2026-10-06 03:24 AM PDT (2026-10-06 10:24:37 UTC).
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
| operator-key auth commit | `9e25b7a1c6596a7ff12b101c032ada6bc882aa84` |
| prior tip (before cookie close) | `113287d3800dbbdcee4deed9895e01dc28a9f995` |
| cookie and template-key commit | `f0cde0ba2804833220c85eadf04f44bac66bf507` |
| prior tip (before data-dir close) | `af3a9aa12de9875f6d1fe13857de609d1bce5754` |
| data-dir commit | `46dc8556fb28d8ca934113423f3faa72dd0e74af` |
| prior tip (before beacon close) | `dd2148ad5c0bc9af4f18bbb52a0882c059cf2c26` |
| beacon and login commit | `cfa58b0896ee012ec506392d1278c408ae16872b` |
| prior tip (before proxy-forward close) | `b12210c600e74eb90d98d6c6bd27724c3034998f` |
| proxy-path commit | `ac8352e0547f0144d35915bd079b6b4d08e8d61c` |
| prior tip (before proxy-forward functional close) | `4437a89348bab276b51e36b66e841ed81ddd9d5e` |
| proxy-forward commit | `410915c0dfc098a0a79f481d2bc8dad7c85de45c` |
| prior tip (before this close) | `465e9678d43ce1ad4d582a2e6f98b420cdb8fd4a` |
| head (canonical-target commit) | `3a271f78f286f75f64d6e994a2384cb879d6f852` |

`head` is `3a271f78f286f75f64d6e994a2384cb879d6f852`, the commit that rejects a request target unless it is already canonical and forwards that same path and query. This line records that id. The pull request description repeats `git rev-parse HEAD` after the final push. A commit object cannot contain its own id.

Working directory for every command: repository root.

## Commands

| Command | Exit | Passed | Failed | Skipped |
|---------|------|--------|--------|---------|
| `node backend/test/allowlist.test.js` | 0 | 19 | 0 | 0 |
| `node backend/test/auth.test.js` | 0 | 165 | 0 | 0 |
| `node backend/test/c2-socket.test.js` | 0 | 17 | 0 | 0 |
| `node frontend/test/xss-static.test.js` | 0 | 11 | 0 | 0 |
| `node frontend/test/csp-headers.test.js` | 0 | 34 | 0 | 0 |
| `node frontend/test/ui-auth.test.js` | 0 | 213 | 0 | 0 |
| `node frontend/test/step5-harness.test.js` | 0 | 62 | 0 | 0 |

Harness line: `STEP5_SUMMARY executed=16 blocked=0 passed=62 failed=0 skipped=0`

Combined checks: **521 passed, 0 failed, 0 skipped.** Auth is 165 (startup refusal, trimmed key length, padded placeholders, example-file key literals, repo-root `./data` from `backend/`, CGNAT, CORS, index 503, allowlist-off purge on a loaded map, auto-remediate host allowlist, beacon command delivered once, policy sync does not enroll, 253-character host cap, reserved host names, OTA signature required before apply, OTA public base, core fail-start, repo data files unchanged). CSP is 34. `ui-auth.test.js` is 213. Step 5 is 62. Allowlist 19, socket 17, XSS 11.

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
| 16 | Offline and paused → mutating controls stay disabled | executed | 13 | 0 | 0 | `[data-mutate="1"]` buttons disable on offline and pause, enable on online and resume. The fake DOM is seeded from real static ids. A missing id stays null. Pause click, mesh keyup (hides a non-matching node), and OTA change (writes the file name) are dispatched |

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

Each item below is fixed in `9e25b7a1c6596a7ff12b101c032ada6bc882aa84`. None are left as documentation-only.

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

At `9e25b7a`, `GET /login` was the only unauthenticated UI page and `GET /` returned 401. Hub client scripts under `core/` still fell back to a public literal when `WATCHTOWER_API_KEY` was unset. Both of those are changed in `f0cde0ba2804833220c85eadf04f44bac66bf507`, recorded below.

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
| `GET /api/v2/c2/beacon` | Queued C2 for a host. Each command id is returned at most once. The host is not enrolled. A name longer than 253 characters is 400. | `authenticate` |
| `POST /api/v2/c2/beacon` | Enrollment path. A new host of at most 253 characters is mapped to Default, then remaining commands are returned and cleared. | `authenticate` |
| `GET /api/v2/policies/sync` | Host group policy. An unknown host receives the Default policy and is not written into `deviceGroupMap`. A name longer than 253 characters is 400. | `authenticate` |
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
- `serve_ui.js` responses: CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `connect-src 'self'`, pinned socket.io script, per-response nonce), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.

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

## Independent review close (tip 113287d NOT_GRADE_A)

Each item below is fixed in `f0cde0ba2804833220c85eadf04f44bac66bf507`. None are left as documentation-only. No 2FA/TOTP and no audit log were added.

| Item | Status | What changed |
|------|--------|----------------|
| P1 malformed cookie crashes the UI | fixed | `readCookieHeader` catches `decodeURIComponent`. A bad cookie is HTTP 400 `{ error: "Bad request" }` with no stack and no path. The WebSocket upgrade writes 400 and destroys the socket. The Express error handler returns a generic JSON body. HTTP and upgrade tests use `wt_session=%E0%A4%A` and confirm the process still serves `/login`. |
| P1 `.env.example` key is accepted | fixed | `generate_a_secure_random_key_here` is a built-in placeholder. Any value equal to a literal in an example or template file is also rejected, on the API and the UI, before the length check. Startup logs the reason and not the key. |
| P2 tests rewrite `data/infrastructure.json` | fixed | `WATCHTOWER_DATA_DIR` selects the data directory. `startApi` points it at a temp directory. The auth test compares the repo `data/` files before and after and does not write them. |
| Origin check on proxied writes | fixed | `POST`/`PUT`/`PATCH`/`DELETE` through the UI proxy require an `Origin` or `Referer` of the request host or `WATCHTOWER_UI_ORIGIN`. A missing origin is 403. |
| Login throttle | fixed | Per-IP backoff starts on the fifth failure (1s, doubling, cap 60s). The next attempt in that window is 429. |
| Logout, expiry, reaping | fixed | `POST /logout` deletes the token and sets `Max-Age=0`. Sessions expire after `WATCHTOWER_UI_SESSION_MS` (default 8h). Login reaps expired sessions and caps the map at 32. |
| Secure cookie | fixed | `WATCHTOWER_UI_COOKIE_SECURE=1` adds `Secure`. `0` forces it off. Otherwise `Secure` follows an `https://` `WATCHTOWER_UI_ORIGIN`. |
| UI proxy default port | fixed | Default `WATCHTOWER_API_PORT` is `3000`, the same as `backend` / `.env.example`. |
| `GET /` when logged out | fixed | No session redirects to `/login` (302). A malformed `wt_session` on `/` also redirects to `/login`. |
| Auto-remediate allowlist | fixed | Ingest calls `assertC2Command` before queueing. An unknown host is not queued. An enrolled host in a mapped group is queued only when the profile has `purge`. |
| Vacuous `ALLOWLIST=0` test | fixed | The test keeps a valid on-disk allowlist with a mapped group and no purge cap. The deny is `DENY_PURGE_WITHOUT_CAP`. The log does not say `fail-closed empty map`. |
| Harness checks that were hard-coded true | fixed | `getElementById` returns null unless the id is in `watchtower.html`. Mesh keyup hides a non-matching `.mesh-node`. OTA change writes the selected file name into the label. |
| Core client public key fallback | fixed | Hub clients call `core/operator_key.py` and exit 1 when the key is unset, empty, a public placeholder, or shorter than 32 characters. `watchtower_beacon.py` without a key exits 1. The AD sensor script does the same. |

`GET /login` remains the operator key form. It contains no key and no fleet data. `GET /` redirects there when the cookie is absent. At `f0cde0b`, any malformed cookie returned 400. `46dc8556fb28d8ca934113423f3faa72dd0e74af` limits that to `wt_session`, recorded below.

## Independent review close (tip af3a9aa NOT_GRADE_A)

Each item below is fixed in `46dc8556fb28d8ca934113423f3faa72dd0e74af`. No 2FA/TOTP and no audit log were added.

| Item | Status | What changed |
|------|--------|----------------|
| P1 `WATCHTOWER_DATA_DIR` follows cwd | fixed | Relative values resolve with `path.resolve(__dirname, '..', value)`. Starting from `backend/` with `./data` uses repo-root `data/` and does not create `backend/data`. Absolute paths, including the test temp dir, stay absolute. |
| WebSocket Origin | fixed | The upgrade path uses the same Origin/Referer check as a proxied write and writes 403 before any 101. Matching, missing, and mismatched origins are covered. The missing-Origin case is `35cb2f054496b112e5ef8738c757bbfc11cb28ee`. |
| Sockets survive logout and expiry | fixed | Open upgrade sockets are tracked per session and destroyed on `POST /logout` and when the session timer fires. |
| `GET /api/v2/c2/beacon` mutates | superseded | `46dc855` stopped GET from enrolling. `cfa58b0` then delivers each command id once, which removes it from the queue. The UI proxy does not forward that route, including case, slash, encoding, and dot-segment variants (`ac8352e`). |
| API error handler always returned 500 | fixed | A 4xx `err.status` or `err.statusCode` is returned as that status with a generic body. Malformed JSON is 400 `{ error: "Bad request" }` and the body has no stack. |
| Unrelated malformed cookies | fixed | A bad cookie other than `wt_session` is ignored. `/login` stays 200. A bad `wt_session` is still 400. |
| Login throttle behind a proxy | fixed | `X-Forwarded-For` is used only when the socket address equals `WATCHTOWER_TRUSTED_PROXY`. Otherwise the socket address is the bucket. |
| OTA zip path in tests | fixed | The upload test sets `WATCHTOWER_UPDATES_DIR` to a temp directory. `backend/updates/update_core.zip` is not written. |
| Public OTA base | fixed | `.env.example` documents `WATCHTOWER_PUBLIC_BASE_URL`. If it is unset, startup warns and upload returns 503. No `127.0.0.1` target is queued. |

At `46dc855`, `GET /api/v2/policies/sync` still enrolled an unknown host, and a beacon that polled with GET saw the same command on every poll. Both are closed in `cfa58b0896ee012ec506392d1278c408ae16872b`, recorded below.

## Independent review close (tip dd2148ad NOT_GRADE_A)

P0 and P1 were 0. The data-dir fix stayed. Each item below is fixed in `cfa58b0896ee012ec506392d1278c408ae16872b`. No 2FA/TOTP and no audit log were added. The `0.0.0.0` bind, OTA signing, and the beacon port were left as they are.

| Item | Status | What changed |
|------|--------|----------------|
| P2 GET beacons re-run queued commands | fixed | Every queued command gets an id. `GET /api/v2/c2/beacon` returns the pending commands and removes them, so a command is delivered at most once per host. It does not enroll. `POST /api/v2/c2/beacon` still enrolls and returns whatever has not already been delivered. The UI proxy answers 403 for `/api/v2/c2/beacon` and `/api/v2/policies/sync`, so a browser session cannot consume the queue. |
| P2 login throttle trusts the leftmost `X-Forwarded-For` hop | fixed | When the socket address equals `WATCHTOWER_TRUSTED_PROXY`, the bucket is the rightmost hop, the one the proxy appended. Otherwise the socket address is the bucket. `loginFailures` drops finished backoff rows and evicts the oldest entry past 64 keys. |
| P2 `GET /api/v2/policies/sync` enrolls unknown hosts | fixed | That GET no longer writes `deviceGroupMap`. Enrollment is `POST /api/v2/c2/beacon` only. Every beacon, sync, and policy-reassign path rejects a host longer than 253 characters with 400, and that name is not stored. |
| P2 malformed `wt_session` on `/login` is 400 | fixed | `GET /login` and `POST /login` treat a malformed `wt_session` as absent. `/watchtower.html` and the WebSocket upgrade still return 400. |
| P2 session timer, cookie, logout, route table | fixed | `WATCHTOWER_UI_SESSION_MS` is clamped to 2147483647 ms before `setTimeout`. The session cookie `Max-Age` is that TTL in seconds (at least 1). `POST /logout` requires a matching Origin and leaves the session in place on 403. The Glass Pane has a Log out control that POSTs `/logout`. This route table matches those handlers. |

The exact-path proxy deny in that table was bypassed by Express path normalization. That bypass, and the items below, are closed in `ac8352e0547f0144d35915bd079b6b4d08e8d61c`.

## Independent review close (tip b12210c NOT_GRADE_A)

P0 was 0. There was one new P1. No 2FA/TOTP and no audit log were added. The `0.0.0.0` bind, the beacon port, and delivery ack were left as they are.

| Item | Status | What changed |
|------|--------|----------------|
| P1 proxy agent-route 403 fails open | fixed | The proxy normalizes the path (one percent-decode, lowercase, collapsed slashes, no dot segments, no trailing slash) and forwards only an allowlist under `/api/v2`: infrastructure, topology, OTA upload, and policy update. Every other `/api/v2` path is 403, including case, trailing-slash, double-slash, percent-encoded, and dot-segment forms. State-changing proxy requests still require a matching Origin. Those probes leave the beacon queue intact. |
| P2 socket `c2_command` accepts internal verbs | fixed | The socket accepts only `quarantine`, `lock_dir`, `kill`, and `disable_user`. `rollback` is not a socket verb. `UPDATE_CORE` and `UPDATE_POLICY` stay on the server OTA and policy paths. `watchtower_beacon.py` refuses to apply an update when the HMAC is missing or does not match the payload. |
| P2 padded placeholder key | fixed | `operatorKeyProblem`, `operator_key.py`, and the AD sensor compare the trimmed value to the placeholder list. A non-placeholder key is stored as given. The socket handshake rejects a token whose trimmed form is a placeholder. |
| P2 failure-map cap evicts active lockouts | fixed | Finished backoff rows are dropped first. Further eviction removes the oldest inactive rows only. An active lock stays when the map is over 64. |
| P2 `GET /` malformed cookie is 400 | fixed | `GET /` redirects to `/login`. Duplicate `wt_session` cookies are kept only when every value is identical; otherwise the session is absent. |
| P2 prototype host names return 500 | fixed | Host maps use `Object.create(null)`. `__proto__`, `constructor`, `prototype`, and `toString` are 400 and are not stored. |

Forwarding the canonical path broke Socket.IO polling. That, and the items below, are closed in `410915c0dfc098a0a79f481d2bc8dad7c85de45c`.

## Independent review close (tip 4437a89 NOT_GRADE_A)

P0 was 0. The prior proxy-bypass P1 stayed fixed. One new P1 came from forwarding the canonical path. No 2FA/TOTP and no audit log were added. The `0.0.0.0` bind, the beacon port, and delivery ack were left as they are.

| Item | Status | What changed |
|------|--------|----------------|
| P1 canonical path is forwarded | fixed | Allow and deny still use the normalized path. The proxy and the WebSocket upgrade forward the original path and query, so `/socket.io/?EIO=4&transport=polling` keeps its trailing slash. A default-transport client polls, upgrades, and receives `sync_state`. `/api/alerts%20` is forwarded encoded and is 404, not 500. Agent-route variants stay 403 and leave the queue intact. |
| P2 upgrade path | fixed | An upgrade is allowed only when the canonical path is `/socket.io` or `/socket.io/…`. Beacon and policy-sync upgrade variants, including case, slash, and dot-segment forms, are 403 and not 101. The raw URL is forwarded when the upgrade is allowed. |
| P2 trimmed key length | fixed | `operatorKeyProblem` measures `key.trim().length`. A 31-character key plus two spaces is refused by Node and by `operator_key.py`. The AD sensor already measures `$ApiKeyTrimmed.Length`. A non-placeholder key is still returned raw. |
| P2 `Origin: null` | fixed | `Origin: null` stays 403 on a state-changing proxy POST. The Glass Pane sets `Referrer-Policy: no-referrer`. A same-origin POST that sends `Origin` and no Referer still succeeds. |
| P2 soft failure-map cap | fixed | When every slot is an active lock, a new address is 429 and no bucket is added. Active lockouts are not evicted. Inactive rows are still dropped first to make room. |
| Review: socket `rollback` | fixed | `rollback` is not in the socket command set. The agents do not execute it, so the socket rejects it and does not queue it. |

Forwarding the original URL after a normalized allow check let a fragment reach an agent route. That, and the items below, are closed in `3a271f78f286f75f64d6e994a2384cb879d6f852`.

## Independent review close (tip 465e9678 NOT_A)

P0 was 0. The trailing-slash forward, the upgrade allow check, `Origin: null`, and case preservation stayed fixed. One new P1 came from checking a normalized path and forwarding a different string. No 2FA/TOTP and no audit log were added. The `0.0.0.0` bind, the beacon port, and delivery ack were left as they are.

| Item | Status | What changed |
|------|--------|----------------|
| P1 fragment allowlist bypass | fixed | The proxy parses the request target once, before Express sees it. A target that contains `#`, does not start with `/`, contains a backslash, NUL, or a control character, or whose path has an encoded slash (`%2f` / `%5c`), an encoded fragment (`%23`), an encoded dot (`%2e`), a raw dot-segment, or a duplicate slash is 400. The allowlist comparison lowercases a copy of that path. The proxy forwards that same path plus the original query, and does not forward `originalUrl`. The WebSocket upgrade uses the same parse. `#`, `%23`, backslash, `%2f`, dot-segment, and double-slash forms of beacon, policy sync, inventory ingest, and threat ingest are 400 on POST and on upgrade. Those probes do not reach the backend, and the beacon queue stays intact. `/socket.io/?EIO=4&transport=polling` still polls, upgrades, and receives `sync_state`. |
| P2 logout redirects when the request fails | fixed | The Log out control assigns `/login` only when the logout response is ok. A failed response or a network error shows "Log out failed" and stays on the page. |
| P2 lockout expiry clears the failure count | fixed | An expired lock keeps its failure count for 15 minutes. The next failure continues the backoff. Active locks are still not evicted, and a full map of active locks still answers 429. |
| P2 `Referrer-Policy: no-referrer` | fixed | The Glass Pane sends `Referrer-Policy: strict-origin-when-cross-origin`. `Origin: null` stays 403 on a state-changing proxy POST, including when `Sec-Fetch-Site` is `same-origin`. A same-origin POST that sends `Origin` and no Referer still succeeds. |
