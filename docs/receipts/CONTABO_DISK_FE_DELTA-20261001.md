# CONTABO DISK FE DELTA — 2026-10-01 (PR0 + tip-bump)

**Stamp:** 2026-10-01 ~2:11 PM PT  
**Authority:** Escalation Exact GO — Contabo disk = FE baseline; Bugbot NOT_A tip-bump (P0-1 + P1-1)  
**HOLD:** AUTH-01/M1 live enroll · secret dumps · Contabo mutate · deploy

## What this PR does
1. **PR0:** Overlay Contabo disk `watchtower.html` as FE baseline (nginx/proxy `API_PORT=443`).
2. **Tip-bump (Bugbot NOT_A / IR FIX_LIST):** Surgical **parse-clean** delta on that baseline — **no Contabo live mutate**.
   - **P0-1** Fix socket.io `SyntaxError` (broken `io(...)` / dangling `auth:`) → single valid `io(origin,{path,auth})`.
   - **P1-1** Restore truncated `#ota-modal` markup from upstream @ `16ea815c…` so OTA JS IDs resolve (group select / file / deploy btn).
`frontend/serve_ui.js` unchanged (disk ↔ upstream identical).

## Hashes
| Artifact | sha256 | bytes |
|----------|--------|------:|
| Contabo disk baseline (pre tip-bump) | `cb019399943724a1d9bcc7c11cc8399d8986c265fa099807a6f8911e4acc5971` | 53372 |
| **This tip `frontend/watchtower.html`** | `8edb9c2471aa33485c768c4a62b78a265df41fc2ec56645b0f93b41adb247e6c` | 55252 |
| Upstream `frontend/watchtower.html` @ `16ea815c…` | `f409812d2fbd27a86f573928464d4d54bc0641fc79b902351a88b94d5b696be7` | 55601 |
| Disk + upstream `serve_ui.js` | `96e0fc1c6ae628b045f12f4d5ac3b04d84f4fb6304756ac3b248584cc1a81c77` | 828 |

## Structural deltas (`watchtower.html`) — sanitized
| Topic | Contabo disk baseline | This tip (parse-clean) | Upstream @ 16ea815c |
|-------|----------------------|------------------------|---------------------|
| `API_PORT` | `"443"` nginx/proxy | same | `'4040'` direct |
| Socket | **BROKEN** (SyntaxError L425-427) | `io(origin,{path:"/socket.io/",auth:{token:placeholder}})` | host:4040 style |
| OTA modal | truncated hollow header | restored from upstream pin | full modal |
| API key placeholder | `YOUR_SECRET_API_KEY_HERE` only | same | same |

## Secrets policy
- Scanned before commit: no `ghp_` / live keys.
- Placeholder `YOUR_SECRET_API_KEY_HERE` retained for `serve_ui` inject.
- Tip-bump is **paper/code only** — Contabo disk left untouched (AUTH-01 HOLD).

## Paper / SoT cites
- Bugbot letter: `/workspace/receipts/BUGBOT_A_WT1_21fd5a78_20261001-140945-0700.md` (NOT_A tip `21fd5a78…`)
- Diff paper: `WATCHTOWER_DISK_VS_UPSTREAM-20261001.md` (box)
- Blueprint: `VAO_MASTER_ARCHITECTURAL_BLUEPRINT-20261001.md` sha `7063eedc…`
- Upstream pin: `docs/receipts/UPSTREAM_PIN-16ea815c.md`

Semper Fi.
