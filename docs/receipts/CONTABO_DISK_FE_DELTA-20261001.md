# CONTABO DISK FE DELTA — 2026-10-01 (PR0)

**Stamp:** 2026-10-01 ~2:06 PM PT  
**Authority:** Escalation Exact GO — Contabo disk = FE baseline  
**HOLD:** AUTH-01/M1 live enroll · secret dumps · Contabo mutate · deploy

## What this PR does
Replace `frontend/watchtower.html` with Contabo disk bytes (production FE baseline).  
`frontend/serve_ui.js` left unchanged (already identical disk ↔ upstream).

## Hashes
| Artifact | sha256 | bytes |
|----------|--------|------:|
| Contabo disk / PR `frontend/watchtower.html` | `cb019399943724a1d9bcc7c11cc8399d8986c265fa099807a6f8911e4acc5971` | 53372 |
| Upstream `frontend/watchtower.html` @ `16ea815c…` | `f409812d2fbd27a86f573928464d4d54bc0641fc79b902351a88b94d5b696be7` | 55601 |
| Disk + upstream `serve_ui.js` | `96e0fc1c6ae628b045f12f4d5ac3b04d84f4fb6304756ac3b248584cc1a81c77` | 828 |

## Structural deltas (`watchtower.html`) — sanitized
| Topic | Contabo disk (baseline / this PR) | Upstream @ 16ea815c |
|-------|-----------------------------------|---------------------|
| `API_PORT` | `"443"` — proxied through nginx | `'4040'` direct host:port |
| Socket / fetch host | prefer origin/proxy style | `hostname:API_PORT` (4040) |
| API key placeholder | `YOUR_SECRET_API_KEY_HERE` only (no live keys) | same placeholder |

## Secrets policy
- Scanned before commit: no `ghp_` / live keys.
- Placeholder `YOUR_SECRET_API_KEY_HERE` retained for `serve_ui` inject.

## Paper / SoT cites
- Diff paper: `WATCHTOWER_DISK_VS_UPSTREAM-20261001.md` (box)
- Blueprint: `VAO_MASTER_ARCHITECTURAL_BLUEPRINT-20261001.md` sha `7063eedc…`
- Upstream pin: `docs/receipts/UPSTREAM_PIN-16ea815c.md`

Semper Fi.
