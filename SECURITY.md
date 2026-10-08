# Security Policy

## Supported Versions
We currently support and offer security patches exclusively for the v1.6.9 branch natively.

| Version | Supported          |
| ------- | ------------------ |
| >= 5.0.0| :white_check_mark: |
| < 5.0.0 | :x:                |

## Reporting a Vulnerability

Watchtower is a Sovereign Enterprise-Grade Network Detection & Response tool. If you discover a security vulnerability, an authentication bypass, or a structural architecture flaw within the Hub parsing or Agent Supervisor payload delivery mechanisms:

**DO NOT POST IT PUBLICLY TO GITHUB ISSUES OR PULL REQUESTS.**

Please email **watchtowerprotocol@proton.me** directly. We will validate the payload against a local v1.6.9 simulation mesh natively, issue a patch, and formally credit your discovery.

You should receive a response back indicating triage acceptance within 48 hours natively.

## Glass Pane UI settings

These environment variables change how the Glass Pane UI (`frontend/serve_ui.js`) protects the operator session.

| Variable | Effect |
|---|---|
| `WATCHTOWER_UI_COOKIE_SECURE=1` (or `true`) | Always add `Secure` to the `wt_session` cookie. |
| `WATCHTOWER_UI_COOKIE_SECURE=0` (or `false`) | **Opt-out.** Never add `Secure`. Use only for a plain-HTTP UI bound to loopback or a lab network. |
| unset | `Secure` is added only when `WATCHTOWER_UI_ORIGIN` starts with `https://`. |

`WATCHTOWER_UI_COOKIE_SECURE=0` is an intentional opt-out, not a bug. Without `Secure`, a browser will send the session cookie over plain HTTP, where it can be read on the network. At startup the UI logs a `NOTICE` when the opt-out is set, and a `WARNING` when it overrides an `https://` origin. The log line never contains the operator key.

### Request paths

The UI proxy accepts one spelling per path. A `%` must start a valid `%XX` escape, and an escape may not encode a letter, digit, `-`, `.`, `_` or `~` (for example `/api/%61gents`). Those requests get `403 Forbidden`. Escapes for other characters, such as `%20`, are forwarded unchanged. Query strings are not checked.

### C2 action names

The backend allowlist matches C2 action names without regard to case or surrounding spaces, so `KILL` is treated as `kill` for the purge-capability, audit-mode and rollback checks. Host Group and profile names are matched exactly; a differently cased name is unmapped and denied.
