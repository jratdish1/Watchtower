'use strict';
// A27: one bind-address and listen-error rule for every Watchtower HTTP listener (backend/app.js, frontend/serve_ui.js).
// Loopback by default, exactly one IP literal, never every interface, never a hostname.
// "Every interface" is decided on the parsed 16 address bytes, never on the spelling: a text check let
// ::ffff:0:0, 0:0:0:0:0:ffff:0:0, ::ffff:0000:0000, ::FFFF:0:0 (IPv4 wildcard) and ::%lo (IPv6 wildcard + zone)
// through, and wrongly refused real addresses such as 64:ff9b::0.0.0.0. Unparseable input is refused (fail closed).
// start.sh keeps a quick shell pre-check; this module is the authority.
const net = require('net');

const DEFAULT_BIND = '127.0.0.1';

function ipBytes(v) {
    const s = String(v).split('%')[0]; // an IPv6 zone index (fe80::1%en0) does not change which address it is
    if (net.isIPv4(s)) return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...s.split('.').map(Number)];
    if (!net.isIPv6(s)) return null;
    let t = s;
    const m = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(t); // embedded IPv4 tail -> two hex groups
    if (m) t = m[1] + ((+m[2] << 8) | +m[3]).toString(16) + ':' + ((+m[4] << 8) | +m[5]).toString(16);
    const parts = t.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    const groups = [...left, ...Array(parts.length > 1 ? 8 - left.length - right.length : 0).fill('0'), ...right];
    const h = groups.map((g) => parseInt(g, 16));
    if (h.length !== 8 || h.some((x) => !(x >= 0 && x <= 0xffff))) return null;
    return h.flatMap((x) => [x >> 8, x & 0xff]);
}

function isEveryInterface(v) {
    const b = ipBytes(v);
    if (!b) return true; // cannot prove it is one interface -> treat as every interface (fail closed)
    const zeroTail = b.slice(12).every((x) => x === 0);
    const v4Mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
    return b.every((x) => x === 0) || (v4Mapped && zeroTail);
}

// Returns { ok: true, address } or { ok: false, address } (address = trimmed input or the default).
function checkBindAddress(raw) {
    const address = (raw === undefined || raw === null || String(raw).trim() === '') ? DEFAULT_BIND : String(raw).trim();
    const ok = net.isIP(address) !== 0 && !isEveryInterface(address);
    return { ok, address };
}

// For startup: returns the address, or prints one [FATAL] line and exits 1 (a service manager sees a failure).
function requireBindAddress(raw, name = 'bind address') {
    const r = checkBindAddress(raw);
    if (!r.ok) {
        console.error(`[FATAL] ${name} must be one IP address, not every interface or a hostname (got ${JSON.stringify(r.address.slice(0, 40))}).`);
        process.exit(1);
    }
    return r.address;
}

// IPv6 literals need brackets in a URL: http://[::1]:3000, not http://::1:3000.
// A zone index is written %25<zone> inside a URL (RFC 6874): http://[fe80::1%25en0]:3000.
function urlHost(address) {
    const a = String(address);
    return a.includes(':') ? `[${a.replace('%', '%25')}]` : a;
}

// HTTP Host header for a proxied request: brackets for IPv6, never a zone index (RFC 9110 / RFC 6874).
function hostHeader(host, port) {
    return `${urlHost(String(host).split('%')[0])}:${port}`;
}

// Where the UI proxy reaches the API. The API and the UI run on the same host (start.sh), so the default is the
// address the API binds: a fleet hub that binds the API to its Tailscale IP keeps a working UI proxy without a
// second setting. WATCHTOWER_API_HOST overrides (hostname allowed: it is a destination, not a listener).
// Brackets around an IPv6 literal are removed (http.request wants the bare address).
function apiTargetHost(env) {
    const e = env || {};
    const explicit = e.WATCHTOWER_API_HOST === undefined || e.WATCHTOWER_API_HOST === null ? '' : String(e.WATCHTOWER_API_HOST).trim();
    if (explicit) return explicit.replace(/^\[(.*)\]$/, '$1');
    const bind = checkBindAddress(e.WATCHTOWER_BIND_ADDRESS);
    return bind.ok ? bind.address : DEFAULT_BIND;
}

// A busy port at boot is often transient (the previous process is still exiting), so retry it a bounded number
// of times, then fail loud. Every other listen error (address not on this host, no IPv6, permission) is fatal
// at once. One [FATAL] line and exit 1 either way, so a service manager sees a failure and never a silent loop.
const LISTEN_RETRY_DELAY_MS = 3000;
const LISTEN_RETRY_DEFAULT = 20; // about one minute

function listenRetryMax(raw) {
    const s = raw === undefined || raw === null ? '' : String(raw).trim();
    if (!/^\d{1,4}$/.test(s)) return LISTEN_RETRY_DEFAULT;
    const n = Number(s);
    return n >= 0 && n <= 1000 ? n : LISTEN_RETRY_DEFAULT;
}

// Attach the listen-error policy to a server. The caller keeps its own server.listen(port, address, cb):
// Node registers cb as a once('listening') handler, so it fires on the retry that succeeds.
function handleListenErrors(server, port, address, label, env) {
    const max = listenRetryMax((env || process.env).WATCHTOWER_LISTEN_RETRY_MAX);
    let attempts = 0;
    server.on('error', (e) => {
        if (e && e.code === 'EADDRINUSE' && attempts < max) {
            attempts++;
            console.error(`[WARN] ${label}: Port ${port} is occupied. Retry ${attempts}/${max} in ${LISTEN_RETRY_DELAY_MS / 1000} seconds...`);
            setTimeout(() => server.listen(port, address), LISTEN_RETRY_DELAY_MS);
            return;
        }
        const why = (e && (e.code || e.message)) || 'unknown error';
        // After a successful bind an 'error' is a runtime server failure (for example EMFILE), not a listen failure.
        const what = server.listening ? 'server error on' : 'cannot listen on';
        console.error(`[FATAL] ${label} ${what} ${urlHost(address)}:${port}: ${why}`);
        process.exit(1);
    });
}

module.exports = {
    DEFAULT_BIND, ipBytes, isEveryInterface, checkBindAddress, requireBindAddress, urlHost, hostHeader,
    apiTargetHost, listenRetryMax, handleListenErrors, LISTEN_RETRY_DELAY_MS, LISTEN_RETRY_DEFAULT,
};
