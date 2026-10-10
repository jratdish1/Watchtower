const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { securityHeaders } = require('./security_headers');
const { keysEqual, requireOperatorKey } = require('../backend/auth');
const { requireBindAddress, urlHost, hostHeader, apiTargetHost, handleListenErrors } = require('../backend/bind_address');

const app = express();
const port = process.env.WATCHTOWER_UI_PORT || 8080;
// A27: same rule as the API (one shared module): loopback by default, one IP, never every interface.
const bindAddress = requireBindAddress(process.env.WATCHTOWER_UI_BIND_ADDRESS, 'WATCHTOWER_UI_BIND_ADDRESS');
const apiKey = requireOperatorKey(process.env.WATCHTOWER_API_KEY);
const apiPort = process.env.WATCHTOWER_API_PORT || '3000';
// A27: default to the address the API binds (same host), so a hub that binds the API to its Tailscale IP
// keeps a working proxy. WATCHTOWER_API_HOST overrides.
const apiHost = apiTargetHost(process.env);

const sessions = new Map();
const sessionSockets = new Map();
const sessionTimers = new Map();
const MAX_TIMEOUT_MS = 2147483647;
const REQUESTED_SESSION_MS = Number(process.env.WATCHTOWER_UI_SESSION_MS);
const SESSION_MS = REQUESTED_SESSION_MS > 0
    ? Math.min(REQUESTED_SESSION_MS, MAX_TIMEOUT_MS)
    : 8 * 60 * 60 * 1000;
const MAX_SESSIONS = 32;
function loginFailureCap() {
    const raw = Number(process.env.WATCHTOWER_UI_LOGIN_FAILURE_CAP);
    if (!Number.isInteger(raw) || raw < 1) return 64;
    return Math.min(raw, 64);
}
const LOGIN_FAILURE_CAP = loginFailureCap();
const LOGIN_HISTORY_MS = 15 * 60 * 1000;
const LOGO_PATH = path.join(__dirname, '../assets/watchtower_logo.png');
const loginFailures = new Map();

function applySecurityHeaders(res, nonce) {
    const headers = securityHeaders(nonce);
    for (const [name, value] of Object.entries(headers)) {
        res.setHeader(name, value);
    }
}

// IR P3-3 (Watchtower #6): WATCHTOWER_UI_COOKIE_SECURE=0 (or false) is an
// intentional opt-out that drops the Secure flag. It exists for plain-HTTP
// loopback or lab use only. See SECURITY.md "Glass Pane UI settings".
function cookieSecure() {
    const flag = process.env.WATCHTOWER_UI_COOKIE_SECURE;
    if (flag === '1' || flag === 'true') return true;
    if (flag === '0' || flag === 'false') return false;
    const origin = process.env.WATCHTOWER_UI_ORIGIN || '';
    return origin.startsWith('https://');
}

function cookieSecureOptOutWarning() {
    const flag = process.env.WATCHTOWER_UI_COOKIE_SECURE;
    if (flag !== '0' && flag !== 'false') return null;
    const origin = process.env.WATCHTOWER_UI_ORIGIN || '';
    if (origin.startsWith('https://')) {
        return '[Watchtower V2 Glass Pane] WARNING: WATCHTOWER_UI_COOKIE_SECURE=' + flag
            + ' overrides an https:// WATCHTOWER_UI_ORIGIN. The session cookie will not carry Secure.';
    }
    return '[Watchtower V2 Glass Pane] NOTICE: WATCHTOWER_UI_COOKIE_SECURE=' + flag
        + ' is set. The session cookie will not carry Secure (intended for plain-HTTP loopback only).';
}

function sessionCookie(token) {
    const secure = cookieSecure() ? '; Secure' : '';
    if (!token) return 'wt_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + secure;
    const maxAge = Math.max(1, Math.floor(SESSION_MS / 1000));
    return 'wt_session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + maxAge + secure;
}

function readCookieHeader(header) {
    const cookies = {};
    const sessions = [];
    let malformed = false;
    String(header || '').split(';').forEach((part) => {
        const i = part.indexOf('=');
        if (i === -1) return;
        const name = part.slice(0, i).trim();
        const value = part.slice(i + 1).trim();
        if (!name) return;
        if (name === 'wt_session') {
            try {
                sessions.push(decodeURIComponent(value));
            } catch (_) {
                malformed = true;
            }
            return;
        }
        try {
            cookies[name] = decodeURIComponent(value);
        } catch (_) {}
    });
    if (!malformed && sessions.length && sessions.every((value) => value === sessions[0])) {
        cookies.wt_session = sessions[0];
    }
    return { cookies, malformed };
}

function cookiesOf(req) {
    if (!req._cookieParse) req._cookieParse = readCookieHeader(req.headers.cookie);
    return req._cookieParse;
}

function closeSessionSockets(token) {
    const sockets = sessionSockets.get(token);
    if (!sockets) return;
    sessionSockets.delete(token);
    for (const sock of sockets) {
        try { sock.destroy(); } catch (_) {}
    }
}

function destroySession(token) {
    sessions.delete(token);
    const timer = sessionTimers.get(token);
    if (timer) {
        clearTimeout(timer);
        sessionTimers.delete(token);
    }
    closeSessionSockets(token);
}

function armSession(token) {
    const exp = sessions.get(token);
    const prev = sessionTimers.get(token);
    if (prev) clearTimeout(prev);
    const delay = Math.min(MAX_TIMEOUT_MS, Math.max(0, exp - Date.now()));
    const timer = setTimeout(() => {
        if (sessions.has(token) && sessions.get(token) <= Date.now()) destroySession(token);
    }, delay);
    if (timer.unref) timer.unref();
    sessionTimers.set(token, timer);
}

function trackSessionSocket(token, socket) {
    let set = sessionSockets.get(token);
    if (!set) {
        set = new Set();
        sessionSockets.set(token, set);
    }
    set.add(socket);
    socket.on('close', () => {
        const current = sessionSockets.get(token);
        if (!current) return;
        current.delete(socket);
        if (current.size === 0) sessionSockets.delete(token);
    });
}

function reapSessions() {
    const now = Date.now();
    for (const [token, exp] of [...sessions]) {
        if (exp <= now) destroySession(token);
    }
    while (sessions.size > MAX_SESSIONS) {
        const oldest = sessions.keys().next().value;
        destroySession(oldest);
    }
}

function sessionValid(cookies) {
    const token = cookies && cookies.wt_session;
    if (!token || !sessions.has(token)) return false;
    if (sessions.get(token) <= Date.now()) {
        destroySession(token);
        return false;
    }
    return true;
}

function normalizeIp(value) {
    const raw = String(value || '').trim().toLowerCase();
    if (raw.startsWith('::ffff:')) return raw.slice('::ffff:'.length);
    return raw;
}

function clientIp(req) {
    const socketIp = normalizeIp(req.socket && req.socket.remoteAddress);
    const trusted = normalizeIp(process.env.WATCHTOWER_TRUSTED_PROXY || '');
    if (trusted && socketIp === trusted) {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            const hops = String(forwarded).split(',').map((part) => part.trim()).filter(Boolean);
            const last = hops.length ? hops[hops.length - 1] : '';
            if (last) return normalizeIp(last);
        }
    }
    return socketIp || 'unknown';
}

function pruneLoginFailures(now) {
    for (const [ip, row] of [...loginFailures]) {
        const locked = row.until > now;
        if (!locked && now - (row.seen || 0) > LOGIN_HISTORY_MS) loginFailures.delete(ip);
    }
    if (loginFailures.size <= LOGIN_FAILURE_CAP) return;
    const inactive = [];
    for (const [ip, row] of loginFailures) {
        if (!(row.until > now)) inactive.push(ip);
    }
    for (const ip of inactive) {
        if (loginFailures.size <= LOGIN_FAILURE_CAP) return;
        loginFailures.delete(ip);
    }
}

function loginThrottled(ip) {
    pruneLoginFailures(Date.now());
    const row = loginFailures.get(ip);
    return !!(row && row.until > Date.now());
}

function noteLoginFailure(ip) {
    const now = Date.now();
    pruneLoginFailures(now);
    if (!loginFailures.has(ip) && loginFailures.size >= LOGIN_FAILURE_CAP) {
        let freed = false;
        for (const [key, row] of loginFailures) {
            if (!(row.until > now)) {
                loginFailures.delete(key);
                freed = true;
                break;
            }
        }
        if (!freed) return false;
    }
    const row = loginFailures.get(ip) || { count: 0, until: 0, seen: 0 };
    row.count += 1;
    row.seen = now;
    if (row.count >= 5) {
        const delay = Math.min(60000, 1000 * Math.pow(2, row.count - 5));
        row.until = now + delay;
    }
    loginFailures.delete(ip);
    loginFailures.set(ip, row);
    pruneLoginFailures(now);
    return true;
}

function noteLoginSuccess(ip) {
    loginFailures.delete(ip);
}

function generic(res, status) {
    const error = status === 400 ? 'Bad request'
        : status === 401 ? 'Unauthorized'
        : status === 403 ? 'Forbidden'
        : status === 404 ? 'Not found'
        : status === 429 ? 'Too many requests'
        : status === 502 ? 'API unavailable'
        : 'Request failed';
    res.status(status).json({ error });
}

function originAllowed(req) {
    const origin = req.headers.origin;
    const referer = req.headers.referer || req.headers.referrer;
    const allowed = [];
    if (req.headers.host) {
        allowed.push('http://' + req.headers.host);
        allowed.push('https://' + req.headers.host);
    }
    if (process.env.WATCHTOWER_UI_ORIGIN) allowed.push(process.env.WATCHTOWER_UI_ORIGIN);
    function matches(value) {
        if (!value) return false;
        return allowed.some((item) => value === item || value.startsWith(item + '/'));
    }
    if (origin) return matches(origin);
    if (referer) return matches(referer);
    return false;
}

function loginPage(nonce) {
    return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Watchtower</title></head><body>'
        + '<form id="login"><label>Operator key <input id="key" type="password" autocomplete="current-password"></label>'
        + '<button type="submit">Unlock</button><p id="err"></p></form>'
        + '<script nonce="' + nonce + '">'
        + 'document.getElementById("login").addEventListener("submit", async (ev) => {'
        + 'ev.preventDefault();'
        + 'const key = document.getElementById("key").value;'
        + 'const res = await fetch("/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) });'
        + 'if (res.ok) location.assign("/watchtower.html");'
        + 'else document.getElementById("err").textContent = "Unauthorized";'
        + '});'
        + '</script></body></html>';
}

function sendLogin(req, res) {
    const nonce = crypto.randomBytes(16).toString('base64url');
    applySecurityHeaders(res, nonce);
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(loginPage(nonce));
}

app.use((req, res, next) => {
    applySecurityHeaders(res, null);
    next();
});

app.get('/login', sendLogin);

app.get('/', (req, res) => {
    const parsed = cookiesOf(req);
    if (parsed.malformed || !sessionValid(parsed.cookies)) return res.redirect('/login');
    res.redirect('/watchtower.html');
});

app.post('/login', express.json({ limit: '8kb' }), (req, res) => {
    const ip = clientIp(req);
    if (loginThrottled(ip)) return generic(res, 429);
    const provided = req.body && typeof req.body.key === 'string' ? req.body.key : req.headers['x-api-key'];
    if (!keysEqual(provided, apiKey)) {
        if (!noteLoginFailure(ip)) return generic(res, 429);
        console.warn('[UI Auth] Operator login failed.');
        return generic(res, 401);
    }
    noteLoginSuccess(ip);
    reapSessions();
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_MS);
    armSession(token);
    reapSessions();
    res.setHeader('Set-Cookie', sessionCookie(token));
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true });
});

app.post('/logout', (req, res) => {
    const parsed = cookiesOf(req);
    if (parsed.malformed) return generic(res, 400);
    if (!originAllowed(req)) return generic(res, 403);
    const token = parsed.cookies.wt_session;
    if (token) destroySession(token);
    res.setHeader('Set-Cookie', sessionCookie(''));
    res.json({ ok: true });
});

app.use((req, res, next) => {
    const parsed = cookiesOf(req);
    if (parsed.malformed) return generic(res, 400);
    if (sessionValid(parsed.cookies)) return next();
    return generic(res, 401);
});

app.get('/watchtower.html', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('base64url');
    applySecurityHeaders(res, nonce);
    res.setHeader('Cache-Control', 'no-store');
    let html = fs.readFileSync(path.join(__dirname, 'watchtower.html'), 'utf8');
    html = html.replace('<style>', '<style nonce="' + nonce + '">');
    html = html.replace(
        '<script>\n        const socket',
        '<script nonce="' + nonce + '">\n        const socket'
    );
    res.type('html').send(html);
});

app.get('/assets/watchtower_logo.png', (req, res) => {
    if (!fs.existsSync(LOGO_PATH)) return generic(res, 404);
    res.sendFile(LOGO_PATH);
});

const BROWSER_V2 = new Set([
    '/api/v2/infrastructure',
    '/api/v2/topology',
    '/api/v2/ota/upload',
    '/api/v2/policies/update',
]);

// IR P3-1 (Watchtower #6): one canonical spelling per path.
// A '%' must start a valid %XX escape, and an escape may not encode an
// unreserved character (RFC 3986 2.3: A-Z a-z 0-9 - . _ ~). '/api/%76%32/x'
// is a second spelling of '/api/v2/x'; the proxy refuses it (403) so the
// /api/v2 browser allowlist cannot be sidestepped if a router ever decodes
// before matching.
// Reserved or non-ASCII escapes such as %20 are still forwarded as-is.
function canonicalPercentEncoding(pathname) {
    if (/%(?![0-9A-Fa-f]{2})/.test(pathname)) return false;
    const escapes = pathname.match(/%[0-9A-Fa-f]{2}/g) || [];
    for (const esc of escapes) {
        const ch = String.fromCharCode(parseInt(esc.slice(1), 16));
        if (/[A-Za-z0-9\-._~]/.test(ch)) return false;
    }
    return true;
}

function requestTarget(urlPath) {
    const raw = String(urlPath || '');
    if (!raw.startsWith('/') || raw.includes('#') || raw.includes('\\') || /[\u0000-\u001F\u007F]/.test(raw)) return null;
    const q = raw.indexOf('?');
    const pathname = q === -1 ? raw : raw.slice(0, q);
    const query = q === -1 ? '' : raw.slice(q);
    if (pathname.includes('//') || /%(?:2f|5c|23|2e)/i.test(pathname)) return null;
    const segments = pathname.split('/');
    for (let i = 0; i < segments.length; i++) {
        const segment = segments[i];
        if (i === 0) {
            if (segment !== '') return null;
            continue;
        }
        if (segment === '') continue;
        if (segment === '.' || segment === '..') return null;
    }
    return { pathname, query };
}

function proxyPathAllowed(pathname) {
    if (!canonicalPercentEncoding(pathname)) return false;
    const compared = pathname.toLowerCase();
    if (compared === '/socket.io' || compared.startsWith('/socket.io/')) return true;
    if (compared === '/api/v2' || compared.startsWith('/api/v2/')) return BROWSER_V2.has(compared);
    return compared.startsWith('/api/');
}

function proxyToApi(req, res) {
    const target = req.checkedTarget;
    if (!target) return generic(res, 400);
    if (!proxyPathAllowed(target.pathname)) return generic(res, 403);
    const method = String(req.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && !originAllowed(req)) {
        return generic(res, 403);
    }
    const headers = Object.assign({}, req.headers);
    headers['x-api-key'] = apiKey;
    delete headers.cookie;
    headers.host = hostHeader(apiHost, apiPort);
    const preq = http.request({
        hostname: apiHost,
        port: Number(apiPort),
        path: target.pathname + target.query,
        method: req.method,
        headers,
    }, (pres) => {
        res.writeHead(pres.statusCode || 502, pres.headers);
        pres.pipe(res);
    });
    preq.on('error', (err) => {
        console.error('[UI proxy] ' + (err && err.message ? err.message : 'request failed'));
        if (!res.headersSent) generic(res, 502);
    });
    req.pipe(preq);
}

app.use('/api', proxyToApi);
app.use('/socket.io', proxyToApi);

app.use((req, res) => {
    generic(res, 404);
});

app.use((err, req, res, next) => {
    console.error('[UI] ' + (err && err.message ? err.message : 'handler error'));
    if (res.headersSent) return;
    const status = err && Number(err.status) >= 400 && Number(err.status) < 500 ? Number(err.status) : 500;
    generic(res, status);
});

function rejectNonCanonical(res) {
    applySecurityHeaders(res, null);
    const body = JSON.stringify({ error: 'Bad request' });
    res.writeHead(400, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
}

const server = http.createServer((req, res) => {
    const target = requestTarget(req.url);
    if (!target) return rejectNonCanonical(res);
    req.checkedTarget = target;
    app(req, res);
});

function socketIoUpgradeTarget(urlPath) {
    const target = requestTarget(urlPath);
    if (!target) return { status: 400 };
    if (!canonicalPercentEncoding(target.pathname)) return { status: 403 };
    const compared = target.pathname.toLowerCase();
    if (compared === '/socket.io' || compared.startsWith('/socket.io/')) {
        return { forward: target.pathname + target.query };
    }
    return { status: 403 };
}

server.on('upgrade', (req, socket, head) => {
    try {
        const upgradeTarget = socketIoUpgradeTarget(req.url);
        if (!upgradeTarget.forward) {
            const status = upgradeTarget.status === 400 ? 400 : 403;
            const reason = status === 400 ? 'Bad Request' : 'Forbidden';
            socket.write('HTTP/1.1 ' + status + ' ' + reason + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
            socket.destroy();
            return;
        }
        const parsed = readCookieHeader(req.headers.cookie);
        if (parsed.malformed || !sessionValid(parsed.cookies)) {
            const status = parsed.malformed ? 400 : 401;
            const reason = parsed.malformed ? 'Bad Request' : 'Unauthorized';
            socket.write('HTTP/1.1 ' + status + ' ' + reason + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
            socket.destroy();
            return;
        }
        if (!originAllowed(req)) {
            socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
            socket.destroy();
            return;
        }
        trackSessionSocket(parsed.cookies.wt_session, socket);
        const headers = Object.assign({}, req.headers);
        headers['x-api-key'] = apiKey;
        delete headers.cookie;
        headers.host = hostHeader(apiHost, apiPort);
        const preq = http.request({
            hostname: apiHost,
            port: Number(apiPort),
            path: upgradeTarget.forward,
            method: req.method || 'GET',
            headers,
        });
        preq.on('upgrade', (pres, psocket, phead) => {
            let raw = 'HTTP/1.1 ' + pres.statusCode + ' ' + (pres.statusMessage || '') + '\r\n';
            Object.keys(pres.headers).forEach((name) => {
                const value = pres.headers[name];
                if (Array.isArray(value)) value.forEach((item) => { raw += name + ': ' + item + '\r\n'; });
                else raw += name + ': ' + value + '\r\n';
            });
            raw += '\r\n';
            socket.write(raw);
            if (phead && phead.length) socket.write(phead);
            psocket.pipe(socket);
            socket.pipe(psocket);
            const kill = () => { socket.destroy(); psocket.destroy(); };
            socket.on('error', kill);
            psocket.on('error', kill);
            socket.on('close', () => psocket.destroy());
            psocket.on('close', () => socket.destroy());
        });
        preq.on('error', () => socket.destroy());
        preq.on('response', (pres) => {
            socket.write('HTTP/1.1 ' + pres.statusCode + ' ' + (pres.statusMessage || '') + '\r\nConnection: close\r\n\r\n');
            socket.destroy();
            pres.resume();
        });
        if (head && head.length) preq.write(head);
        preq.end();
    } catch (err) {
        console.error('[UI upgrade] ' + (err && err.message ? err.message : 'upgrade failed'));
        socket.destroy();
    }
});

// A27: same listen-error rule as the API (backend/bind_address.js): a busy port is retried a bounded number of
// times, then exit 1; any other listen failure is one [FATAL] line and exit 1, never a raw stack trace.
handleListenErrors(server, port, bindAddress, 'UI');

server.listen(port, bindAddress, () => {
    console.log('[Watchtower V2 Glass Pane] Operator API key loaded from environment');
    const secureOptOut = cookieSecureOptOutWarning();
    if (secureOptOut) console.warn(secureOptOut);
    console.log(`[Watchtower V2 Glass Pane] UI Server listening on http://${urlHost(bindAddress)}:${port}`);
});
