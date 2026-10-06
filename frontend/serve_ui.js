const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { securityHeaders } = require('./security_headers');
const { keysEqual, requireOperatorKey } = require('../backend/auth');

const app = express();
const port = process.env.WATCHTOWER_UI_PORT || 8080;
const bindAddress = process.env.WATCHTOWER_UI_BIND_ADDRESS || '127.0.0.1';
const apiKey = requireOperatorKey(process.env.WATCHTOWER_API_KEY);
const apiPort = process.env.WATCHTOWER_API_PORT || '3000';
const apiHost = process.env.WATCHTOWER_API_HOST || '127.0.0.1';

const sessions = new Map();
const sessionSockets = new Map();
const sessionTimers = new Map();
const SESSION_MS = Number(process.env.WATCHTOWER_UI_SESSION_MS) > 0
    ? Number(process.env.WATCHTOWER_UI_SESSION_MS)
    : 8 * 60 * 60 * 1000;
const MAX_SESSIONS = 32;
const LOGO_PATH = path.join(__dirname, '../assets/watchtower_logo.png');
const loginFailures = new Map();

function applySecurityHeaders(res, nonce) {
    const headers = securityHeaders(nonce);
    for (const [name, value] of Object.entries(headers)) {
        res.setHeader(name, value);
    }
}

function cookieSecure() {
    const flag = process.env.WATCHTOWER_UI_COOKIE_SECURE;
    if (flag === '1' || flag === 'true') return true;
    if (flag === '0' || flag === 'false') return false;
    const origin = process.env.WATCHTOWER_UI_ORIGIN || '';
    return origin.startsWith('https://');
}

function sessionCookie(token) {
    const secure = cookieSecure() ? '; Secure' : '';
    if (!token) return 'wt_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + secure;
    return 'wt_session=' + token + '; HttpOnly; SameSite=Strict; Path=/' + secure;
}

function readCookieHeader(header) {
    const cookies = {};
    let malformed = false;
    String(header || '').split(';').forEach((part) => {
        const i = part.indexOf('=');
        if (i === -1) return;
        const name = part.slice(0, i).trim();
        const value = part.slice(i + 1).trim();
        if (!name) return;
        try {
            cookies[name] = decodeURIComponent(value);
        } catch (_) {
            if (name === 'wt_session') malformed = true;
        }
    });
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
    const delay = Math.max(0, exp - Date.now());
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
            const first = String(forwarded).split(',')[0].trim();
            if (first) return normalizeIp(first);
        }
    }
    return socketIp || 'unknown';
}

function loginThrottled(ip) {
    const row = loginFailures.get(ip);
    return !!(row && row.until > Date.now());
}

function noteLoginFailure(ip) {
    const row = loginFailures.get(ip) || { count: 0, until: 0 };
    row.count += 1;
    if (row.count >= 5) {
        const delay = Math.min(60000, 1000 * Math.pow(2, row.count - 5));
        row.until = Date.now() + delay;
    }
    loginFailures.set(ip, row);
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
    const parsed = cookiesOf(req);
    if (parsed.malformed) return generic(res, 400);
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
    if (parsed.malformed) return generic(res, 400);
    if (!sessionValid(parsed.cookies)) return res.redirect('/login');
    res.redirect('/watchtower.html');
});

app.post('/login', express.json({ limit: '8kb' }), (req, res) => {
    const parsed = cookiesOf(req);
    if (parsed.malformed) return generic(res, 400);
    const ip = clientIp(req);
    if (loginThrottled(ip)) return generic(res, 429);
    const provided = req.body && typeof req.body.key === 'string' ? req.body.key : req.headers['x-api-key'];
    if (!keysEqual(provided, apiKey)) {
        noteLoginFailure(ip);
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

function proxyToApi(req, res) {
    const method = String(req.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && !originAllowed(req)) {
        return generic(res, 403);
    }
    const headers = Object.assign({}, req.headers);
    headers['x-api-key'] = apiKey;
    delete headers.cookie;
    headers.host = apiHost + ':' + apiPort;
    const preq = http.request({
        hostname: apiHost,
        port: Number(apiPort),
        path: req.originalUrl || req.url,
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

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
    try {
        if (!req.url || req.url.indexOf('/socket.io/') !== 0) {
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
        headers.host = apiHost + ':' + apiPort;
        const preq = http.request({
            hostname: apiHost,
            port: Number(apiPort),
            path: req.url,
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

server.listen(port, bindAddress, () => {
    console.log('[Watchtower V2 Glass Pane] Operator API key loaded from environment');
    console.log(`[Watchtower V2 Glass Pane] UI Server listening on http://${bindAddress}:${port}`);
});
