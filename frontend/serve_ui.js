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
const apiPort = process.env.WATCHTOWER_API_PORT || '4040';
const apiHost = process.env.WATCHTOWER_API_HOST || '127.0.0.1';

const sessions = new Map();
const SESSION_MS = 8 * 60 * 60 * 1000;
const LOGO_PATH = path.join(__dirname, '../assets/watchtower_logo.png');

function applySecurityHeaders(res, nonce) {
    const headers = securityHeaders(nonce);
    for (const [name, value] of Object.entries(headers)) {
        res.setHeader(name, value);
    }
}

function parseCookies(req) {
    const out = {};
    const raw = req.headers.cookie || '';
    raw.split(';').forEach((part) => {
        const i = part.indexOf('=');
        if (i === -1) return;
        const name = part.slice(0, i).trim();
        const value = part.slice(i + 1).trim();
        if (name) out[name] = decodeURIComponent(value);
    });
    return out;
}

function sessionValid(req) {
    const token = parseCookies(req).wt_session;
    if (!token || !sessions.has(token)) return false;
    if (sessions.get(token) < Date.now()) {
        sessions.delete(token);
        return false;
    }
    return true;
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

app.post('/login', express.json({ limit: '8kb' }), (req, res) => {
    const provided = req.body && typeof req.body.key === 'string' ? req.body.key : req.headers['x-api-key'];
    if (!keysEqual(provided, apiKey)) {
        console.warn('[UI Auth] Operator login failed.');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_MS);
    res.setHeader('Set-Cookie', 'wt_session=' + token + '; HttpOnly; SameSite=Strict; Path=/');
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true });
});

app.use((req, res, next) => {
    if (sessionValid(req)) return next();
    res.status(401).json({ error: 'Unauthorized' });
});

app.get('/', (req, res) => {
    res.redirect('/watchtower.html');
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
    if (!fs.existsSync(LOGO_PATH)) return res.status(404).json({ error: 'Not found' });
    res.sendFile(LOGO_PATH);
});

function proxyToApi(req, res) {
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
        if (!res.headersSent) res.status(502).json({ error: 'API unavailable' });
    });
    req.pipe(preq);
}

app.use('/api', proxyToApi);
app.use('/socket.io', proxyToApi);

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
    if (!req.url || req.url.indexOf('/socket.io/') !== 0) {
        socket.destroy();
        return;
    }
    if (!sessionValid(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        socket.destroy();
        return;
    }
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
});

server.listen(port, bindAddress, () => {
    console.log('[Watchtower V2 Glass Pane] Operator API key loaded from environment');
    console.log(`[Watchtower V2 Glass Pane] UI Server listening on http://${bindAddress}:${port}`);
});
