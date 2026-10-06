const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
const port = process.env.WATCHTOWER_UI_PORT || 8080;

const fs = require('fs');
const { securityHeaders } = require('./security_headers');
const apiKey = process.env.WATCHTOWER_API_KEY || "WATCHTOWER_DEFAULT_KEY";
const apiPort = process.env.WATCHTOWER_API_PORT || "4040";

function applySecurityHeaders(res, nonce) {
    const headers = securityHeaders(nonce);
    for (const [name, value] of Object.entries(headers)) {
        res.setHeader(name, value);
    }
}

app.use((req, res, next) => {
    applySecurityHeaders(res, null);
    next();
});

app.get('/watchtower.html', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('base64url');
    applySecurityHeaders(res, nonce);
    let html = fs.readFileSync(path.join(__dirname, 'watchtower.html'), 'utf8');
    html = html.replaceAll('YOUR_SECRET_API_KEY_HERE', apiKey);
    html = html.replaceAll('YOUR_SECRET_API_PORT_HERE', apiPort);
    html = html.replace('<style>', '<style nonce="' + nonce + '">');
    html = html.replace(
        '<script>\n        const API_PORT',
        '<script nonce="' + nonce + '">\n        const API_PORT'
    );
    res.type('html').send(html);
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.redirect('/watchtower.html');
});

app.listen(port, () => {
    console.log(`[Watchtower V2 Glass Pane] UI Server listening on http://localhost:${port}`);
});
