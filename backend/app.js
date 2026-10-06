const express = require('express');
const http = require('http');
const crypto = require('crypto');
const cors = require('cors'); 
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { Server } = require('socket.io');
const { keysEqual, operatorKeyProblem, requireOperatorKey } = require('./auth');
const { ipAllowed } = require('./ip_allow');

const app = express();
const server = http.createServer(app);

function configuredUiOrigin() {
    const explicit = process.env.WATCHTOWER_UI_ORIGIN;
    if (explicit && String(explicit).trim()) return String(explicit).trim();
    const uiPort = process.env.WATCHTOWER_UI_PORT || '8080';
    return 'http://127.0.0.1:' + uiPort;
}

const UI_ORIGIN = configuredUiOrigin();
const io = new Server(server, {
    cors: {
        origin: UI_ORIGIN,
        methods: ["GET", "POST"]
    }
});

const port = process.env.WATCHTOWER_API_PORT || 3000;

/**
 * Relative paths are resolved from the repository root (parent of backend/),
 * not from process.cwd(). start.sh launches this file from backend/, and
 * .env.example sets WATCHTOWER_DATA_DIR=./data.
 */
function resolveFromRepo(value, fallbackAbs) {
    if (value === undefined || value === null || String(value).trim() === '') return fallbackAbs;
    const raw = String(value).trim();
    if (path.isAbsolute(raw)) return path.resolve(raw);
    return path.resolve(__dirname, '..', raw);
}

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------
const BIND_ADDRESS = process.env.WATCHTOWER_BIND_ADDRESS || '0.0.0.0';
const API_KEY = requireOperatorKey(process.env.WATCHTOWER_API_KEY);
const DATA_DIR = resolveFromRepo(process.env.WATCHTOWER_DATA_DIR, path.join(__dirname, '..', 'data'));
function dataFile(name) {
    return path.join(DATA_DIR, name);
}
const UPDATES_DIR = resolveFromRepo(process.env.WATCHTOWER_UPDATES_DIR, path.join(__dirname, 'updates'));
const PUBLIC_BASE_URL = process.env.WATCHTOWER_PUBLIC_BASE_URL && String(process.env.WATCHTOWER_PUBLIC_BASE_URL).trim()
    ? String(process.env.WATCHTOWER_PUBLIC_BASE_URL).trim().replace(/\/$/, '')
    : '';
if (!PUBLIC_BASE_URL) {
    console.warn('[OTA] WATCHTOWER_PUBLIC_BASE_URL is unset. OTA upload is refused so a beacon is not sent a loopback URL.');
}
let c2Queue = Object.create(null);

console.log('[Watchtower Command Center] Operator API key loaded from environment');
console.log(`[Watchtower API Gateway] Listening on ${BIND_ADDRESS}:${port}`);

app.set('trust proxy', false);
app.use(cors({ origin: UI_ORIGIN, methods: ['GET', 'POST', 'DELETE'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.raw({ type: 'application/zip', limit: '50mb' }));

// SECURITY: IP allowlist. Static mounts are after this gate.
app.use((req, res, next) => {
    const ip = req.ip || (req.connection && req.connection.remoteAddress);
    if (ipAllowed(ip)) {
        next();
    } else {
        console.warn(`[SECURITY] Blocked unauthorized access attempt from IP: ${ip}`);
        res.status(403).send("403 Forbidden: Access restricted to Tailscale/Local network.");
    }
});
app.use('/updates', express.static(UPDATES_DIR));
app.use('/assets', express.static(path.join(__dirname, '../assets')));

// ------------------------------------------------------------------
// IN-MEMORY DATABASE (MVP)
// ------------------------------------------------------------------

const allowlist = require('./allowlist');

const MAX_HOST_NAME = 253;

/** Assign a stable id so each command is delivered at most once, including to GET-polling beacons. */
function enqueueCommand(host, fields) {
    if (!c2Queue[host]) c2Queue[host] = [];
    const command = { id: crypto.randomUUID(), timestamp: Date.now() };
    Object.keys(fields).forEach((key) => { command[key] = fields[key]; });
    c2Queue[host].push(command);
    return command;
}

function takeCommands(host) {
    const commands = c2Queue[host] ? c2Queue[host].slice() : [];
    if (Object.prototype.hasOwnProperty.call(c2Queue, host)) delete c2Queue[host];
    return commands;
}

const RESERVED_HOSTS = new Set(['__proto__', 'constructor', 'prototype', 'tostring']);

function parseHost(value) {
    if (typeof value !== 'string') return { status: 400, error: 'Host parameter required' };
    const host = value.trim();
    if (!host) return { status: 400, error: 'Host parameter required' };
    if (host.length > MAX_HOST_NAME || RESERVED_HOSTS.has(host.toLowerCase())) {
        return { status: 400, error: 'Bad request' };
    }
    return { host };
}

function nullHostMap(source) {
    const map = Object.create(null);
    if (!source || typeof source !== 'object') return map;
    Object.keys(source).forEach((key) => {
        if (RESERVED_HOSTS.has(String(key).toLowerCase())) return;
        map[key] = source[key];
    });
    return map;
}

/** Queue a beacon command. Destructive verbs require purge capability, even when the group allowlist flag is off. */
function queueHostCommand(host, action, target) {
    if (allowlist.isPurgeOrDestructiveAction(action)) {
        const deny = allowlist.assertPurgeCapability();
        if (deny) {
            console.warn(`[C2 PURGE DENY] ${deny.rule} action=${action} host=${host}`);
            return deny;
        }
    }
    enqueueCommand(host, { action: action, target: target });
    return null;
}

const DB_FILE = resolveFromRepo(process.env.WATCHTOWER_DB_PATH, dataFile('watchtower_db.json'));
console.log('[Watchtower DB] Data directory ' + DATA_DIR);
if (!fs.existsSync(path.dirname(DB_FILE))) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
}


let alertsDB = [];
let threatDB = [];
let assetRegistry = Object.create(null); // New Device/User Catalog
let globalInventory = Object.create(null); // { Hostname: [ {name, hash, uptime...} ] }
let groupDB = {
    "Default": {
        "ENABLE_FIM": true, "ENABLE_ORACLE": true, "ENABLE_BEHAVIORAL": true, "ENABLE_DECOY": true,
        "ENABLE_COMPLIANCE": true, "ENABLE_ROLLBACK": true, "ENABLE_YARA": true, "ENABLE_NDR": true,
        "WATCHTOWER_AUDIT_MODE": true
    }
};
let deviceGroupMap = Object.create(null); // { Hostname: "Group_Name" }

if (fs.existsSync(DB_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        alertsDB = data.alerts || [];
        threatDB = data.threats || [];
        assetRegistry = nullHostMap(data.assets);
        groupDB = data.groups || groupDB;
        deviceGroupMap = nullHostMap(data.deviceGroups);
        console.log(`[Watchtower DB] Loaded ${alertsDB.length} alerts, ${threatDB.length} threats, and ${Object.keys(assetRegistry).length} known assets.`);
    } catch (e) {
        console.error('[Watchtower DB] Failed to load DB, starting fresh.');
    }
}

function saveDB() {
    fs.writeFileSync(DB_FILE, JSON.stringify({ alerts: alertsDB, threats: threatDB, assets: assetRegistry, groups: groupDB, deviceGroups: deviceGroupMap }, null, 2));
}

function registerAsset(source, ip) {
    const key = source || ip || 'UnknownDevice';
    if (!assetRegistry[key]) {
        assetRegistry[key] = {
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            incident_count: 1
        };
        console.log(`[ASSET CATALOG] Discovered new network entity: ${key}`);
        io.emit('new_asset_discovered', { id: key, data: assetRegistry[key] });
    } else {
        assetRegistry[key].last_seen = new Date().toISOString();
        assetRegistry[key].incident_count++;
    }
}

// ------------------------------------------------------------------
// WEBSOCKETS (Task 1.2)
// ------------------------------------------------------------------

const OPERATOR_SOCKET_ACTIONS = new Set(['quarantine', 'lock_dir', 'kill', 'disable_user']);
const RESERVED_QUEUE_ACTIONS = new Set(['update_core', 'update_policy']);

io.use((socket, next) => {
    const headerKey = socket.handshake.headers && socket.handshake.headers['x-api-key'];
    const token = (socket.handshake.auth && socket.handshake.auth.token) || headerKey;
    if (operatorKeyProblem(token) === 'placeholder') {
        console.warn(`[WebSocket Auth] Blocked unauthorized connection attempt from ${socket.id}`);
        return next(new Error('Authentication error'));
    }
    if (keysEqual(token, API_KEY)) {
        return next();
    }
    console.warn(`[WebSocket Auth] Blocked unauthorized connection attempt from ${socket.id}`);
    return next(new Error('Authentication error'));
});

io.on('connection', (socket) => {
    console.log(`[WebSocket] Client connected: ${socket.id}`);
    
    // Send initial state upon connection
    socket.emit('sync_state', {
        alerts: alertsDB.slice(0, 50),
        threats: threatDB.slice(0, 50),
        assets: assetRegistry,
        inventory: globalInventory,
        groups: groupDB,
        deviceGroups: deviceGroupMap
    });

    
    socket.on('c2_command', (cmd) => {
    const actionName = cmd && typeof cmd === 'object' && !Array.isArray(cmd) && typeof cmd.action === 'string'
        ? cmd.action.trim().toLowerCase()
        : '';
    const operatorAction = OPERATOR_SOCKET_ACTIONS.has(actionName) && !RESERVED_QUEUE_ACTIONS.has(actionName);
    if (!cmd || typeof cmd !== 'object' || Array.isArray(cmd) || !operatorAction) {
        socket.emit('c2_result', {
            ok: false,
            error: 'invalid_c2_action',
            rule: 'INVALID_C2_ACTION',
            action: cmd && typeof cmd === 'object' && !Array.isArray(cmd) ? cmd.action : undefined,
            target: cmd && typeof cmd === 'object' && !Array.isArray(cmd) ? cmd.target : undefined,
            host: cmd && typeof cmd === 'object' && !Array.isArray(cmd) ? cmd.host : undefined
        });
        return;
    }
    if (typeof cmd.host === 'string' && RESERVED_HOSTS.has(cmd.host.trim().toLowerCase())) {
        socket.emit('c2_result', {
            ok: false,
            error: 'invalid_c2_action',
            rule: 'INVALID_C2_ACTION',
            action: cmd.action,
            target: cmd.target,
            host: cmd.host
        });
        return;
    }
    console.log(`[C2 COMMAND RECEIVED] Action: ${cmd.action}, Target: ${cmd.target}, Host: ${cmd.host}`);

    // Allowlist adapter: host-scoped deny for unmapped/missing/wrong-profile/audit/purge.
    // Not gated on WATCHTOWER_ALLOWLIST (that switch cannot turn enforcement off).
    const deny = allowlist.assertC2Command(cmd, deviceGroupMap, groupDB);
    if (deny) {
        console.warn(`[C2 ALLOWLIST DENY] ${deny.rule} host=${cmd && cmd.host}`);
        socket.emit('c2_result', {
            action: cmd && cmd.action,
            target: cmd && cmd.target,
            host: cmd && cmd.host,
            result: allowlist.socketDenyPayload(deny),
            allowlist_denied: true
        });
        return;
    }
    
    // If it's a remote host, queue it for the beacon
    if (cmd.host && cmd.host !== 'mac-mini-hub' && cmd.host !== 'Local-Node' && cmd.host !== 'localhost' && cmd.host !== 'Austins-Mac-mini.local') {
        const queued = queueHostCommand(cmd.host, cmd.action, cmd.target);
        if (queued) {
            socket.emit('c2_result', {
                action: cmd.action,
                target: cmd.target,
                host: cmd.host,
                result: allowlist.socketDenyPayload(queued),
                allowlist_denied: true
            });
            return;
        }
        console.log(`[C2 QUEUED] Command queued for remote host: ${cmd.host}`);
        
        io.emit('new_threat_intel', {
            id: crypto.randomUUID(),
            ingested_at: new Date().toISOString(),
            source: "Watchtower Command",
            title: `C2 Queued for ${cmd.host}: ${cmd.action.toUpperCase()}`,
            ai_verdict: "PENDING_BEACON",
            ai_reason: `Waiting for ${cmd.host} to check in and pull the command...`,
            severity: "warning"
        });
        return;
    }

    // Local execution
    const scriptPath = path.join(__dirname, '../core/watchtower_quarantine.py');
    const venvPython = process.env.PYTHON_BIN || 'python3';
    const { execFile } = require('child_process');
    
    execFile(venvPython, [scriptPath, '--action', cmd.action, '--target', cmd.target == null ? '' : String(cmd.target)], (err, stdout, stderr) => {
        if (err) {
            console.error('[C2 ERROR] ' + (stderr || err.message || 'command failed'));
            io.emit('c2_result', { ok: false, action: cmd.action, target: cmd.target, error: 'c2_failed' });
            return;
        }
        const resultText = String(stdout || '').trim();
        console.log('[C2 SUCCESS]');
        io.emit('c2_result', { ok: true, status: 'ok', action: cmd.action, target: cmd.target, result: resultText });
        
        io.emit('new_threat_intel', {
            id: crypto.randomUUID(),
            ingested_at: new Date().toISOString(),
            source: "Watchtower Command",
            title: `C2 Execution: ${cmd.action.toUpperCase()}`,
            ai_verdict: "RESOLVED",
            ai_reason: 'Command completed',
            severity: "success"
        });
    });
});

socket.on('disconnect', () => {
        console.log(`[WebSocket] Client disconnected: ${socket.id}`);
    });
});

// ------------------------------------------------------------------
// MIDDLEWARE (API AUTH ONLY)
// ------------------------------------------------------------------
const authenticate = (req, res, next) => {
    const clientKey = req.headers['x-api-key'];
    if (!keysEqual(clientKey, API_KEY)) {
        console.warn(`[Auth Failure] IP: ${req.ip}. Missing or invalid API key.`);
        return res.status(401).json({ error: 'Unauthorized: Invalid or missing API Key' });
    }
    next();
};

/** §5 rule 9. Independent of WATCHTOWER_ALLOWLIST. Returns true when the response is already a coded purge deny. */
function denyPurgeWithoutCap(res) {
    return allowlist.sendHttpDeny(res, allowlist.assertPurgeCapability());
}

// ------------------------------------------------------------------
// ROUTES - API V1 (Legacy Support)
// ------------------------------------------------------------------
app.get('/api/v1/heartbeat', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/api/agents', authenticate, (req, res) => {
    res.json([{ id: 'mac-studio', hostname: 'Austins-Mac-mini.local', status: 'online', last_seen: new Date().toISOString() }]);
});

app.post('/api/alerts', authenticate, (req, res) => {
    const alert = req.body;
    const enrichedAlert = {
        id: crypto.randomUUID(),
        received_at: new Date().toISOString(),
        ...alert
    };
    alertsDB.unshift(enrichedAlert);
    if (alertsDB.length > 500) alertsDB.pop();
    saveDB();
    
    console.log(`[ALERT V1] ${alert.device?.hostname || 'Unknown'} | File: ${alert.file_path} | Event: ${alert.event_type}`);
    io.emit('new_fim_alert', enrichedAlert); // Emit to websocket
    
    res.status(201).json({ status: 'received', id: enrichedAlert.id });
});

app.get('/api/alerts', authenticate, (req, res) => {
    res.json(alertsDB);
});

// ------------------------------------------------------------------
// ROUTES - API V2 (Task 1.3 & Network Topography)
// ------------------------------------------------------------------
app.post('/api/v2/infrastructure', authenticate, (req, res) => {
    const payload = req.body;
    const infraPath = dataFile('infrastructure.json');
    let infra = [];
    if (fs.existsSync(infraPath)) {
        try { infra = JSON.parse(fs.readFileSync(infraPath, 'utf8')); } catch(e){}
    }
    // Prevent duplicates
    infra = infra.filter(i => i.ip !== payload.ip);
    infra.push(payload);
    fs.writeFileSync(infraPath, JSON.stringify(infra, null, 2));
    res.json({ status: 'ok', msg: 'Infrastructure added securely.' });
});

app.delete('/api/v2/infrastructure', authenticate, (req, res) => {
    if (denyPurgeWithoutCap(res)) return;
    const infraPath = dataFile('infrastructure.json');
    if (fs.existsSync(infraPath)) fs.unlinkSync(infraPath);
    res.json({ status: 'ok', msg: 'Infrastructure cleared.' });
});

app.get('/api/v2/topology', authenticate, (req, res) => {
    const topoPath = dataFile('detailed_network_topology.csv');
    if (!fs.existsSync(topoPath)) return res.json([]);
    const data = fs.readFileSync(topoPath, 'utf8');
    const lines = data.split('\n').filter(l => l.trim().length > 0);
    if(lines.length < 2) return res.json([]);
    const headers = lines[0].split(',');
    const results = [];
    for(let i=1; i<lines.length; i++) {
        const obj = {};
        const currentline = lines[i].split(',');
        for(let j=0; j<headers.length; j++){
            obj[headers[j]] = currentline[j];
        }
        results.push(obj);
    }
    res.json(results);
});

app.delete('/api/v2/topology', authenticate, (req, res) => {
    if (denyPurgeWithoutCap(res)) return;
    const topoPath = dataFile('detailed_network_topology.csv');
    const jsonPath = dataFile('historical_topology.json');
    if (fs.existsSync(topoPath)) fs.unlinkSync(topoPath);
    if (fs.existsSync(jsonPath)) fs.unlinkSync(jsonPath);
    
    // Also clear raw dumps
    const dumpsDir = dataFile('raw_mac_dumps');
    if (fs.existsSync(dumpsDir)) {
        fs.readdirSync(dumpsDir).forEach(f => fs.unlinkSync(path.join(dumpsDir, f)));
    }
    
    res.json({ status: 'ok', msg: 'Topology cache cleared.' });
});

app.post('/api/v2/ingest/fim', authenticate, (req, res) => {
    const payload = req.body;
    const enrichedPayload = {
        id: crypto.randomUUID(),
        ingested_at: new Date().toISOString(),
        ...payload
    };
    alertsDB.unshift(enrichedPayload);
    registerAsset(enrichedPayload.source, enrichedPayload.ip);
    if (alertsDB.length > 500) alertsDB.pop();
    saveDB();

    console.log(`[INGEST V2 FIM] Received telemetry from ${payload.source || 'unknown sensor'}`);
    io.emit('new_fim_alert', enrichedPayload);
    
    res.status(201).json({ status: 'ingested', id: enrichedPayload.id });
});

app.post('/api/v2/ingest/inventory', authenticate, (req, res) => {
    const payload = req.body;
    const host = payload.source;
    if (!host) return res.status(400).json({error: "Missing source"});
    
    globalInventory[host] = payload.inventory;
    io.emit('new_inventory_update', { host: host, inventory: payload.inventory });
    res.status(200).json({ status: 'ingested' });
});


app.get('/api/v2/c2/beacon', authenticate, (req, res) => {
    const parsed = parseHost(req.query.host);
    if (parsed.error) return res.status(parsed.status).json({ error: parsed.error });
    // Does not enroll. Each command id is removed after this response so a GET-polling
    // beacon runs it once. The UI proxy refuses this path so a browser cannot consume it.
    const commands = takeCommands(parsed.host);
    res.json({ status: 'ok', commands });
});

app.post('/api/v2/c2/beacon', authenticate, (req, res) => {
    const raw = (req.body && req.body.host) || req.query.host;
    const parsed = parseHost(raw);
    if (parsed.error) return res.status(parsed.status).json({ error: parsed.error });
    const host = parsed.host;

    if (!deviceGroupMap[host]) {
        deviceGroupMap[host] = 'Default';
        saveDB();
        io.emit('policy_sync', { groups: groupDB, deviceGroups: deviceGroupMap });
    }

    const commands = takeCommands(host);
    res.json({ status: 'ok', commands });
});

app.get('/api/v2/policies/sync', authenticate, (req, res) => {
    const parsed = parseHost(req.query.host);
    if (parsed.error) return res.status(parsed.status).json({ error: parsed.error });
    // Read-only. Unknown hosts receive the Default policy and are not written into deviceGroupMap.
    const groupName = deviceGroupMap[parsed.host] || 'Default';
    const policy = groupDB[groupName] || groupDB['Default'];
    res.json({ status: 'ok', policy: policy, group: groupName });
});

app.post('/api/v2/policies/update', authenticate, (req, res) => {
    const { group, policy, host, newGroup } = req.body;
    if (typeof host === 'string' && host !== '') {
        const parsedHost = parseHost(host);
        if (parsedHost.error) return res.status(parsedHost.status).json({ error: parsedHost.error });
    }

    // Allowlist adapter (CALL A). WATCHTOWER_ALLOWLIST=0 does not skip this.
    if (host && newGroup) {
        const deny = allowlist.assertReassign(host, newGroup, deviceGroupMap);
        if (allowlist.sendHttpDeny(res, deny)) return;
    } else if (group && policy) {
        const deny = allowlist.assertPolicyGroupWrite(group, groupDB);
        if (allowlist.sendHttpDeny(res, deny)) return;
    }
    
    if (host && newGroup) {
        if (!groupDB[newGroup]) groupDB[newGroup] = {...groupDB["Default"]};
        deviceGroupMap[host] = newGroup;
        saveDB();
        
        enqueueCommand(host, { action: 'UPDATE_POLICY', target: 'Refresh' });
        console.log(`[POLICY] Assigned ${host} to Group '${newGroup}'`);
        
    } else if (group && policy) {
        groupDB[group] = policy;
        saveDB();
        
        Object.keys(deviceGroupMap).forEach(h => {
             if (deviceGroupMap[h] === group) {
                 enqueueCommand(h, { action: 'UPDATE_POLICY', target: 'Refresh' });
             }
        });
        console.log(`[POLICY] Updated group '${group}'`);
    }
    
    io.emit('policy_sync', { groups: groupDB, deviceGroups: deviceGroupMap });
    res.json({ status: 'ok' });
});

app.post('/api/v2/ota/upload', authenticate, (req, res) => {
    const groupName = req.query.group;
    if (!groupName) return res.status(400).json({ error: 'Group parameter required' });

    const deny = allowlist.assertOtaGroup(groupName);
    if (allowlist.sendHttpDeny(res, deny)) return;

    if (!PUBLIC_BASE_URL) {
        console.error('[OTA] Refusing upload: WATCHTOWER_PUBLIC_BASE_URL is unset.');
        return res.status(503).json({ error: 'OTA unavailable' });
    }

    if (!fs.existsSync(UPDATES_DIR)) fs.mkdirSync(UPDATES_DIR, { recursive: true });
    const zipPath = path.join(UPDATES_DIR, 'update_core.zip');
    
    try {
        fs.writeFileSync(zipPath, req.body);
        
        // Generate HMAC signature natively using API_KEY
        const crypto = require('crypto');
        const fileHmac = crypto.createHmac('sha256', API_KEY).update(req.body).digest('hex');
        
        let hostsUpdated = 0;
        const targetUrl = PUBLIC_BASE_URL + '/updates/update_core.zip';
        
        Object.keys(deviceGroupMap).forEach(h => {
             if (deviceGroupMap[h] === groupName || groupName === "ALL") {
                 enqueueCommand(h, { action: 'UPDATE_CORE', target: targetUrl, hmac: fileHmac });
                 hostsUpdated++;
             }
        });
        
        console.log(`[OTA] Queued UPDATE_CORE for ${hostsUpdated} host(s) in group ${groupName}`);
        res.json({ status: 'ok', hostsUpdated });
    } catch(e) {
        console.error('[OTA] Upload failed: ' + (e && e.message ? e.message : 'unknown'));
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.post('/api/v2/ingest/threat', authenticate, (req, res) => {
    const payload = req.body;
    const enrichedPayload = {
        id: crypto.randomUUID(),
        ingested_at: new Date().toISOString(),
        ...payload
    };
    threatDB.unshift(enrichedPayload);
    registerAsset(enrichedPayload.source, enrichedPayload.ip);
    if (threatDB.length > 500) threatDB.pop();
    saveDB();

    console.log(`[INGEST V2 THREAT] Received intel from ${payload.source || 'unknown sensor'}`);
    io.emit('new_threat_intel', enrichedPayload);
    
    // TIER 1: AUTONOMOUS REMEDIATION (THE BRAIN)
    if (process.env.AUTO_REMEDIATE === 'true' && (enrichedPayload.ai_verdict === 'MALICIOUS' || (enrichedPayload.severity === 'high' && enrichedPayload.event_type?.includes('AD_SECURITY_EVENT')))) {
        const host = enrichedPayload.source;
        // Attempt to extract target from title/filepath, fallback to unknown
        const target = enrichedPayload.file_path || "UnknownTarget"; 
        
        console.log(`[!] AUTONOMOUS REMEDIATION TRIGGERED for ${host}. Threat level: HIGH.`);
        
        if (host && host !== 'mac-mini-hub' && host !== 'Local-Node' && host !== 'Austins-Mac-mini.local' && host !== 'localhost') {
            const action = enrichedPayload.event_type?.includes('AD') ? 'disable_user' : 'quarantine';
            const allowDeny = allowlist.assertC2Command({ action: action, target: target, host: host }, deviceGroupMap, groupDB);
            const queued = allowDeny || queueHostCommand(host, action, target);
            if (queued) {
                console.warn(`[C2 AUTO-REMEDIATE DENY] ${queued.rule} action=${action} host=${host}`);
            } else {
                console.log(`[C2 AUTO-QUEUED] ${action} command queued for ${host}`);
                io.emit('new_threat_intel', {
                    id: crypto.randomUUID(),
                    ingested_at: new Date().toISOString(),
                    source: "Watchtower Autonomous Responder",
                    title: `Auto-Remediation Triggered: ${action.toUpperCase()}`,
                    ai_verdict: "PENDING_BEACON",
                    ai_reason: `AI flagged event as Malicious/High Severity. Command queued for remote host: ${host}.`,
                    severity: "warning"
                });
            }
        }
    }
    
    res.status(201).json({ status: 'ingested', id: enrichedPayload.id });
});

// --- SOVEREIGN COGNITIVE ENGINE (SCE) ENDPOINT ---
app.get('/api/memory/search', authenticate, (req, res) => {
    const query = req.query.q;
    if (!query) {
        return res.status(400).json({ error: 'Query parameter "q" is required.' });
    }

    const scriptPath = path.join(__dirname, '../core/search_vector_index.py');
    if (!fs.existsSync(scriptPath)) {
        console.error('[SCE] Search index script is not present');
        return res.status(503).json({ error: 'index unavailable' });
    }
    const venvPython = process.env.PYTHON_BIN || 'python3';
    
    const { execFile } = require('child_process');
    execFile(venvPython, [scriptPath, query], (error, stdout, stderr) => {
        if (error) {
            console.error('[SCE] Search Error: ' + (stderr || error.message || 'search failed'));
            return res.status(503).json({ error: 'index unavailable' });
        }
        try {
            const jsonStart = stdout.indexOf('{');
            if(jsonStart === -1) throw new Error('No JSON found in output');
            const cleanJson = stdout.substring(jsonStart);
            
            const results = JSON.parse(cleanJson);
            res.json(results);
        } catch (parseError) {
            console.error('[SCE] JSON Parse Error: ' + (parseError && parseError.message ? parseError.message : 'parse failed'));
            res.status(503).json({ error: 'index unavailable' });
        }
    });
});

// ------------------------------------------------------------------
// START
// ------------------------------------------------------------------
app.use((err, req, res, next) => {
    const status = Number(err && (err.status || err.statusCode));
    const code = status >= 400 && status < 500 ? status : 500;
    console.error('[API] ' + (code === 400 ? 'bad request' : 'handler error'));
    if (res.headersSent) return;
    const error = code === 400 ? 'Bad request'
        : code === 401 ? 'Unauthorized'
        : code === 403 ? 'Forbidden'
        : code === 404 ? 'Not found'
        : 'Request failed';
    res.status(code).json({ error });
});

server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`[FATAL] Port ${port} is occupied. Retrying in 3 seconds...`);
        setTimeout(() => {
            server.close();
            server.listen(port, BIND_ADDRESS);
        }, 3000);
    }
});

server.listen(port, BIND_ADDRESS, () => {
    console.log(`[Watchtower Command Center API] Server listening on http://${BIND_ADDRESS}:${port}`);
    console.log(`[Watchtower Command Center API] WebSocket Server attached.`);
    console.log(`[Watchtower Allowlist] enabled=${allowlist.isEnabled()} operator_profile=${allowlist.getOperatorProfileId() || '(unset → fail-closed)'}`);
});