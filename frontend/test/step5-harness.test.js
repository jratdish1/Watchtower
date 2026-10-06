/**
 * Step 5 isolated harness — paper VAO-TASK-20261002-STEP5-HARNESS-PAPER.md
 * rows 1–16. In-process allowlist doubles + a vm DOM for the Glass Pane.
 * No live hosts, no VIC Hermes, no Contabo, no AUTH-01 enrollment.
 *
 * Run: node frontend/test/step5-harness.test.js
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const allowlist = require('../../backend/allowlist');

const htmlPath = path.join(__dirname, '..', 'watchtower.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const scriptMatch = html.match(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
  console.error('inline script missing');
  process.exit(1);
}
const scriptSrc = scriptMatch[1];

function makeEl(id) {
  const el = {
    id: id || '',
    tagName: 'DIV',
    className: '',
    textContent: '',
    value: '',
    disabled: false,
    _html: '',
    children: [],
    attributes: {},
    dataset: {},
    style: {},
    parent: null,
  };
  el.classList = {
    add(...names) {
      const set = new Set(String(el.className || '').split(/\s+/).filter(Boolean));
      names.forEach((n) => set.add(n));
      el.className = [...set].join(' ');
    },
    remove(...names) {
      const drop = new Set(names);
      el.className = String(el.className || '').split(/\s+/).filter((n) => n && !drop.has(n)).join(' ');
    },
    contains(name) {
      return String(el.className || '').split(/\s+/).includes(name);
    },
  };
  Object.defineProperty(el, 'innerHTML', {
    get() { return el._html; },
    set(v) {
      el._html = String(v);
      el.children = [];
    },
  });
  Object.defineProperty(el, 'innerText', {
    get() { return el.textContent || el._html || ''; },
    set(v) { el.textContent = String(v); },
  });
  el.setAttribute = (k, v) => { el.attributes[k] = String(v); };
  el.getAttribute = (k) => (Object.prototype.hasOwnProperty.call(el.attributes, k) ? el.attributes[k] : null);
  el.removeAttribute = (k) => { delete el.attributes[k]; };
  el.addEventListener = () => {};
  el.appendChild = (child) => {
    child.parent = el;
    el.children.push(child);
    return child;
  };
  el.prepend = (child) => {
    child.parent = el;
    el.children.unshift(child);
    return child;
  };
  el.remove = () => {
    if (el.parent) el.parent.children = el.parent.children.filter((c) => c !== el);
  };
  el.querySelector = function querySelector(sel) {
    if (String(this._html).includes('data-fe-reassign') && String(sel).includes('data-fe-reassign')) {
      return makeEl('reassign-select');
    }
    const hits = [];
    walk(this, (node) => {
      if (node !== this && matches(node, sel)) hits.push(node);
    });
    return hits[0] || null;
  };
  el.querySelectorAll = function querySelectorAll(sel) {
    const hits = [];
    walk(this, (node) => {
      if (node !== this && selectorList(sel).some((s) => matches(node, s))) hits.push(node);
    });
    return hits;
  };
  return el;
}

function selectorList(sel) {
  return String(sel).split(',').map((s) => s.trim()).filter(Boolean);
}

function matches(el, sel) {
  if (!sel) return false;
  if (sel.startsWith('#')) return el.id === sel.slice(1);
  if (sel.startsWith('.')) return String(el.className || '').split(/\s+/).includes(sel.slice(1));
  if (sel === '[data-mutate="1"]') return el.attributes['data-mutate'] === '1';
  return false;
}

function walk(node, fn) {
  fn(node);
  (node.children || []).forEach((child) => walk(child, fn));
}

function bootGlass() {
  const byId = new Map();
  const body = makeEl('body');
  const handlers = {};
  const emits = [];
  const document = {
    body,
    createElement() { return makeEl(''); },
    getElementById(id) {
      if (!byId.has(id)) {
        const el = makeEl(id);
        el.id = id;
        if (/btn|button|purge|ota-deploy|fe-/.test(id)) el.tagName = 'BUTTON';
        body.appendChild(el);
        byId.set(id, el);
      }
      return byId.get(id);
    },
    querySelectorAll(sel) {
      const sels = selectorList(sel);
      sels.forEach((s) => {
        if (s.startsWith('#')) document.getElementById(s.slice(1));
      });
      const hits = [];
      walk(body, (node) => {
        if (sels.some((s) => matches(node, s))) hits.push(node);
      });
      return hits;
    },
    querySelector(sel) {
      return document.querySelectorAll(sel)[0] || null;
    },
  };

  const mutateIds = ['fe-purge-vault', 'fe-clear-maps', 'ota-deploy-btn', 'fe-save-infra', 'fe-open-ota'];
  mutateIds.forEach((id) => {
    const el = document.getElementById(id);
    el.tagName = 'BUTTON';
    el.setAttribute('data-mutate', '1');
  });
  document.getElementById('mesh-search').value = '';
  document.getElementById('inv-search').value = '';

  const sandbox = {
    document,
    window: { location: { origin: 'http://127.0.0.1:8080' } },
    console,
    alert() {},
    confirm() { return true; },
    fetch: async () => ({ ok: true, status: 200, json: async () => [] }),
    navigator: { clipboard: { writeText: async () => {} } },
    setTimeout() { return 0; },
    clearTimeout() {},
    io() {
      return {
        connected: true,
        on(event, fn) { handlers[event] = fn; },
        emit(event, payload) { emits.push({ event, payload }); },
      };
    },
    handlers,
    emits,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(scriptSrc, sandbox, { filename: 'watchtower.html' });
  return sandbox;
}

function withAllowlist(fn) {
  const keys = ['WATCHTOWER_ALLOWLIST', 'WATCHTOWER_OPERATOR_PROFILE_ID', 'WATCHTOWER_ALLOWLIST_PATH', 'WATCHTOWER_OTA_ALLOW_ALL'];
  const saved = {};
  keys.forEach((k) => { saved[k] = process.env[k]; });
  try {
    allowlist.resetForTests();
    process.env.WATCHTOWER_ALLOWLIST = '1';
    delete process.env.WATCHTOWER_OPERATOR_PROFILE_ID;
    delete process.env.WATCHTOWER_ALLOWLIST_PATH;
    delete process.env.WATCHTOWER_OTA_ALLOW_ALL;
    allowlist.loadConfig(true);
    return fn();
  } finally {
    keys.forEach((k) => {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    });
    allowlist.resetForTests();
  }
}

function toastText(ui) {
  return ui.document.getElementById('fe-toast-stack').children.map((c) => c.textContent || '').join('\n');
}

function connState(ui) {
  return ui.document.getElementById('connection-status-box').getAttribute('data-state');
}

function resetChrome(ui) {
  ui.operatorPaused = false;
  if (typeof ui.setConnState === 'function') ui.setConnState('conn.online', 'LINK SECURE // MESH ONLINE');
  const stack = ui.document.getElementById('fe-toast-stack');
  stack.children = [];
}

async function expectBlocked(ui, code, via) {
  resetChrome(ui);
  if (via === 'socket') {
    ui.handlers.c2_result({
      action: 'quarantine',
      target: '/tmp/x',
      host: 'fixture-host',
      allowlist_denied: true,
      result: { ok: false, error: code, rule: 'FIXTURE' },
    });
  } else {
    await ui.handleAllowlistResponse({ status: 403 }, { error: code });
  }
  return connState(ui) === 'conn.blocked' && toastText(ui).includes(code);
}

const ROWS = [];

async function runRow(n, title, fn) {
  const ok = [];
  const bad = [];
  const check = (name, cond, info) => {
    if (cond) ok.push(name);
    else bad.push(name + (info ? ' :: ' + info : ''));
  };
  try {
    await fn(check);
  } catch (err) {
    bad.push('threw: ' + (err && err.stack ? err.stack : err));
  }
  const entry = {
    n,
    title,
    status: 'executed',
    passed: ok.length,
    failed: bad.length,
    skipped: 0,
    failures: bad,
  };
  ROWS.push(entry);
  console.log('ROW ' + n + ' ' + title + ' [' + entry.status + '] pass ' + ok.length + ' fail ' + bad.length + ' skip 0');
  ok.forEach((name) => console.log('  ok  - ' + name));
  bad.forEach((name) => console.log('  FAIL- ' + name));
}

(async () => {
  console.log('Step 5 harness (isolated)\n');
  let ui;
  let bootError = null;
  try {
    ui = bootGlass();
  } catch (err) {
    bootError = err;
    console.error('FE boot failed\n' + (err && err.stack ? err.stack : err));
  }

  const deviceGroups = { 'ops-1': 'Ops-Fleet', 'lab-host': 'Builder-Lab' };
  const quietPolicy = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: false, ENABLE_ROLLBACK: true } };
  const auditPolicy = { 'Ops-Fleet': { WATCHTOWER_AUDIT_MODE: true, ENABLE_ROLLBACK: true } };

  await runRow(1, 'Unmapped Default group', async (check) => {
    const deny = withAllowlist(() => allowlist.assertMappedGroup('Default'));
    check('deny allowlist_unmapped_group', deny && deny.error === 'allowlist_unmapped_group' && deny.rule === 'DENY_UNMAPPED_GROUP');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (HTTP)', await expectBlocked(ui, deny.error, 'http'));
    check('FE blocked (socket)', await expectBlocked(ui, deny.error, 'socket'));
  });

  await runRow(2, 'Missing host → group', async (check) => {
    const deny = withAllowlist(() => allowlist.assertC2Command(
      { action: 'refresh', target: '/tmp/x', host: 'ghost-host' },
      deviceGroups,
      quietPolicy,
      'GitHub vets-ops'
    ));
    check('deny allowlist_missing_host_group', deny && deny.error === 'allowlist_missing_host_group');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (socket)', await expectBlocked(ui, deny.error, 'socket'));
  });

  await runRow(3, 'OTA group ALL with flag unset', async (check) => {
    const deny = withAllowlist(() => {
      process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
      return allowlist.assertOtaGroup('ALL');
    });
    check('deny allowlist_ota_all_forbidden', deny && deny.error === 'allowlist_ota_all_forbidden' && deny.rule === 'DENY_OTA_ALL_DEFAULT');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (HTTP)', await expectBlocked(ui, deny.error, 'http'));
  });

  await runRow(4, 'Operator profile not in the group map', async (check) => {
    const deny = withAllowlist(() => allowlist.assertC2Command(
      { action: 'refresh', target: '/tmp/x', host: 'lab-host' },
      deviceGroups,
      { 'Builder-Lab': { WATCHTOWER_AUDIT_MODE: false } },
      'GitHub vets-ops'
    ));
    check('deny allowlist_wrong_profile', deny && deny.error === 'allowlist_wrong_profile' && deny.rule === 'DENY_WRONG_PROFILE');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (HTTP)', await expectBlocked(ui, deny.error, 'http'));
    check('FE blocked (socket)', await expectBlocked(ui, deny.error, 'socket'));
  });

  await runRow(5, 'Operator profile unset on a mapped group', async (check) => {
    const deny = withAllowlist(() => allowlist.assertProfileAllowed('Ops-Fleet'));
    check('fail-closed deny', deny && deny.rule === 'DENY_WRONG_PROFILE' && deny.detail && deny.detail.reason === 'operator_profile_unset');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked', await expectBlocked(ui, deny.error, 'http'));
  });

  await runRow(6, 'Reassign onto unmapped Default', async (check) => {
    const deny = withAllowlist(() => {
      process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
      return allowlist.assertReassign('ops-1', 'Default', deviceGroups);
    });
    check('deny allowlist_reassign_unmapped', deny && deny.error === 'allowlist_reassign_unmapped');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (HTTP)', await expectBlocked(ui, deny.error, 'http'));
  });

  await runRow(7, 'Audit mode kill', async (check) => {
    const deny = withAllowlist(() => {
      process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
      return allowlist.assertC2Command(
        { action: 'kill', target: 'pid:1', host: 'ops-1' },
        deviceGroups,
        auditPolicy
      );
    });
    check('deny allowlist_c2_denied', deny && deny.error === 'allowlist_c2_denied' && deny.rule === 'DENY_C2_ACTION_NOT_ALLOWED');
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('FE blocked (socket)', await expectBlocked(ui, deny.error, 'socket'));
  });

  await runRow(8, 'Omit group from override file', async (check) => {
    withAllowlist(() => {
      allowlist.setConfigForTests({
        host_group_to_profiles: { Default: ['UNMAPPED'] },
        ota: { allow_all: false },
        c2: { destructive_actions: [], audit_blocked_actions: ['kill'] },
        profile_capabilities: {},
      });
      process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
      const d = allowlist.assertMappedGroup('Ops-Fleet');
      check('Ops-Fleet revoked', d && d.rule === 'DENY_UNMAPPED_GROUP');
      const d2 = allowlist.assertProfileAllowed('Builder-Lab', 'Hermes vets-developer');
      check('Builder-Lab not retained from seed', d2 && d2.rule === 'DENY_UNMAPPED_GROUP');
    });
  });

  await runRow(9, 'Allowlist path missing', async (check) => {
    withAllowlist(() => {
      const missing = path.join(os.tmpdir(), 'wt-step5-missing-' + process.pid + '.json');
      try { fs.unlinkSync(missing); } catch (_) {}
      process.env.WATCHTOWER_ALLOWLIST_PATH = missing;
      allowlist.resetForTests();
      const cfg = allowlist.loadConfig(true);
      check('empty map', cfg && Object.keys(cfg.host_group_to_profiles).length === 0);
      process.env.WATCHTOWER_OPERATOR_PROFILE_ID = 'GitHub vets-ops';
      const d = allowlist.assertMappedGroup('Ops-Fleet');
      check('deny, no illustrative fall-open', d && d.rule === 'DENY_UNMAPPED_GROUP');
    });
  });

  await runRow(10, 'Bad profile shape', async (check) => {
    withAllowlist(() => {
      const p = path.join(os.tmpdir(), 'wt-step5-badshape-' + process.pid + '.json');
      fs.writeFileSync(p, JSON.stringify({ host_group_to_profiles: { 'Ops-Fleet': 'GitHub vets-ops' } }));
      process.env.WATCHTOWER_ALLOWLIST_PATH = p;
      allowlist.resetForTests();
      let d;
      check('assert does not throw', (() => {
        try {
          allowlist.loadConfig(true);
          d = allowlist.assertProfileAllowed('Ops-Fleet', 'GitHub vets-ops');
          return true;
        } catch (_) {
          return false;
        }
      })());
      check('deny instead of throw', d && d.rule === 'DENY_UNMAPPED_GROUP');
      fs.unlinkSync(p);
    });
  });

  const hostile = '<img src=x onerror=alert(1)>';
  const escaped = '&lt;img src=x onerror=alert(1)&gt;';

  await runRow(11, 'Hostile markup rendered as text', async (check) => {
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    resetChrome(ui);
    ui.addEventToUI({
      id: 'hostile-1',
      event_type: 'FIM',
      file_path: hostile,
      source: '<script>alert(1)</script>',
      title: '<svg onload=alert(1)>',
      ai_verdict: '"><img src=x>',
      ai_reason: hostile,
      severity: 'high',
    }, true);
    const matrix = ui.document.getElementById('alert-matrix').children.map((c) => c.innerHTML).join('\n');
    const stream = ui.document.getElementById('cognitive-stream').children.map((c) => c.innerHTML).join('\n');
    const rendered = matrix + '\n' + stream;
    check('matrix escapes the img payload', rendered.includes(escaped) && !rendered.includes('<img'));
    check('matrix escapes script source', rendered.includes('&lt;script&gt;alert(1)&lt;/script&gt;') && !rendered.includes('<script'));
    check('matrix escapes svg title', !rendered.includes('<svg'));

    ui.handlers.new_asset_discovered({ id: hostile, data: { incident_count: 1, last_seen: null } });
    const mesh = ui.document.getElementById('mesh-grid').children.map((c) => c.innerHTML).join('\n');
    check('mesh host id escaped', mesh.includes(escaped) && !mesh.includes('<img'));

    ui.handlers.new_inventory_update({
      host: 'lab-host',
      inventory: [{ name: hostile, user: 'u', host: hostile, hash: hostile, uptime: 5 }],
    });
    const inv = ui.document.getElementById('inv-grid').children.map((c) => c.innerHTML).join('\n');
    check('inventory fields escaped', inv.includes(escaped) && !inv.includes('<img'));

    ui.handlers.sync_state({
      alerts: [],
      threats: [],
      assets: {},
      inventory: {},
      groups: { 'Ops-Fleet': {}, Default: {} },
      deviceGroups: { [hostile]: 'Ops-Fleet' },
      synced_at: '2026-10-06T00:00:00Z',
    });
    ui.renderPolicyModal();
    const hosts = ui.document.getElementById('host-enrollment-list').children.map((c) => c.innerHTML).join('\n');
    check('policy host id escaped', hosts.includes(escaped) && !hosts.includes('<img'));

    ui.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => [{ Switch_IP: hostile, Port_Topology: 'clean' }],
    });
    await ui.fetchTopology();
    const topo = ui.document.getElementById('topo-grid').innerHTML;
    check('topology switch name escaped', topo.includes(escaped) && !topo.includes('<img'));
  });

  await runRow(12, 'Partial escHtml wrap rejected by static guard', async (check) => {
    const guard = fs.readFileSync(path.join(__dirname, 'xss-static.test.js'), 'utf8');
    check('guard rejects a closed call plus concatenation', guard.includes('partial escHtml wrap is rejected'));
    const open = 'escHtml(';
    const partial = 'escHtml(event.title) + String(event.file_path)';
    function isEscHtmlWrapped(expr) {
      if (!expr.startsWith(open)) return false;
      let i = open.length;
      let depth = 1;
      while (i < expr.length) {
        const c = expr[i];
        if (c === "'" || c === '"' || c === '`') {
          const q = c;
          i++;
          while (i < expr.length) {
            if (expr[i] === '\\') { i += 2; continue; }
            if (expr[i] === q) { i++; break; }
            i++;
          }
          continue;
        }
        if (c === '(') depth++;
        else if (c === ')') {
          depth--;
          if (depth === 0) return expr.slice(i + 1).trim() === '';
        }
        i++;
      }
      return false;
    }
    check('partial wrap is not wholly wrapped', isEscHtmlWrapped(partial) === false);
    check('full wrap is wholly wrapped', isEscHtmlWrapped('escHtml(event.file_path)') === true);
  });

  await runRow(13, 'No data-built inline on* ; C2 payload byte-exact', async (check) => {
    check('HTML has no inline on* attributes', !/\son[a-z]+\s*=/i.test(html));
    check('script builds no on* attribute from ${}', !/\son[a-z]+="[^"]*\$\{/i.test(scriptSrc));
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    resetChrome(ui);
    ui.emits.length = 0;
    const rawTarget = `quote'"<tag>&`;
    const rawHost = 'host<>&"\'';
    ui.issueCommand('quarantine', rawTarget, rawHost);
    const emitted = ui.emits.filter((e) => e.event === 'c2_command');
    check('one c2_command emitted', emitted.length === 1, JSON.stringify(ui.emits));
    check('target is byte-exact', emitted[0] && emitted[0].payload.target === rawTarget);
    check('host is byte-exact', emitted[0] && emitted[0].payload.host === rawHost);
    check('action is the raw action string', emitted[0] && emitted[0].payload.action === 'quarantine');
  });

  await runRow(14, 'escHtml edges', async (check) => {
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('markup', ui.escHtml('<img src=x onerror=alert(1)>') === '&lt;img src=x onerror=alert(1)&gt;');
    check('quotes and backtick', ui.escHtml(`'"\``) === '&#39;&quot;&#96;');
    check('null and undefined', ui.escHtml(null) === '' && ui.escHtml(undefined) === '');
    check('numbers', ui.escHtml(0) === '0' && ui.escHtml(42) === '42');
  });

  await runRow(15, 'Missing event time → TIME UNKNOWN', async (check) => {
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    check('null', ui.formatStamp(null).display === 'TIME UNKNOWN');
    check('empty', ui.formatStamp('').display === 'TIME UNKNOWN');
    check('unparseable', ui.formatStamp('not-a-time').display === 'TIME UNKNOWN');
    resetChrome(ui);
    ui.document.getElementById('alert-matrix').innerHTML = '';
    ui.addEventToUI({
      id: 'no-time',
      event_type: 'FIM',
      file_path: '/tmp/plain',
      source: 'node-a',
      title: 'quiet',
      ai_verdict: 'OK',
      severity: 'low',
    }, true);
    const card = ui.document.getElementById('alert-matrix').children.map((c) => c.innerHTML).join('\n');
    check('rendered card says TIME UNKNOWN', card.includes('TIME UNKNOWN'));
    resetChrome(ui);
    ui.handlers.c2_result({ ok: true, action: 'refresh', status: 'ok' });
    check('success toast does not invent a stamp', toastText(ui).includes('TIME UNKNOWN'));
  });

  await runRow(16, 'Offline and paused disable mutates', async (check) => {
    if (!ui) return check('fe boot', false, bootError && bootError.message);
    const buttons = () => ui.document.querySelectorAll('[data-mutate="1"]').filter((el) => el.tagName === 'BUTTON');
    check('mutate buttons present', buttons().length > 0);
    ui.handlers.sync_state({
      alerts: [],
      threats: [],
      assets: {},
      inventory: {},
      groups: { 'Ops-Fleet': {} },
      deviceGroups: {},
      synced_at: '2026-10-06T00:00:00Z',
    });
    ui.setConnState('conn.offline', 'LINK LOST // RECONNECTING');
    check('offline disables mutate buttons', buttons().every((el) => el.disabled === true));
    ui.setConnState('conn.online', 'LINK SECURE // MESH ONLINE');
    check('online re-enables mutate buttons', buttons().every((el) => el.disabled === false));
    ui.toggleOperatorPause();
    check('pause disables mutate buttons', connState(ui) === 'conn.paused' && buttons().every((el) => el.disabled === true));
    ui.toggleOperatorPause();
    check('resume re-enables mutate buttons', connState(ui) === 'conn.online' && buttons().every((el) => el.disabled === false));
  });

  const executed = ROWS.filter((r) => r.status === 'executed').length;
  const blocked = ROWS.filter((r) => r.status === 'blocked').length;
  const passed = ROWS.reduce((n, r) => n + r.passed, 0);
  const failed = ROWS.reduce((n, r) => n + r.failed, 0);
  const skipped = ROWS.reduce((n, r) => n + r.skipped, 0);
  console.log('\nMATRIX');
  ROWS.forEach((r) => {
    console.log(
      r.n + '\t' + r.status + '\tpass=' + r.passed + '\tfail=' + r.failed + '\tskip=' + r.skipped + '\t' + r.title
    );
  });
  console.log('STEP5_SUMMARY executed=' + executed + ' blocked=' + blocked + ' passed=' + passed + ' failed=' + failed + ' skipped=' + skipped);
  console.log(passed + ' passed, ' + failed + ' failed, ' + skipped + ' skipped');
  process.exit(failed || ROWS.length !== 16 ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
