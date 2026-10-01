/**
 * FE-XSS-01 static guard (zero-dependency): every ${...} interpolation inside an
 * innerHTML template literal or an actionButtons/killBtn/selectOpts HTML fragment must be
 * escHtml(...) or a reviewed constant/computed-safe expression. No inline on*="" handler
 * may be built from interpolated data.
 *
 * Run: node frontend/test/xss-static.test.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, '..', 'watchtower.html');
const html = fs.readFileSync(htmlPath, 'utf8');
let passed = 0;
let failed = 0;
function check(name, cond, info) {
  if (cond) { passed++; console.log('  ok  - ' + name); }
  else { failed++; console.log('  FAIL- ' + name + (info ? '\n        ' + info : '')); }
}

// Reviewed safe interpolations: constants, booleans, or values computed only from
// constants (no agent/API-controlled text reaches the DOM through these).
const SAFE = new Set([
  'typeClass',
  'actionButtons',
  'killBtn',
  'selectOpts',
  'bColor',
  "isChecked ? 'checked' : ''",
  "g===hg ? 'selected' : ''",
  'opt.label',
  'opt.id',
  "activeDeviceFilter === id ? 'active' : ''",
  "data.incident_count > 0 ? 'color:var(--danger); font-weight:bold;' : 'color:var(--success);'",
  "event.severity === 'high' ? 'var(--danger)' : event.severity === 'medium' ? 'var(--warning)' : 'var(--success)'",
  "rogueCount > 0 ? `<div style=\"color:var(--danger); font-size:0.7rem; margin-top:4px;\">⚠️ ${escHtml(rogueCount)} Port Density Anomalies!</div>` : ''",
]);

const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
check('inline scripts present', scripts.length > 0);
scripts.forEach((src, i) => {
  let ok = true; let err = '';
  try { new vm.Script(src); } catch (e) { ok = false; err = e.message; }
  check('inline script ' + i + ' parses', ok, err);
});
const js = scripts.join('\n');

check('escHtml helper defined', /function escHtml\(value\)/.test(js));

// Extract top-level ${...} expressions from every template literal (handles one nesting level).
function interpolations(tpl) {
  const out = [];
  let i = 0;
  while ((i = tpl.indexOf('${', i)) !== -1) {
    let depth = 1; let j = i + 2; let inTpl = false;
    while (j < tpl.length && depth > 0) {
      const c = tpl[j];
      if (c === '`') inTpl = !inTpl;
      else if (!inTpl && c === '{') depth++;
      else if (!inTpl && c === '}') depth--;
      j++;
    }
    out.push(tpl.slice(i + 2, j - 1).trim());
    i = j;
  }
  return out;
}

// Template literals that produce HTML: assigned to innerHTML, or html fragment variables.
const tplRe = /(innerHTML\s*\+?=\s*|actionButtons\s*\+?=\s*|killBtn\s*=[^`]*?|selectOpts\s*\+?=\s*)`((?:\\`|\$\{(?:[^{}]|\{[^{}]*\})*\}|[^`])*)`/g;
let tplCount = 0;
const offenders = [];
for (const m of js.matchAll(tplRe)) {
  tplCount++;
  for (const expr of interpolations(m[2])) {
    if (/^escHtml\(/.test(expr) && expr.endsWith(')')) continue;
    if (SAFE.has(expr)) continue;
    offenders.push(expr);
  }
}
check('HTML template literals found (' + tplCount + ')', tplCount >= 15);
check('every HTML interpolation is escHtml() or reviewed-safe', offenders.length === 0,
  'unescaped: ' + JSON.stringify(offenders));

// No inline handler attribute built from interpolated data.
const inlineHandler = /\son[a-z]+="[^"]*\$\{/i;
check('no inline on*= handler built from ${...} data', !inlineHandler.test(js));

// Regression: escHtml behaviour.
const ctx = {};
const helperSrc = js.match(/function escHtml\(value\)[\s\S]*?\n        \}/);
if (helperSrc) vm.runInNewContext(helperSrc[0] + '\nthis.escHtml = escHtml;', ctx);
else ctx.escHtml = () => null;
check('escHtml escapes markup', ctx.escHtml('<img src=x onerror=alert(1)>') === '&lt;img src=x onerror=alert(1)&gt;');
check('escHtml escapes quotes/backtick', ctx.escHtml(`'"\``) === '&#39;&quot;&#96;');
check('escHtml null/undefined -> empty', ctx.escHtml(null) === '' && ctx.escHtml(undefined) === '');
check('escHtml numbers', ctx.escHtml(0) === '0' && ctx.escHtml(42) === '42');

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
