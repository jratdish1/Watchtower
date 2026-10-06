/**
 * Operator API-key compare.
 * Constant-time over the longer input so a length mismatch does not return
 * before the compare. Empty provided or expected keys never match (fail closed).
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MIN_OPERATOR_KEY_LENGTH = 32;
const BUILTIN_PLACEHOLDER_KEYS = [
  'WATCHTOWER_DEFAULT_KEY',
  'YOUR_SECRET_API_KEY_HERE',
  'generate_a_secure_random_key_here',
];

function isExampleTemplateName(name) {
  const base = String(name || '').toLowerCase();
  return base === '.env.example'
    || base.endsWith('.example')
    || base.endsWith('.template')
    || base.includes('template');
}

/** Non-empty assignment values and quoted literals. Never logged. */
function literalsInText(text) {
  const out = [];
  String(text || '').split(/\r?\n/).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return;
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (value) out.push(value);
  });
  const quoted = String(text || '').matchAll(/"([^"\\\n]+)"|'([^'\\\n]+)'/g);
  for (const match of quoted) {
    const value = match[1] || match[2];
    if (value) out.push(value);
  }
  return out;
}

function exampleTemplateLiterals(root) {
  const found = new Set(BUILTIN_PLACEHOLDER_KEYS);
  const start = root || path.join(__dirname, '..');
  function walk(dir, depth) {
    if (depth > 6) return;
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_) {
      return;
    }
    entries.forEach((ent) => {
      if (ent.name === 'node_modules' || ent.name === '.git' || ent.name === 'data') return;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(full, depth + 1);
        return;
      }
      if (!isExampleTemplateName(ent.name)) return;
      try {
        literalsInText(fs.readFileSync(full, 'utf8')).forEach((value) => found.add(value));
      } catch (_) {}
    });
  }
  walk(start, 0);
  return found;
}

let _exampleLiterals = null;
function placeholderKeySet() {
  if (!_exampleLiterals) _exampleLiterals = exampleTemplateLiterals();
  return _exampleLiterals;
}

/**
 * Why a configured operator key must not be used.
 * null means the value is acceptable. Never include the key in the reason.
 */
function operatorKeyProblem(raw) {
  if (raw === undefined || raw === null) return 'unset';
  const key = String(raw);
  if (key.length === 0 || key.trim() === '') return 'empty';
  if (placeholderKeySet().has(key.trim())) return 'placeholder';
  if (key.length < MIN_OPERATOR_KEY_LENGTH) return 'too_short';
  return null;
}

/**
 * Accept a private operator key or exit non-zero.
 * The message names the problem and never prints the key.
 */
function requireOperatorKey(raw) {
  const problem = operatorKeyProblem(raw);
  if (!problem) return String(raw);
  const why = {
    unset: 'WATCHTOWER_API_KEY is unset',
    empty: 'WATCHTOWER_API_KEY is empty',
    placeholder: 'WATCHTOWER_API_KEY is a built-in placeholder',
    too_short: 'WATCHTOWER_API_KEY is shorter than ' + MIN_OPERATOR_KEY_LENGTH + ' characters',
  };
  const msg = '[Watchtower] Refusing to start: ' + (why[problem] || 'WATCHTOWER_API_KEY is not usable')
    + '. Set WATCHTOWER_API_KEY to a private value of at least ' + MIN_OPERATOR_KEY_LENGTH + ' characters.\n';
  fs.writeSync(2, msg);
  process.exit(1);
}

function keysEqual(provided, expected) {
  const a = Buffer.from(provided === undefined || provided === null ? '' : String(provided), 'utf8');
  const b = Buffer.from(expected === undefined || expected === null ? '' : String(expected), 'utf8');
  const len = Math.max(a.length, b.length, 1);
  const pa = Buffer.alloc(len);
  const pb = Buffer.alloc(len);
  a.copy(pa);
  b.copy(pb);
  const sameBytes = crypto.timingSafeEqual(pa, pb);
  return sameBytes && a.length === b.length && a.length > 0 && b.length > 0;
}

module.exports = {
  keysEqual,
  operatorKeyProblem,
  requireOperatorKey,
  MIN_OPERATOR_KEY_LENGTH,
  BUILTIN_PLACEHOLDER_KEYS,
  PLACEHOLDER_OPERATOR_KEYS: BUILTIN_PLACEHOLDER_KEYS,
  isExampleTemplateName,
  literalsInText,
  exampleTemplateLiterals,
  placeholderKeySet,
};
