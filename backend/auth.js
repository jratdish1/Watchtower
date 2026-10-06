/**
 * Operator API-key compare.
 * Constant-time over the longer input so a length mismatch does not return
 * before the compare. Empty provided or expected keys never match (fail closed).
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MIN_OPERATOR_KEY_LENGTH = 32;
const PLACEHOLDER_OPERATOR_KEYS = ['WATCHTOWER_DEFAULT_KEY', 'YOUR_SECRET_API_KEY_HERE'];

/**
 * Why a configured operator key must not be used.
 * null means the value is acceptable. Never include the key in the reason.
 */
function operatorKeyProblem(raw) {
  if (raw === undefined || raw === null) return 'unset';
  const key = String(raw);
  if (key.length === 0 || key.trim() === '') return 'empty';
  if (PLACEHOLDER_OPERATOR_KEYS.indexOf(key) !== -1) return 'placeholder';
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
  PLACEHOLDER_OPERATOR_KEYS,
};
