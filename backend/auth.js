/**
 * Operator API-key compare.
 * Constant-time over the longer input so a length mismatch does not return
 * before the compare. Empty provided or expected keys never match (fail closed).
 */
'use strict';

const crypto = require('crypto');

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

module.exports = { keysEqual };
