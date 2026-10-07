/**
 * Socket-address allowlist for the API.
 * Shared CGNAT space is 100.64.0.0/10 (RFC 6598), not a substring match on "100.".
 */
'use strict';

function ipv4ToInt(ip) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!match) return null;
  const parts = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function inCidr(ip, baseIp, bits) {
  const addr = ipv4ToInt(ip);
  const base = ipv4ToInt(baseIp);
  if (addr === null || base === null) return false;
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  return (addr & mask) === (base & mask);
}

function ipAllowed(ip) {
  const raw = ip === undefined || ip === null ? '' : String(ip);
  if (raw === '127.0.0.1' || raw === '::1' || raw === '::ffff:127.0.0.1') return true;
  if (raw === '169.254.204.75' || raw === '::ffff:169.254.204.75') return true;
  const v4 = raw.startsWith('::ffff:') ? raw.slice('::ffff:'.length) : raw;
  return inCidr(v4, '100.64.0.0', 10);
}

module.exports = { ipAllowed, inCidr, ipv4ToInt };
