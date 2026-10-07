/**
 * Glass Pane response headers.
 *
 * Unavoidable allowances (do not widen these):
 * - style-src-attr 'unsafe-inline': watchtower.html sets presentation with
 *   style="" attributes. A nonce/hash cannot cover those attributes. Moving
 *   every attribute into classes would be a UI rebuild. style-src-attr is the
 *   narrow directive that permits them.
 * - style-src 'unsafe-inline': fallback only for user agents that ignore
 *   style-src-elem / style-src-attr. Browsers that implement those directives
 *   use style-src-elem (nonce, no unsafe-inline) for <style> and <link>, and
 *   style-src-attr for attributes. 'unsafe-inline' on style-src-elem is NOT set.
 * - script-src does NOT use 'unsafe-inline'. The inline program and the
 *   <style> block receive a per-response nonce. Event handlers are bound from
 *   that script (no onclick= attributes).
 * - https://cdn.socket.io/4.7.4/socket.io.min.js is the exact script the page
 *   loads. connect-src 'self' covers same-origin /api fetches and the socket.io
 *   client (window.location.origin). CSP3 'self' matches that origin's http(s)
 *   and ws(s). Host is not reflected into connect-src.
 * - fonts.googleapis.com / fonts.gstatic.com: the existing Inter / Fira Code
 *   stylesheet. No other external origins.
 */
'use strict';

const SOCKET_IO_SCRIPT = 'https://cdn.socket.io/4.7.4/socket.io.min.js';
const FONT_STYLESHEET_ORIGIN = 'https://fonts.googleapis.com';
const FONT_FILE_ORIGIN = 'https://fonts.gstatic.com';

function contentSecurityPolicy(nonce) {
  const scriptSrc = ["'self'", SOCKET_IO_SCRIPT];
  const styleElem = ["'self'", FONT_STYLESHEET_ORIGIN];
  if (nonce) {
    const token = "'nonce-" + nonce + "'";
    scriptSrc.push(token);
    styleElem.push(token);
  }
  const directives = [
    "default-src 'self'",
    'script-src ' + scriptSrc.join(' '),
    "style-src 'self' 'unsafe-inline' " + FONT_STYLESHEET_ORIGIN,
    'style-src-elem ' + styleElem.join(' '),
    "style-src-attr 'unsafe-inline'",
    "font-src 'self' " + FONT_FILE_ORIGIN,
    "img-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ];
  return directives.join('; ');
}

function securityHeaders(nonce) {
  return {
    'Content-Security-Policy': contentSecurityPolicy(nonce),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

module.exports = {
  SOCKET_IO_SCRIPT,
  FONT_STYLESHEET_ORIGIN,
  FONT_FILE_ORIGIN,
  contentSecurityPolicy,
  securityHeaders,
};
