/**
 * WATCHTOWER_API_KEY surrounding whitespace (KB #395 backlog, Watchtower PR #6 follow-up).
 * A padded or CRLF-terminated key must never pass startup and then 401 at request time.
 * The key is trimmed once at load and that one value is used for every compare.
 * Placeholder key only. No live hosts. Never prints a key.
 *
 * Run: node backend/test/operator-key-trim.test.js
 */
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { keysEqual, requireOperatorKey } = require('../auth');
const { request, startApi, TEST_OPERATOR_KEY } = require('./spawn_api');

const KEY = TEST_OPERATOR_KEY;
const CORE = path.join(__dirname, '../../core');
let passed = 0;
let failed = 0;

function check(name, cond, info) {
  if (cond) {
    passed++;
    console.log('  ok  - ' + name);
  } else {
    failed++;
    console.log('  FAIL- ' + name + (info ? '\n        ' + info : ''));
  }
}

(async () => {
  console.log('operator key trim-at-load tests\n');

  // Node: requireOperatorKey returns the trimmed value.
  const padded = '  ' + KEY + '  ';
  const crlf = KEY + '\r\n';
  const tabbed = '\t' + KEY + '\t';
  check('padded key loads as the trimmed key', requireOperatorKey(padded) === KEY);
  check('CRLF-terminated key loads as the trimmed key', requireOperatorKey(crlf) === KEY);
  check('tab-padded key loads as the trimmed key', requireOperatorKey(tabbed) === KEY);
  check('clean key is unchanged', requireOperatorKey(KEY) === KEY);
  const inner = 'abcdefghijklmnop qrstuvwxyz0123456789';
  check('interior whitespace is preserved', requireOperatorKey(inner) === inner);
  check('trimmed client key matches a padded configured key', keysEqual(KEY, requireOperatorKey(padded)) === true);
  check('padded client key still does not match', keysEqual(padded, requireOperatorKey(padded)) === false);

  // Node end to end: backend started with a padded key accepts the trimmed key.
  for (const [label, envKey] of [['padded', padded], ['CRLF', crlf]]) {
    let api;
    try {
      api = await startApi({ WATCHTOWER_API_KEY: envKey });
      const ok = await request(api.port, 'GET', '/api/alerts', { 'x-api-key': KEY });
      check('backend with ' + label + ' key: trimmed key → 200 (no silent 401)', ok.status === 200, String(ok.status));
      const bad = await request(api.port, 'GET', '/api/alerts', { 'x-api-key': KEY.slice(0, -1) + 'Z' });
      check('backend with ' + label + ' key: wrong key → 401', bad.status === 401, String(bad.status));
      check('backend with ' + label + ' key: log does not print the key', !api.log().includes(KEY));
    } catch (err) {
      check('backend with ' + label + ' key starts', false, String(err && err.message ? err.message.split('\n')[0] : err));
    } finally {
      if (api) api.stop();
    }
  }

  // Python clients: require_operator_key() returns the stripped value.
  const py = 'import os\nfrom operator_key import require_operator_key\nprint("MATCH" if require_operator_key() == os.environ["WT_EXPECT"] else "MISMATCH")';
  for (const [label, envKey] of [['padded', padded], ['CRLF', crlf]]) {
    const run = spawnSync('python3', ['-c', py], {
      cwd: CORE,
      env: Object.assign({}, process.env, { WATCHTOWER_API_KEY: envKey, WT_EXPECT: KEY }),
      encoding: 'utf8',
      timeout: 5000,
    });
    const out = (run.stdout || '') + (run.stderr || '');
    check('python client with ' + label + ' key returns the stripped key', run.status === 0 && out.trim() === 'MATCH', String(run.status) + ' ' + out.trim());
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
