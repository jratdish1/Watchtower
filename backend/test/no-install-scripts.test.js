'use strict';
// A14: CI installs with `npm ci --ignore-scripts`. No dependency in either
// lockfile needs an install script today, so lifecycle scripts only add risk
// (a hijacked package could run code on the CI runner). This ratchet fails if
// a dependency starts needing install scripts, or if CI drops the flag.
const fs = require('fs');
const path = require('path');

const repo = path.join(__dirname, '..', '..');
let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name + (detail ? ' :: ' + detail : '')); }
}

for (const dir of ['backend', 'frontend']) {
  const lockPath = path.join(repo, dir, 'package-lock.json');
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  const pkgs = lock.packages || {};
  const withScripts = Object.keys(pkgs).filter((k) => k && pkgs[k] && pkgs[k].hasInstallScript);
  check(`${dir}/package-lock.json has lockfileVersion >= 2`, Number(lock.lockfileVersion) >= 2, String(lock.lockfileVersion));
  check(`${dir}: no dependency needs an install script`, withScripts.length === 0, withScripts.join(', '));
}

const ci = fs.readFileSync(path.join(repo, '.github', 'workflows', 'ci.yml'), 'utf8');
const installLines = ci.split('\n').filter((l) => /\bnpm\s+(ci|install|i)\b/.test(l));
check('ci.yml runs npm ci for backend and frontend', installLines.length >= 2, String(installLines.length));
for (const l of installLines) {
  check(`ci.yml install uses --ignore-scripts: ${l.trim()}`, /--ignore-scripts\b/.test(l));
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
