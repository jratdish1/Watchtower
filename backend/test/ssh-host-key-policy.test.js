'use strict';
// Static guard: Python SSH clients must not trust unknown host keys.
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..', '..');
let pass = 0, fail = 0;
const check = (name, ok) => { if (ok) pass++; else { fail++; console.error('FAIL ' + name); } };
const pyFiles = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p); else if (e.name.endsWith('.py')) pyFiles.push(p);
  }
})(root);
check('found python files to scan', pyFiles.length > 0);
for (const f of pyFiles) {
  const src = fs.readFileSync(f, 'utf8');
  const rel = path.relative(root, f);
  check(rel + ': no AutoAddPolicy', !/AutoAddPolicy/.test(src));
  check(rel + ': no WarningPolicy', !/WarningPolicy/.test(src));
}
const scraper = fs.readFileSync(path.join(root, 'core', 'watchtower_net_scraper.py'), 'utf8');
check('scraper loads system host keys', /client\.load_system_host_keys\(\)/.test(scraper));
check('scraper sets RejectPolicy', /set_missing_host_key_policy\(paramiko\.RejectPolicy\(\)\)/.test(scraper));
check('RejectPolicy is set before connect', scraper.indexOf('RejectPolicy') < scraper.indexOf('client.connect('));
console.log(pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
