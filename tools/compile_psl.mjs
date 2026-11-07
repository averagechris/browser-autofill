// Offline compilation of the pinned PSL, including ICANN and PRIVATE rules.
import { readFileSync, writeFileSync } from 'node:fs';
const source = new URL('../hardened/vendor/public_suffix_list.dat', import.meta.url);
const rules = readFileSync(source, 'utf8').split(/\r?\n/).map(line => line.trim().split(/\s+/)[0]).filter(line => line && !line.startsWith('//')).map(rule => {
  const prefix = rule.startsWith('!') ? '!' : rule.startsWith('*.') ? '*.' : '';
  const hostname = new URL(`https://${rule.slice(prefix.length)}`).hostname;
  if (!hostname || hostname.endsWith('.') || !/^[a-z0-9.-]+$/.test(hostname)) throw Error('Invalid PSL rule');
  return prefix + hostname;
});
writeFileSync(new URL('../hardened/vendor/public-suffix-rules.js', import.meta.url), '// Derived from public_suffix_list.dat. SPDX-License-Identifier: MPL-2.0\n// See PSL-LICENSE and PSL-PROVENANCE.json. Regenerate with tools/compile_psl.mjs.\nexport default ' + JSON.stringify(rules) + ';\n');
