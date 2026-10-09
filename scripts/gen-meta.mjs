#!/usr/bin/env node
// Regenerate site/public/data/meta.json: the irreversible map as GET /v1/meta serves it (without the app origins), kept for
// the website's map tabs when the Worker cannot be reached (site/public/landing.js tries /v1/meta first, then this file).
// Run from the repo root after any change to server/src/providers.js:
//   node scripts/gen-meta.mjs          rewrite the file
//   node scripts/gen-meta.mjs --check  exit 1 if it is out of date (server/test/map-1010.test.js checks this too)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { metaOf } from '../server/src/providers.js';

const FILE = fileURLToPath(new URL('../site/public/data/meta.json', import.meta.url));
const want = JSON.stringify(metaOf());
if (process.argv.includes('--check')) {
  const have = existsSync(FILE) ? readFileSync(FILE, 'utf8') : '';
  if (have !== want) { console.error('site/public/data/meta.json is out of date: run node scripts/gen-meta.mjs'); process.exit(1); }
  console.log('meta.json is current');
} else {
  writeFileSync(FILE, want);
  console.log(`wrote ${FILE} (${want.length} bytes)`);
}
