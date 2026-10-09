// One brand, one place: server/src/brand.js. The rebrand script has been run for the current values, the site's
// constants file is generated from it, every page shows the wordmark, and the three old product names are gone from
// user-facing text (internal identifiers such as LEASH_TOKENS, x-leash and lsh_ stay on purpose).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BRAND, LOG_ORIGIN_DEFAULT } from '../src/brand.js';
import { files, brandModule, KEYS } from '../../scripts/rebrand.mjs';
import { rp } from '../src/auth.js';

const ROOT = new URL('../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');

test('the rebrand script is in step with brand.js', () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('scripts/rebrand.mjs', ROOT)), '--check'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(read('site/public/brand.js'), brandModule());
  const lock = JSON.parse(read('brand.lock.json'));
  for (const k of KEYS) assert.equal(lock[k], BRAND[k], k);
});

test('the server takes its names from brand.js', () => {
  assert.equal(rp({}).name, BRAND.name);
  assert.match(LOG_ORIGIN_DEFAULT, /^[\x21-\x7e]+\/log$/);
  assert.match(read('server/wrangler.jsonc'), new RegExp(`"LOG_ORIGIN": "${LOG_ORIGIN_DEFAULT.replace(/\./g, '\\.')}"`), 'the deployed log name matches the frozen default');
});

test('user-facing text carries the brand and none of the three old product names', () => {
  const OLD = /\b(LEASH|WITNESS|SIGIL|Leash|Witness|Sigil)\b(?![_-])/;
  const bad = [];
  for (const f of files()) {
    const rel = f.slice(fileURLToPath(ROOT).length);
    const lines = readFileSync(f, 'utf8').split('\n');
    lines.forEach((l, i) => {
      // allowed: environment variable names, history notes that say where code came from
      if (OLD.test(l.replace(/\bLEASH_[A-Z_]+\b/g, '')) && !/brand:history/.test(l)) bad.push(`${rel}:${i + 1}: ${l.trim().slice(0, 120)}`);
    });
    if (/\.html$/.test(f) && !/404\.html$/.test(f)) assert.ok(readFileSync(f, 'utf8').includes(`</svg>${BRAND.wordmark}</a>`), rel + ' shows the wordmark');
  }
  assert.deepEqual(bad, []);
});
