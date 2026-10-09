#!/usr/bin/env node
// Keeps the copies of the guard files in step with their sources.
//   node scripts/sync-guard.mjs           write the copies
//   node scripts/sync-guard.mjs --check   exit 1 if a copy differs (CI and server/test run this)
//
//   sdk/shellmap.mjs                      the shell map. Its SQL part is a verbatim copy of the SQL part of
//                                         server/src/providers.js (checked here), so both read SQL the same way.
//   cli/shellmap.mjs                      the copy the npm package ships (the SDK is not published)
//   plugins/counterseal/scripts/*.mjs     the plugin runs pinned copies of the CLI files, never npx at hook time
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const SQL_HEAD = '// ---------------------------------------------------------------- SQL\n';
export const SQL_TAIL = 'export const sqlDestructive = (sql) => !sqlReadOnly(sql);';
/** the SQL tokenizer and read-only classifier, from its heading to sqlDestructive */
export function sqlBlock(text) {
  const a = text.indexOf(SQL_HEAD), b = text.indexOf(SQL_TAIL);
  return a < 0 || b < a ? null : text.slice(a, b + SQL_TAIL.length);
}
export const COPIES = [
  ['sdk/shellmap.mjs', 'cli/shellmap.mjs'],
  ['cli/guard.mjs', 'plugins/counterseal/scripts/guard.mjs'],
  ['cli/shellmap.mjs', 'plugins/counterseal/scripts/shellmap.mjs'],
  ['cli/leash.mjs', 'plugins/counterseal/scripts/leash.mjs'],
  ['cli/sign.mjs', 'plugins/counterseal/scripts/sign.mjs'],
];
const read = (p) => readFileSync(join(ROOT, p), 'utf8');

/** a list of problems; empty when everything is in step */
export function check() {
  const bad = [];
  const server = sqlBlock(read('server/src/providers.js')), guard = sqlBlock(read('sdk/shellmap.mjs'));
  if (!server) bad.push('server/src/providers.js: the SQL block was not found');
  else if (!guard) bad.push('sdk/shellmap.mjs: the SQL block was not found');
  else if (server !== guard) bad.push('sdk/shellmap.mjs: its SQL block differs from server/src/providers.js (copy it over, byte for byte)');
  for (const [from, to] of COPIES) {
    if (!existsSync(join(ROOT, to))) bad.push(`${to}: missing (run node scripts/sync-guard.mjs)`);
    else if (read(from) !== read(to)) bad.push(`${to}: differs from ${from} (run node scripts/sync-guard.mjs)`);
  }
  return bad;
}
export function sync() {
  for (const [from, to] of COPIES) {
    mkdirSync(dirname(join(ROOT, to)), { recursive: true });
    writeFileSync(join(ROOT, to), read(from));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--check')) {
    const bad = check();
    if (bad.length) { console.error(bad.join('\n')); process.exit(1); }
    console.log('guard copies in step');
  } else {
    sync();
    const bad = check();
    if (bad.length) { console.error(bad.join('\n')); process.exit(1); }
    console.log(`wrote ${COPIES.length} copies`);
  }
}
