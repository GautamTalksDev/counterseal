// The files that exist in more than one place are identical, and the SQL part of the shell map is the server's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, COPIES, sqlBlock } from '../../scripts/sync-guard.mjs';
import { readFileSync } from 'node:fs';

test('every copy of a guard file matches its source, and the API map and the SQL block are the server\'s (run: node scripts/sync-guard.mjs)', async () => {
  assert.deepEqual(await check(), []);
  assert.ok(COPIES.length >= 1);
});

test('the SQL block found in both files is the same bytes and is the whole tokenizer', () => {
  const a = sqlBlock(readFileSync(new URL('../../server/src/providers.js', import.meta.url), 'utf8'));
  const b = sqlBlock(readFileSync(new URL('../../sdk/shellmap.mjs', import.meta.url), 'utf8'));
  assert.ok(a && a === b);
  for (const name of ['export function sqlTokens', 'export function sqlReadOnly', 'const SQL_WRITE', 'const SQL_SAFE_FN', 'const SQL_FN']) assert.ok(a.includes(name), name);
  assert.ok(a.length > 3000);
});
