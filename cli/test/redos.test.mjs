// Worst-case timing for every regex CodeQL reported as (polynomial) ReDoS, after the rewrite to linear-time code, and
// the same answers as the old regexes on ordinary and random inputs. Each worst case is far larger than any real input and
// must finish in well under a second (the old forms took seconds to hours on these).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { looksLikeSql } from '../mcp-policy.mjs';
import { escapeArgument, plan } from '../spawn.mjs';
import { posixPath, loadConfig } from '../guard.mjs';
import { loadGuard } from '../mcp-ask.mjs';
import { classify } from '../shellmap.mjs';
import { Receipts } from '../../sdk/receipts.mjs';

const BUDGET_MS = 250;
const timed = (label, fn) => {
  const t0 = performance.now();
  const r = fn();
  const ms = performance.now() - t0;
  assert.ok(ms < BUDGET_MS, `${label} took ${ms.toFixed(1)} ms`);
  return r;
};

// the regexes as they were, used only as a reference on small inputs
const OLD_SQL_START = /^(?:\s+|\/\*[\s\S]*?\*\/|--[^\n]*(?:\n|$)|\()*(select|with|insert|update|delete|drop|create|alter|truncate|grant|revoke|merge|replace|upsert|call|do|exec|execute|copy|vacuum|reindex|analyze|set|reset|begin|commit|rollback|savepoint|pragma|attach|detach|lock|show|explain|values|table|use|load|import|refresh|cluster|comment|notify|listen|prepare|deallocate)\b/i;
const oldQuote = (arg) => String(arg).replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1');
const newQuote = (arg) => escapeArgument(arg, false).replace(/\^(.)/g, '$1').slice(1, -1);

// a small deterministic generator (no dependency): xorshift32
const rng = (seed) => () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) / 2 ** 32; };
const pick = (r, a) => a[Math.floor(r() * a.length)];

test('looksLikeSql: linear on long runs of space, comments and parentheses', () => {
  const n = 200_000;
  for (const [label, s] of [
    ['spaces then no keyword', ' '.repeat(n) + '!'],
    ['tabs and newlines', '\t\n'.repeat(n / 2) + '!'],
    ['parentheses', '('.repeat(n) + '!'],
    ['many closed comments', '/**/'.repeat(n / 4) + '!'],
    ['an unclosed comment', '/*' + ' '.repeat(n)],
    ['line comments', '--x\n'.repeat(n / 4) + '!'],
    ['unicode space', '\u00a0'.repeat(n) + '!'],
    ['comment ends then line comments', '/*' + '*/--'.repeat(n / 4) + '!'],
    ['many possible comment ends', '/*' + ' */'.repeat(n / 3) + '!'],
    ['nested openings', '/*'.repeat(n / 2) + '!'],
  ]) assert.equal(timed(label, () => looksLikeSql(s)), false, label);
  assert.equal(timed('a keyword after a long prefix', () => looksLikeSql(' '.repeat(n) + '(/* c */ DROP TABLE x')), true);
});

test('looksLikeSql: same answers as the old regex', () => {
  for (const s of ['select 1', '  SELECT 1', '(select 1)', '/* c */ drop table t', '-- c\ninsert into t', '-- only a comment', '/* open', 'selection', 'find cats', '', 'with x as (select 1) select 1', '\u00a0\u2003update t', 'deleted rows', 'DO $$ $$', '/* /* */ */ drop table t', ' /**/( */select', '--a\n--b\n(select', '--a--\nselect']) {
    assert.equal(looksLikeSql(s), OLD_SQL_START.test(s), JSON.stringify(s));
  }
  const r = rng(0x5eed);
  const parts = [' ', '\t', '\n', '(', ')', '/*', '*/', '--', 'select', 'Drop', 'x', ';', 'selectx', '\u00a0', '*', '/', '-'];
  for (let i = 0; i < 20_000; i++) {
    let s = '';
    for (let k = Math.floor(r() * 8); k >= 0; k--) s += pick(r, parts);
    assert.equal(looksLikeSql(s), OLD_SQL_START.test(s), JSON.stringify(s));
  }
}); 

test('escapeArgument: linear on long runs of backslashes, same quoting as before', () => {
  const n = 500_000;
  timed('backslashes then a quote', () => escapeArgument('\\'.repeat(n) + '"', true));
  timed('backslashes then a letter', () => escapeArgument('\\'.repeat(n) + 'x', true));
  timed('only backslashes', () => escapeArgument('\\'.repeat(n), true));
  for (const s of ['', 'a', 'a b', 'a"b', 'a\\"b', 'a\\\\"b', 'end\\', 'end\\\\', '\\"\\', 'C:\\Program Files\\x\\', '100%', '"quoted"', '\u00e9\\']) {
    assert.equal(newQuote(s), oldQuote(s), JSON.stringify(s));
  }
  const r = rng(0xbeef);
  for (let i = 0; i < 20_000; i++) {
    let s = '';
    for (let k = Math.floor(r() * 10); k >= 0; k--) s += pick(r, ['\\', '"', 'a', ' ', '%', '^', '&', '\u00e9']);
    assert.equal(newQuote(s), oldQuote(s), JSON.stringify(s));
  }
});

test('spawn on Windows never puts a line break or NUL into a cmd.exe line', () => {
  const opts = { platform: 'win32', env: { PATH: 'C:\\bin', PATHEXT: '.CMD' }, cwd: 'C:\\w', exists: (f) => f.toLowerCase() === 'c:\\bin\\npx.cmd' };
  assert.ok(plan('npx', ['-y', 'pkg'], opts).verbatim, 'a .cmd shim runs through cmd.exe');
  for (const bad of ['a\nb', 'a\r\nb', 'a\rb', 'a\0b', '"&calc\n']) assert.throws(() => plan('npx', ['-y', bad], opts), /line break or NUL/, JSON.stringify(bad));
  assert.throws(() => escapeArgument('x\ny'), /line break or NUL/);
  // the metacharacters cmd.exe knows are escaped, so they stay text
  const line = plan('npx', ['a&b|c>d<e^f%g!h'], opts).args[3];
  assert.ok(!/[^^][&|<>]/.test(line.replace(/\^\^/g, '')), line);
});

test('trailing slashes are trimmed in linear time everywhere a server address or path is read', () => {
  const many = '/'.repeat(200_000);
  assert.equal(timed('posixPath', () => posixPath('C:\\x' + many + 'y' + many)), '/c/x' + many + 'y');
  assert.equal(timed('posixPath drive', () => posixPath('C:\\' + many)), '/c');
  const cfg = timed('guard config server', () => loadConfig({ HOME: '/nonexistent-home' }, { readJson: () => ({ server: 'https://example.test' + many + 'x' + many }) }));
  assert.equal(cfg.server, 'https://example.test' + many + 'x');
  const key = 'lsg_' + 'a'.repeat(43);
  timed('MCP wrapper server', () => loadGuard({ LEASH_GUARD_KEY: key, LEASH_URL: 'https://example.test' + many + 'x' + many }, () => null));
  assert.equal(loadGuard({ LEASH_GUARD_KEY: key, LEASH_URL: 'https://example.test///' }, () => null).server, 'https://example.test');
  const rc = timed('Receipts url', () => new Receipts({ key: 'lsr_x', url: 'https://example.test' + many + 'x' + many }));
  assert.equal(rc.url, 'https://example.test' + many + 'x');
  assert.equal(new Receipts({ key: 'lsr_x', url: 'https://example.test///' }).url, 'https://example.test');
});

test('the shell map reads path names with many slashes in linear time', () => {
  const many = '/'.repeat(50_000);
  for (const cmd of [`rm -rf "$(basename ${many}x${many})"`, `rm -rf "$(dirname ${many}x${many}y)"`, `${many}bin${many}rm -rf /`, `ls ${many}a${many} | xargs rm`, `rm -rf ${many}x${many}y`, `rm -rf ${many}x${many}*`, `rm -rf ${many}x${many}.*`, `rm -rf ./${"*".repeat(50_000)}`]) {
    const r = timed(cmd.slice(0, 30), () => classify(cmd));
    assert.ok(r && typeof r === 'object', 'an answer');
  }
});
