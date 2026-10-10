// Property-based fuzzing (fast-check) of the code that reads untrusted text: the shell map, the MCP wrapper's SQL and
// tool-name policy, the strict JSON reader and the strict form reader. Run: cd fuzz && npm ci && npm test
// FUZZ_RUNS raises the number of cases (CI uses the default; a long local run: FUZZ_RUNS=200000 npm test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { classify, normPath, globMatch } from '../sdk/shellmap.mjs';
import { looksLikeSql, words } from '../cli/mcp-policy.mjs';
import { parseStrict, JsonError } from '../cli/mcp-json.mjs';
import { strictForm, paramCopies } from '../server/src/providers.js';
import { readMoneyCall } from '../server/src/money.js';
import { escapeArgument } from '../cli/spawn.mjs';

const numRuns = Number(process.env.FUZZ_RUNS) || 2000;
const opts = { numRuns };
// text that looks like shell: words, quotes, operators, expansions, paths
const shellPiece = fc.oneof(
  fc.constantFrom('rm', '-rf', '/', '~', '.', '..', '*', 'git', 'push', '--force', 'kubectl', 'delete', 'psql', '-c', 'DROP TABLE t', 'curl', '-X', 'DELETE', 'https://api.github.com/repos/a/b', 'echo', 'eval', 'bash', '-c', 'sudo', 'xargs', 'find', '-delete', 'dd', 'of=/dev/sda', 'terraform', 'destroy'),
  fc.constantFrom(' ', ' ', ';', '&&', '||', '|', '&', '\n', '"', "'", '`', '$(', ')', '${', '}', '$X', '\\', '<(', '>', '2>&1', '#', '=', '{', '(', '!'),
  fc.string({ maxLength: 6 }),
);
const shellText = fc.array(shellPiece, { maxLength: 40 }).map((a) => a.join(''));

test('shell map: any text gets an answer, never an exception, and the answer has the documented shape', () => {
  fc.assert(fc.property(fc.oneof(shellText, fc.string({ maxLength: 300 }), fc.string({ unit: 'grapheme', maxLength: 120 })), (cmd) => {
    const r = classify(cmd);
    assert.equal(typeof r.hold, 'boolean');
    assert.ok(Array.isArray(r.hits));
    assert.equal(r.hold, r.hits.length > 0);
    assert.equal(typeof r.unreadable, 'boolean');
    assert.deepEqual(classify(cmd), r, 'the same text gets the same answer');
  }), opts);
});

test('shell map: a destructive command stays held whatever harmless command is put before it', () => {
  const harmless = fc.constantFrom('ls', 'echo hi', 'pwd', 'git status', 'cat README.md', 'true', 'date');
  const glue = fc.constantFrom('; ', ' && ', ' || ', '\n', ' | ', ' & ');
  const bad = fc.constantFrom('rm -rf /', 'git push --force origin main', 'kubectl delete ns prod', 'terraform destroy -auto-approve', 'psql -c "DROP TABLE users"');
  fc.assert(fc.property(fc.array(fc.tuple(harmless, glue), { maxLength: 6 }), bad, (pre, b) => {
    const cmd = pre.map(([h, g]) => h + g).join('') + b;
    assert.equal(classify(cmd).hold, true, cmd);
  }), opts);
});

test('shell map: path helpers never throw and normalise to an absolute path', () => {
  fc.assert(fc.property(fc.array(fc.constantFrom('/', 'a', '.', '..', '//', 'b', '*'), { maxLength: 30 }).map((a) => '/' + a.join('')), (p) => {
    const n = normPath(p);
    assert.ok(n === null || (typeof n === 'string' && n.startsWith('/')), String(n));
    globMatch('/**', p);
  }), opts);
});

test('MCP policy: looksLikeSql and words never throw; words are lower case letters and digits', () => {
  fc.assert(fc.property(fc.oneof(fc.string({ maxLength: 200 }), fc.array(fc.constantFrom(' ', '(', '/*', '*/', '--', '\n', 'select', 'DROP', 'x'), { maxLength: 40 }).map((a) => a.join(''))), (s) => {
    assert.equal(typeof looksLikeSql(s), 'boolean');
    for (const w of words(s)) assert.match(w, /^[a-z0-9]+$/);
  }), opts);
});

test('strict JSON reader: reads what JSON.stringify writes exactly as JSON.parse does, refuses with JsonError otherwise', () => {
  fc.assert(fc.property(fc.jsonValue({ maxDepth: 8 }), (v) => {
    const text = JSON.stringify(v);
    assert.deepEqual(parseStrict(text).value, JSON.parse(text));
  }), opts);
  fc.assert(fc.property(fc.string({ maxLength: 200 }), (s) => {
    try { parseStrict(s); } catch (e) { assert.ok(e instanceof JsonError, `${e?.name}: ${e?.message}`); }
  }), opts);
});

test('strict form reader and the money reader: never throw on any body or query string', () => {
  const formPiece = fc.oneof(fc.constantFrom('amount', 'charge', 'currency', '=', '&', ';', '%', '%61', '[]', '[x]', '+', ' ', 'ch_1234567890', '100', '999999', 'usd', '%26', '%3D'), fc.string({ maxLength: 5 }));
  const form = fc.array(formPiece, { maxLength: 30 }).map((a) => a.join(''));
  fc.assert(fc.property(form, fc.oneof(fc.constant(''), form), (body, search) => {
    const r = strictForm(body, search, ['amount', 'charge', 'currency']);
    assert.ok(r === undefined || (r && typeof r === 'object'));
    paramCopies(body, search, ['amount']);
    for (const kind of ['refund', 'payout']) {
      const m = readMoneyCall(kind, 'application/x-www-form-urlencoded', body, search);
      assert.equal(typeof m.ok, 'boolean');
    }
  }), opts);
});

test('cmd.exe quoting: never lets a metacharacter through unescaped, refuses line breaks', () => {
  fc.assert(fc.property(fc.string({ maxLength: 60 }), (s) => {
    let q;
    try { q = escapeArgument(s, false); } catch (e) { assert.match(e.message, /line break or NUL/); assert.ok(/[\0\r\n]/.test(s)); return; }
    // every cmd.exe metacharacter in the result is preceded by a caret
    for (let i = 0; i < q.length; i++) {
      if (q[i] === '^') { i++; continue; } // a caret escapes the next character
      assert.ok(!'()][%!"`<>&|;, *?'.includes(q[i]), `${JSON.stringify(s)} -> ${q}: unescaped ${q[i]} at ${i}`);
    }
  }), opts);
});
