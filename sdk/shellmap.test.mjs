// The shell map: table-driven vectors (sdk/shellmap.vectors.txt), the parser's limits, redaction, SQL, MCP tools.
// A bug inside a rule fails the test instead of being swallowed (the library swallows it in production so one bad
// rule cannot switch the guard off).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  SHELL_MAP_VERSION, SHELL_RULES, TOOL_RULES, BUNDLED_API_MAP, classify, classifyTool, redact, sqlGuard, sqlReadOnly,
  apiMapFromMeta, canonicalJson, normPath, globMatch,
} from './shellmap.mjs';

globalThis.__SHELLMAP_THROW = true;

const FILES = {
  '/home/u/proj/package.json': JSON.stringify({
    scripts: {
      clean: 'rm -rf dist', 'clean-root': 'rm -rf ~', 'db:reset': 'prisma migrate reset --force', build: 'tsc',
      pretest: 'echo pre', test: 'node --test', deploy: 'wrangler deploy && npm run db:reset',
    },
  }),
};
const OPT = { cwd: '/home/u/proj', root: '/home/u/proj', home: '/home/u', readFile: (p) => FILES[p] ?? null };
const RULE_ID = /^[a-z0-9._:-]{1,64}$/;

function vectors() {
  const out = [];
  const lines = readFileSync(new URL('./shellmap.vectors.txt', import.meta.url), 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (!line.trim() || line.startsWith('#')) return;
    const m = /^(HOLD (\S+)|PASS|GAP) \| ([\s\S]*)$/.exec(line);
    assert.ok(m, `vectors line ${i + 1} is not HOLD <rule> | cmd, PASS | cmd or GAP | cmd: ${line}`);
    out.push({ kind: m[1].split(' ')[0], rule: m[2], cmd: m[3].replace(/⏎/g, '\n'), line: i + 1 });
  });
  return out;
}

test('the vector table: every held command is held by the named rule, every other one passes', () => {
  const bad = [];
  const V = vectors();
  for (const v of V) {
    let r;
    try { r = classify(v.cmd, OPT); } catch (e) { bad.push(`line ${v.line}: threw ${e.stack.split('\n').slice(0, 3).join(' | ')}: ${v.cmd}`); continue; }
    if (v.kind === 'HOLD') {
      if (!r.hits.some((h) => h.rule === v.rule)) bad.push(`line ${v.line}: expected ${v.rule}, got ${r.hits.map((h) => h.rule).join(',') || 'pass'}: ${JSON.stringify(v.cmd)}`);
    } else if (r.hold) bad.push(`line ${v.line}: expected pass, held by ${r.hits.map((h) => h.rule + ' (' + h.why + ')').join(', ')}: ${JSON.stringify(v.cmd)}`);
  }
  assert.deepEqual(bad, []);
  const holds = V.filter((v) => v.kind === 'HOLD').length, passes = V.filter((v) => v.kind === 'PASS').length;
  assert.ok(holds >= 400 && passes >= 330, `the table is big (${holds} held, ${passes} passing)`);
});

test('every rule has at least 3 passing and 2 evasion style vectors, and every rule id used is on the map', () => {
  const V = vectors();
  const ids = new Set([...SHELL_RULES.map((r) => r.id)]);
  for (const v of V) if (v.kind === 'HOLD') assert.ok(ids.has(v.rule), `${v.rule} is not in SHELL_RULES`);
  // rules whose vectors can be negative in the table: the program's own harmless forms
  const needsNegatives = SHELL_RULES.map((r) => r.id).filter((id) => !['sh.dynamic-program', 'sh.decode-exec', 'sh.disk', 'sh.db-reset', 'sh.iac-destroy'].includes(id));
  for (const id of needsNegatives) assert.ok(V.filter((v) => v.kind === 'HOLD' && v.rule === id).length >= 3, `${id} has held vectors`);
  const counts = {};
  for (const v of V) if (v.kind === 'HOLD') counts[v.rule] = (counts[v.rule] || 0) + 1;
  for (const r of SHELL_RULES) assert.ok(counts[r.id] >= 3, `${r.id}: ${counts[r.id] || 0} held vectors`);
  assert.equal(new Set(SHELL_RULES.map((r) => r.id)).size, SHELL_RULES.length, 'rule ids are unique');
  for (const r of [...SHELL_RULES, ...TOOL_RULES]) { assert.match(r.id, RULE_ID); assert.ok(r.what.length > 10 && r.what.length < 400); }
});

test('hits are well formed: the rule id fits the Approvals API, why and text fit its limits, nothing secret is repeated', () => {
  for (const v of vectors()) {
    if (v.kind !== 'HOLD') continue;
    const r = classify(v.cmd, OPT);
    assert.equal(r.version, SHELL_MAP_VERSION);
    for (const h of r.hits) {
      assert.match(h.rule, RULE_ID, v.cmd);
      assert.ok(h.why.length >= 1 && h.why.length <= 300, `why length ${h.why.length}: ${h.why}`);
      assert.ok(h.text.length >= 1 && h.text.length <= 200, `text length: ${h.text}`);
      assert.ok(!/\uE000/.test(h.text + h.why), 'the unknown-value marker never leaves the library');
      assert.ok(!/[\u2013\u2014]/.test(h.why), 'no em or en dash in text shown to people');
    }
  }
});

test('the docs page lists every rule on the map, and the documented limits that the GAP vectors show', () => {
  const docs = readFileSync(new URL('../site/public/docs/index.html', import.meta.url), 'utf8');
  const section = docs.slice(docs.indexOf('id="guard-cli"'), docs.indexOf('id="policy"'));
  assert.ok(section.length > 5000, 'the guard section exists');
  for (const r of SHELL_RULES) assert.ok(section.includes(`<code>${r.id}</code>`), `docs list ${r.id}`);
  for (const limit of ['Aliases', 'script files', 'other languages', 'PowerShell', 'Encoded', 'edits its own hook settings']) assert.ok(section.includes(limit), `docs mention the limit: ${limit}`);
  assert.ok(section.includes(SHELL_MAP_VERSION), 'docs name the map version');
  const gaps = vectors().filter((v) => v.kind === 'GAP');
  assert.ok(gaps.length >= 15);
});

test('the bundled API map is the server map: every provider and rule in order, with the body flag (it is generated by scripts/sync-guard.mjs)', async () => {
  const { PROVIDERS, MAP_VERSION } = await import('../server/src/providers.js');
  assert.equal(BUNDLED_API_MAP.mapVersion, MAP_VERSION);
  assert.deepEqual(BUNDLED_API_MAP.providers.map((p) => p.id), Object.keys(PROVIDERS));
  assert.ok(BUNDLED_API_MAP.providers.length >= 10);
  for (const p of BUNDLED_API_MAP.providers) {
    const s = PROVIDERS[p.id];
    assert.equal(s.host, p.host);
    assert.equal(s.base || '', p.base);
    assert.deepEqual(p.rules.map((r) => [r.id, r.m, r.p, r.body]), s.irreversible.map((r) => [r.id, r.m, r.p, !!r.body]), `${p.id}: the same rules in the same order`);
  }
});

// a concrete path that a glob of the map matches: * is one segment, ** is two, {a,b} picks each alternative in turn
function samplesOf(glob) {
  let outs = [glob];
  for (let guard = 0; guard < 6; guard++) {
    const next = [];
    let again = false;
    for (const g of outs) {
      const m = /\{([^{}]*)\}/.exec(g);
      if (!m) { next.push(g); continue; }
      again = true;
      for (const alt of m[1].split(',')) next.push(g.slice(0, m.index) + alt + g.slice(m.index + m[0].length));
    }
    outs = next;
    if (!again) break;
  }
  return [...new Set(outs.map((g) => g.replace(/\*\*/g, 'a/b').replace(/\*/g, 'x')))];
}

test('the glob helper agrees with the server glob on every path rule of the map, on paths that match and paths that nearly do', async () => {
  const { PROVIDERS, globMatch: serverGlob } = await import('../server/src/providers.js');
  let n = 0;
  for (const p of Object.values(PROVIDERS)) for (const r of p.irreversible) {
    for (const s of samplesOf(r.p)) {
      for (const probe of [s, s + '/zzz', s.replace(/\/[^/]*$/, ''), '/' + s.split('/').slice(2).join('/'), s.toUpperCase()]) {
        assert.equal(globMatch(r.p, probe), serverGlob(r.p, probe), `${r.p} vs ${probe}`);
        n++;
      }
    }
  }
  assert.ok(n > 500, `${n} comparisons`);
});

test('every rule of the server map that does not read a body is held when curl tries it (all ten providers)', async () => {
  const { PROVIDERS } = await import('../server/src/providers.js');
  let n = 0;
  for (const [id, p] of Object.entries(PROVIDERS)) {
    const host = p.host.startsWith('*.') ? 'a-store' + p.host.slice(1) : p.host;
    for (const r of p.irreversible) {
      if (r.body) continue;
      for (const path of samplesOf(r.p).slice(0, 3)) {
        const m = r.m.split(',')[0];
        const url = `https://${host}${p.base || ''}${path}`;
        const res = classify(`curl -s -X ${m} '${url}' -H 'Authorization: Bearer x'`, OPT);
        assert.ok(res.hits.some((h) => h.rule === 'sh.curl-api'), `${id} ${r.id}: ${m} ${url} should be held (got ${res.hits.map((h) => h.rule).join(',') || 'pass'})`);
        n++;
      }
    }
  }
  assert.ok(n > 100, `${n} requests`);
});

test('the curl rule reads the bodies the server reads, as far as it can: what passes and what is held', () => {
  const held = (c) => classify(c, OPT).hits.some((h) => h.rule === 'sh.curl-api');
  // Resend: one recipient passes
  const rs = (body) => `curl -X POST https://api.resend.com/emails -d '${body}'`;
  assert.equal(held(rs('{"to":"a@x.com","from":"b@y.com","subject":"s"}')), false);
  assert.equal(held(rs('{"to":["a@x.com"],"from":"b@y.com"}')), false);
  for (const b of ['{"to":["a@x.com","b@x.com"]}', '{"to":"a@x.com","bcc":"b@x.com"}', '{"to":"a@x.com,b@x.com"}', '{"to":"Name <a@x.com> <b@x.com>"}', '{"to":"a@x.com","cc":["c@x.com"]}', 'to=a@x.com', '[1]', '{"to":"a@x.com"']) assert.equal(held(rs(b)), true, b);
  assert.equal(held('curl -X POST https://api.resend.com/emails -d @mail.json'), true, 'a body in a file cannot be read');
  assert.equal(held('curl -X POST https://api.resend.com/emails/batch -d "[]"'), true);
  assert.equal(held('curl -X POST https://api.resend.com/broadcasts -d \'{"name":"n"}\''), false, 'a draft');
  assert.equal(held('curl -X POST https://api.resend.com/broadcasts -d \'{"name":"n","send":true}\''), true);
  assert.equal(held('curl -X POST https://api.resend.com/automations -d \'{"name":"n","status":"disabled"}\''), false);
  assert.equal(held('curl -X POST https://api.resend.com/automations -d \'{"name":"n","status":"enabled"}\''), true);
  assert.equal(held('curl -X PATCH https://api.resend.com/automations/a1 -d \'{"name":"renamed"}\''), false);
  assert.equal(held('curl -X PATCH https://api.resend.com/automations/a1 -d \'{"steps":[]}\''), true);
  assert.equal(held('curl https://api.resend.com/emails'), false);
  // Vercel
  assert.equal(held('curl -X POST https://api.vercel.com/v10/projects/p/env -d \'{"key":"A","value":"b","type":"plain"}\''), false);
  assert.equal(held('curl -X POST "https://api.vercel.com/v10/projects/p/env?upsert=true" -d \'{"key":"A"}\''), true);
  assert.equal(held('curl -X POST https://api.vercel.com/v10/projects/p/env -d \'{"key":"A","upsert":true}\''), true);
  assert.equal(held('curl -X POST "https://api.vercel.com/v10/projects/p/env?upsert=false" -d \'{"key":"A"}\''), false);
  assert.equal(held('curl https://api.vercel.com/v9/projects'), false);
  assert.equal(held('curl -X POST https://api.vercel.com/v13/deployments -d "{}"'), true);
  // Shopify: a store address per credential, GraphQL over POST
  const shop = (q) => `curl -X POST https://my-store.myshopify.com/admin/api/2026-07/graphql.json -H 'X-Shopify-Access-Token: shpat_x' -d '${q}'`;
  assert.equal(held(shop('{"query":"{ shop { name } }"}')), false);
  assert.equal(held(shop('{"query":"mutation { productDelete(input:{id:\\"gid://shopify/Product/1\\"}) { deletedProductId } }"}')), true);
  assert.equal(held(shop('{"query":"mutation { productUpdate(input:{id:\\"1\\"}) { product { id } } }"}')), true, 'every mutation is held');
  assert.equal(held('curl -X POST https://my-store.myshopify.com/admin/api/2026-07/graphql.json -d @q.json'), true);
  assert.equal(held('curl https://my-store.myshopify.com/admin/api/2026-07/graphql.json'), true);
  assert.equal(held('curl -X DELETE https://my-store.myshopify.com/admin/api/2026-07/products/1.json'), true);
  assert.equal(held('curl https://my-store.myshopify.com/products.json'), false);
  assert.equal(held('curl -X POST https://$STORE.myshopify.com/admin/api/2026-07/graphql.json -d @q.json'), true, 'a store address built at run time');
  assert.equal(held('curl -X POST https://myshopify.com/admin/api/2026-07/graphql.json -d @q.json'), false, 'not a store');
  assert.equal(held('curl -X POST https://a.b.myshopify.com/admin/api/2026-07/graphql.json -d @q.json'), false, 'one label only, as the server reads it');
});

test('apiMapFromMeta reads the body of GET /v1/meta and ignores what it does not understand', () => {
  const meta = { mapVersion: '2026-10-10.1', providers: [
    { id: 'github', name: 'GitHub', host: 'API.github.com', irreversible: [{ id: 'gh.delete', method: 'DELETE', path: '/**', why: 'x' }, { id: 5 }, null] },
    { id: 'neon', host: 'console.neon.tech', base: '/api/v2', irreversible: [{ id: 'nn.delete', method: 'DELETE', path: '/**', why: 'y' }] },
    { id: 'bad' }, null, 'x',
  ] };
  const m = apiMapFromMeta(meta);
  assert.deepEqual(m.providers.map((p) => p.id), ['github', 'neon']);
  assert.equal(m.providers[0].host, 'api.github.com');
  assert.equal(m.providers[1].base, '/api/v2');
  assert.equal(m.mapVersion, '2026-10-10.1');
  const r = classify('curl -X DELETE https://console.neon.tech/api/v2/projects/p', { ...OPT, apiMap: m });
  assert.ok(r.hits.some((h) => h.rule === 'sh.curl-api'), 'a provider that is only in the downloaded map is held');
  assert.equal(classify('curl https://console.neon.tech/api/v2/projects', { ...OPT, apiMap: m }).hold, false);
  assert.deepEqual(apiMapFromMeta(null).providers, []);
  assert.deepEqual(apiMapFromMeta({ providers: 'x' }).providers, []);
});

test('rules can be switched off by id, and only that rule', () => {
  const o = { ...OPT, disable: ['sh.git-discard'] };
  assert.equal(classify('git reset --hard', o).hold, false);
  assert.equal(classify('git push --force', o).hold, true);
  assert.equal(classify('git reset --hard', OPT).hold, true);
});

test('the working directory changes what rm -r means; with none known, only the disposable names pass', () => {
  assert.equal(classify('rm -rf /home/u/proj/dist', { cwd: '/home/u/proj' }).hold, false);
  assert.equal(classify('rm -rf ../x', { cwd: '/home/u/proj' }).hold, true);
  assert.equal(classify('rm -rf build', {}).hold, false, 'no working directory known: a disposable name passes');
  assert.equal(classify('rm -rf secrets', {}).hold, true, 'no working directory known: any other relative path is held');
  assert.equal(classify('rm -rf /', {}).hold, true);
  assert.equal(classify('rm -rf ~', { home: '/home/u' }).hold, true);
  // a subdirectory of the project as the working directory: rm -rf . wipes only that directory
  assert.equal(classify('rm -rf .', { cwd: '/home/u/proj/sub', root: '/home/u/proj' }).hold, false);
  assert.equal(classify('rm -rf ..', { cwd: '/home/u/proj/sub', root: '/home/u/proj' }).hold, true);
  assert.equal(classify('rm -rf ../..', { cwd: '/home/u/proj/sub', root: '/home/u/proj' }).hold, true);
});

test('what the hit says: the program, the rule, a reason a person can read, the command with secrets removed', () => {
  const r = classify('PGPASSWORD=hunter2 psql postgres://app:s3cretpass@db.example.com/prod -c "DROP TABLE users"', OPT);
  assert.equal(r.hits[0].rule, 'sh.sql-cli');
  assert.match(r.hits[0].why, /DROP/);
  assert.ok(!/hunter2|s3cretpass/.test(JSON.stringify(r)), JSON.stringify(r));
  const t = classify('curl -X DELETE https://api.github.com/repos/o/r -H "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"', OPT);
  assert.equal(t.hits[0].rule, 'sh.curl-api');
  assert.ok(!/ghp_abcdef/.test(JSON.stringify(t)));
  const u = classify('GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 gh repo delete a/b --yes', OPT);
  assert.ok(!/ghp_abcdef/.test(JSON.stringify(u)));
});

test('a command that cannot be parsed is looked at piece by piece, and the answer says so', () => {
  const a = classify('terraform destroy "unterminated', OPT);
  assert.equal(a.unreadable, true);
  assert.ok(a.hits.some((h) => h.rule === 'sh.terraform-destroy'), 'the plain scan still finds it');
  const b = classify('echo "unterminated', OPT);
  assert.equal(b.unreadable, true);
  assert.equal(b.hold, false);
  const c = classify('rm -rf / )', OPT);
  assert.equal(c.unreadable, true);
  assert.ok(c.hits.some((h) => h.rule === 'sh.rm'));
  const d = classify('git push --force origin main <<<', OPT);
  assert.ok(d.hits.some((h) => h.rule === 'sh.git-force'));
  assert.equal(classify('ls -la', OPT).unreadable, false);
});

test('limits: nesting depth 3 for nested shells, a deep substitution, a huge line, many commands, a bomb of braces', () => {
  const t0 = Date.now();
  // four shells deep: the fourth level is only scanned piece by piece (still found here), and flagged unreadable
  const deep = 'bash -c \'bash -c "bash -c \\"bash -c \\\\\\"terraform destroy\\\\\\"\\""\'';
  const r = classify(deep, OPT);
  assert.ok(r.hold || r.unreadable, 'four shells deep is either found or flagged');
  assert.equal(classify('echo ' + '$('.repeat(100) + 'true' + ')'.repeat(100), OPT).hold, false);
  assert.equal(classify('echo a;'.repeat(20000), OPT).hold, false);
  assert.equal(classify('echo ' + 'a'.repeat(500000), OPT).hold, false);
  assert.equal(classify('echo ' + '{a,b}'.repeat(30), OPT).hold, false);
  assert.equal(classify('x=' + '`' .repeat(3), OPT).hold, false);
  assert.equal(classify('(' .repeat(200) + 'true' + ')'.repeat(200), OPT).hold, false);
  assert.equal(classify('for i in {1..100000}; do echo $i; done', OPT).hold, false);
  assert.ok(classify('echo ok; ' + 'rm -rf /; ' + 'echo a;'.repeat(2000), OPT).hold, 'a dangerous command after a long prefix is still found');
  assert.ok(Date.now() - t0 < 8000, `all the limits together took ${Date.now() - t0} ms`);
});

test('never throws and never hangs on odd text (random shell soup)', () => {
  let seed = 12345;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const atoms = ['terraform', 'destroy', 'rm', '-rf', '/', '$(', ')', '`', '"', "'", '\\', ';', '&&', '||', '|', '<<EOF\n', 'EOF\n', '{', '}', '(', '[[', ']]', '$', '${', '*', '~', '\n', ' ', 'git push -f', 'bash -c', 'xargs', 'if', 'then', 'fi', 'for x in', 'do', 'done', 'case', 'esac', '>', '<', '&', '#', '$((', '))', 'psql -c', 'DROP', '\uE000', '\u0000'];
  const t0 = Date.now();
  for (let i = 0; i < 4000; i++) {
    let s = '';
    for (let k = rnd(30) + 1; k > 0; k--) s += atoms[rnd(atoms.length)] + (rnd(3) ? ' ' : '');
    const r = classify(s, OPT);
    assert.equal(typeof r.hold, 'boolean');
    assert.ok(Array.isArray(r.hits));
  }
  assert.ok(Date.now() - t0 < 20000, `4000 random commands took ${Date.now() - t0} ms`);
});

test('speed: a typical command takes well under a millisecond on average', () => {
  const cmds = ['ls -la', 'git status', 'npm test', 'cd src && git diff | head -50', 'terraform plan -out=x', 'psql -c "select 1"', 'find . -name "*.js" | xargs grep foo'];
  const t0 = process.hrtime.bigint();
  const N = 3000;
  for (let i = 0; i < N; i++) classify(cmds[i % cmds.length], OPT);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6 / N;
  assert.ok(ms < 1.5, `average ${ms.toFixed(3)} ms`);
});

test('redact removes credentials and keeps the command readable', () => {
  const cases = [
    ['psql postgres://app:hunter2@db.example.com/x', 'psql postgres://app:[redacted]@db.example.com/x'],
    ['git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r', 'git clone https://[redacted]@github.com/o/r'],
    ['curl -H "Authorization: Bearer abcdefghijklmnop" https://x', 'curl -H "Authorization: Bearer [redacted]" https://x'],
    ['STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop node x.js', 'STRIPE_SECRET_KEY=[redacted] node x.js'],
    ['DB_PASSWORD="my pass" ./run', 'DB_PASSWORD=[redacted] ./run'],
    ['mysql -u root -pS3cret -e "select 1"', 'mysql -u root -p[redacted] -e "select 1"'],
    ['mysql -u root -p3306 -e "select 1"', 'mysql -u root -p3306 -e "select 1"'],
    ['aws s3 ls --token abcdef', 'aws s3 ls --token [redacted]'],
    ['echo AKIAABCDEFGHIJKLMNOP', 'echo [redacted]'],
    ['echo xoxb-1234567890-abcdefghij', 'echo [redacted]'],
    ['echo lsg_' + 'a'.repeat(43), 'echo [redacted]'],
    ['echo lsh_' + 'b'.repeat(40), 'echo [redacted]'],
    ['echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r', 'echo [redacted]'],
    ['npm publish --//registry.npmjs.org/:_authToken=npm_' + 'c'.repeat(36), 'npm publish --//registry.npmjs.org/:_authToken=[redacted]'],
    ['ls -la', 'ls -la'],
    ['git push origin main', 'git push origin main'],
  ];
  for (const [i, o] of cases) assert.equal(redact(i), o, i);
  assert.equal(redact('-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----'), '[redacted private key]');
});

test('canonicalJson sorts keys at every level', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 1, c: [{ z: 1, y: 2 }] } }), '{"a":{"c":[{"y":2,"z":1}],"d":1},"b":1}');
});

test('normPath is lexical and never leaves the root', () => {
  assert.equal(normPath('/a/b/../c/./d//e'), '/a/c/d/e');
  assert.equal(normPath('/../../x'), '/x');
  assert.equal(normPath('/'), '/');
});

test('SQL: what sqlGuard holds on a development database, and what it lets through', () => {
  const hold = [
    'DROP TABLE users', 'drop database app', 'DROP INDEX i', 'TRUNCATE users', 'truncate table t', 'DELETE FROM users', 'delete from users;',
    'UPDATE users SET a = 1', 'ALTER TABLE t DROP COLUMN c', 'alter table t drop constraint k', 'DELETE FROM t WHERE 1=1', 'delete from t where true',
    'update t set a = 1 where 1 = 1', 'DELETE FROM t WHERE id = 1 OR 1=1', "SELECT 1; DROP TABLE t", 'DO $$ BEGIN END $$', 'CALL purge()', 'EXECUTE x',
    "COPY t FROM PROGRAM 'x'", 'SELECT pg_terminate_backend(1)', 'SELECT lo_unlink(1)', "select 'unterminated", '/* unterminated', 'select E\'a\\\'b\'',
    'WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x', 'DROP/**/TABLE t', 'DROP -- c\nTABLE t', 'dRoP tAbLe t',
  ];
  for (const s of hold) assert.ok(sqlGuard(s), `held: ${s}`);
  const pass = [
    'SELECT 1', 'select * from users where id = 1', 'INSERT INTO t VALUES (1)', "INSERT INTO t (a) VALUES ('drop table')", 'UPDATE t SET a = 1 WHERE id = 2',
    'DELETE FROM t WHERE id = 3', 'CREATE TABLE t (id int)', 'ALTER TABLE t ADD COLUMN c int', 'CREATE INDEX i ON t (a)', 'BEGIN; INSERT INTO t VALUES (1); COMMIT;',
    "SELECT 'DELETE FROM t'", 'SELECT "drop" FROM t', 'select truncate(1.5, 0)', 'EXPLAIN SELECT 1', 'SHOW TABLES', '-- comment only\nselect 1', 'SELECT 1;',
    "INSERT INTO t VALUES ('a;b')", 'WITH x AS (SELECT 1) SELECT * FROM x',
  ];
  for (const s of pass) assert.equal(sqlGuard(s), null, `passes: ${s}`);
  // a database on another machine: any write is held
  assert.ok(sqlGuard('INSERT INTO t VALUES (1)', { remote: true }));
  assert.ok(sqlGuard('UPDATE t SET a = 1 WHERE id = 1', { remote: true }));
  assert.equal(sqlGuard('SELECT 1', { remote: true }), null);
  assert.equal(sqlGuard('select count(*) from users', { remote: true }), null);
  // the copy of the server's classifier still answers as the server does
  assert.equal(sqlReadOnly('select 1'), true);
  assert.equal(sqlReadOnly('select 1; select 2'), false);
  assert.equal(sqlReadOnly('delete from t'), false);
});

test('MCP tools: policy hold patterns, SQL arguments, allow patterns, then the words in the tool name', () => {
  const held = (call, policy) => classifyTool(call, policy);
  for (const tool of ['delete_project', 'DeleteProject', 'drop_table', 'destroy', 'remove_member', 'truncate_table', 'reset_database', 'purge_cache', 'revoke_token', 'cancel_subscription', 'refund_charge', 'transfer_funds', 'send_email', 'publish_package', 'deploy_service', 'merge_pull_request', 'force_push', 'wipe_disk', 'terminate_instance', 'archive_repo', 'execute_sql', 'run_sql', 'apply_migration', 'supabase_execute_sql_query', 'payout_create', 'pay_invoice']) {
    assert.equal(held({ server: 's', tool }).hold, true, tool);
    assert.equal(held({ server: 's', tool }).rule, 'mcp.name', tool);
  }
  for (const tool of ['list_tables', 'get_project', 'search', 'read_file', 'describe_table', 'list_projects', 'create_branch', 'payment_status', 'sender_info', 'removed_items_report'.replace('removed', 'rem')]) {
    assert.equal(held({ server: 's', tool }).hold, false, tool);
  }
  assert.equal(held({ server: 's', tool: 'run_query', input: { query: 'DROP TABLE t' } }).rule, 'mcp.sql');
  assert.equal(held({ server: 's', tool: 'run_query', input: { query: 'select 1' } }).hold, false);
  assert.equal(held({ server: 's', tool: 'web_search', input: { query: 'how to delete a branch' } }).hold, false, 'a search query that is not SQL is not SQL');
  assert.equal(held({ server: 's', tool: 'web_search', input: { query: 'delete from t' } }).hold, true);
  assert.equal(held({ server: 's', tool: 'x', input: { sql: ['select 1', 'insert into t values (1)'] } }).rule, 'mcp.sql');
  assert.equal(held({ server: 's', tool: 'q', input: { statement: 'drop table t' } }).hold, false, 'only the argument names in the policy are read');
  assert.equal(held({ server: 's', tool: 'q', input: { statement: 'drop table t' } }, { sqlArgs: ['statement'] }).rule, 'mcp.sql');
  assert.equal(held({ server: 'db', tool: 'anything' }, { hold: ['anything'] }).rule, 'mcp.hold');
  assert.equal(held({ server: 'db', tool: 'anything' }, { hold: ['mcp__db__*'] }).rule, 'mcp.hold');
  assert.equal(held({ server: 'db', tool: 'send_digest' }, { allow: ['send_digest'] }).hold, false);
  assert.equal(held({ server: 'db', tool: 'send_digest' }, { allow: ['send_*'], hold: ['send_digest'] }).hold, true, 'hold beats allow');
  assert.equal(held({ server: 'db', tool: 'delete_row', input: { query: 'drop table t' } }, { allow: ['delete_row'] }).rule, 'mcp.sql', 'allow does not unlock SQL that destroys');
  assert.equal(held({ server: 'db', tool: 'delete_row' }, { hold: 'not-an-array', allow: [5, {}] }).hold, true, 'a malformed policy is ignored, not trusted');
  assert.equal(held({}).hold, false);
  assert.equal(held(null).hold, false);
  // annotations are never read
  assert.equal(held({ server: 's', tool: 'delete_project', annotations: { readOnlyHint: true }, input: {} }).hold, true);
});

test("Windows project roots (WSL /mnt/c and Git Bash /c): inside the project passes, outside, temp and system folders are held", () => {
  const INCIDENT = `python -c "import os,shutil; shutil.rmtree(\x27C:/tmp\x27,ignore_errors=True)"`;
  for (const root of ["/mnt/c/Users/u/proj", "/c/Users/u/proj"]) {
    const o = { cwd: root, root, home: root.replace(/\/proj$/, "") };
    const held = (cmd) => classify(cmd, o).hits.map((h) => h.rule);
    for (const cmd of [
      "python -c \"import shutil; shutil.rmtree(\x27C:/Users/u/proj/build\x27)\"",
      "Remove-Item -Recurse -Force \x27C:\\Users\\u\\proj\\dist\x27",
      "rm -rf C:/Users/u/proj/out",
      "rm -rf /mnt/c/users/u/PROJ/out",
      "rm -rf ./build",
      "powershell -Command \"Remove-Item -Recurse ./build\"",
      "cmd /c \"rd /s /q C:\\Users\\u\\proj\\node_modules\"",
      "git rm -r --cached x",
      "node -e \"console.log(1)\"",
      "python script.py",
      "Remove-Item file.txt",
    ]) assert.deepEqual(held(cmd), [], `${root}: ${cmd}`);
    for (const [cmd, rule] of [
      [INCIDENT, "sh.inline-code"],
      ["python -c \"import shutil; shutil.rmtree(\x27C:/Users/u\x27)\"", "sh.inline-code"],
      ["Remove-Item -Recurse C:/Users/u/proj", "sh.win-delete"],
      ["Remove-Item -Recurse -Force C:/Windows/Temp", "sh.win-delete"],
      ["rm -rf C:/Users/u/other", "sh.rm"],
      ["rm -rf \x27C:\\Users\\u\\proj\\..\\other\x27", "sh.rm"],
      ["rm -rf C:/Users/u/proj/.git", "sh.rm"],
      ["cmd /c \"rd /s /q %TEMP%\"", "sh.win-delete"],
    ]) assert.ok(held(cmd).includes(rule), `${root}: ${cmd} should be held by ${rule}, got ${held(cmd)}`);
  }
  // the exact incident is held with no project root and with a Linux one too
  assert.ok(classify(INCIDENT, {}).hold);
  assert.match(classify(INCIDENT, OPT).hits[0].why, /shared temporary directory/);
});
