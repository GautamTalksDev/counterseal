// Work limits (providers.js LIMITS). A request body is read several ways before any rule decides, and that work grows with the
// size of the request; Workers Free allows 10 ms of CPU per request. Measured in Node on 9 Oct 2026, before the limits: a 200 KB
// GraphQL document cost about 28 ms and a 1 MB body of "a&a&..." about 270 ms. The GraphQL providers (GitHub, Railway, Shopify)
// now refuse to read more than the limits: a bigger request is held unread (never forwarded unparsed), cannot be pre-approved,
// and costs about 2 ms whatever its size. A large but legal request (inside the limits) behaves exactly as before.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import * as M from '../src/providers.js';
import { preview } from '../src/broker.js';

const { LIMITS } = M;
const J = JSON.stringify;
const P = { origin: null, xleash: false };
const PATH = { github: '/graphql', railway: '/', shopify: '/admin/api/2026-07/graphql.json' };
const rule = (prov, b, q = '', m = 'POST') => M.irreversibleRule(prov, m, PATH[prov], b, q)?.id;
/** a GraphQL document of exactly `chars` characters made of whole operations, then spaces, then `tail` */
const pad = (chars, tail = '') => {
  const unit = 'query { viewer { login } } ';
  const body = unit.repeat(Math.max(0, Math.floor((chars - tail.length) / unit.length)));
  return body + ' '.repeat(Math.max(0, chars - tail.length - body.length)) + tail;
};
const DEL = { github: 'mutation { deleteRepository(input: {repositoryId: "R"}) { clientMutationId } }', railway: 'mutation { volumeDelete(volumeId: "v") }', shopify: 'mutation { productDelete(input: {id: "gid://shopify/Product/1"}) { deletedProductId } }' };
const DELRULE = { github: 'gh.graphql', railway: 'rw.mutation', shopify: 'sh.delete' };
const READ = { github: '{ viewer { login } }', railway: '{ me { email } }', shopify: '{ shop { name } }' };
const UNREADABLE = { github: 'gh.graphql', railway: 'rw.mutation', shopify: 'sh.unreadable' };
const PROVS = ['github', 'railway', 'shopify'];

test('the limits are what the docs say, and only the GraphQL providers have them', () => {
  assert.deepEqual({ ...LIMITS }, { gqlBody: 131072, gqlQuery: 32768, gqlSearch: 4096, gqlParts: 512, sql: 32768, summary: 131072 });
  assert.deepEqual(Object.entries(M.PROVIDERS).filter(([, p]) => p.graphql).map(([id, p]) => [id, p.graphql]), [['github', '/graphql'], ['railway', '/**'], ['shopify', '/admin/api/*/graphql.json']]);
  assert.ok(M.COMMON.some((r) => r.id === 'any.too-large' && r.always), 'listed with the common rules, and never pre-approvable');
  assert.equal(M.COMMON[0].id, 'any.too-large', 'first: nothing else reads a request this big');
});

test('gqlTooBig: exact boundaries for the body, the query string and the number of "&" or ";" pieces', () => {
  const T = M.gqlTooBig;
  assert.equal(T('x'.repeat(LIMITS.gqlBody), ''), false);
  assert.equal(T('x'.repeat(LIMITS.gqlBody + 1), ''), true);
  assert.equal(T('', '?' + 'x'.repeat(LIMITS.gqlSearch - 1)), false);
  assert.equal(T('', '?' + 'x'.repeat(LIMITS.gqlSearch)), true);
  assert.equal(T('a&'.repeat(LIMITS.gqlParts - 1) + 'a', ''), false, 'exactly 512 pieces');
  assert.equal(T('a&'.repeat(LIMITS.gqlParts) + 'a', ''), true, '513 pieces');
  assert.equal(T('a;'.repeat(LIMITS.gqlParts) + 'a', ''), true, '";" splits too');
  assert.equal(T('', '?' + 'a&'.repeat(LIMITS.gqlParts) + 'a'), true, 'in the query string');
  assert.equal(T('a&b;'.repeat(256) + 'c', ''), true, 'both separators count together');
  assert.equal(T(null, null), false); assert.equal(T(undefined, undefined), false); assert.equal(T('', ''), false);
});

test('a request over the limits is held unread on GitHub, Railway and Shopify, in every shape; a document just over its own limit is unreadable', () => {
  for (const prov of PROVS) {
    assert.equal(rule(prov, J({ query: pad(200_000, READ[prov]) })), 'any.too-large', prov + ': 200 KB, a harmless read');
    assert.equal(rule(prov, J({ query: pad(200_000, DEL[prov]) })), 'any.too-large', prov + ': 200 KB with a delete at the end');
    assert.equal(rule(prov, J({ query: '{ a }', variables: { v: 'x'.repeat(LIMITS.gqlBody) } })), 'any.too-large', prov + ': a huge variable');
    assert.equal(rule(prov, 'a&'.repeat(500_000)), 'any.too-large', prov + ': a million-character form');
    assert.equal(rule(prov, J({ query: '{ a }', variables: { v: 'x&'.repeat(LIMITS.gqlParts + 10) } })), 'any.too-large', prov + ': more than 512 "&" pieces inside a string');
    assert.equal(rule(prov, J({ query: READ[prov] }), '?' + 'q=1&'.repeat(LIMITS.gqlParts + 10)), 'any.too-large', prov + ': a query string of many pieces');
    assert.equal(rule(prov, null, '?' + 'x'.repeat(LIMITS.gqlSearch + 1), 'GET'), 'any.too-large', prov + ': GET with a long query string');
    assert.equal(rule(prov, J({ query: pad(200_000, READ[prov]) }), '', 'HEAD'), 'any.too-large', prov + ': HEAD');
    // a method override inside a body this big is held as too large, which cannot be pre-approved either
    assert.equal(M.irreversibleRule(prov, 'POST', PATH[prov], 'x'.repeat(LIMITS.gqlBody) + '&_method=DELETE', '')?.always, true, prov);
    // the document (the part the lexer reads) has a smaller limit of its own, inside a body that is otherwise fine
    const over = J({ query: pad(LIMITS.gqlQuery + 1, DEL[prov]) }), at = J({ query: pad(LIMITS.gqlQuery, DEL[prov]) });
    assert.equal(rule(prov, over), UNREADABLE[prov], prov + ': 32 KB and one character is not read');
    assert.match(preview('', over), /GraphQL document of 32769 characters is too large/);
    assert.equal(rule(prov, at), DELRULE[prov], prov + ': exactly 32 KB is read, and its delete is found');
    assert.match(preview('', at), /GraphQL mutations: (deleteRepository|volumeDelete|productDelete)/);
    assert.equal(rule(prov, J({ query: pad(LIMITS.gqlQuery, READ[prov]) })), undefined, prov + ': a 32 KB read passes');
  }
});

test('a large but legal request is read as before: a 30 KB document and a 120 KB body (115 KB variable) keep their rules and their summary', () => {
  for (const prov of PROVS) {
    const big = J({ query: pad(30_000, DEL[prov]) });
    assert.equal(rule(prov, big), DELRULE[prov], prov);
    const pv = preview('', big);
    assert.match(pv, /GraphQL mutations: (deleteRepository|volumeDelete|productDelete)/, prov + ': the summary still names the mutation');
    assert.match(pv, /only the first part is shown below\. The \S+ summary above covers all of it/);
    // 115 KB of variables around a short document
    const withVars = J({ query: prov === 'shopify' ? 'mutation($v: String) { productDelete(input: {id: $v}) { deletedProductId } }' : DEL[prov], variables: { v: 'y'.repeat(115_000) } });
    assert.ok(withVars.length > 115_000 && withVars.length < LIMITS.gqlBody);
    assert.equal(rule(prov, withVars), DELRULE[prov], prov + ': held by its own rule, not as too large');
    assert.match(preview('', withVars), /GraphQL mutations/);
    // a read of that size, and a query string within the limits, are allowed
    assert.equal(rule(prov, J({ query: READ[prov], variables: { v: 'y'.repeat(115_000) } })), undefined, prov + ': a read with big variables passes');
    assert.equal(rule(prov, J({ query: READ[prov], variables: { v: 'a&b&c' } })), undefined, prov + ': a few "&" in a string are fine');
  }
});

test('end to end: an oversized GraphQL request is held, cannot be pre-approved, never reaches the provider, shows its start to the owner; the same request under the limits goes through', async () => {
  const w = new World();
  const u = await w.user();
  const mk = async (provider, secret, host) => {
    const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: provider, ...(host ? { host } : {}) } });
    assert.equal(c.status, 200, J(c.body));
    // a passkey-made token that pre-approves every POST: oversized requests must still wait
    const b = (await w.req('POST', '/v1/tokens/passkey/begin', { cookie: u.cookie, body: {} })).body;
    const t = await w.req('POST', '/v1/tokens/passkey/finish', { cookie: u.cookie, body: { challengeId: b.challengeId, credential: await u.auth.get(b.options), credentialId: c.body.id, policy: { unattendedIrreversible: [{ method: 'POST', path: '/**' }], perMinute: 600 } } });
    assert.equal(t.status, 200, J(t.body));
    return t.body.token;
  };
  const toks = { github: await mk('github', 'ghp_' + 'A'.repeat(36)), railway: await mk('railway', 'rw_' + 'R'.repeat(30)), shopify: await mk('shopify', 'shpat_' + 'S'.repeat(32), 'limits.myshopify.com') };
  const send = (prov, raw, ct = 'application/json') => w.req('POST', '/p/' + prov + (PATH[prov] === '/' ? '/' : PATH[prov]), { bearer: toks[prov], ...P, raw, headers: { 'content-type': ct } });
  for (const prov of PROVS) {
    const n = w.upstream.length;
    // inside the limits: the pre-approval lets a delete through, as it always did
    const ok = await send(prov, J({ query: DEL[prov] }));
    assert.equal(ok.status, 200, prov + ' ' + J(ok.body));
    assert.equal(w.upstream.length, n + 1);
    // over the limits: held although the same path is pre-approved, and nothing is sent
    for (const raw of [J({ query: pad(200_000, DEL[prov]) }), J({ query: pad(200_000, READ[prov]) }), 'a&'.repeat(300_000)]) {
      const h = await send(prov, raw, raw.startsWith('a&') ? 'application/x-www-form-urlencoded' : 'application/json');
      assert.equal(h.status, 428, prov + ' ' + J(h.body).slice(0, 200));
      assert.equal(h.body.rule, 'any.too-large');
      assert.equal(w.upstream.length, n + 1, prov + ': never forwarded unparsed');
    }
    // the owner sees why, and only the start of the request
    const mine = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.filter((x) => x.rule === 'any.too-large');
    assert.ok(mine.length >= 3);
    assert.match(mine[0].preview, /too large for \S+ to read, so it was not summarised/);
    assert.ok(mine[0].preview.length <= 2200, 'the preview stays small: ' + mine[0].preview.length);
    assert.match(mine[0].preview, /\[truncated\]$/);
  }
  // a human can still approve the exact oversized request, once
  const raw = J({ query: pad(200_000, READ.github) });
  const h = await send('github', raw);
  const b = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } })).status, 200);
  const n = w.upstream.length;
  assert.equal((await send('github', raw)).status, 200, 'the approved request goes through, byte for byte');
  assert.equal(w.upstream.length, n + 1);
  assert.equal(w.upstream.at(-1).body, raw);
  assert.equal((await send('github', raw)).status, 428, 'and only once');
});

test('the cost of reading does not grow with the size of a GraphQL request (before the limits: 270 ms for a 1 MB body, 28 ms for a 200 KB document)', () => {
  const best = (fn, n = 5) => { let m = Infinity; for (let i = 0; i < n; i++) { const t = process.hrtime.bigint(); fn(); m = Math.min(m, Number(process.hrtime.bigint() - t) / 1e6); } return m; };
  const cases = ['a&'.repeat(500_000), J({ query: pad(200_000, DEL.github) }), J({ query: '{ a }', variables: { v: 'x&'.repeat(450_000) } }), '{'.repeat(60) + '}'.repeat(60) + 'x'.repeat(900_000)];
  for (const prov of PROVS)
    for (const b of cases) {
      const ms = best(() => { M.jsonView('{}'); M.gqlMutationFields('{a}'); const r = M.irreversibleRule(prov, 'POST', PATH[prov], b, ''); assert.equal(r.id, 'any.too-large'); preview('', b); });
      assert.ok(ms < 20, `${prov} ${b.length} chars took ${ms.toFixed(1)} ms`);
    }
});

test('the preview of a big request cuts before it makes invisible characters visible, and shows exactly what it showed before', () => {
  // the reference: the old algorithm (make the whole text visible, then cut)
  const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00ad\u061c]/g;
  const visible = (t) => String(t).replace(INVISIBLE, (c) => `<U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);
  const old = (raw, max = 2048) => {
    const head = [];
    if (raw.length > max) head.push(`Request is ${raw.length} characters; only the first part is shown below. The Counterseal summary above covers all of it.`);
    if (INVISIBLE.test(raw)) head.push('Contains invisible or direction-changing characters (shown as <U+...>).');
    INVISIBLE.lastIndex = 0;
    const top = head.map((h) => visible(h)).join('\n');
    const room = Math.max(256, max - top.length - 2);
    let body = visible(raw);
    if (body.length > room) body = body.slice(0, room - 12) + '\n[truncated]';
    return (top ? top + '\n\n' : '') + body;
  };
  let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const alphabet = ['a', 'b', ' ', '\n', '\u202e', '\u200b', '\u2066', '\ufeff', '\u00ad', 'xxxxx'];
  for (let i = 0; i < 300; i++) {
    const len = [10, 300, 1900, 2100, 5000][i % 5] + Math.floor(rnd() * 400);
    let t = ''; while (t.length < len) t += alphabet[Math.floor(rnd() * alphabet.length)];
    assert.equal(preview('', t), old(t), `case ${i} (${t.length} chars)`);
  }
  // beyond the summary limit the head says so, and the shown text is still the start of the request
  const p = preview('', '\u202e' + 'z'.repeat(LIMITS.summary + 500));
  assert.match(p, /^Request body of \d+ characters is too large/);
  assert.match(p, /<U\+202E>zzz/);
  assert.ok(p.length < 2300);
});

test('SQL over the limit is not plainly a read, so it is held on Cloudflare and Supabase; ordinary reads are unchanged', () => {
  const sel = (n) => 'select ' + 'a, '.repeat(n) + 'b from t';
  assert.equal(M.sqlReadOnly(sel(100)), true);
  assert.equal(M.sqlReadOnly(sel(Math.floor((LIMITS.sql - 20) / 3))), true, 'just under the limit');
  assert.equal(M.sqlReadOnly('select 1' + ' '.repeat(LIMITS.sql)), false, 'over it');
  assert.equal(M.sqlTokens('x'.repeat(LIMITS.sql + 1)), null);
  assert.equal(M.irreversibleRule('cloudflare', 'POST', '/accounts/a/d1/database/d/query', J({ sql: sel(300_000) }), '')?.id, 'cf.d1-sql');
  assert.equal(M.irreversibleRule('supabase', 'POST', '/v1/projects/p/database/query', J({ query: sel(300_000) }), '')?.id, 'sb.sql');
  assert.equal(M.irreversibleRule('cloudflare', 'POST', '/accounts/a/d1/database/d/query', J({ sql: sel(100) }), ''), null);
  assert.match(M.sqlSummary(sel(20_000)), /^too long to read \(\d+ characters\), so it is held$/);
  assert.match(preview('', J({ sql: sel(20_000) })), /SQL: too long to read \(\d+ characters\), so it is held/);
});

test('the other providers are untouched: a big form body is still read in full, and big REST bodies behave as before', () => {
  const form = Array.from({ length: 2000 }, (_, i) => `metadata[k${i}]=v${i}`).join('&') + '&confirm=true';
  assert.ok(form.length < 100_000);
  assert.equal(M.irreversibleRule('stripe', 'POST', '/v1/payment_intents', form, '')?.id, 'st.pi-confirm', 'a 2,000-parameter form is read and the confirm found');
  assert.equal(M.irreversibleRule('stripe', 'POST', '/v1/customers', form, ''), null);
  assert.equal(M.irreversibleRule('github', 'POST', '/repos/a/b/issues', J({ title: 'x', body: 'y&'.repeat(5000) }), ''), null, 'GitHub REST is not GraphQL');
  // GitHub's REST API shares the provider with its GraphQL endpoint: only /graphql has the limits
  assert.equal(M.irreversibleRule('github', 'PUT', '/repos/a/b/contents/f.txt', J({ message: 'm', content: 'A'.repeat(500_000) }), ''), null, 'a 500 KB file through the contents API');
  assert.equal(M.irreversibleRule('github', 'POST', '/repos/a/b/issues/1/comments', J({ body: 'x;'.repeat(5000) + 'y&'.repeat(5000) }), ''), null, 'a comment with thousands of ";" and "&"');
  for (const p of ['/graphql', '/GraphQL', '/graphql.json']) assert.equal(M.irreversibleRule('github', 'POST', p, 'a&'.repeat(5000), '')?.id, 'any.too-large', p);
  assert.equal(M.irreversibleRule('github', 'POST', '/graphql-not', 'a&'.repeat(5000), ''), null, 'only that path');
  // the limit lives in `graphql`, nowhere else
  for (const id of ['cloudflare', 'stripe', 'supabase', 'vercel', 'neon', 'fly', 'resend']) assert.equal(M.PROVIDERS[id].graphql, undefined, id);
});

test('/v1/meta lists the new common rule, and its reason names the limits', async () => {
  const w = new World();
  const r = (await w.req('GET', '/v1/meta', { ...P })).body.common.find((x) => x.id === 'any.too-large');
  assert.ok(r); assert.match(r.why, /128 KB/); assert.match(r.why, /512/); assert.match(r.why, /cannot be pre-approved/);
  assert.ok(!/[\u2013\u2014]/.test(r.why));
});
