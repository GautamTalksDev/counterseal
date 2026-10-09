// Pre-launch hardening: privacy of the public log, field limits, quota accounting, abuse caps, read rate limits,
// CORS on public errors, a malformed log key, account deletion, owner bundles and pagination.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World, logKeyJwk } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { verifyBundle, submitterCommitment } from '../../sdk/receipts.mjs';

const anon = { origin: null, xw: false };
beforeEach(() => _resetMemoryBuckets());

async function setup(env = {}) {
  const w = await World.create();
  Object.assign(w.env, env);
  const u = await w.user();
  const k = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body;
  const send = (receipts) => w.req('POST', '/v1/receipts', { bearer: k.key, ...anon, body: { receipts } });
  const usage = () => w.env.DB.raw.prepare('SELECT COALESCE(SUM(receipts), 0) AS n FROM usage').get().n;
  const size = () => w.core.size();
  return { w, u, k, send, usage, size };
}
const many = (n, p = 'x') => Array.from({ length: n }, (_, i) => ({ agent: 'a', action: p + i }));

test('the public log never shows the account id or key id; the owner gets an opening that proves the entry is theirs', async () => {
  const { w, u, k, send } = await setup();
  const accountId = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.id;
  const r = await send([{ agent: 'a', action: 'one' }]);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const pubEntries = await w.req('GET', '/v1/log/entries', anon);
  const raw = JSON.stringify(pubEntries.body);
  assert.ok(!raw.includes(accountId), 'no account id in public entries');
  assert.ok(!raw.includes(k.id), 'no key id in public entries');
  const e = pubEntries.body.entries[0].entry;
  assert.deepEqual(Object.keys(e).sort(), ['receipt', 'received_at', 'submitter', 'v']);
  assert.equal(e.v, 2);
  assert.match(e.submitter, /^[0-9a-f]{64}$/);
  // the owner's bundle carries the opening; it matches the public commitment and still verifies
  const b = r.body.receipts[0];
  assert.equal(b.opening.account_id, accountId);
  assert.equal(b.opening.key_id, k.id);
  assert.equal(await submitterCommitment(b.opening), e.submitter);
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  assert.equal((await verifyBundle(b, vk)).ownerProved, true);
  const forged = structuredClone(b); forged.opening.account_id = 'someone-else';
  await assert.rejects(verifyBundle(forged, vk), /opening/);
  // two receipts from the same key do not share a commitment (salted per entry), so entries cannot be grouped
  const r2 = await send([{ agent: 'a', action: 'two' }]);
  assert.notEqual(r2.body.receipts[0].entry.submitter, e.submitter);
  // the owner's own view keeps the mapping
  const mine = (await w.req('GET', '/v1/my/receipts', { cookie: u.cookie })).body.receipts;
  assert.equal(mine.length, 2);
  assert.ok(mine.every((x) => x.opening && x.opening.account_id === accountId));
});

test('free-text fields are short labels: agent, action, run <= 80, subject <= 120, meta <= 8 keys of <= 120', async () => {
  const { send } = await setup();
  const one = async (r) => (await send([{ agent: 'a', action: 'b', ...r }])).body.error || 'ok';
  assert.equal(await one({ agent: 'x'.repeat(80) }), 'ok');
  assert.equal(await one({ agent: 'x'.repeat(81) }), 'bad_agent');
  assert.equal(await one({ action: 'x'.repeat(81) }), 'bad_action');
  assert.equal(await one({ run: 'x'.repeat(81) }), 'bad_run');
  assert.equal(await one({ subject: 'x'.repeat(120) }), 'ok');
  assert.equal(await one({ subject: 'x'.repeat(121) }), 'bad_subject');
  assert.equal(await one({ meta: Object.fromEntries(Array.from({ length: 8 }, (_, i) => ['k' + i, i])) }), 'ok');
  assert.equal(await one({ meta: Object.fromEntries(Array.from({ length: 9 }, (_, i) => ['k' + i, i])) }), 'bad_meta');
  assert.equal(await one({ meta: { k: 'x'.repeat(121) } }), 'bad_meta');
  assert.equal(await one({ meta: { k: 'line\nbreak' } }), 'bad_meta');
});

test('quota: checked before counting, a batch crossing the limit is refused whole and counts nothing', async () => {
  const { send, usage, size } = await setup({ FREE_LIMIT: '3' });
  let r = await send(many(4));
  assert.equal(r.status, 402); assert.equal(r.body.error, 'quota');
  assert.equal(usage(), 0, 'a refused batch counts nothing'); assert.equal(size(), 0);
  assert.equal((await send(many(2))).status, 200);
  assert.equal(usage(), 2);
  r = await send(many(2));
  assert.equal(r.status, 402); assert.equal(r.body.remaining, 1);
  assert.equal(usage(), 2, 'still only what was appended');
  assert.equal((await send(many(1))).status, 200);
  assert.equal(usage(), 3); assert.equal(size(), 3);
  assert.equal((await send(many(1))).status, 402);
  assert.equal(usage(), 3);
});

test('quota: if the append itself fails, nothing is counted', async () => {
  const { w, send, usage } = await setup();
  const real = w.log.append;
  w.log.append = async () => { throw new Error('storage down'); };
  assert.equal((await send(many(3))).status, 500);
  assert.equal(usage(), 0);
  assert.equal(w.env.DB.raw.prepare('SELECT COALESCE(SUM(receipts), 0) AS n FROM global_usage').get().n, 0);
  w.log.append = real;
  assert.equal((await send(many(3))).status, 200);
  assert.equal(usage(), 3);
});

test('global daily append cap returns 503 and counts nothing', async () => {
  const { send, usage, size } = await setup({ GLOBAL_DAILY_CAP: '3' });
  assert.equal((await send(many(2))).status, 200);
  const r = await send(many(2));
  assert.equal(r.status, 503); assert.equal(r.body.error, 'log_at_capacity');
  assert.equal(usage(), 2); assert.equal(size(), 2);
  assert.equal((await send(many(1))).status, 200);
});

test('registration is limited per IP per day, on top of the per-minute limit', async () => {
  const w = await World.create();
  for (let i = 0; i < 5; i++) assert.ok((await w.user('U' + i, '198.51.100.7')).cookie, `account ${i + 1}`);
  const sixth = await w.user('U6', '198.51.100.7');
  assert.equal(sixth.status, 429);
  assert.ok((await w.user('Other', '198.51.100.8')).cookie, 'another address is unaffected');
});

test('public reads do not write D1 per request; the in-memory bucket limits them; errors keep CORS', async () => {
  const w = await World.create();
  w.env.PUB_RPM = '3';
  const rows = () => w.env.DB.raw.prepare('SELECT COUNT(*) AS n FROM ratelimits').get().n;
  const before = rows();
  for (let i = 0; i < 3; i++) assert.equal((await w.req('GET', '/v1/stats', anon)).status, 200);
  assert.equal(rows(), before, 'no D1 writes for public reads');
  const r = await w.req('GET', '/v1/stats', anon);
  assert.equal(r.status, 429);
  assert.equal(r.headers.get('access-control-allow-origin'), '*', 'public errors are readable cross-origin');
  // a Workers Rate Limiting binding takes over when configured
  _resetMemoryBuckets();
  let calls = 0;
  w.env.READ_LIMITER = { limit: async () => ({ success: ++calls < 2 }) };
  assert.equal((await w.req('GET', '/v1/stats', anon)).status, 200);
  assert.equal((await w.req('GET', '/v1/stats', anon)).status, 429);
  assert.equal(calls, 2);
});

test('CORS on public 400 and 404 responses', async () => {
  const w = await World.create();
  const bad = await w.req('GET', '/v1/log/proof/inclusion?index=abc', anon);
  assert.equal(bad.status, 400); assert.equal(bad.headers.get('access-control-allow-origin'), '*');
  const nf = await w.req('GET', '/v1/log/nope', anon);
  assert.equal(nf.status, 404); assert.equal(nf.headers.get('access-control-allow-origin'), '*');
  const priv = await w.req('GET', '/v1/me', anon);
  assert.equal(priv.headers.get('access-control-allow-origin'), null, 'private endpoints stay same-origin');
});

test('a malformed LOG_KEY_JWK gives a clear 503, not a 500', async () => {
  const w = await World.create();
  for (const bad of ['not json', '{"d":"x"}', JSON.stringify({ d: 'AAAA', x: 'BBBB' })]) {
    w.env.LOG_KEY_JWK = bad;
    const r = await w.req('GET', '/v1/log/key', anon);
    assert.equal(r.status, 503, bad); assert.equal(r.body.error, 'log_key_invalid');
  }
  w.env.LOG_KEY_JWK = await logKeyJwk();
  assert.equal((await w.req('GET', '/v1/log/key', anon)).status, 200);
});

test('account deletion needs a fresh passkey assertion; it removes keys, sessions, passkeys and the account; log entries remain unlinked', async () => {
  const { w, u, k, send, size } = await setup();
  const other = await w.user('Other');
  await send(many(2));
  const accountId = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.id;
  // no assertion, wrong passkey, a challenge for another account, or no CSRF header: refused
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete' } })).status, 400);
  let b = (await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} })).body;
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.challengeId, credential: await other.auth.get(b.options) } })).body.error, 'unknown_passkey');
  b = (await w.req('POST', '/v1/me/delete/begin', { cookie: other.cookie, body: {} })).body;
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.challengeId, credential: await u.auth.get(b.options) } })).body.error, 'forbidden');
  b = (await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} })).body;
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, xw: false, body: { confirm: 'delete', challengeId: b.challengeId, credential: await u.auth.get(b.options) } })).body.error, 'csrf');
  // the real thing
  b = (await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} })).body;
  const d = await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.challengeId, credential: await u.auth.get(b.options) } });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.match(d.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).status, 401);
  assert.equal((await send(many(1))).body.error, 'api_key_invalid');
  const db = w.env.DB.raw;
  for (const t of ['accounts WHERE id', 'passkeys WHERE account_id', 'sessions WHERE account_id', 'api_keys WHERE account_id', 'usage WHERE account_id']) {
    assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${t} = ?`).get(accountId).n, 0, t);
  }
  assert.equal(size(), 2, 'public log entries remain by design');
  assert.equal(w.sql.raw.prepare('SELECT COUNT(*) AS n FROM leaves WHERE tenant = ? OR opening IS NOT NULL').get(accountId).n, 0, 'unlinked server-side');
  // the passkey can no longer sign in, and the other account is untouched
  const lb = (await w.req('POST', '/v1/auth/login/begin', { body: {} })).body;
  assert.equal((await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb.challengeId, credential: await u.auth.get(lb.options) } })).status, 401);
  assert.equal((await w.req('GET', '/v1/me', { cookie: other.cookie })).status, 200);
  void k;
});

test('owner bundles and pagination past 50 receipts', async () => {
  const { w, u, send } = await setup();
  const o = await w.user('Other');
  for (const p of ['a', 'b', 'c']) await send(many(20, p)); // three batches (the cap is 25)
  const p1 = (await w.req('GET', '/v1/my/receipts', { cookie: u.cookie })).body;
  assert.equal(p1.receipts.length, 50); assert.equal(p1.more, true);
  assert.equal(p1.receipts[0].index, 59);
  const p2 = (await w.req('GET', `/v1/my/receipts?before=${p1.receipts.at(-1).index}`, { cookie: u.cookie })).body;
  assert.equal(p2.receipts.length, 10); assert.equal(p2.more, false);
  assert.equal(p2.receipts.at(-1).index, 0);
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  const b = await w.req('GET', '/v1/my/receipts/3/bundle', { cookie: u.cookie });
  assert.equal(b.status, 200);
  assert.equal(b.body.tree_size, 60, 'proved against the latest checkpoint');
  const v = await verifyBundle(b.body, vk);
  assert.equal(v.ok, true); assert.equal(v.ownerProved, true);
  assert.equal((await w.req('GET', '/v1/my/receipts/3/bundle', { cookie: o.cookie })).status, 404, 'not someone else\'s');
  assert.equal((await w.req('GET', '/v1/my/receipts/999/bundle', { cookie: u.cookie })).status, 404);
  const me = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body;
  assert.equal(me.usage, 60); assert.equal(me.quota, 10000);
});
