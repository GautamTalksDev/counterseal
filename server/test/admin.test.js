// The operator's private launch numbers: aggregate counts only, hidden without the secret, cheap.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const anon = { origin: null, xleash: false };
const TOKEN = 'st_' + 'k'.repeat(40);

test('GET /v1/admin/stats: 404 without the secret or with a wrong token; counts only, within the query budget', async () => {
  const w = new World();
  const get = (bearer) => w.req('GET', '/v1/admin/stats', { ...anon, bearer });
  assert.equal((await get(TOKEN)).status, 404, 'unset secret: the route does not exist');
  w.env.STATS_TOKEN = TOKEN;
  for (const bad of [undefined, 'nope', TOKEN + 'x', TOKEN.slice(0, -1), TOKEN.toUpperCase()]) {
    const r = await get(bad);
    assert.equal(r.status, 404, String(bad)); assert.deepEqual(r.body, { error: 'not_found', message: 'not_found' });
  }
  w.env.STATS_TOKEN = 'short';
  assert.equal((await get('short')).status, 404, 'a secret under 32 characters is treated as unset');
  w.env.STATS_TOKEN = TOKEN;
  // some activity: two accounts, a token, a hold approved, a denial, an agent key, a push device, a CLI sign-in
  const u = await w.user('Jane Example'), v = await w.user('Other', '198.51.100.40');
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'S'.repeat(36) } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  const h = await w.req('DELETE', '/p/github/repos/a/b', { bearer: tok, ...anon });
  const b = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  await w.req('DELETE', '/p/github/repos/a/c', { bearer: tok, ...anon });
  const h2 = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0];
  await w.req('POST', `/v1/holds/${h2.id}/deny`, { cookie: u.cookie, body: {} });
  const r = await get(TOKEN);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.queries <= 12, `${r.queries} queries`);
  assert.equal(r.writes, 0, 'reading the numbers writes nothing');
  assert.equal(r.headers.get('cache-control'), 'no-store');
  const s = r.body;
  assert.deepEqual([s.accounts.total, s.accounts.last24h, s.accounts.last7d, s.accounts.active7d, s.accounts.paidPlans], [2, 2, 2, 2, 0]);
  assert.equal(s.accounts.byDay30d.length, 1); assert.equal(s.accounts.byDay30d[0].n, 2);
  assert.equal(s.tokens.minted, 1);
  assert.deepEqual([s.decisions.holds.total, s.decisions.approvals.total, s.decisions.denials.total], [2, 1, 1]);
  assert.equal(s.receipts.logEntries, 4, 'held, approved, held, denied');
  assert.deepEqual(s.guard, { keys: 0, activeKeys: 0, keysLast7d: 0, holdsLast7dByKind: { proxy: 2 } });
  assert.deepEqual(s.decisions.commandsRunAfterApproval, { total: 0, last7d: 0 });
  // nothing that identifies anyone
  const text = JSON.stringify(s);
  for (const secret of ['Jane', 'Other', '203.0.113', '198.51.100', tok, cred, await w.accountId(u.cookie), await w.accountId(v.cookie), 'api.github.com', '/repos/']) assert.ok(!text.includes(secret), secret);
  assert.ok(Object.values(s.accounts.byDay30d[0]).every((x) => typeof x === 'number' || /^\d{4}-\d{2}-\d{2}$/.test(x)));
});

test('every account starts on the free plan (the seam for a paid plan; no billing exists)', async () => {
  const w = new World();
  const u = await w.user();
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.plan, 'free');
  assert.equal(w.env.DB.raw.prepare('SELECT plan FROM accounts').get().plan, 'free');
});
