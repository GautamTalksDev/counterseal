// Brakes, the breaker: a token that sets limits trips when it makes too many writes in an hour, or sends the same exact
// request too many times in 5 minutes. A tripped token's writes wait (reads pass) until a passkey resets it. Counting is
// one statement per write that goes upstream, costs nothing for a token without limits, and cannot be tripped by replaying
// a signed request, or dodged by changing a header.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { signBrokerRequest, generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';
import { sweep } from '../src/index.js';
import {
  anon, FORM, CH, MONEY, charge, stripeWorld, account, mint, mintPre, stripe, refund, posts, approve, cliSession, withVapid, subscribe, db, spend, auditRows, publicEntries,
} from './brakes-helpers.js';

const cust = (w, tok, n = 0, headers = FORM) => stripe(w, tok, '/v1/customers', `email=user${n}%40example.com`, headers);
const counters = (w) => db(w).prepare('SELECT k, n FROM counters ORDER BY k').all().map((r) => ({ ...r }));
const tokenRow = (w, id) => ({ ...db(w).prepare('SELECT tripped_at, tripped_why FROM tokens WHERE id = ?').get(id) });
async function reset(w, u, tokenId, o = {}) {
  const b = await w.req('POST', `/v1/tokens/${tokenId}/reset/begin`, { cookie: u.cookie, body: {}, ...o });
  if (b.status !== 200) return b;
  return w.req('POST', `/v1/tokens/${tokenId}/reset/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) }, ...o });
}

test('too many writes in an hour: the next one trips the token, is held, wakes the owner once; reads still pass; the record says so', async () => {
  const w = stripeWorld();
  await withVapid(w);
  const u = await account(w);
  await subscribe(w, u);
  const t = await mint(w, u, { limits: { writesPerHour: 3 } });
  for (let i = 0; i < 3; i++) assert.equal((await cust(w, t.token, i)).status, 200, 'write ' + i);
  assert.equal(w.pushes.length, 0);
  const r = await cust(w, t.token, 3);
  assert.equal(r.status, 428);
  assert.equal(r.body.rule, 'brake.tripped');
  assert.match(r.body.message, /held this request: This token made more writes in an hour than its limit allows, so its breaker tripped\. Its writes wait until you reset it with your passkey; reads still pass\./);
  assert.ok(!/cannot be undone/.test(r.body.message));
  assert.equal(posts(w).length, 3, 'the fourth never reached Stripe');
  assert.deepEqual(tokenRow(w, t.id).tripped_why, 'writes_per_hour');
  assert.ok(tokenRow(w, t.id).tripped_at > 0);
  assert.equal(w.pushes.length, 1, 'the call that tripped it woke the owner: one push');
  // while tripped: every write waits (each different one gets its own hold, quietly), reads pass
  const r5 = await cust(w, t.token, 4);
  assert.equal(r5.status, 428); assert.equal(r5.body.rule, 'brake.tripped'); assert.notEqual(r5.body.hold_id, r.body.hold_id);
  assert.equal((await cust(w, t.token, 4)).body.hold_id, r5.body.hold_id, 'a retry reuses its hold');
  assert.equal(w.pushes.length, 1, 'later holds of a tripped token do not wake the owner again');
  const get = await w.req('GET', '/p/stripe/v1/customers', { bearer: t.token, ...anon });
  assert.equal(get.status, 200, 'reads pass'); assert.equal(get.headers.get('x-leash-decision'), 'allowed');
  assert.equal((await w.req('HEAD', '/p/stripe/v1/customers', { bearer: t.token, ...anon })).status, 200);
  assert.equal(posts(w).length, 3);
  // it shows in the token list and the holds, and the owner's log has the trip once
  const listed = (await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens.find((x) => x.id === t.id);
  assert.equal(listed.tripped_why, 'writes_per_hour'); assert.ok(listed.tripped_at);
  assert.deepEqual((await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.map((h) => h.rule), ['brake.tripped', 'brake.tripped']);
  const trips = auditRows(w, u.id).filter((a) => a.action === 'brake_tripped');
  assert.equal(trips.length, 1);
  assert.deepEqual(trips[0].detail, { token: t.id, why: 'writes_per_hour', count: 4, limit: 3 });
  // the public receipts: three allowed writes, two holds with a fixed rule id, nothing else
  const es = (await publicEntries(w)).map((e) => [e.entry.receipt.decision, e.entry.receipt.meta.rule]);
  assert.deepEqual(es, [['allowed', 'default'], ['allowed', 'default'], ['allowed', 'default'], ['held', 'brake.tripped'], ['held', 'brake.tripped']]);
});

test('the same exact request again and again trips it at the third, however its headers change; a different request does not count against it', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mint(w, u, { limits: { repeatsPer5Min: 2 } });
  assert.equal((await cust(w, t.token, 1)).status, 200);
  assert.equal((await cust(w, t.token, 1, { ...FORM, 'idempotency-key': 'a' })).status, 200);
  for (let i = 2; i < 9; i++) assert.equal((await cust(w, t.token, i)).status, 200, 'different requests never repeat');
  const third = await cust(w, t.token, 1, { ...FORM, 'idempotency-key': 'a-different-key', 'user-agent': 'other', accept: 'text/plain' });
  assert.equal(third.status, 428, 'a new idempotency key or user agent does not make it a new request');
  assert.equal(third.body.rule, 'brake.tripped');
  assert.match(third.body.message, /sent the same request more times in 5 minutes than its limit allows/);
  assert.equal(tokenRow(w, t.id).tripped_why, 'repeat');
  assert.equal(posts(w).length, 9);
  // the key of a window is the token and the request: a query string or another path is another request
  const w2 = stripeWorld();
  const u2 = await account(w2);
  const t2 = await mint(w2, u2, { limits: { repeatsPer5Min: 2 } });
  for (let i = 0; i < 2; i++) { assert.equal((await stripe(w2, t2.token, '/v1/customers?a=1', 'x=1')).status, 200); assert.equal((await stripe(w2, t2.token, '/v1/customers', 'x=1')).status, 200); assert.equal((await stripe(w2, t2.token, '/v1/products', 'x=1')).status, 200); }
  assert.equal(counters(w2).length, 3);
  assert.equal((await stripe(w2, t2.token, '/v1/customers?a=1', 'x=1')).status, 428);
});

test('both limits: changing the body dodges the repeat window but not the hourly count', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mint(w, u, { limits: { writesPerHour: 5, repeatsPer5Min: 3 } });
  for (let i = 0; i < 5; i++) assert.equal((await cust(w, t.token, i)).status, 200);
  assert.equal(tokenRow(w, t.id).tripped_at, null);
  assert.equal((await cust(w, t.token, 99)).body.rule, 'brake.tripped');
  assert.equal(tokenRow(w, t.id).tripped_why, 'writes_per_hour');
});

test('replaying a signed request cannot trip a bound token or be used to dodge the breaker: the replay is refused before anything is counted', async () => {
  const w = new World();
  const u = await account(w, { provider: 'github', secret: 'ghp_' + 'Q'.repeat(36) });
  const jwk = await generateAgentKey(), key = await importAgentKey(jwk);
  const b = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
  const ak = (await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b.challengeId, proof: await proveAgentKey(key, b.sign) } })).body;
  const t = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: u.cred, agentKeyId: ak.id, policy: { limits: { repeatsPer5Min: 2 } } } })).body;
  const url = 'https://leash.test/p/github/repos/acme/app/issues';
  const raw = JSON.stringify({ title: 'x' });
  const signed = await signBrokerRequest({ method: 'POST', url, body: raw, contentType: 'application/json' }, { key, kid: ak.keyid });
  const send = (h) => w.req('POST', url, { bearer: t.token, ...anon, raw, headers: { 'content-type': 'application/json', ...h } });
  assert.equal((await send(signed)).status, 200);
  for (let i = 0; i < 6; i++) { const r = await send(signed); assert.equal(r.status, 401); assert.equal(r.body.error, 'agent_signature_replayed'); }
  assert.equal(tokenRow(w, t.id).tripped_at, null, 'replays did not trip it');
  assert.deepEqual(counters(w).map((c) => c.n), [1], 'and were not counted');
  // a thief with only the token gets nowhere either: unsigned requests are refused first
  for (let i = 0; i < 4; i++) assert.equal((await send({})).body.error, 'agent_signature_required');
  assert.deepEqual(counters(w).map((c) => c.n), [1]);
  // the real agent, signing each request freshly, is counted and trips at the third
  const again = async () => send(await signBrokerRequest({ method: 'POST', url, body: raw, contentType: 'application/json' }, { key, kid: ak.keyid }));
  assert.equal((await again()).status, 200);
  assert.equal((await again()).status, 428);
});

test('one token tripping leaves the others alone; a finished window starts again; limits only count what goes upstream', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const a = await mint(w, u, { limits: { writesPerHour: 2 } }, 'a');
  const b = await mint(w, u, { limits: { writesPerHour: 2 } }, 'b');
  for (let i = 0; i < 3; i++) await cust(w, a.token, i);
  assert.ok(tokenRow(w, a.id).tripped_at);
  for (let i = 0; i < 2; i++) assert.equal((await cust(w, b.token, i)).status, 200);
  assert.equal(tokenRow(w, b.id).tripped_at, null);
  // a window that has ended is reused from 1
  const w2 = stripeWorld();
  const u2 = await account(w2);
  const c = await mint(w2, u2, { limits: { writesPerHour: 2 } });
  await cust(w2, c.token, 1); await cust(w2, c.token, 2);
  assert.deepEqual(counters(w2).map((x) => x.n), [2]);
  db(w2).prepare('UPDATE counters SET expires_at = 1').run();
  assert.equal((await cust(w2, c.token, 3)).status, 200);
  assert.deepEqual(counters(w2).map((x) => x.n), [1]);
  assert.ok(db(w2).prepare('SELECT expires_at FROM counters').get().expires_at > Date.now() + 3500_000, 'a new hour');
  // the sweep takes ended windows away
  db(w2).prepare('UPDATE counters SET expires_at = 1').run();
  await sweep(w2.env);
  assert.deepEqual(counters(w2), []);
  // denied, held and approved calls are not writes that happened: they are not counted
  const w3 = stripeWorld();
  const u3 = await account(w3);
  const d = await mintPre(w3, u3, { limits: { writesPerHour: 2, repeatsPer5Min: 2 }, deny: [{ method: 'POST', path: '/v1/customers/cus_deny' }] });
  for (let i = 0; i < 5; i++) assert.equal((await stripe(w3, d.token, '/v1/customers/cus_deny', 'x=1')).status, 403);
  const del = await w3.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: d.token, ...anon });
  assert.equal(del.status, 428);
  for (let i = 0; i < 5; i++) await w3.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: d.token, ...anon });
  assert.equal((await approve(w3, u3, del.body.hold_id)).status, 200);
  assert.equal((await w3.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: d.token, ...anon })).status, 200);
  assert.deepEqual(counters(w3), []);
  assert.equal(tokenRow(w3, d.id).tripped_at, null);
});

test('many writes at once trip it exactly once: one trip in the log, one push, and no more writes get through than the limit', async () => {
  const w = stripeWorld();
  await withVapid(w);
  const u = await account(w);
  await subscribe(w, u);
  const t = await mint(w, u, { limits: { writesPerHour: 2 } });
  const rs = await Promise.all(Array.from({ length: 9 }, (_, i) => cust(w, t.token, i)));
  assert.equal(rs.filter((r) => r.status === 200).length, 2);
  assert.deepEqual([...new Set(rs.filter((r) => r.status !== 200).map((r) => r.body.rule))], ['brake.tripped']);
  assert.equal(posts(w).length, 2);
  assert.equal(auditRows(w, u.id).filter((a) => a.action === 'brake_tripped').length, 1);
  assert.equal(w.pushes.length, 1);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE rule = 'brake.tripped'").get().n, 7);
});

test('a tripped token cannot flood the holds or the phone: 20 waiting requests per token, then nothing new is held, and only the call that tripped it wakes the owner', async () => {
  const w = stripeWorld();
  await withVapid(w);
  const u = await account(w);
  await subscribe(w, u);
  const t = await mint(w, u, { limits: { writesPerHour: 1 } });
  await cust(w, t.token, 0);
  for (let i = 1; i <= 20; i++) assert.equal((await cust(w, t.token, i)).status, 428, 'hold ' + i);
  assert.equal(w.pushes.length, 1, 'twenty holds of a tripped token: the trip woke the owner once and the rest were quiet');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n, 20);
  const before = { holds: db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, audit: db(w).prepare('SELECT COUNT(*) n FROM audit').get().n, pushes: w.pushes.length };
  const over = await cust(w, t.token, 21);
  assert.equal(over.status, 429); assert.equal(over.body.error, 'too_many_holds');
  for (let i = 0; i < 5; i++) assert.equal((await cust(w, t.token, 22 + i)).status, 429);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, before.holds, 'no new hold');
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM audit').get().n, before.audit, 'no new log entry');
  assert.equal(w.pushes.length, before.pushes, 'no new alert');
  assert.equal(posts(w).length, 1, 'and nothing reached the provider');
  // one of the twenty still waiting can be retried and approved: that is not a new hold
  const first = await cust(w, t.token, 1);
  assert.equal(first.status, 428);
  assert.equal((await approve(w, u, first.body.hold_id)).status, 200);
  assert.equal((await cust(w, t.token, 1)).status, 200, 'an approved write goes through even while tripped');
  assert.equal(posts(w).length, 2);
  // a freeze or a reset closes the rest: after the reset the token writes again
  assert.equal((await reset(w, u, t.id)).status, 200);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n, 0);
  assert.equal((await cust(w, t.token, 30)).status, 200);
});

test('resetting a tripped breaker needs a passkey: not a command line session, not a plain web request, not another account, not the wrong token', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const other = await account(w, { name: 'Eve', ip: '198.51.100.9' });
  const t = await mint(w, u, { limits: { writesPerHour: 2 } });
  const t2 = await mint(w, u, { limits: { writesPerHour: 2 } }, 'second');
  const cli = await cliSession(w, u);
  const hit = async (tok) => { for (let i = 0; i < 3; i++) await cust(w, tok.token, i); };
  await hit(t); await hit(t2);
  const held = db(w).prepare("SELECT COUNT(*) n FROM holds WHERE token_id = ? AND status = 'pending'").get(t.id).n;
  assert.equal(held, 1);
  // a command line session
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/begin`, { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/finish`, { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  // a web session without the ceremony, or without the CSRF header
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/finish`, { cookie: u.cookie, body: {} })).status, 400);
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/begin`, { cookie: u.cookie, body: {}, xleash: false })).body.error, 'csrf');
  // another account
  assert.equal((await reset(w, other, t.id)).status, 404);
  // a ceremony made for one token does not reset another
  const b = await w.req('POST', `/v1/tokens/${t.id}/reset/begin`, { cookie: u.cookie, body: {} });
  const wrong = await w.req('POST', `/v1/tokens/${t2.id}/reset/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(wrong.status, 400);
  assert.ok(tokenRow(w, t.id).tripped_at && tokenRow(w, t2.id).tripped_at, 'still tripped');
  // a challenge of another kind (an approval) is not a reset
  const h = await w.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon });
  const ab = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/finish`, { cookie: u.cookie, body: { challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } })).status, 400);
  // the right ceremony
  const ok = await reset(w, u, t.id);
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(tokenRow(w, t.id).tripped_at, null); assert.equal(tokenRow(w, t.id).tripped_why, null);
  assert.ok(tokenRow(w, t2.id).tripped_at, 'the other token is untouched');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE token_id = ? AND rule = 'brake.tripped' AND status = 'pending'").get(t.id).n, 0, 'the writes that waited are closed');
  assert.deepEqual(counters(w).filter((c) => c.k.includes(t.id)), [], 'a fresh window');
  assert.equal((await cust(w, t.token, 7)).status, 200, 'writes flow again');
  const re = auditRows(w, u.id).filter((a) => a.action === 'brake_reset');
  assert.equal(re.length, 1); assert.match(re[0].detail.passkey, /^[0-9a-f]{16}$/); assert.equal(re[0].detail.token, t.id);
  // not tripped (any more): nothing to reset
  assert.equal((await reset(w, u, t.id)).body.error, 'not_tripped');
  assert.equal((await reset(w, u, '0'.repeat(24))).status, 404);
  // after a reset it trips again at the limit, not at once
  assert.equal((await cust(w, t.token, 8)).status, 200);
  assert.equal((await cust(w, t.token, 9)).status, 428);
});

test('what the breaker costs: nothing without limits, one statement per upstream write with them, nothing for reads; well inside 50 queries', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const none = await mint(w, u, {}, 'none');
  const hour = await mint(w, u, { limits: { writesPerHour: 1000 } }, 'hour');
  const both = await mint(w, u, { limits: { writesPerHour: 1000, repeatsPer5Min: 50 } }, 'both');
  w.env.DB.cap = 50;
  const measure = async (t) => { await cust(w, t.token, 1); return cust(w, t.token, 2); }; // the second call: markSeen and the first counter row are paid
  await cust(w, none.token, 0);
  const base = await measure(none);
  const h = await measure(hour);
  const b = await measure(both);
  for (const r of [base, h, b]) assert.equal(r.status, 200);
  assert.equal(h.queries - base.queries, 1); assert.equal(h.writes - base.writes, 1);
  assert.equal(b.queries - base.queries, 1, 'both windows are one statement'); assert.equal(b.writes - base.writes, 1);
  assert.equal(counters(w).length, 1 + 3, 'one row for the hourly window; for both limits, the hourly window and one window per distinct request');
  const g = await w.req('GET', '/p/stripe/v1/customers', { bearer: both.token, ...anon });
  const g0 = await w.req('GET', '/p/stripe/v1/customers', { bearer: none.token, ...anon });
  assert.equal(g.queries, g0.queries); assert.equal(g.writes, g0.writes);
  // the trip itself (the busiest breaker path): a held write that trips, updates the token, audits, seals and wakes devices
  await withVapid(w);
  await subscribe(w, u);
  const small = await mint(w, u, { limits: { writesPerHour: 1 } }, 'small');
  await cust(w, small.token, 0);
  const tripping = await cust(w, small.token, 1);
  assert.equal(tripping.status, 428);
  assert.ok(tripping.queries <= 30, `${tripping.queries} queries for a write that trips the breaker`);
});

test('account deletion erases the totals and windows of its tokens', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const keep = await account(w, { name: 'Other', ip: '198.51.100.5' });
  w.charges.ch_3NabcdefGHIJKLMNOP01 = { id: 'ch_3NabcdefGHIJKLMNOP01', object: 'charge', amount: 8000, amount_captured: 8000, amount_refunded: 0, captured: true, currency: 'usd' };
  const t = await mintPre(w, u, { money: { currency: 'usd', perCall: 5000, perDay: 9000 }, limits: { writesPerHour: 100, repeatsPer5Min: 5 } });
  const k = await mintPre(w, keep, { money: { currency: 'usd', perCall: 5000, perDay: 9000 }, limits: { writesPerHour: 100 } });
  for (const tok of [t, k]) assert.equal((await stripe(w, tok.token, '/v1/refunds', 'charge=ch_3NabcdefGHIJKLMNOP01&amount=100')).status, 200);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM spend').get().n, 2);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM counters').get().n, 3);
  const del = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  const fin = await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: del.body.challengeId, credential: await u.auth.get(del.body.options) } });
  assert.equal(fin.status, 200, JSON.stringify(fin.body));
  assert.deepEqual(db(w).prepare('SELECT token_id FROM spend').all().map((r) => r.token_id), [k.id]);
  assert.deepEqual(counters(w).map((c) => c.k.slice(2, 26)), [k.id]);
});

test('money caps and the breaker together: a refund that trips the breaker hands its reservation back, and a tripped token reserves and asks Stripe for nothing', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const t = await mintPre(w, u, { money: MONEY, limits: { writesPerHour: 1 } });
  const ok = await refund(w, t.token, `charge=${CH}&amount=2500`);
  assert.equal(ok.status, 200);
  assert.deepEqual(spend(w).map((s) => s.amount), [2500]);
  // the second refund fits the caps, reserves, and is then counted past the limit: it waits, and the reservation goes back
  const tripped = await refund(w, t.token, `charge=${CH}&amount=1500`);
  assert.equal(tripped.status, 428); assert.equal(tripped.body.rule, 'brake.tripped');
  assert.deepEqual(spend(w).map((s) => s.amount), [2500], 'what the held call reserved was handed back');
  assert.equal(posts(w).length, 1);
  const h = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.find((x) => x.id === tripped.body.hold_id);
  assert.equal(h.headline, null, 'a breaker hold is not a money hold: no amount in large type');
  // while tripped: no lookup at Stripe, no reservation, whatever the amount
  const before = w.upstream.length;
  // (a refund is held by the map anyway, so it keeps that rule; the breaker only holds what would have been allowed)
  for (const amount of [100, 4000, 90000]) assert.equal((await refund(w, t.token, `charge=${CH}&amount=${amount}`)).body.rule, 'st.money');
  assert.equal(w.upstream.length, before, 'nothing was asked of Stripe');
  assert.deepEqual(spend(w).map((s) => s.amount), [2500]);
  // after a reset the caps work as before
  assert.equal((await reset(w, u, t.id)).status, 200);
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=1500`)).status, 200);
  assert.deepEqual(spend(w).map((s) => s.amount), [4000]);
});

test('the breaker counts writes of every provider the same way and never the reads', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mint(w, u, { limits: { writesPerHour: 2 } });
  for (let i = 0; i < 20; i++) assert.equal((await w.req('GET', '/p/stripe/v1/customers?limit=' + i, { bearer: t.token, ...anon })).status, 200);
  assert.deepEqual(counters(w), [], '20 reads counted nothing');
  assert.equal((await stripe(w, t.token, '/v1/customers', 'a=1')).status, 200);
  assert.equal((await w.req('PUT', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon, headers: FORM, raw: 'a=1' })).status, 200);
  assert.equal((await w.req('PATCH', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon, headers: FORM, raw: 'a=1' })).status, 428, 'the third write trips it');
  assert.equal((await w.req('GET', '/p/stripe/v1/customers', { bearer: t.token, ...anon })).status, 200);
});
