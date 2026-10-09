// Shared by the Brakes tests: a world with a fake Stripe (charges and payment intents to look up, a switchable answer for
// the refund or payout itself), accounts with a Stripe key, tokens made in a passkey ceremony, and small readers.
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetBrakeMemory } from '../src/brakes.js';

export const anon = { origin: null, xleash: false };
export const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
export const SK = 'sk_test_' + 'q'.repeat(24);
export const CH = 'ch_3NabcdefGHIJKLMNOP01', PI = 'pi_3NabcdefGHIJKLMNOP02';
export const MONEY = { currency: 'usd', perCall: 5000, perDay: 20000 }; // 50.00 a call, 200.00 a day

export const charge = (id, o = {}) => ({ id, object: 'charge', amount: 8000, amount_captured: o.captured === false ? 0 : (o.amount ?? 8000), amount_refunded: 0, captured: true, currency: 'usd', ...o });
export const intent = (id, o = {}) => ({ id, object: 'payment_intent', amount: 3000, amount_received: 3000, currency: 'usd', status: 'succeeded', ...o });

/** a world whose upstream is a fake Stripe:
 *  w.charges / w.intents: id -> object (JSON answer) or a function returning a Response; missing ids answer 404
 *  w.postStatus: what a refund or payout gets: a status number, or 'throw' for a network failure */
export function stripeWorld() {
  _resetMemoryBuckets(); _resetBrakeMemory();
  const w = new World();
  w.charges = {}; w.intents = {}; w.postStatus = 200;
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
  w.reply = (url, init) => {
    const u = new URL(url);
    if (init.method === 'GET') {
      const m = u.pathname.match(/^\/v1\/(charges|payment_intents)\/([A-Za-z0-9_]+)$/);
      if (!m) return json({ object: 'list', data: [] }); // any other read
      const o = (m[1] === 'charges' ? w.charges : w.intents)[m[2]];
      if (!o) return json({ error: { message: 'No such object' } }, 404);
      return typeof o === 'function' ? o() : json(o);
    }
    if (w.postStatus === 'throw') throw new Error('network down');
    if (w.postStatus !== 200) return json({ error: { message: 'refused' } }, w.postStatus);
    return json({ id: 're_1', object: 'refund', status: 'succeeded' });
  };
  return w;
}

export async function account(w, { name = 'Gautam', ip, provider = 'stripe', secret = SK } = {}) {
  const u = await w.user(name, ip);
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: 'live' } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  return { ...u, cred: c.body.id, id: await w.accountId(u.cookie) };
}

/** a token minted in a passkey ceremony (the only way to set money caps or pre-approvals) */
export async function mintPre(w, u, policy, label = 'support agent') {
  const b = await w.req('POST', '/v1/tokens/passkey/begin', { cookie: u.cookie, body: {} });
  const r = await w.req('POST', '/v1/tokens/passkey/finish', { cookie: u.cookie, body: { credentialId: u.cred, label, policy, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}
/** a token minted without a passkey (any session): limits only */
export async function mint(w, u, policy, label = 'support agent') {
  const r = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: u.cred, label, policy } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}

export const stripe = (w, tok, path, raw, headers = FORM) => w.req('POST', '/p/stripe' + path, { bearer: tok, ...anon, headers, raw });
export const refund = (w, tok, params) => stripe(w, tok, '/v1/refunds', params);
export const payout = (w, tok, params) => stripe(w, tok, '/v1/payouts', params);
export const posts = (w) => w.upstream.filter((x) => x.method === 'POST');
export const lookups = (w) => w.upstream.filter((x) => x.method === 'GET');

export async function approve(w, u, holdId) {
  const b = await w.req('POST', `/v1/holds/${holdId}/approve/begin`, { cookie: u.cookie, body: {} });
  if (b.status !== 200) return b;
  return w.req('POST', `/v1/holds/${holdId}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
/** a command line session (device sign-in approved with the passkey); returns its bearer token */
export async function cliSession(w, u) {
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  const af = await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  assert.equal(af.status, 200, JSON.stringify(af.body));
  return (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon })).body.access_token;
}
export async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url, init) => { w.pushes.push({ url, init }); return new Response(null, { status: 201 }); };
  return w;
}
export const FCM = 'https://fcm.googleapis.com/fcm/send/device';
export async function subscribe(w, u, endpoint = FCM) {
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint } })).status, 200);
}

export const db = (w) => w.env.DB.raw;
export const spend = (w) => db(w).prepare('SELECT token_id, day, currency, amount FROM spend ORDER BY token_id, day, currency').all().map((r) => ({ ...r }));
export const auditRows = (w, acct) => db(w).prepare('SELECT action, actor, detail FROM audit WHERE account_id = ? ORDER BY seq').all(acct).map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
export const publicEntries = async (w) => (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries;
export const today = () => new Date().toISOString().slice(0, 10);
