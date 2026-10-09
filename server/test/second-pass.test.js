// Second adversarial pass (10 Oct 2026 launch review): approval fatigue and push spam, a forkable audit chain, audit
// gaps, passkey removal, resource ceilings (OWASP API4), proxied answers acting on a browser at our origin, push
// devices from a CLI session, and the site's security headers on pages the Worker serves.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { World, Authenticator } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { audit } from '../src/audit.js';
import { generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const GH = 'ghp_' + 'P'.repeat(36);
const FCM = 'https://fcm.googleapis.com/fcm/send/';
const bare = { origin: null, xleash: false };
async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url) => { w.pushes.push(url); return new Response(null, { status: 201 }); };
}
async function tokenFor(w, u, cred) { return (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token; }
async function cliFor(w, u) {
  const d = (await w.req('POST', '/v1/device/start', { ...bare, body: {}, ip: '198.51.100.' + Math.floor(Math.random() * 250) })).body;
  const b = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.user_code, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  return (await w.req('POST', '/v1/device/poll', { ...bare, body: { device_code: d.device_code } })).body.access_token;
}

test('approval fatigue: at most 20 waiting requests per token and 100 per account, and one alert a minute per account', async () => {
  const w = new World();
  await withVapid(w);
  const u = await w.user();
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: FCM + 'phone' } })).status, 200);
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = await tokenFor(w, u, cred);
  const del = (t, i) => w.req('DELETE', `/p/github/repos/acme/r${i}`, { bearer: t, ...bare });
  const first = await del(tok, 0);
  assert.equal(first.status, 428);
  for (let i = 1; i < 20; i++) assert.equal((await del(tok, i)).status, 428, 'hold ' + i);
  const over = await del(tok, 20);
  assert.equal(over.status, 429); assert.equal(over.body.error, 'too_many_holds'); assert.match(over.body.message, /20 requests from this token/);
  assert.equal(w.upstream.length, 0, 'nothing reached GitHub');
  assert.equal((await del(tok, 0)).body.hold_id, first.body.hold_id, 'a request already waiting is still answered with its hold');
  assert.equal(w.pushes.length, 1, 'twenty holds in a minute are one alert, not twenty');
  assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n, 20);
  // a minute later the next new hold alerts again
  await timeShift(61_000, async () => { assert.equal((await del(await tokenFor(w, u, cred), 'late')).status, 428); });
  assert.equal(w.pushes.length, 2);
  // the account as a whole: 100 waiting requests across tokens
  for (let t = 0; t < 4; t++) { const k = await tokenFor(w, u, cred); for (let i = 0; i < 20; i++) await del(k, `t${t}-${i}`); }
  const acct = await del(await tokenFor(w, u, cred), 'one-more');
  assert.equal(acct.status, 429); assert.match(acct.body.message, /101|100 requests are/);
  // once the human decides, room opens again
  const ab = await w.req('POST', `/v1/holds/${first.body.hold_id}/deny`, { cookie: u.cookie, body: {} });
  assert.equal(ab.status, 200);
  assert.equal((await del(tok, 'after-deny')).status, 428);
});

test('the audit chain does not fork when one account writes in parallel', async () => {
  const w = new World();
  const u = await w.user();
  const id = await w.accountId(u.cookie);
  // straight at the function, as several isolates would: eight appends that all start from the same head
  await Promise.all(Array.from({ length: 8 }, (_, i) => audit(w.env, id, 'web', 'parallel', { i })));
  // and through the API: parallel writes by an agent
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = await tokenFor(w, u, cred);
  const rs = await Promise.all(Array.from({ length: 6 }, (_, i) => w.req('POST', '/p/github/repos/acme/app/issues', { bearer: tok, ...bare, body: { title: 't' + i } })));
  assert.ok(rs.every((r) => r.status === 200));
  const v = await w.req('GET', '/v1/audit/verify', { cookie: u.cookie });
  assert.equal(v.body.ok, true, JSON.stringify(v.body));
  const rows = w.env.DB.raw.prepare('SELECT prev_hash FROM audit WHERE account_id = ?').all(id);
  assert.equal(new Set(rows.map((r) => r.prev_hash)).size, rows.length, 'no two entries follow the same entry');
  assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM audit WHERE action = 'parallel'").get().n, 8);
});

test('who can sign and record for the account is on the record: agent keys and receipts keys, made and revoked', async () => {
  const w = new World();
  const u = await w.user();
  const jwk = await generateAgentKey(); const key = await importAgentKey(jwk);
  const kb = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
  const ak = (await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, label: 'laptop', challengeId: kb.challengeId, proof: await proveAgentKey(key, kb.sign) } })).body;
  assert.equal((await w.req('DELETE', `/v1/agent-keys/${ak.id}`, { cookie: u.cookie })).status, 200);
  const rk = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'deploy' } })).body;
  assert.equal((await w.req('DELETE', `/v1/keys/${rk.id}`, { cookie: u.cookie })).status, 200);
  assert.equal((await w.req('DELETE', `/v1/keys/${rk.id}`, { cookie: u.cookie })).status, 404, 'a revoked key is not revoked twice');
  const actions = (await w.req('GET', '/v1/audit', { cookie: u.cookie })).body.entries.map((e) => [e.action, e.detail]);
  const find = (a) => actions.find(([x]) => x === a)?.[1];
  assert.deepEqual(find('agent_key_registered'), { id: ak.id, keyid: ak.keyid, label: 'laptop' });
  assert.deepEqual(find('agent_key_revoked'), { id: ak.id, keyid: ak.keyid });
  assert.deepEqual(find('receipts_key_created'), { id: rk.id, label: 'deploy', signed: false });
  assert.deepEqual(find('receipts_key_revoked'), { id: rk.id });
  assert.ok(!JSON.stringify(actions).includes(rk.key), 'never the key itself');
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
});

test('phone alerts belong to the browser: a CLI session cannot add, remove or test a device; a moved browser counts toward its new account', async () => {
  const w = new World();
  await withVapid(w);
  const u = await w.user('A', '192.0.2.1');
  const cli = await cliFor(w, u);
  for (const p of ['/v1/push/subscribe', '/v1/push/unsubscribe', '/v1/push/test']) {
    assert.equal((await w.req('POST', p, { bearer: cli, ...bare, body: { endpoint: FCM + 'x' } })).body.error, 'passkey_required', p);
  }
  assert.equal((await w.req('GET', '/v1/push/key', { bearer: cli, ...bare })).status, 200, 'reading the public key is fine');
  // B has 10 devices; A's browser signs in to B and turns alerts on: B is full, so A keeps it
  const v = await w.user('B', '192.0.2.2');
  for (let i = 0; i < 10; i++) await w.req('POST', '/v1/push/subscribe', { cookie: v.cookie, body: { endpoint: FCM + 'b' + i } });
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: FCM + 'shared' } });
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: v.cookie, body: { endpoint: FCM + 'shared' } })).body.error, 'too_many_devices');
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) n FROM push_subs WHERE account_id = (SELECT account_id FROM push_subs WHERE endpoint = ?)').get(FCM + 'b0').n, 10);
});
