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
import { SITE_HEADERS } from '../src/index.js';
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

test('removing a passkey needs a fresh passkey and signs out the other browsers; a passkey added by a move link alerts every device', async () => {
  const NEW = 'https://counterseal.test', OLD = 'https://leash.test';
  const w = new World();
  const u = await w.user('Old', '198.51.100.61');
  Object.assign(w.env, { ORIGIN: NEW, RP_ID: 'counterseal.test', LEGACY_ORIGIN: OLD, LEGACY_RP_ID: 'leash.test' });
  await withVapid(w);
  const at = (host, path, o = {}) => [host + path, { origin: host, ...o }];
  assert.equal((await w.req('POST', ...at(OLD, '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: FCM + 'old-phone' } }))).status, 200);
  // a second browser signed in on the old host
  const lb = await w.req('POST', ...at(OLD, '/v1/auth/login/begin', { body: {} }));
  const other = (await w.req('POST', ...at(OLD, '/v1/auth/login/finish', { body: { challengeId: lb.body.challengeId, credential: await u.auth.get(lb.body.options) } }))).headers.get('set-cookie').split(';')[0];
  await timeShift(5 * 60_000, async () => {
    // the move: whoever holds the link gets a passkey, and every device hears about it at once
    const mb = await w.req('POST', ...at(OLD, '/v1/me/move/begin', { cookie: u.cookie, body: {} }));
    const link = (await w.req('POST', ...at(OLD, '/v1/me/move/finish', { cookie: u.cookie, body: { challengeId: mb.body.challengeId, credential: await u.auth.get(mb.body.options) } }))).body.url;
    const token = link.split('#move=')[1];
    const auth = new Authenticator(NEW, 'counterseal.test');
    const rb = await w.req('POST', ...at(NEW, '/v1/move/begin', { body: { token } }));
    const rf = await w.req('POST', ...at(NEW, '/v1/move/finish', { body: { token, challengeId: rb.body.challengeId, credential: await auth.create(rb.body.options) } }));
    assert.equal(rf.status, 200);
    assert.deepEqual(w.pushes, [FCM + 'old-phone'], 'the old phone is woken');
    const al = (await w.req('GET', OLD + '/v1/alerts', { cookie: u.cookie, ...bare })).body;
    assert.equal(al.passkeys.length, 1); assert.equal(al.passkeys[0].host, NEW);
    const cookie = rf.headers.get('set-cookie').split(';')[0];
    const pks = (await w.req('GET', NEW + '/v1/passkeys', { cookie, ...bare })).body.passkeys;
    const oldId = pks.find((p) => p.host === OLD).id;
    // no ceremony, no removal; a CLI session never; a ceremony for another passkey id does not carry over
    assert.equal((await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/finish`, { cookie, body: {} }))).status, 400);
    const cli = await cliFor(w, u);
    assert.equal((await w.req('POST', OLD + `/v1/passkeys/${oldId}/remove/begin`, { bearer: cli, ...bare, body: {} })).body.error, 'passkey_required');
    const newId = pks.find((p) => p.host === NEW).id;
    const wrong = await w.req('POST', ...at(NEW, `/v1/passkeys/${newId}/remove/begin`, { cookie, body: {} }));
    assert.equal((await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/finish`, { cookie, body: { challengeId: wrong.body.challengeId, credential: await auth.get(wrong.body.options) } }))).body.error, 'challenge_expired');
    // the real thing
    const b = await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/begin`, { cookie, body: {} }));
    const f = await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/finish`, { cookie, body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } }));
    assert.equal(f.status, 200, JSON.stringify(f.body)); assert.equal(f.body.signedOut, 2);
    for (const c of [u.cookie, other]) assert.equal((await w.req('GET', OLD + '/v1/me', { cookie: c, ...bare })).status, 401, 'the other browsers are signed out');
    assert.equal((await w.req('GET', NEW + '/v1/me', { cookie, ...bare })).status, 200, 'this one stays');
    assert.equal((await w.req('GET', NEW + '/v1/tokens', { bearer: cli, ...bare })).status, 200, 'CLI sessions are listed and revoked on their own');
    const e = w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'passkey_removed'").get();
    assert.deepEqual(JSON.parse(e.detail), { passkey: oldId, signed_out: 2 });
  });
});

test('ceilings on what one account can create: 50 vault keys, 200 live tokens, 20 receipts keys', async () => {
  const w = new World();
  const a = await w.user('A', '192.0.2.1');
  for (let i = 0; i < 50; i++) assert.equal((await w.req('POST', '/v1/credentials', { cookie: a.cookie, body: { provider: 'github', secret: 'ghp_' + String(i).padStart(36, 'x') } })).status, 200, 'key ' + i);
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: a.cookie, body: { provider: 'github', secret: GH } })).body.error, 'too_many_credentials');
  const b = await w.user('B', '192.0.2.2');
  const cred = (await w.req('POST', '/v1/credentials', { cookie: b.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const ids = [];
  for (let i = 0; i < 200; i++) { const t = await w.req('POST', '/v1/tokens', { cookie: b.cookie, body: { credentialId: cred } }); assert.equal(t.status, 200, 'token ' + i); ids.push(t.body.id); }
  assert.equal((await w.req('POST', '/v1/tokens', { cookie: b.cookie, body: { credentialId: cred } })).body.error, 'too_many_tokens');
  await w.req('DELETE', `/v1/tokens/${ids[0]}`, { cookie: b.cookie });
  assert.equal((await w.req('POST', '/v1/tokens', { cookie: b.cookie, body: { credentialId: cred } })).status, 200, 'a revoked token frees its place');
  const c = await w.user('C', '192.0.2.3');
  for (let i = 0; i < 20; i++) assert.equal((await w.req('POST', '/v1/keys', { cookie: c.cookie, body: { label: 'k' + i } })).status, 200);
  assert.equal((await w.req('POST', '/v1/keys', { cookie: c.cookie, body: { label: 'one more' } })).body.error, 'too_many_keys');
});

test('a proxied answer cannot act on a browser at our origin: upstream CORS, cookies, site-data clearing and policies are dropped', async () => {
  const w = new World();
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = await tokenFor(w, u, cred);
  w.reply = () => new Response('<script>alert(1)</script>', { status: 200, headers: { 'content-type': 'text/html', 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true', 'clear-site-data': '"cookies", "storage"', 'content-security-policy': "script-src *", link: '</evil.js>; rel=preload', refresh: '0; url=https://evil.test', 'set-cookie': 'a=1', etag: '"keep-me"', 'x-github-request-id': 'ABC' } });
  const r = await w.req('GET', '/p/github/repos/acme/app', { bearer: tok, ...bare });
  assert.equal(r.status, 200);
  for (const h of ['access-control-allow-origin', 'access-control-allow-credentials', 'clear-site-data', 'link', 'refresh', 'set-cookie']) assert.equal(r.headers.get(h), null, h);
  assert.equal(r.headers.get('content-security-policy'), "default-src 'none'; sandbox; frame-ancestors 'none'");
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.equal(r.headers.get('etag'), '"keep-me"', 'ordinary API headers pass through'); assert.equal(r.headers.get('x-github-request-id'), 'ABC');
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

test('pages the Worker serves carry the site security headers even when the asset server adds none, the same as _headers', async () => {
  const w = new World();
  w.env.ASSETS = { fetch: async (r) => (new URL(r.url).pathname === '/kept' ? new Response('x', { headers: { 'x-frame-options': 'SAMEORIGIN' } }) : new Response('<!doctype html>', { headers: { 'content-type': 'text/html' } })) };
  const r = await w.req('GET', '/', bare);
  for (const [k, v] of Object.entries(SITE_HEADERS)) assert.equal(r.headers.get(k), v, k);
  assert.equal((await w.req('GET', '/kept', bare)).headers.get('x-frame-options'), 'SAMEORIGIN', 'a header the asset has is kept');
  // the Worker's list is exactly the "/*" block of site/public/_headers
  const lines = readFileSync(new URL('../../site/public/_headers', import.meta.url), 'utf8').split('\n');
  const block = {};
  for (const l of lines.slice(lines.indexOf('/*') + 1)) { if (!/^\s/.test(l)) break; const i = l.indexOf(':'); block[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); }
  assert.deepEqual(block, SITE_HEADERS);
});

test('a CLI sign-in and where it came from never reach the public log', async () => {
  const w = new World();
  const u = await w.user();
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.receipts.on, true);
  // a sealed decision, so the log is not empty
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  assert.equal((await w.req('POST', '/p/github/repos/acme/app/issues', { bearer: await tokenFor(w, u, cred), ...bare, body: { title: 'x' } })).status, 200);
  const d =(await w.req('POST', '/v1/device/start', { ...bare, body: {}, cf: { country: 'DE', asOrganization: 'Hetzner Online GmbH', asn: 24940 } })).body;
  const b = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.user_code, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  const cli = (await w.req('POST', '/v1/device/poll', { ...bare, body: { device_code: d.device_code } })).body.access_token;
  const sid = (await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions[0].id;
  await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: u.cookie });
  const leaves = w.sql.raw.prepare('SELECT entry, tenant, opening FROM leaves').all();
  assert.ok(leaves.length >= 1);
  const dump = JSON.stringify(leaves);
  for (const s of ['DE', 'Hetzner', 'cli_', d.user_code, sid, cli]) assert.ok(!dump.includes(s), s);
});

test('policy globs that would backtrack for seconds are refused; the worst allowed shape stays fast on the longest path', async () => {
  const w = new World();
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const mint = (path) => w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, policy: { allow: [{ method: 'GET', path }] } } });
  // three "**" against a 400 character path took 8.8 s before this check (catastrophic backtracking)
  for (const p of ['/**/a/**/a/**/b', '/*a*b', '/**a**b', '/x/{**/a,**/b}/**', '/repos/*x*/issues']) assert.equal((await mint(p)).body.error, 'bad_policy', p);
  for (const p of ['/repos/**', '/**/issues/**', '/repos/*/*/releases/*', '/{repos,orgs}/acme/**', '/repos/acme/release-*']) assert.equal((await mint(p)).status, 200, p);
  const allow = Array.from({ length: 50 }, (_, i) => ({ method: 'GET', path: `/**/a${i}/**/b` }));
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, policy: { allow } } })).body.token;
  const t0 = performance.now();
  const r = await w.req('GET', '/p/github/' + 'a/'.repeat(990) + 'c', { bearer: tok, ...bare });
  assert.equal(r.body.error, 'leash_denied');
  assert.ok(performance.now() - t0 < 1500, `50 allowed globs against a 1,981 character path took ${Math.round(performance.now() - t0)} ms`);
});
