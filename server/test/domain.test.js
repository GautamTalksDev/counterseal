// The domain move: the product at counterseal (new passkeys), the old leash host keeping its API, proxy and /app for
// its passkeys, a strict two-origin allow list for WebAuthn and CSRF, 301s for every other page on the old host, and a
// one-time "Move to Counterseal" link. Here counterseal.test is the product and leash.test the old host.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { World, Authenticator } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const NEW = 'https://counterseal.test', OLD = 'https://leash.test';
const TWO = { ORIGIN: NEW, RP_ID: 'counterseal.test', LEGACY_ORIGIN: OLD, LEGACY_RP_ID: 'leash.test' };
const at = (host, path, o = {}) => [host + path, { origin: host, ...o }];

/** a world where an account was made on the old host before the move (its passkey is bound to leash.test) */
async function movedWorld(n = 1) {
  const w = new World(); // single host: ORIGIN leash.test, like the live service today
  const olds = [];
  for (let i = 0; i < n; i++) olds.push(await w.user('Old ' + i, '198.51.100.' + (60 + i)));
  Object.assign(w.env, TWO);
  return { w, olds };
}
async function newUser(w, name = 'New') {
  const auth = new Authenticator(NEW, 'counterseal.test');
  const b = await w.req('POST', ...at(NEW, '/v1/auth/register/begin', { body: { name } }));
  const f = await w.req('POST', ...at(NEW, '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: await auth.create(b.body.options) } }));
  assert.equal(f.status, 200, JSON.stringify(f.body));
  return { cookie: f.headers.get('set-cookie').split(';')[0], auth, setCookie: f.headers.get('set-cookie') };
}
async function login(w, host, auth) {
  const b = await w.req('POST', ...at(host, '/v1/auth/login/begin', { body: {} }));
  return w.req('POST', ...at(host, '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } }));
}
async function moveLink(w, u) {
  const b = await w.req('POST', ...at(OLD, '/v1/me/move/begin', { cookie: u.cookie, body: {} }));
  return w.req('POST', ...at(OLD, '/v1/me/move/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } }));
}
async function completeMove(w, token, auth = new Authenticator(NEW, 'counterseal.test')) {
  const b = await w.req('POST', ...at(NEW, '/v1/move/begin', { body: { token } }));
  if (b.status !== 200) return b;
  const f = await w.req('POST', ...at(NEW, '/v1/move/finish', { body: { token, challengeId: b.body.challengeId, credential: await auth.create(b.body.options) } }));
  return Object.assign(f, { auth });
}
async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }

test('origin to RP ID: each of the two hosts uses its own RP ID, chosen by the Origin; nothing else is accepted', async () => {
  const { w } = await movedWorld();
  const reg = await w.req('POST', ...at(NEW, '/v1/auth/register/begin', { body: { name: 'A', rpId: 'evil.test', rp: { id: 'evil.test' } } }));
  assert.equal(reg.status, 200); assert.equal(reg.body.options.rp.id, 'counterseal.test', 'a client-sent RP ID is ignored');
  assert.equal((await w.req('POST', ...at(NEW, '/v1/auth/login/begin', { body: {} }))).body.options.rpId, 'counterseal.test');
  assert.equal((await w.req('POST', ...at(OLD, '/v1/auth/login/begin', { body: {} }))).body.options.rpId, 'leash.test');
  // sign-up happens on the product's host only
  const old = await w.req('POST', ...at(OLD, '/v1/auth/register/begin', { body: { name: 'B' } }));
  assert.equal(old.status, 403); assert.equal(old.body.error, 'register_on_new_host'); assert.match(old.body.message, /counterseal\.test\/app/);
  // any other Origin, or one host's Origin sent to the other host, is refused
  for (const [url, origin] of [[NEW, 'https://evil.test'], [NEW, OLD], [OLD, NEW], [NEW, 'https://counterseal.test.evil.test'], [NEW, 'http://counterseal.test']]) {
    const r = await w.req('POST', url + '/v1/auth/login/begin', { origin, body: {} });
    assert.equal(r.status, 403, `${origin} -> ${url}`); assert.equal(r.body.error, 'csrf');
  }
  // the CLI and agents (no Origin) get the host they called
  // the sign-in page is always the product's host, where accounts are made (leashcli 0.1.1 calls the old host)
  assert.equal((await w.req('POST', OLD + '/v1/device/start', { origin: null, xleash: false, body: {} })).body.verification_uri, 'https://counterseal.test/app#device');
  assert.equal((await w.req('POST', NEW + '/v1/device/start', { origin: null, xleash: false, body: {} })).body.verification_uri, 'https://counterseal.test/app#device');
  const meta = await w.req('GET', OLD + '/v1/meta', { origin: null, xleash: false });
  assert.equal(meta.body.app, NEW); assert.equal(meta.body.legacyApp, OLD);
  // a code started on the old host (leashcli 0.1.1's default) is approved by a new account on the new host
  const n = await newUser(w, 'Fresh');
  const d = (await w.req('POST', OLD + '/v1/device/start', { origin: null, xleash: false, ip: '192.0.2.40', body: {} })).body;
  const ab = await w.req('POST', ...at(NEW, '/v1/device/approve/begin', { cookie: n.cookie, body: { user_code: d.user_code } }));
  assert.equal((await w.req('POST', ...at(NEW, '/v1/device/approve/finish', { cookie: n.cookie, body: { user_code: d.user_code, challengeId: ab.body.challengeId, credential: await n.auth.get(ab.body.options) } }))).status, 200);
  assert.match((await w.req('POST', OLD + '/v1/device/poll', { origin: null, xleash: false, body: { device_code: d.device_code } })).body.access_token, /^lsc_/);
});

test('cross-origin rejection: a passkey only signs in on its own host, a challenge only finishes on the host that issued it', async () => {
  const { w, olds: [u] } = await movedWorld();
  assert.equal((await login(w, OLD, u.auth)).status, 200, 'an old passkey still signs in on the old host');
  // the old passkey on the new host: the browser would not offer it; a forged attempt is refused
  const b = await w.req('POST', ...at(NEW, '/v1/auth/login/begin', { body: {} }));
  const f = await w.req('POST', ...at(NEW, '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } }));
  assert.equal(f.status, 401); assert.equal(f.body.error, 'unknown_passkey'); assert.match(f.body.message, /leash\.test/);
  // a challenge issued on the old host cannot be finished on the new one
  const ob = await w.req('POST', ...at(OLD, '/v1/auth/login/begin', { body: {} }));
  const cross = await w.req('POST', ...at(NEW, '/v1/auth/login/finish', { body: { challengeId: ob.body.challengeId, credential: await u.auth.get(ob.body.options) } }));
  assert.equal(cross.body.error, 'challenge_expired');
  // an assertion made for the new origin, posted to the old host, fails the origin check
  const ob2 = await w.req('POST', ...at(OLD, '/v1/auth/login/begin', { body: {} }));
  const wrongOrigin = await w.req('POST', ...at(OLD, '/v1/auth/login/finish', { body: { challengeId: ob2.body.challengeId, credential: await u.auth.get(ob2.body.options, { origin: NEW }) } }));
  assert.equal(wrongOrigin.body.error, 'bad_origin');
  // a new account's passkey does not sign in on the old host
  const n = await newUser(w);
  assert.equal((await login(w, NEW, n.auth)).status, 200);
  assert.equal((await login(w, OLD, n.auth)).body.error, 'unknown_passkey');
  // cookies are host-only
  assert.match(n.setCookie, /^__Host-leash=/); assert.ok(!/domain=/i.test(n.setCookie));
  // a passkey stored before rp_id existed (live data) belongs to the old host
  w.env.DB.raw.prepare('UPDATE passkeys SET rp_id = NULL WHERE account_id = (SELECT id FROM accounts WHERE name = ?)').run('Old 0');
  assert.equal((await login(w, OLD, u.auth)).status, 200);
});

test('CSRF: web writes are accepted only same-origin, from one of the two hosts', async () => {
  const { w, olds: [u] } = await movedWorld();
  const add = (url, origin, xleash = true) => w.req('POST', url + '/v1/credentials', { cookie: u.cookie, origin, xleash, body: { provider: 'github', secret: 'ghp_' + 'X'.repeat(36) } });
  assert.equal((await add(OLD, NEW)).body.error, 'csrf', 'the other of our two hosts is still cross-origin');
  assert.equal((await add(OLD, 'https://evil.test')).body.error, 'csrf');
  assert.equal((await add(OLD, OLD, false)).body.error, 'csrf', 'the x-leash header is still required');
  assert.equal((await add(OLD, OLD)).status, 200);
});

test('the old host keeps /v1, /p, security.txt and /app, and 301s every other page to the same path on the new host', async () => {
  const { w, olds: [u] } = await movedWorld();
  const served = [];
  w.env.ASSETS = { fetch: async (r) => { served.push(new URL(r.url).href); return new Response('asset'); } };
  for (const p of ['/', '/docs/', '/docs/?a=1&b=2', '/privacy/', '/security/', '/terms/', '/verify/', '/tools/web-bot-auth/', '/index.html', '/404.html', '/something-unknown']) {
    const r = await w.req('GET', OLD + p, { origin: null, xleash: false });
    assert.equal(r.status, 301, p); assert.equal(r.headers.get('location'), NEW + p, p);
    assert.match(r.headers.get('strict-transport-security'), /max-age=63072000/);
  }
  for (const p of ['/app', '/app/', '/app/app.js', '/sw.js', '/styles.css', '/brand.js', '/manifest.webmanifest', '/fonts/geist.woff2', '/favicon.svg', '/icon-192.png']) {
    assert.equal((await w.req('GET', OLD + p, { origin: null, xleash: false })).body, 'asset', p);
  }
  assert.equal((await w.req('GET', NEW + '/', { origin: null, xleash: false })).body, 'asset', 'the new host serves the pages');
  assert.equal((await w.req('GET', OLD + '/.well-known/security.txt', { origin: null, xleash: false })).status, 200);
  assert.equal((await w.req('GET', OLD + '/v1/meta', { origin: null, xleash: false })).status, 200);
  // the published CLI and agents keep using the old host as before: API and proxy, no redirect
  const cred = (await w.req('POST', OLD + '/v1/credentials', { cookie: u.cookie, origin: OLD, body: { provider: 'github', secret: 'ghp_' + 'Y'.repeat(36) } })).body.id;
  const tok = (await w.req('POST', OLD + '/v1/tokens', { cookie: u.cookie, origin: OLD, body: { credentialId: cred } })).body;
  assert.match(tok.baseUrl, /^https:\/\/leash\.test\/p\/github$/);
  assert.equal((await w.req('GET', OLD + '/p/github/repos/a/b', { bearer: tok.token, origin: null, xleash: false })).status, 200);
  assert.equal((await w.req('GET', NEW + '/p/github/repos/a/b', { bearer: tok.token, origin: null, xleash: false })).status, 200, 'and the new host serves the same proxy');
  // every page in the site is routed through the Worker, so the old host can redirect it
  const wr = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  const site = new URL('../../site/public/', import.meta.url);
  const pages = [];
  const walk = (d, rel) => { for (const n of readdirSync(d)) { const p = new URL(n + (statSync(new URL(n, d)).isDirectory() ? '/' : ''), d); if (n === 'index.html' && rel !== '/app/') pages.push(rel); else if (statSync(p).isDirectory() && n !== 'fonts') walk(p, rel + n + '/'); } };
  walk(site, '/');
  assert.ok(pages.length >= 7);
  for (const p of pages) assert.ok(wr.includes(`"${p}"`), `${p} is in run_worker_first`);
  assert.match(wr, /"pattern": "counterseal\.gautamkhosla\.com", "custom_domain": true/);
  assert.match(wr, /"pattern": "leash\.gautamkhosla\.com", "custom_domain": true/);
});

test('Move to Counterseal: a passkey-confirmed, one-time, 10 minute link adds a new-host passkey to the same account', async () => {
  const { w, olds: [u] } = await movedWorld();
  const id = await w.accountId(u.cookie);
  // only from the old host, only with a web session and a fresh passkey
  const n = await newUser(w);
  assert.equal((await w.req('POST', ...at(NEW, '/v1/me/move/begin', { cookie: n.cookie, body: {} }))).body.error, 'not_on_old_host');
  assert.equal((await w.req('POST', ...at(OLD, '/v1/me/move/finish', { cookie: u.cookie, body: {} }))).status, 400, 'no passkey ceremony, no link');
  assert.equal((await w.req('POST', ...at(OLD, '/v1/me/move/begin', { cookie: u.cookie, body: {}, xleash: false }))).body.error, 'csrf');
  const link = await moveLink(w, u);
  assert.equal(link.status, 200, JSON.stringify(link.body));
  assert.match(link.body.url, /^https:\/\/counterseal\.test\/app#move=[A-Za-z0-9_-]{43}$/, 'the token is in the fragment, never in a path or query');
  const token = link.body.url.split('#move=')[1];
  const dump = JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM move_links').all()) + JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM audit').all());
  assert.ok(!dump.includes(token), 'only a hash of the token is stored, and the audit log never holds it');
  assert.ok(w.env.DB.raw.prepare("SELECT 1 FROM audit WHERE action = 'move_link_created' AND account_id = ?").get(id));
  // the new host only: the token's POST endpoints refuse the old host and other origins
  assert.equal((await w.req('POST', ...at(OLD, '/v1/move/begin', { body: { token } }))).body.error, 'csrf');
  assert.equal((await w.req('POST', NEW + '/v1/move/begin', { origin: 'https://evil.test', body: { token } })).body.error, 'csrf');
  // complete it
  const done = await completeMove(w, token);
  assert.equal(done.status, 200, JSON.stringify(done.body));
  const cookie = done.headers.get('set-cookie').split(';')[0];
  assert.equal((await w.req('GET', NEW + '/v1/me', { cookie, origin: null, xleash: false })).body.account.id, id, 'the same account');
  assert.equal((await login(w, NEW, done.auth)).status, 200, 'the new passkey signs in on the new host');
  assert.equal((await login(w, OLD, u.auth)).status, 200, 'the old passkey keeps working on the old host');
  assert.ok(w.env.DB.raw.prepare("SELECT 1 FROM audit WHERE action = 'passkey_added' AND account_id = ?").get(id));
  // single use
  const again = await completeMove(w, token);
  assert.equal(again.body.error, 'move_link_invalid');
  // the old passkey goes when its owner removes it (web session, never the last one)
  const pks = (await w.req('GET', NEW + '/v1/passkeys', { cookie, origin: null, xleash: false })).body.passkeys;
  assert.deepEqual(pks.map((p) => p.host).sort(), [NEW, OLD].sort());
  const oldId = pks.find((p) => p.host === OLD).id, newId = pks.find((p) => p.host === NEW).id;
  // removing needs a fresh passkey ceremony (second-pass hardening); the one-step DELETE is gone
  assert.equal((await w.req('DELETE', ...at(NEW, `/v1/passkeys/${oldId}`, { cookie }))).status, 404);
  const rb = await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/begin`, { cookie, body: {} }));
  const rf = await w.req('POST', ...at(NEW, `/v1/passkeys/${oldId}/remove/finish`, { cookie, body: { challengeId: rb.body.challengeId, credential: await done.auth.get(rb.body.options) } }));
  assert.equal(rf.status, 200, JSON.stringify(rf.body));
  assert.equal((await login(w, OLD, u.auth)).body.error, 'unknown_passkey');
  assert.equal((await w.req('POST', ...at(NEW, `/v1/passkeys/${newId}/remove/begin`, { cookie, body: {} }))).body.error, 'last_passkey');
});

test('Move link: expiry, replay of a half-used link, wrong account, and the rate limit', async () => {
  const { w, olds: [a, b] } = await movedWorld(2);
  const ta = (await moveLink(w, a)).body.url.split('#move=')[1];
  const tb = (await moveLink(w, b)).body.url.split('#move=')[1];
  // wrong account: a registration started with A's link cannot be finished with B's
  const begin = await w.req('POST', ...at(NEW, '/v1/move/begin', { body: { token: ta } }));
  const auth = new Authenticator(NEW, 'counterseal.test');
  const wrong = await w.req('POST', ...at(NEW, '/v1/move/finish', { body: { token: tb, challengeId: begin.body.challengeId, credential: await auth.create(begin.body.options) } }));
  assert.equal(wrong.body.error, 'move_link_invalid');
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) n FROM passkeys WHERE rp_id = ?').get('counterseal.test').n, 0);
  assert.equal((await completeMove(w, tb)).status, 200, 'B\'s link was not spent by the failed attempt');
  // expired after 10 minutes
  await timeShift(11 * 60_000, async () => assert.equal((await w.req('POST', ...at(NEW, '/v1/move/begin', { body: { token: ta } }))).body.error, 'move_link_invalid'));
  // garbage tokens
  for (const token of ['', 'x', 'A'.repeat(43), ta + 'x']) assert.equal((await w.req('POST', ...at(NEW, '/v1/move/begin', { body: { token } }))).status, 400, token);
  // at most 3 links an hour per account (A already made 1)
  assert.equal((await moveLink(w, a)).status, 200);
  assert.equal((await moveLink(w, a)).status, 200);
  assert.equal((await moveLink(w, a)).status, 429);
});

test('approval links and phone alerts point to the host where the account can sign in', async () => {
  const { w, olds: [u] } = await movedWorld();
  const cred = (await w.req('POST', ...at(OLD, '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'Z'.repeat(36) } }))).body.id;
  const tok = (await w.req('POST', ...at(OLD, '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } }))).body.token;
  const held = (p) => w.req('DELETE', NEW + '/p/github/repos/a/' + p, { bearer: tok, origin: null, xleash: false });
  assert.match((await held('one')).body.approve_url, /^https:\/\/leash\.test\/app#hold=/, 'no passkey on the new host yet: the old host');
  assert.match((await w.req('GET', OLD + '/v1/holds', { cookie: u.cookie, origin: null, xleash: false })).body.holds[0].approve_url, /^https:\/\/leash\.test\/app#hold=/);
  const token = (await moveLink(w, u)).body.url.split('#move=')[1];
  assert.equal((await completeMove(w, token)).status, 200);
  const r = await held('two');
  assert.match(r.body.approve_url, /^https:\/\/counterseal\.test\/app#hold=/); assert.match(r.body.message, /counterseal\.test/);
  assert.ok((await w.req('GET', OLD + '/v1/holds', { cookie: u.cookie, origin: null, xleash: false })).body.holds.every((h) => h.approve_url.startsWith(NEW + '/app#hold=')), 'the alert opens the new host');
  // a single-host deployment (tests, local dev) points to its only host
  const s = new World();
  const su = await s.user();
  const sc = (await s.req('POST', '/v1/credentials', { cookie: su.cookie, body: { provider: 'github', secret: 'ghp_' + 'W'.repeat(36) } })).body.id;
  const st = (await s.req('POST', '/v1/tokens', { cookie: su.cookie, body: { credentialId: sc } })).body.token;
  assert.match((await s.req('DELETE', '/p/github/repos/x/y', { bearer: st, origin: null, xleash: false })).body.approve_url, /^https:\/\/leash\.test\/app#hold=/);
});
