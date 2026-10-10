// One host: counterseal (here counterseal.test) is the only origin and RP ID for WebAuthn and CSRF, and the retired
// leash.gautamkhosla.com answers every request with a 301 to the same path on it.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { World, Authenticator } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { BRAND } from '../src/brand.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const NEW = 'https://counterseal.test', RETIRED = 'https://leash.gautamkhosla.com';
const ONE = { ORIGIN: NEW, RP_ID: 'counterseal.test' };
const at = (host, path, o = {}) => [host + path, { origin: host, ...o }];

function oneWorld() { const w = new World(); Object.assign(w.env, ONE); return w; }
async function newUser(w, name = 'New') {
  const auth = new Authenticator(NEW, 'counterseal.test');
  const b = await w.req('POST', ...at(NEW, '/v1/auth/register/begin', { body: { name } }));
  const f = await w.req('POST', ...at(NEW, '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: await auth.create(b.body.options) } }));
  assert.equal(f.status, 200, JSON.stringify(f.body));
  return { cookie: f.headers.get('set-cookie').split(';')[0], auth, setCookie: f.headers.get('set-cookie') };
}
async function login(w, auth) {
  const b = await w.req('POST', ...at(NEW, '/v1/auth/login/begin', { body: {} }));
  return w.req('POST', ...at(NEW, '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } }));
}

test('one origin, one RP ID: a client never picks the RP ID, and every other Origin is refused', async () => {
  const w = oneWorld();
  const reg = await w.req('POST', ...at(NEW, '/v1/auth/register/begin', { body: { name: 'A', rpId: 'evil.test', rp: { id: 'evil.test' } } }));
  assert.equal(reg.status, 200); assert.equal(reg.body.options.rp.id, 'counterseal.test', 'a client-sent RP ID is ignored');
  assert.equal((await w.req('POST', ...at(NEW, '/v1/auth/login/begin', { body: {} }))).body.options.rpId, 'counterseal.test');
  for (const origin of ['https://evil.test', RETIRED, 'https://leash.test', 'https://counterseal.test.evil.test', 'http://counterseal.test']) {
    const r = await w.req('POST', NEW + '/v1/auth/login/begin', { origin, body: {} });
    assert.equal(r.status, 403, origin); assert.equal(r.body.error, 'csrf');
  }
  assert.equal((await w.req('POST', NEW + '/v1/device/start', { origin: null, xleash: false, body: {} })).body.verification_uri, 'https://counterseal.test/app#device');
  const meta = (await w.req('GET', NEW + '/v1/meta', { origin: null, xleash: false })).body;
  assert.equal(meta.app, NEW); assert.ok(!('legacyApp' in meta));
  // the move endpoints are gone
  for (const p of ['/v1/me/move/begin', '/v1/me/move/finish', '/v1/move/begin', '/v1/move/finish']) assert.equal((await w.req('POST', ...at(NEW, p, { body: {} }))).status, 404, p);
});

test('a passkey made for another RP ID (the retired host) never signs in; cookies are host-only', async () => {
  const w = oneWorld();
  const n = await newUser(w);
  assert.equal((await login(w, n.auth)).status, 200);
  assert.match(n.setCookie, /^__Host-leash=/); assert.ok(!/domain=/i.test(n.setCookie));
  // an account whose passkey was made on leash.gautamkhosla.com (kept, not deleted) cannot sign in here
  w.env.DB.raw.prepare("UPDATE passkeys SET rp_id = 'leash.gautamkhosla.com'").run();
  const f = await login(w, n.auth);
  assert.equal(f.status, 401); assert.equal(f.body.error, 'unknown_passkey');
  // and an assertion for another origin fails the origin check
  w.env.DB.raw.prepare("UPDATE passkeys SET rp_id = 'counterseal.test'").run();
  const b = await w.req('POST', ...at(NEW, '/v1/auth/login/begin', { body: {} }));
  const wrong = await w.req('POST', ...at(NEW, '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await n.auth.get(b.body.options, { origin: RETIRED }) } }));
  assert.equal(wrong.body.error, 'bad_origin');
});

test('CSRF: web writes need the one origin and the x-leash header', async () => {
  const w = oneWorld();
  const u = await newUser(w);
  const add = (origin, xleash = true) => w.req('POST', NEW + '/v1/credentials', { cookie: u.cookie, origin, xleash, body: { provider: 'github', secret: 'ghp_' + 'X'.repeat(36) } });
  assert.equal((await add(RETIRED)).body.error, 'csrf');
  assert.equal((await add('https://evil.test')).body.error, 'csrf');
  assert.equal((await add(NEW, false)).body.error, 'csrf');
  assert.equal((await add(NEW)).status, 200);
});

test('the retired host answers every request, any method, with a 301 to the same path on the one host', async () => {
  const w = oneWorld();
  const u = await newUser(w);
  const served = [];
  w.env.ASSETS = { fetch: async (r) => { served.push(new URL(r.url).href); return new Response('asset'); } };
  assert.equal(new URL(RETIRED).hostname, BRAND.retiredDomain);
  const cred = (await w.req('POST', ...at(NEW, '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'Y'.repeat(36) } }))).body.id;
  const tok = (await w.req('POST', ...at(NEW, '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } }))).body.token;
  const before = w.env.DB.raw.prepare('SELECT (SELECT COUNT(*) FROM holds) + (SELECT COUNT(*) FROM audit) AS n').get().n;
  const paths = ['/', '/docs/', '/docs/?a=1&b=2', '/privacy/', '/security/', '/index.html', '/404.html', '/something-unknown',
    '/app', '/app/', '/app/app.js', '/app#hold=x', '/sw.js', '/styles.css', '/brand.js', '/manifest.webmanifest', '/fonts/geist.woff2', '/favicon.svg', '/icon-192.png',
    '/.well-known/security.txt', '/v1/meta', '/v1/me', '/v1/auth/login/begin', '/v1/device/start', '/v1/holds?status=pending', '/p/github/repos/a/b', '/p/github/user'];
  for (const p of paths) for (const method of ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS']) {
    const r = await w.req(method, RETIRED + p, { cookie: u.cookie, bearer: p.startsWith('/p/') ? tok : undefined, origin: method === 'POST' ? RETIRED : null, body: method === 'POST' ? {} : undefined });
    const want = NEW + new URL(RETIRED + p).pathname + new URL(RETIRED + p).search;
    assert.equal(r.status, 301, `${method} ${p}`); assert.equal(r.headers.get('location'), want, `${method} ${p}`);
    assert.match(r.headers.get('strict-transport-security'), /max-age=63072000; includeSubDomains/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.match(r.headers.get('content-security-policy'), /default-src 'none'; frame-ancestors 'none'/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('set-cookie'), null, 'no session is started, refreshed or cleared there');
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  }
  assert.deepEqual(served, [], 'the retired host serves no asset');
  assert.equal(w.env.DB.raw.prepare('SELECT (SELECT COUNT(*) FROM holds) + (SELECT COUNT(*) FROM audit) AS n').get().n, before, 'nothing is proxied, held or written');
  // the one host still serves its pages, API and proxy
  assert.equal((await w.req('GET', NEW + '/', { origin: null, xleash: false })).body, 'asset');
  assert.equal((await w.req('GET', NEW + '/v1/meta', { origin: null, xleash: false })).status, 200);
  assert.equal((await w.req('GET', NEW + '/p/github/repos/a/b', { bearer: tok, origin: null, xleash: false })).status, 200);
  // the Worker runs first for every request, so the retired host can redirect assets too; both custom domains stay
  const wr = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  assert.match(wr, /"run_worker_first": true/);
  assert.match(wr, /"pattern": "counterseal\.gautamkhosla\.com", "custom_domain": true/);
  assert.match(wr, /"pattern": "leash\.gautamkhosla\.com", "custom_domain": true/);
  assert.ok(!/LEGACY_/.test(wr), 'no second origin or RP ID');
});

test('approval links and phone alerts point to the one host', async () => {
  const w = oneWorld();
  const u = await newUser(w);
  const cred = (await w.req('POST', ...at(NEW, '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'Z'.repeat(36) } }))).body.id;
  const tok = (await w.req('POST', ...at(NEW, '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } }))).body.token;
  const r = await w.req('DELETE', NEW + '/p/github/repos/a/one', { bearer: tok, origin: null, xleash: false });
  assert.match(r.body.approve_url, /^https:\/\/counterseal\.test\/app#hold=/); assert.match(r.body.message, /counterseal\.test/);
  assert.ok((await w.req('GET', NEW + '/v1/holds', { cookie: u.cookie, origin: null, xleash: false })).body.holds.every((h) => h.approve_url.startsWith(NEW + '/app#hold=')));
  const pks = (await w.req('GET', NEW + '/v1/passkeys', { cookie: u.cookie, origin: null, xleash: false })).body.passkeys;
  assert.deepEqual(pks.map((p) => p.host), [NEW]);
});
