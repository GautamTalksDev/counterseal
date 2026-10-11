// Single sign-on (src/sso.js) against a local mock identity provider: discovery, JWKS, an authorization endpoint and a
// token endpoint that checks PKCE, all served by a fake fetch. Every ID token check has a test that breaks it: bad
// signature, wrong key, alg none and HS256, header-supplied keys, wrong issuer, wrong audience and azp, expired, stale
// iat, future nbf, wrong nonce, unverified email, wrong domain, replayed state, a state from another browser, a config
// change during the sign-in, a removed member, a full team. And the rules around it: an owner with a passkey picks the
// provider, SSO never approves (the passkey does), "SSO required" stops passkey-only sign-in for non-owners, JWKS caching.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World, Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { b64u } from '../src/util.js';
import { _resetSso, verifyIdToken, publicHttps } from '../src/sso.js';
import { MAX_MEMBERS } from '../src/team.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); _resetSso(); });
const ISS = 'https://idp.example.com';
const CLIENT = 'counterseal-client';
const te = new TextEncoder();
const enc = (o) => b64u(te.encode(JSON.stringify(o)));
const count = (w, sql, ...a) => w.env.DB.raw.prepare(sql).get(...a).n;
const s256 = async (v) => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(v))));

async function rsaKey() { return crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']); }
async function sign(alg, key, header, claims) {
  const input = enc(header) + '.' + enc(claims);
  const algo = alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
  return input + '.' + b64u(new Uint8Array(await crypto.subtle.sign(algo, key, te.encode(input))));
}

/** the mock identity provider. idp.mint(defaults) makes the ID token for a code; tests override claims, the header,
 *  the signing key or the whole token. */
async function mockIdp(w, { issuer = ISS, algs = ['RS256', 'ES256'], pkce = ['S256'] } = {}) {
  const rsa = await rsaKey();
  const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const idp = {
    rsa, ec, kids: { k1: rsa, e1: ec }, codes: new Map(), calls: { discovery: 0, jwks: 0, token: 0 }, pkceChecked: 0, docIssuer: issuer,
    async jwks() {
      const keys = [];
      for (const [kid, kp] of Object.entries(idp.kids)) {
        const j = await crypto.subtle.exportKey('jwk', kp.publicKey);
        keys.push(j.kty === 'RSA' ? { kty: 'RSA', kid, use: 'sig', alg: 'RS256', n: j.n, e: j.e } : { kty: 'EC', kid, use: 'sig', alg: 'ES256', crv: 'P-256', x: j.x, y: j.y });
      }
      return { keys };
    },
    /** the user signs in at the provider: returns the callback URL with a code */
    authorize(url, { sub = 'user-1', email = 'asha@acme.example', name = 'Asha Rao', claims = {}, header = {}, alg = 'RS256', kid, key, token, error } = {}) {
      const u = new URL(url);
      assert.equal(u.origin + u.pathname, ISS + '/authorize');
      assert.equal(u.searchParams.get('response_type'), 'code');
      assert.equal(u.searchParams.get('client_id'), CLIENT);
      assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(u.searchParams.get('redirect_uri'), ORIGIN + '/v1/sso/callback');
      assert.match(u.searchParams.get('scope'), /\bopenid\b/);
      const state = u.searchParams.get('state');
      if (error) return `/v1/sso/callback?error=${error}&state=${state}`;
      const code = b64u(crypto.getRandomValues(new Uint8Array(16)));
      const t = Math.floor(Date.now() / 1000);
      idp.codes.set(code, {
        challenge: u.searchParams.get('code_challenge'), token,
        alg, key: key || (alg === 'RS256' ? rsa.privateKey : ec.privateKey),
        header: { alg, kid: kid ?? (alg === 'RS256' ? 'k1' : 'e1'), typ: 'JWT', ...header },
        claims: { iss: issuer, aud: CLIENT, sub, email, email_verified: true, name, iat: t, exp: t + 300, nonce: u.searchParams.get('nonce'), ...claims },
      });
      return `/v1/sso/callback?code=${encodeURIComponent(code)}&state=${state}`;
    },
  };
  w.env.__ssoFetch = async (url, init = {}) => {
    const u = new URL(url);
    if (u.href === ISS + '/.well-known/openid-configuration') {
      idp.calls.discovery++;
      return Response.json({ issuer: idp.docIssuer, authorization_endpoint: ISS + '/authorize', token_endpoint: ISS + '/token', jwks_uri: ISS + '/jwks', id_token_signing_alg_values_supported: algs, code_challenge_methods_supported: pkce, token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'] });
    }
    if (u.href === ISS + '/jwks') { idp.calls.jwks++; return Response.json(await idp.jwks()); }
    if (u.href === ISS + '/token' && init.method === 'POST') {
      idp.calls.token++;
      const f = new URLSearchParams(init.body);
      const c = idp.codes.get(f.get('code'));
      idp.codes.delete(f.get('code')); // codes are single use at the provider too
      if (!c || f.get('grant_type') !== 'authorization_code' || f.get('redirect_uri') !== ORIGIN + '/v1/sso/callback') return Response.json({ error: 'invalid_grant' }, { status: 400 });
      if (await s256(f.get('code_verifier') || '') !== c.challenge) return Response.json({ error: 'invalid_grant', error_description: 'PKCE' }, { status: 400 });
      idp.pkceChecked++;
      idp.lastAuth = { basic: init.headers.authorization || null, clientId: f.get('client_id'), secret: f.get('client_secret') };
      return Response.json({ access_token: 'at', token_type: 'Bearer', id_token: c.token ?? await sign(c.alg, c.key, c.header, c.claims) });
    }
    return new Response('not found', { status: 404 });
  };
  return idp;
}

async function owner(w) { const u = await w.user('Gautam'); u.id = await w.accountId(u.cookie); return u; }
const SETTINGS = { issuer: ISS, clientId: CLIENT, domains: ['acme.example'], defaultRole: 'viewer', enforce: false };
async function configure(w, u, settings = SETTINGS, { finish = settings } = {}) {
  const b = await w.req('POST', '/v1/team/sso/begin', { cookie: u.cookie, body: settings });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/team/sso/finish', { cookie: u.cookie, body: { ...finish, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
const cookieOf = (r, name) => (r.headers.getSetCookie().find((c) => c.startsWith(name + '=')) || '').split(';')[0];
/** one browser's sign-in: start, the provider, the callback. Returns the callback answer, the session cookie and more. */
async function signIn(w, idp, team, opts = {}, { binding } = {}) {
  const s = await w.req('POST', '/v1/sso/start', { body: { team } });
  assert.equal(s.status, 200, JSON.stringify(s.body));
  const bind = binding ?? cookieOf(s, '__Host-leash-sso');
  const cb = idp.authorize(s.body.url, opts);
  const r = await w.req('GET', cb, { cookie: bind || undefined, origin: null, xleash: false });
  const loc = r.headers.get('location') || '';
  return { r, cb, bind, loc, status: r.status, error: (loc.match(/#sso-error=([a-z_]+)/) || [])[1] || null, cookie: cookieOf(r, '__Host-leash') };
}

async function setup(opts) {
  const w = new World();
  const idp = await mockIdp(w, opts);
  const u = await owner(w);
  const c = await configure(w, u);
  assert.equal(c.status, 200, JSON.stringify(c.body));
  return { w, idp, u, team: c.body.sso.id, cfg: c.body };
}

test('SSO: an owner sets it up with a passkey; a new person from an allowed domain joins as a viewer and signs in again by sub', async () => {
  const { w, idp, u, team, cfg } = await setup();
  assert.equal(cfg.sso.issuer, ISS);
  assert.equal(cfg.sso.redirectUri, ORIGIN + '/v1/sso/callback');
  assert.equal(cfg.sso.loginLink, `${ORIGIN}/app/#sso=${team}`);
  assert.deepEqual(cfg.sso.algs, ['RS256', 'ES256']);
  assert.equal(cfg.sso.clientSecret, false);
  const one = await signIn(w, idp, team);
  assert.equal(one.status, 303);
  assert.equal(one.error, null, one.loc);
  assert.equal(one.loc, ORIGIN + '/app/#sso-joined');
  assert.ok(one.cookie, 'a session cookie');
  assert.match(one.r.headers.getSetCookie().find((c) => c.startsWith('__Host-leash=')), /HttpOnly; Secure; SameSite=Strict/);
  assert.equal(idp.pkceChecked, 1, 'the provider saw the PKCE verifier that matches the challenge');
  const me = (await w.req('GET', '/v1/me', { cookie: one.cookie })).body;
  assert.equal(me.member.role, 'viewer');
  assert.equal(me.member.name, 'Asha Rao');
  assert.equal(me.account.id, u.id);
  // the same person again (a new email at the same domain): the same member, found by issuer and sub
  const two = await signIn(w, idp, team, { email: 'asha.rao@acme.example' });
  assert.equal(two.loc, ORIGIN + '/app/');
  assert.equal((await w.req('GET', '/v1/me', { cookie: two.cookie })).body.member.id, me.member.id);
  assert.equal(count(w, 'SELECT COUNT(*) AS n FROM members WHERE account_id = ? AND id != ?', u.id, u.id), 1);
  // an owner sees who signed in through SSO; a viewer sees the settings but not the list
  const own = (await w.req('GET', '/v1/team/sso', { cookie: u.cookie })).body;
  assert.equal(own.identities.length, 1);
  assert.equal(own.identities[0].email, 'asha.rao@acme.example');
  assert.equal(own.scim, 'planned');
  assert.equal((await w.req('GET', '/v1/team/sso', { cookie: one.cookie })).body.identities, undefined);
  const acts = w.env.DB.raw.prepare('SELECT action, detail FROM audit WHERE account_id = ? ORDER BY seq').all(u.id).map((r) => r.action);
  for (const a of ['sso_on', 'member_joined', 'sso_login']) assert.ok(acts.includes(a), a);
  // ES256 tokens work as well
  assert.equal((await signIn(w, idp, team, { alg: 'ES256' })).error, null);
});

test('SSO: only an owner, in a web session, with a fresh passkey, picks the provider; settings are checked', async () => {
  const w = new World();
  const idp = await mockIdp(w);
  const u = await owner(w);
  assert.equal((await w.req('POST', '/v1/team/sso/begin', { body: SETTINGS, origin: null, xleash: false })).status, 401);
  // the passkey approves these exact settings
  assert.equal((await configure(w, u, SETTINGS, { finish: { ...SETTINGS, domains: ['evil.example'] } })).body.error, 'sso_changed');
  for (const [s, code] of [
    [{ ...SETTINGS, issuer: 'http://idp.example.com' }, 'sso_bad_url'],
    [{ ...SETTINGS, issuer: 'https://127.0.0.1' }, 'sso_bad_url'],
    [{ ...SETTINGS, issuer: 'https://localhost' }, 'sso_bad_url'],
    [{ ...SETTINGS, domains: [] }, 'bad_domains'],
    [{ ...SETTINGS, domains: ['*.acme.example'] }, 'bad_domains'],
    [{ ...SETTINGS, defaultRole: 'owner' }, 'bad_defaultRole'],
    [{ ...SETTINGS, defaultRole: 'approver' }, 'bad_defaultRole'],
    [{ ...SETTINGS, clientId: '' }, 'bad_clientId'],
  ]) assert.equal((await w.req('POST', '/v1/team/sso/begin', { cookie: u.cookie, body: s })).body.error, code, JSON.stringify(s));
  // the discovery document must name exactly this issuer, offer RS256 or ES256, and PKCE S256 when it lists methods
  idp.docIssuer = 'https://other.example.com';
  assert.equal((await configure(w, u)).body.error, 'sso_discovery');
  idp.docIssuer = ISS;
  assert.equal((await configure(w, u)).status, 200);
  const w2 = new World(); await mockIdp(w2, { algs: ['HS256', 'none'] }); const u2 = await owner(w2);
  assert.equal((await configure(w2, u2)).body.error, 'sso_discovery');
  const w3 = new World(); await mockIdp(w3, { pkce: ['plain'] }); const u3 = await owner(w3);
  assert.equal((await configure(w3, u3)).body.error, 'sso_discovery');
  assert.throws(() => publicHttps('https://user:pw@idp.example.com', 'issuer'), /https/);
});

test('SSO: a viewer or member cannot change SSO, and a client secret is sealed, sent with Basic auth, and never returned', async () => {
  const { w, idp, u, team } = await setup();
  const v = await signIn(w, idp, team);
  assert.equal((await w.req('POST', '/v1/team/sso/begin', { cookie: v.cookie, body: SETTINGS })).body.error, 'role_required');
  assert.equal((await w.req('POST', '/v1/team/sso/off/begin', { cookie: v.cookie, body: {} })).body.error, 'role_required');
  const c = await configure(w, u, { ...SETTINGS, clientSecret: 'shh-secret-value' });
  assert.equal(c.status, 200);
  assert.equal(c.body.sso.clientSecret, true);
  assert.ok(!JSON.stringify(c.body).includes('shh-secret-value'));
  const row = w.env.DB.raw.prepare('SELECT * FROM sso_configs WHERE account_id = ?').get(u.id);
  assert.ok(!JSON.stringify(row).includes('shh-secret-value'), 'stored sealed');
  assert.equal(row.auth_method, 'client_secret_basic');
  assert.equal(row.rev, 2);
  assert.equal((await signIn(w, idp, team)).error, null);
  assert.equal(idp.lastAuth.basic, 'Basic ' + btoa(`${CLIENT}:shh-secret-value`));
  assert.equal(idp.lastAuth.secret, null);
});

for (const [name, opts, code] of [
  ['bad signature (signed with another key under the same kid)', async () => ({ key: (await rsaKey()).privateKey }), 'sso_bad_signature'],
  ['a tampered payload', async () => ({ tamper: true }), 'sso_bad_signature'],
  ['alg none', async () => ({ token: enc({ alg: 'none', kid: 'k1' }) + '.' + enc({ sub: 'x' }) + '.' }), 'sso_alg'],
  ['HS256 keyed with the public key', async () => ({ header: { alg: 'HS256' } }), 'sso_alg'],
  ['a key in the header (jwk)', async () => ({ header: { jwk: { kty: 'RSA' } } }), 'sso_alg'],
  ['a key URL in the header (jku)', async () => ({ header: { jku: 'https://evil.example/jwks' } }), 'sso_alg'],
  ['an unknown kid', async () => ({ kid: 'nope' }), 'sso_unknown_kid'],
  ['the RSA kid with ES256', async () => ({ alg: 'ES256', kid: 'k1' }), 'sso_alg'],
  ['wrong issuer', async () => ({ claims: { iss: 'https://evil.example.com' } }), 'sso_issuer'],
  ['wrong audience', async () => ({ claims: { aud: 'another-client' } }), 'sso_audience'],
  ['several audiences without azp', async () => ({ claims: { aud: [CLIENT, 'other'] } }), 'sso_audience'],
  ['azp of another party', async () => ({ claims: { azp: 'other' } }), 'sso_audience'],
  ['expired', async () => ({ claims: { exp: Math.floor(Date.now() / 1000) - 120 } }), 'sso_expired'],
  ['issued too long ago', async () => ({ claims: { iat: Math.floor(Date.now() / 1000) - 3600 } }), 'sso_expired'],
  ['issued in the future', async () => ({ claims: { iat: Math.floor(Date.now() / 1000) + 600 } }), 'sso_expired'],
  ['not valid yet (nbf)', async () => ({ claims: { nbf: Math.floor(Date.now() / 1000) + 600 } }), 'sso_expired'],
  ['wrong nonce', async () => ({ claims: { nonce: 'another-sign-in' } }), 'sso_nonce'],
  ['no nonce', async () => ({ claims: { nonce: undefined } }), 'sso_nonce'],
  ['email not verified', async () => ({ claims: { email_verified: false } }), 'sso_claims'],
  ['email_verified as a string', async () => ({ claims: { email_verified: 'true' } }), 'sso_claims'],
  ['no email', async () => ({ claims: { email: undefined } }), 'sso_claims'],
  ['wrong domain', async () => ({ email: 'mallory@evil.example' }), 'sso_domain'],
  ['a subdomain of an allowed domain', async () => ({ email: 'x@sub.acme.example' }), 'sso_domain'],
  ['a look-alike domain', async () => ({ email: 'x@acme.example.evil.example' }), 'sso_domain'],
  ['the provider refused', async () => ({ error: 'access_denied' }), 'sso_denied'],
]) {
  test(`SSO refuses an ID token: ${name}`, async () => {
    const { w, idp, u, team } = await setup();
    const o = await opts();
    if (o.tamper) {
      const real = idp.authorize.bind(idp);
      idp.authorize = (url, x) => {
        const cb = real(url, x);
        const code = decodeURIComponent(new URL('https://x' + cb).searchParams.get('code'));
        const c = idp.codes.get(code);
        return sign(c.alg, c.key, c.header, c.claims).then((t) => { const [h, , s] = t.split('.'); c.token = h + '.' + enc({ ...c.claims, email: 'boss@acme.example', sub: 'boss' }) + '.' + s; return cb; });
      };
      const s = await w.req('POST', '/v1/sso/start', { body: { team } });
      const cb = await idp.authorize(s.body.url, {});
      const r = await w.req('GET', cb, { cookie: cookieOf(s, '__Host-leash-sso'), origin: null, xleash: false });
      assert.match(r.headers.get('location'), new RegExp('#sso-error=' + code));
      assert.equal(cookieOf(r, '__Host-leash'), '');
      return;
    }
    const r = await signIn(w, idp, team, o);
    assert.equal(r.status, 303);
    assert.equal(r.error, code, r.loc);
    assert.equal(r.cookie, '', 'no session');
    assert.equal(count(w, 'SELECT COUNT(*) AS n FROM members WHERE account_id = ? AND id != ?', u.id, u.id), 0, 'nobody joined');
    assert.equal(count(w, 'SELECT COUNT(*) AS n FROM sessions WHERE via = ?', 'sso'), 0);
  });
}

test('SSO: a state is single use (replay), bound to the browser that started it, and expires', async () => {
  const { w, idp, team } = await setup();
  const ok = await signIn(w, idp, team);
  assert.equal(ok.error, null);
  // the same callback again (replayed state), with the same binding cookie
  const again = await w.req('GET', ok.cb, { cookie: ok.bind, origin: null, xleash: false });
  assert.match(again.headers.get('location'), /#sso-error=sso_state/);
  assert.equal(cookieOf(again, '__Host-leash'), '');
  // a callback link sent to someone else: their browser has no binding cookie, or another one
  assert.equal((await signIn(w, idp, team, {}, { binding: '' })).error, 'sso_state');
  const other = await w.req('POST', '/v1/sso/start', { body: { team } });
  assert.equal((await signIn(w, idp, team, {}, { binding: cookieOf(other, '__Host-leash-sso') })).error, 'sso_state');
  // a made-up state
  const fake = await w.req('GET', '/v1/sso/callback?code=x&state=' + 'A'.repeat(43), { origin: null, xleash: false });
  assert.match(fake.headers.get('location'), /#sso-error=sso_state/);
  // ten minutes later the state is gone
  const s = await w.req('POST', '/v1/sso/start', { body: { team } });
  const cb = idp.authorize(s.body.url, {});
  const real = Date.now; const t0 = real(); Date.now = () => t0 + 11 * 60_000;
  try {
    const late = await w.req('GET', cb, { cookie: cookieOf(s, '__Host-leash-sso'), origin: null, xleash: false });
    assert.match(late.headers.get('location'), /#sso-error=sso_state/);
  } finally { Date.now = real; }
  // only hashes of states are stored
  const st = w.env.DB.raw.prepare('SELECT hash FROM sso_states').all();
  assert.ok(st.every((r) => /^[0-9a-f]{64}$/.test(r.hash)));
  // start needs the Origin check and a real team id
  assert.equal((await w.req('POST', '/v1/sso/start', { body: { team }, origin: 'https://evil.example' })).body.error, 'csrf');
  assert.equal((await w.req('POST', '/v1/sso/start', { body: { team: 'f'.repeat(24) } })).body.error, 'sso_not_found');
  assert.equal((await w.req('POST', '/v1/sso/start', { body: { team: '../x' } })).body.error, 'bad_team');
});

test('SSO: a change to the settings during a sign-in ends that sign-in; turning SSO off needs a passkey', async () => {
  const { w, idp, u, team } = await setup();
  const s = await w.req('POST', '/v1/sso/start', { body: { team } });
  const cb = idp.authorize(s.body.url, {});
  assert.equal((await configure(w, u, { ...SETTINGS, domains: ['acme.example', 'acme2.example'] })).status, 200);
  const r = await w.req('GET', cb, { cookie: cookieOf(s, '__Host-leash-sso'), origin: null, xleash: false });
  assert.match(r.headers.get('location'), /#sso-error=sso_state/);
  // off: a passkey ceremony of an owner
  const b = await w.req('POST', '/v1/team/sso/off/begin', { cookie: u.cookie, body: {} });
  const stranger = new Authenticator(ORIGIN, RP_ID);
  await stranger.create({ challenge: b64u(new Uint8Array(32)), rp: { id: RP_ID }, user: { id: 'eA', name: 'x' }, pubKeyCredParams: [{ alg: -7 }] });
  assert.equal((await w.req('POST', '/v1/team/sso/off/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await stranger.get(b.body.options) } })).body.error, 'unknown_passkey');
  const b2 = await w.req('POST', '/v1/team/sso/off/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/team/sso/off/finish', { cookie: u.cookie, body: { challengeId: b2.body.challengeId, credential: await u.auth.get(b2.body.options) } })).status, 200);
  assert.equal((await w.req('POST', '/v1/sso/start', { body: { team } })).body.error, 'sso_not_found');
  assert.equal((await w.req('GET', '/v1/team/sso', { cookie: u.cookie })).body.sso, null);
});

test('SSO never approves: an SSO member needs their own passkey; they add their first one from the SSO session only', async () => {
  const { w, idp, u, team } = await setup();
  const m = await signIn(w, idp, team);
  const mid = (await w.req('GET', '/v1/me', { cookie: m.cookie })).body.member.id;
  // even made an approver, an SSO session alone cannot do what needs a passkey (here: unfreeze)
  w.env.DB.raw.prepare("UPDATE members SET role = 'approver' WHERE id = ?").run(mid);
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: m.cookie, body: {} })).status, 200);
  const ub = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: m.cookie, body: {} });
  assert.equal(ub.status, 200, JSON.stringify(ub.body));
  const theirs = new Authenticator(ORIGIN, RP_ID);
  await theirs.create({ challenge: b64u(new Uint8Array(32)), rp: { id: RP_ID }, user: { id: 'eA', name: 'x' }, pubKeyCredParams: [{ alg: -7 }] });
  assert.equal((await w.req('POST', '/v1/me/unfreeze/finish', { cookie: m.cookie, body: { challengeId: ub.body.challengeId, credential: await theirs.get(ub.body.options) } })).body.error, 'unknown_passkey');
  // the owner's passkey is not theirs either
  const ub2 = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: m.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/unfreeze/finish', { cookie: m.cookie, body: { challengeId: ub2.body.challengeId, credential: await u.auth.get(ub2.body.options) } })).body.error, 'unknown_passkey');
  // their first passkey, from the SSO session
  const auth = new Authenticator(ORIGIN, RP_ID);
  const pb = await w.req('POST', '/v1/sso/passkey/begin', { cookie: m.cookie, body: {} });
  assert.equal(pb.status, 200);
  assert.ok(pb.body.options.excludeCredentials.length >= 1, "the account's passkeys are excluded");
  const pf = await w.req('POST', '/v1/sso/passkey/finish', { cookie: m.cookie, body: { challengeId: pb.body.challengeId, credential: await auth.create(pb.body.options) } });
  assert.equal(pf.status, 200, JSON.stringify(pf.body));
  assert.equal((await w.req('POST', '/v1/sso/passkey/begin', { cookie: m.cookie, body: {} })).body.error, 'has_passkey');
  // now their own passkey unfreezes
  const ub3 = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: m.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/unfreeze/finish', { cookie: m.cookie, body: { challengeId: ub3.body.challengeId, credential: await auth.get(ub3.body.options) } })).status, 200);
  // a passkey session cannot use the first-passkey route (a stolen cookie must not add a passkey)
  assert.equal((await w.req('POST', '/v1/sso/passkey/begin', { cookie: u.cookie, body: {} })).body.error, 'passkey_required');
});

test('SSO required: members other than owners cannot sign in with a passkey alone; removed members cannot sign in at all', async () => {
  const { w, idp, u, team } = await setup();
  const m = await signIn(w, idp, team);
  const mid = (await w.req('GET', '/v1/me', { cookie: m.cookie })).body.member.id;
  const auth = new Authenticator(ORIGIN, RP_ID);
  const pb = await w.req('POST', '/v1/sso/passkey/begin', { cookie: m.cookie, body: {} });
  await w.req('POST', '/v1/sso/passkey/finish', { cookie: m.cookie, body: { challengeId: pb.body.challengeId, credential: await auth.create(pb.body.options) } });
  const passkeyLogin = async (a) => { const b = await w.req('POST', '/v1/auth/login/begin', { body: {} }); return w.req('POST', '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await a.get(b.body.options) } }); };
  assert.equal((await passkeyLogin(auth)).status, 200, 'without enforce a passkey signs in');
  assert.equal((await configure(w, u, { ...SETTINGS, enforce: true })).status, 200);
  assert.equal((await passkeyLogin(auth)).body.error, 'sso_required');
  assert.equal((await passkeyLogin(u.auth)).status, 200, 'owners keep passkey sign-in');
  assert.equal((await signIn(w, idp, team)).error, null, 'SSO still signs them in');
  // removed at the provider: the provider refuses them (simulated as access_denied); removed in the app: refused here
  assert.equal((await signIn(w, idp, team, { error: 'access_denied' })).error, 'sso_denied');
  w.env.DB.raw.prepare('UPDATE members SET removed_at = ? WHERE id = ?').run(Date.now(), mid);
  assert.equal((await signIn(w, idp, team)).error, 'sso_removed');
});

test('SSO: the team limit holds, and names that are taken get a number', async () => {
  const { w, idp, u, team } = await setup();
  for (let i = 1; i < MAX_MEMBERS; i++) assert.equal((await signIn(w, idp, team, { sub: 'p' + i, name: 'Gautam' })).error, null, 'person ' + i);
  const names = w.env.DB.raw.prepare('SELECT name FROM members WHERE account_id = ? ORDER BY created_at').all(u.id).map((r) => r.name);
  assert.equal(new Set(names.map((n) => n.toLowerCase())).size, names.length, names.join(','));
  assert.equal((await signIn(w, idp, team, { sub: 'one-too-many' })).error, 'sso_team_full');
});

test('SSO: JWKS are cached per provider, and an unknown kid refetches once a minute at most (key rotation)', async () => {
  const { w, idp, team } = await setup();
  await signIn(w, idp, team); await signIn(w, idp, team, { sub: 'u2' });
  assert.equal(idp.calls.jwks, 1, 'one key set fetch for two sign-ins');
  const k2 = await rsaKey();
  idp.kids.k2 = k2;
  // a new kid within a minute of the last fetch: refused without hammering the provider
  assert.equal((await signIn(w, idp, team, { kid: 'k2', key: k2.privateKey })).error, 'sso_unknown_kid');
  assert.equal(idp.calls.jwks, 1);
  const real = Date.now; const t0 = real(); Date.now = () => t0 + 61_000 + (real() - t0);
  try { assert.equal((await signIn(w, idp, team, { kid: 'k2', key: k2.privateKey, sub: 'u3' })).error, null); } finally { Date.now = real; }
  assert.equal(idp.calls.jwks, 2, 'one refetch for the rotated key');
});

test('verifyIdToken directly: a token for another configuration (audience) is refused', async () => {
  const { w, idp } = await setup();
  const t = Math.floor(Date.now() / 1000);
  const cfg = { issuer: ISS, client_id: 'other-app', jwks_uri: ISS + '/jwks', algs: '["RS256"]' };
  const tok = await sign('RS256', idp.rsa.privateKey, { alg: 'RS256', kid: 'k1' }, { iss: ISS, aud: CLIENT, sub: 's', email: 'a@acme.example', email_verified: true, iat: t, exp: t + 60, nonce: 'n' });
  await assert.rejects(verifyIdToken(w.env, cfg, tok, 'n'), { code: 'sso_audience' });
  await assert.rejects(verifyIdToken(w.env, { ...cfg, client_id: CLIENT }, tok, 'm'), { code: 'sso_nonce' });
  await assert.rejects(verifyIdToken(w.env, { ...cfg, client_id: CLIENT }, 'a.b', 'n'), { code: 'sso_malformed' });
  await assert.rejects(verifyIdToken(w.env, { ...cfg, client_id: CLIENT }, 'x'.repeat(20000), 'n'), { code: 'sso_malformed' });
  assert.equal((await verifyIdToken(w.env, { ...cfg, client_id: CLIENT }, tok, 'n')).sub, 's');
});

test('SSO: deleting the account removes its SSO rows (foreign keys)', async () => {
  const { w, idp, u, team } = await setup();
  await signIn(w, idp, team);
  const b = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } })).status, 200);
  for (const t of ['sso_configs', 'sso_states', 'sso_identities']) assert.equal(count(w, `SELECT COUNT(*) AS n FROM ${t}`), 0, t);
});
