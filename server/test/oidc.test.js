// GitHub Actions OIDC verification: forged and malformed tokens, wrong issuer and audience, time, replay, the claims'
// shapes, and GitHub's key set (cache, rotation, outages, hostile documents). Tokens are signed by a stand-in issuer
// (test/gh.js) with a real RSA-2048 key; the Worker fetches its key set through env.__oidcFetch.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { makeGithub } from './gh.js';
import { verifyGithubToken, _resetOidc, _oidcState, ISSUER, JWKS_URL, JWKS_TTL, JWKS_STALE_OK, JWKS_REFETCH_MIN, SKEW, MAX_TOKEN } from '../src/oidc.js';
import { b64u } from '../src/util.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { anon, world, makeGate, gateId, ask, audienceFor, db, timeShift } from './gate-helpers.js';

beforeEach(() => { _resetOidc(); _resetMemoryBuckets(); });
const AUD = 'https://leash.test/gate/gate_x';
const now = () => Date.now();
const enc = new TextEncoder();
async function setup() { const gh = await makeGithub(); return { gh, env: { __oidcFetch: gh.fetch } }; }
const verify = (env, token, o = {}) => verifyGithubToken(env, token, { audience: AUD, now: now(), ...o });
const fails = async (p, code, status = 401) => { try { await p; } catch (e) { assert.equal(e.code, code, `${e.code}: ${e.message}`); assert.equal(e.status, status); return e; } assert.fail('expected ' + code); };

test('a good token verifies and its claims come back in strict shapes (ids as digit strings, as GitHub sends them)', async () => {
  const { gh, env } = await setup();
  const c = await verify(env, await gh.token(gh.claims()));
  assert.deepEqual({ ...c, jti: 'x', exp: 0, iat: 0, workflow: undefined, job_workflow: undefined }, {
    jti: 'x', exp: 0, iat: 0, repository: 'acme/app', repository_id: '1001', repository_owner: 'acme', repository_owner_id: '77', ref: 'refs/heads/main', sha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main', workflow: undefined, job_workflow: undefined,
    environment: 'production', event_name: 'push', run_id: '812', run_attempt: '1', check_run_id: '5551', actor: 'octocat', visibility: 'private', runner: 'github-hosted',
  });
  assert.deepEqual(c.workflow, { repository: 'acme/app', path: '.github/workflows/deploy.yml', ref: 'refs/heads/main' });
  // numbers are accepted for ids; no environment and no check_run_id are fine; an odd actor is blanked, not trusted
  const n = await verify(env, await gh.token(gh.claims({ repository_id: 1001, run_id: 812, run_attempt: 2, environment: undefined, check_run_id: undefined, actor: 'bad actor\n', repository_visibility: 'weird' })));
  assert.equal(n.repository_id, '1001'); assert.equal(n.run_attempt, '2'); assert.equal(n.environment, ''); assert.equal(n.check_run_id, ''); assert.equal(n.actor, ''); assert.equal(n.visibility, '');
  // the bot actors GitHub uses are fine
  assert.equal((await verify(env, await gh.token(gh.claims({ actor: 'dependabot[bot]' })))).actor, 'dependabot[bot]');
});

test('forged tokens: alg none, HS256 keyed with the public key, another alg, a key of the attacker\'s own, a tampered payload', async () => {
  const { gh, env } = await setup();
  const good = gh.claims();
  const jwk = gh.jwks().keys[0];
  // alg: none, with and without a signature part
  await fails(verify(env, await gh.token(good, { header: { alg: 'none' }, sig: 'AAAA' })), 'oidc_alg');
  await fails(verify(env, await gh.token(good, { header: { alg: 'none' }, sig: '' })), 'oidc_alg');
  await fails(verify(env, await gh.token(good, { header: { alg: 'None' }, sig: 'AAAA' })), 'oidc_alg');
  // HS256 signed with the RSA public key's material as the HMAC secret (the classic downgrade)
  for (const secret of [enc.encode(jwk.n), Uint8Array.from(Buffer.from(jwk.n, 'base64url')), enc.encode(JSON.stringify(jwk))]) {
    const k = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const head = b64u(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: gh.current }))), body = b64u(enc.encode(JSON.stringify(good)));
    const sig = b64u(new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(`${head}.${body}`))));
    await fails(verify(env, `${head}.${body}.${sig}`), 'oidc_alg');
  }
  // other algorithms are not GitHub's: pinned, never taken from the token
  for (const alg of ['RS384', 'RS512', 'PS256', 'ES256', 'EdDSA', 'rs256', 'RS256 ', '', null, 5, ['RS256']]) await fails(verify(env, await gh.token(good, { header: { alg } })), 'oidc_alg', 401);
  await fails(verify(env, await gh.token(good, { header: { alg: undefined } })), 'oidc_alg');
  // a key of the attacker's own, under GitHub's kid: the signature does not verify
  const evil = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  await fails(verify(env, await gh.token(good, { key: evil.privateKey })), 'oidc_bad_signature');
  // the attacker's own key set is not consulted: the key never comes from the token
  for (const h of [{ jwk: { kty: 'RSA' } }, { jku: 'https://evil.example/jwks' }, { x5u: 'https://evil.example/c.pem' }, { x5c: ['AAAA'] }, { crit: ['exp'] }, { crit: [] }]) {
    await fails(verify(env, await gh.token(good, { header: h })), 'oidc_malformed');
  }
  await fails(verify(env, await gh.token(good, { header: { typ: 'at+jwt' } })), 'oidc_malformed');
  // a payload changed after signing
  for (const t of [{ repository: 'evil/app' }, { sha: 'f'.repeat(40) }, { aud: 'x' }, { exp: good.exp + 99999 }, { environment: 'staging' }]) await fails(verify(env, await gh.token(good, { tamper: t })), 'oidc_bad_signature');
  // a signature copied from another token
  const other = await gh.token(gh.claims({ run_id: '1' }));
  await fails(verify(env, await gh.token(good, { sig: other.split('.')[2] })), 'oidc_bad_signature');
  // truncated, extended, wrong-length and non-base64 signatures
  const sig = (await gh.token(good)).split('.')[2];
  for (const s of [sig.slice(0, -4), sig + 'AAAA', 'AAAA', sig.slice(0, 100)]) await fails(verify(env, await gh.token(good, { sig: s })), 'oidc_bad_signature');
  for (const s of ['!!!!', sig + '=', sig.replace(/.$/, '+')]) await fails(verify(env, await gh.token(good, { sig: s })), 'oidc_malformed');
  // a kid that is not GitHub's, or is not a kid at all
  await fails(verify(env, await gh.token(good, { header: { kid: 'attacker-key' } })), 'oidc_unknown_kid');
  for (const kid of [undefined, '', 5, 'a b', 'x'.repeat(129), '../../etc']) await fails(verify(env, await gh.token(good, { header: { kid } })), 'oidc_malformed');
});

test('shape: not three base64url parts, too big, not JSON, not an object', async () => {
  const { gh, env } = await setup();
  const tok = await gh.token(gh.claims());
  const [h, p, s] = tok.split('.');
  const bad = [undefined, null, 5, {}, '', 'a.b', `${h}.${p}`, `${tok}.x`, `${h}..${s}`, `.${p}.${s}`, ` ${tok}`, `${tok}\n`, `${h}.${p}.${s}.`, 'x'.repeat(MAX_TOKEN + 1), `${h}.${b64u(enc.encode('[]'))}.${s}`, `${h}.${b64u(enc.encode('not json'))}.${s}`, `${b64u(enc.encode('[]'))}.${p}.${s}`, `${b64u(enc.encode('{'))}.${p}.${s}`];
  for (const t of bad) { const e = await verify(env, t).catch((x) => x); assert.ok(e && e.status === 401 && /^oidc_/.test(e.code), String(t).slice(0, 40) + ' ' + (e && e.code)); }
  // payload not UTF-8
  const body = b64u(Uint8Array.of(0xff, 0xfe, 0x7b, 0x7d));
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: gh.current })));
  const sig = b64u(new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, gh.keys.get(gh.current).kp.privateKey, enc.encode(`${head}.${body}`))));
  await fails(verify(env, `${head}.${body}.${sig}`), 'oidc_malformed');
});

test('issuer and audience are exact: another issuer, a path on the issuer, an array, another gate, the origin alone, GitHub\'s default audience', async () => {
  const { gh, env } = await setup();
  for (const iss of ['https://evil.example', ISSUER + '/', ISSUER + '/acme', 'http://token.actions.githubusercontent.com', ISSUER.toUpperCase(), '', undefined, null, [ISSUER]]) {
    await fails(verify(env, await gh.token(gh.claims({ iss }))), 'oidc_issuer');
  }
  for (const aud of ['https://leash.test/gate/gate_y', 'https://leash.test', 'https://leash.test/gate/gate_x/', 'https://leash.test/gate/GATE_X', 'https://github.com/acme', 'https://counterseal.gautamkhosla.com/gate/gate_x', '', undefined, null, 5, [AUD], [AUD, 'https://other.example'], ['https://other.example']]) {
    await fails(verify(env, await gh.token(gh.claims({ aud }))), 'oidc_audience');
  }
  await fails(verify(env, await gh.token(gh.claims()), { audience: 'https://leash.test/gate/gate_z' }), 'oidc_audience');
});

test('time: expiry, not-before and issued-at with 60 seconds of skew, and no token valid for more than an hour', async () => {
  const { gh, env } = await setup();
  const t = Math.floor(Date.now() / 1000);
  const ok = (over) => verify(env, gh.token(gh.claims(over)).then ? undefined : undefined);
  void ok;
  const at = async (over) => verify(env, await gh.token(gh.claims(over)));
  assert.ok(await at({ iat: t, nbf: t - 600, exp: t + 300 }));
  assert.ok(await at({ iat: t - 400, nbf: t - 1000, exp: t - SKEW + 5 }), 'a few seconds inside the skew after expiry still verifies');
  await fails(at({ iat: t - 400, nbf: t - 1000, exp: t - SKEW - 5 }), 'oidc_expired');
  await fails(at({ iat: t - 4000, nbf: t - 4000, exp: t - 3000 }), 'oidc_expired');
  assert.ok(await at({ iat: t, nbf: t + SKEW - 5, exp: t + 300 }), 'nbf slightly in the future is clock skew');
  await fails(at({ iat: t, nbf: t + 120, exp: t + 300 }), 'oidc_not_yet_valid');
  assert.ok(await at({ iat: t + SKEW - 5, nbf: t - 100, exp: t + 300 }));
  await fails(at({ iat: t + 120, nbf: t - 100, exp: t + 500 }), 'oidc_not_yet_valid');
  await fails(at({ iat: t, nbf: t, exp: t + 3600 + SKEW + 30 }), 'oidc_lifetime');
  assert.ok(await at({ iat: t, nbf: t, exp: t + 3600 }));
  await fails(at({ iat: t, nbf: t, exp: t }), 'oidc_lifetime');
  await fails(at({ iat: t + 5, nbf: t, exp: t + 3 }), 'oidc_lifetime');
  for (const bad of ['9999999999', null, undefined, NaN, -1, 5e9, true, [1]]) {
    await fails(at({ exp: bad }), 'oidc_claims'); await fails(at({ nbf: bad }), 'oidc_claims'); await fails(at({ iat: bad }), 'oidc_claims');
  }
  // the clock is the Worker's: a verification "in the future" sees the same token as expired
  await fails(verifyGithubToken(env, await gh.token(gh.claims()), { audience: AUD, now: Date.now() + 10 * 60_000 }), 'oidc_expired');
});

test('claims are strict: a missing or odd value for anything the gate decides on is a refusal, not a guess', async () => {
  const { gh, env } = await setup();
  const at = async (over) => verify(env, await gh.token(gh.claims(over)));
  const bad = {
    jti: [undefined, '', 5, 'a b', 'x'.repeat(129), '\n'],
    repository: [undefined, 'acme', 'acme/app/x', 'ac me/app', 'acme/ap p', '/app', 'acme/', 5, 'a'.repeat(40) + '/app', 'acme/' + 'a'.repeat(101)],
    repository_id: [undefined, '', 'abc', '12 3', -1, 1.5, '1'.repeat(21), null],
    repository_owner: [undefined, 'ac me', 'other'], repository_owner_id: [undefined, 'x'],
    ref: [undefined, 'main', 'heads/main', 'refs/', 5, 'refs/heads/a b', 'refs/heads/a\nb'],
    sha: [undefined, '', 'a'.repeat(39), 'a'.repeat(41), 'A'.repeat(40), 'g'.repeat(40), 5],
    workflow_ref: [undefined, 'acme/app/.github/workflows/deploy.yml', 'acme/app/deploy.yml@refs/heads/main', 'acme/app/.github/workflows/sub/deploy.yml@refs/heads/main', 'acme/app/.github/workflows/deploy.txt@refs/heads/main', 'acme/app/.github/workflows/deploy.yml@main', 'acme/app/.github/workflows/deploy.yml@refs/heads/ma in', 5],
    job_workflow_ref: [undefined, '', 'acme/app/.github/workflows/deploy.yml', 'acme/app/.github/actions/x.yml@refs/heads/main'],
    event_name: [undefined, '', 'PUSH', 'push!', 5], run_id: [undefined, 'x', '1 2'], run_attempt: [undefined, '', 'a'], check_run_id: ['x', '1 2', 1.5],
    environment: ['bad\nenv', 'x'.repeat(256), 5, 'a​b'],
  };
  for (const [name, list] of Object.entries(bad)) for (const v of list) await fails(at({ [name]: v }), 'oidc_claims').catch((e) => { throw new Error(`${name}=${JSON.stringify(v)}: ${e.message}`); });
  assert.ok(await at({ repository: 'Acme/App', repository_owner: 'acme' }), 'the owner is compared without case');
  assert.ok(await at({ ref: 'refs/tags/v1.0.0' }));
  assert.ok(await at({ sha: 'a'.repeat(64) }), 'a SHA-256 repository');
  assert.ok(await at({ environment: 'Production (EU) / blue' }));
  assert.ok(await at({ ref: 'refs/pull/12/merge' }), 'any refs/ value verifies; whether a gate accepts it is the gate\'s decision');
});

test('GitHub\'s key set: fetched once per ten minutes, the imported key reused, one fetch for concurrent first requests', async () => {
  const { gh, env } = await setup();
  const imports = []; const real = crypto.subtle.importKey.bind(crypto.subtle);
  crypto.subtle.importKey = (fmt, ...rest) => { imports.push(fmt); return real(fmt, ...rest); };
  try {
    const t0 = Date.now();
    // ten requests at once on a cold isolate: one fetch
    await Promise.all(Array.from({ length: 10 }, async () => verify(env, await gh.token(gh.claims()), { now: t0 })));
    assert.equal(gh.fetches, 1); assert.equal(gh.lastUrl, JWKS_URL);
    for (let i = 0; i < 20; i++) await verify(env, await gh.token(gh.claims()), { now: t0 + i * 1000 });
    assert.equal(gh.fetches, 1, 'cached');
    assert.equal(imports.filter((f) => f === 'jwk').length, 1, 'the key is imported once and kept');
    // after ten minutes it is fetched again, and the unchanged key is not imported again
    const t1 = t0 + JWKS_TTL + 1000;
    const c = gh.claims(); c.iat = Math.floor(t1 / 1000); c.nbf = c.iat - 600; c.exp = c.iat + 300;
    await verify(env, await gh.token(c), { now: t1 });
    assert.equal(gh.fetches, 2);
    assert.equal(imports.filter((f) => f === 'jwk').length, 1);
  } finally { crypto.subtle.importKey = real; }
});

test('key rotation: a token signed by a new key is accepted after one early refetch (at most one a minute); the retired key stops', async () => {
  const { gh, env } = await setup();
  const t0 = Date.now();
  const oldKid = gh.current, oldKey = gh.keys.get(oldKid).kp.privateKey;
  // signs with the key that belongs to the kid when GitHub still has one; a retired or invented kid is signed with a real key (the old one)
  const at = async (kid, t, over = {}) => { const c = gh.claims(over); c.iat = Math.floor(t / 1000); c.nbf = c.iat - 600; c.exp = c.iat + 300; return verify(env, await gh.token(c, { kid, key: gh.keys.get(kid)?.kp.privateKey || oldKey }), { now: t }); };
  await at(oldKid, t0);
  assert.equal(gh.fetches, 1);
  const newKid = await gh.rotate();
  // right after a fetch, the new kid is unknown and does not cause another fetch
  await fails(at(newKid, t0 + 5_000), 'oidc_unknown_kid');
  assert.equal(gh.fetches, 1, 'no fetch for a kid seen 5 seconds after the last one');
  // a minute later, the refetch finds it
  assert.ok(await at(newKid, t0 + JWKS_REFETCH_MIN + 1_000));
  assert.equal(gh.fetches, 2);
  // the old key left the set: it fails (after at most one more refetch, itself spaced a minute)
  await fails(at(oldKid, t0 + JWKS_REFETCH_MIN + 2_000), 'oidc_unknown_kid');
  assert.equal(gh.fetches, 2);
  // a new key published while the old stays (GitHub rotates with overlap): both verify
  const third = await gh.rotate({ keep: true });
  assert.ok(await at(third, t0 + 3 * JWKS_REFETCH_MIN));
  assert.ok(await at(newKid, t0 + 3 * JWKS_REFETCH_MIN + 1));
  // a flood of tokens with random kids costs one fetch a minute, not one each
  const before = gh.fetches;
  for (let i = 0; i < 60; i++) await fails(at('k' + i, t0 + 5 * JWKS_REFETCH_MIN + i * 500), 'oidc_unknown_kid');
  assert.ok(gh.fetches - before <= 1, `${gh.fetches - before} fetches for 60 random kids in 30 seconds`);
});

test('GitHub unreachable: a cold start fails closed (503) without hammering; cached keys outlive an outage for an hour, then nothing verifies', async () => {
  const { gh, env } = await setup();
  const t0 = Date.now();
  const at = async (t, over = {}) => { const c = gh.claims(over); c.iat = Math.floor(t / 1000); c.nbf = c.iat - 600; c.exp = c.iat + 300; return verify(env, await gh.token(c), { now: t }); };
  gh.failing = true;
  await fails(at(t0), 'oidc_keys_unavailable', 503);
  await fails(at(t0 + 2_000), 'oidc_keys_unavailable', 503);
  assert.equal(gh.fetches, 1, 'one attempt, then a pause of ten seconds');
  gh.failing = false;
  await fails(at(t0 + 5_000), 'oidc_keys_unavailable', 503);
  assert.equal(gh.fetches, 1);
  assert.ok(await at(t0 + 11_000), 'after the pause it tries again');
  // an outage after the keys were cached: they still verify for an hour past their ten minutes
  gh.failing = true;
  const t1 = t0 + 11_000 + JWKS_TTL + 1000;
  assert.ok(await at(t1));
  assert.ok(await at(t1 + JWKS_STALE_OK - 5_000));
  const n = gh.fetches;
  assert.ok(await at(t1 + 1_000));
  assert.equal(gh.fetches, n, 'during the outage it retries every ten seconds, not on every request');
  await fails(at(t1 + JWKS_STALE_OK + 60_000), 'oidc_keys_unavailable', 503);
  // GitHub is back: the first request refetches and verifies
  gh.failing = false;
  assert.ok(await at(t1 + JWKS_STALE_OK + 120_000));
});

test('a hostile or broken key set is never trusted: not JSON, wrong shapes, small or odd keys, redirects, oversize', async () => {
  const { gh } = await setup();
  const good = gh.jwks().keys[0];
  const run = async (resp, expect) => {
    _resetOidc();
    const env = { __oidcFetch: async () => resp() };
    const t = await gh.token(gh.claims());
    if (expect === 'ok') assert.ok(await verify(env, t)); else await fails(verify(env, t), expect, expect === 'oidc_keys_unavailable' ? 503 : 401);
  };
  const json = (o, init = {}) => () => new Response(JSON.stringify(o), { status: 200, ...init });
  await run(json({ keys: [good] }), 'ok');
  await run(() => new Response('<html>nope</html>', { status: 200 }), 'oidc_keys_unavailable');
  await run(() => new Response('', { status: 200 }), 'oidc_keys_unavailable');
  await run(json({ keys: 'x' }), 'oidc_keys_unavailable'); await run(json([good]), 'oidc_keys_unavailable'); await run(json({}), 'oidc_keys_unavailable'); await run(json({ keys: [] }), 'oidc_keys_unavailable');
  await run(json({ keys: Array.from({ length: 21 }, () => good) }), 'oidc_keys_unavailable');
  await run(() => new Response('{}', { status: 302, headers: { location: 'https://evil.example/jwks' } }), 'oidc_keys_unavailable');
  await run(() => new Response('{}', { status: 500 }), 'oidc_keys_unavailable');
  await run(() => { throw new Error('network'); }, 'oidc_keys_unavailable');
  await run(() => new Response(JSON.stringify({ keys: [good], pad: 'x'.repeat(70_000) }), { status: 200 }), 'oidc_keys_unavailable');
  // keys that are skipped: wrong kty, alg, use, exponent, size, kid; with only those, there is no key set
  const small = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const sj = await crypto.subtle.exportKey('jwk', small.publicKey);
  for (const k of [{ ...good, kty: 'EC' }, { ...good, alg: 'RS384' }, { ...good, alg: 'HS256' }, { ...good, use: 'enc' }, { ...good, e: 'Aw' }, { ...good, kid: 'a b' }, { ...good, kid: undefined }, { ...good, n: 'AAAA' }, { ...good, n: '!!' }, { kty: 'RSA', kid: good.kid, n: sj.n, e: sj.e }, null, 'x', 5]) {
    await run(json({ keys: [k] }), 'oidc_keys_unavailable');
  }
  // a good key next to junk is still used
  await run(json({ keys: [null, { kty: 'EC' }, good, 'x'] }), 'ok');
  // a key set that swaps a key under the same kid is a different key (the imported one is not reused)
  const { gh: other } = await setup();
  _resetOidc();
  const t = await gh.token(gh.claims());
  const env = { __oidcFetch: async () => new Response(JSON.stringify({ keys: [{ ...other.jwks().keys[0], kid: good.kid }] })) };
  await fails(verify(env, t), 'oidc_bad_signature');
});

test('through the API: a token is spent by its first use; a refused run spends nothing and writes nothing; a token for one gate is no use at another', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u), g2 = await gateId(w, u, { label: 'other' });
  const jwt = await gh.token(gh.claims({ aud: audienceFor(w.env, g) }));
  const r = await ask(w, gh, g, {}, { token: jwt });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const rows = db(w).prepare("SELECT k, expires_at FROM nonces WHERE k LIKE 'oidc:%'").all();
  assert.equal(rows.length, 1);
  const exp = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')).exp;
  assert.equal(rows[0].expires_at, (exp + SKEW) * 1000, 'remembered until it could no longer verify');
  // replayed, to the same gate: refused, and no second hold, poll secret or alert
  const holdsBefore = db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, pollsBefore = db(w).prepare('SELECT COUNT(*) n FROM gate_polls').get().n;
  const again = await ask(w, gh, g, {}, { token: jwt });
  assert.equal(again.status, 401); assert.equal(again.body.error, 'oidc_replayed');
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, holdsBefore); assert.equal(db(w).prepare('SELECT COUNT(*) n FROM gate_polls').get().n, pollsBefore);
  // a token made for one gate, sent to another (the body names it), or with the audience of the product alone
  const other = await ask(w, gh, g2, {}, { token: await gh.token(gh.claims({ aud: audienceFor(w.env, g) })), body: { gate: g2 } });
  assert.equal(other.body.error, 'oidc_audience');
  assert.equal((await ask(w, gh, g, {}, { token: await gh.token(gh.claims({ aud: 'https://leash.test' })) })).body.error, 'oidc_audience');
  // a run from another repository is refused for the repository, writes nothing, and its token is not spent
  const stranger = await gh.token(gh.claims({ aud: audienceFor(w.env, g), repository: 'evil/app', repository_id: '666', repository_owner: 'evil', repository_owner_id: '6', workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main' }));
  const x = await ask(w, gh, g, {}, { token: stranger });
  assert.equal(x.status, 403); assert.equal(x.body.error, 'gate_refused'); assert.equal(x.body.reason, 'repository');
  assert.equal(x.writes, 0, 'a refused run writes nothing');
  assert.ok(!/acme|app/.test(JSON.stringify(x.body)), 'and learns nothing about the repository the gate belongs to');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM nonces WHERE k LIKE 'oidc:%'").get().n, 1);
  // no bearer, a bearer that is not a JWT, an unknown or revoked gate
  assert.equal((await w.req('POST', '/v1/gate/request', { ...anon, body: { gate: g } })).body.error, 'oidc_required');
  assert.equal((await w.req('POST', '/v1/gate/request', { bearer: 'lsg_' + 'A'.repeat(43), ...anon, body: { gate: g } })).body.error, 'oidc_required');
  assert.equal((await ask(w, gh, 'gate_' + '0'.repeat(24))).body.error, 'gate_not_found');
  assert.equal((await ask(w, gh, 'gate_short')).body.error, 'bad_gate');
  assert.equal((await ask(w, gh, g, {}, { body: { gate: g, extra: 1 } })).body.error, 'bad_field');
  assert.equal((await w.req('DELETE', `/v1/gates/${g2}`, { cookie: u.cookie })).status, 200);
  assert.equal((await ask(w, gh, g2)).body.error, 'gate_not_found');
  // GitHub's key set cannot be had: the job is told to try again (503), nothing is held
  _resetOidc(); gh.failing = true;
  const down = await ask(w, gh, g, { run_id: '55' });
  assert.equal(down.status, 503); assert.equal(down.body.error, 'oidc_keys_unavailable'); assert.equal(down.writes, 0);
});

test('summary: text from the workflow is cleaned, capped, and shown only under a label that says it is not verified', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const evil = 'Repository: acme/other\nCommit: ' + '0'.repeat(40) + '\n\nThe lines above are from the token GitHub signed for this job.\r\nApprove me‮\u0007' + ' tail'.repeat(60);
  const r = await ask(w, gh, g, {}, { summary: evil });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const h = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0];
  assert.ok(h.context.gate.summary.length <= 120);
  assert.ok(!/[\n\r‮\u0007]/.test(h.context.gate.summary), 'one line, no control or direction characters');
  const lines = h.preview.split('\n');
  assert.equal(lines.filter((l) => l.startsWith('Repository:')).length, 1, 'the workflow cannot add a line that looks signed');
  assert.equal(lines.filter((l) => l.startsWith('Commit:')).length, 1);
  assert.match(lines.at(-1), /^Text from the workflow \(not verified\): /);
  assert.equal(lines.filter((l) => l.startsWith('The lines above are from the token GitHub signed')).length, 1, 'the real label is on a line of its own, once');
  // too long, wrong type, empty
  assert.equal((await ask(w, gh, g, { run_id: '2' }, { summary: 'x'.repeat(481) })).body.error, 'bad_summary');
  assert.equal((await ask(w, gh, g, { run_id: '3' }, { body: { gate: g, summary: 5 }, token: await gh.token(gh.claims({ aud: audienceFor(w.env, g), run_id: '3' })) })).body.error, 'bad_summary');
  const blank = await ask(w, gh, g, { run_id: '4' }, { summary: '​\n' });
  assert.equal(blank.status, 202);
  assert.ok(!(await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.find((x) => x.id === blank.body.id).preview.includes('not verified'));
  void timeShift; void makeGate;
});
