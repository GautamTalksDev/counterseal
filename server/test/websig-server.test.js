// The SIGIL registry is not part of the merged product (research, 9 Oct 2026: Cloudflare already runs the registry).
// These are the equivalents of its server tests for what was kept: the SSRF-safe directory fetch (now behind the free
// Web Bot Auth checker), security.txt, duplicate passkeys, IPv6 rate-limit buckets and private-key refusal.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World, Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { ipBucket, _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetToolCache } from '../src/tools.js';
import { generateIdentity, directory, signRequest, verifyRequest } from '../../sdk/websig.mjs';

beforeEach(() => { _resetMemoryBuckets(); _resetToolCache(); });
const anon = { origin: null, xleash: false };
const DIR = '/.well-known/http-message-signatures-directory';

test('/.well-known serves security.txt and 404s the rest; the Worker publishes no key directory of its own', async () => {
  const w = new World();
  const st = await w.req('GET', '/.well-known/security.txt', anon);
  assert.equal(st.status, 200);
  assert.match(st.body, /Contact: mailto:security@gautamkhosla\.com/);
  assert.match(st.body, /Canonical: https:\/\/leash\.test\/\.well-known\/security\.txt/);
  assert.equal((await w.req('GET', DIR, anon)).status, 404);
  assert.equal((await w.req('POST', '/.well-known/security.txt', anon)).status, 405);
});

test('checker directory fetch: SSRF-unsafe agents are refused before any fetch', async () => {
  const w = new World();
  let fetched = 0;
  w.env.__toolFetch = async () => { fetched++; return new Response('{"keys":[]}'); };
  for (const [i, bad] of ['https://127.0.0.1', 'https://localhost', 'https://169.254.169.254', 'https://internal.corp.internal', 'https://x.example.com:8443', 'https://[::1]', 'https://metadata.google.internal', 'http://bots.acme.com', 'https://u:p@bots.acme.com', 'notaurl', ''].entries()) {
    const r = await w.req('GET', '/v1/tools/directory?agent=' + encodeURIComponent(bad), { ...anon, ip: '192.0.2.' + (i + 1) });
    assert.equal(r.status, 400, bad); assert.match(r.body.error, /agent_not_allowed|bad_agent/, bad);
  }
  assert.equal(fetched, 0);
});

test('checker directory fetch: origin only, no redirects, size cap, cached, negatively cached, and limited without D1 writes', async () => {
  const w = new World();
  const id = await generateIdentity();
  const calls = [];
  const hosts = { 'https://bots.acme.com': () => Response.json(directory([id.publicJwk])), 'https://down.acme.com': () => new Response('no', { status: 500 }),
    'https://moved.acme.com': () => new Response('', { status: 302, headers: { location: 'http://169.254.169.254/' } }), 'https://big.acme.com': () => new Response('x'.repeat(70000)) };
  w.env.__toolFetch = async (u, init) => { calls.push([u, init.redirect]); return hosts[new URL(u).origin](); };
  const get = (a, ip) => w.req('GET', '/v1/tools/directory?agent=' + encodeURIComponent(a), { ...anon, ip });
  const ok = await get('https://bots.acme.com/some/path?q=1');
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.url, 'https://bots.acme.com' + DIR, 'only the well-known path at the origin');
  assert.deepEqual(ok.body.keys, [id.publicJwk]);
  assert.deepEqual(calls[0], ['https://bots.acme.com' + DIR, 'manual']);
  assert.equal((await get('https://bots.acme.com')).body.cached, true);
  assert.equal(calls.length, 1, 'cached');
  for (const [a, re] of [['https://down.acme.com', /HTTP 500/], ['https://moved.acme.com', /redirects are not followed/], ['https://big.acme.com', /too large/]]) {
    const r = await get(a);
    assert.equal(r.status, 502, a); assert.match(r.body.message, re);
  }
  const n = calls.length;
  assert.equal((await get('https://down.acme.com')).status, 502);
  assert.equal(calls.length, n, 'a failed host is not fetched again for 10 minutes');
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) n FROM ratelimits').get().n, 0, 'no D1 row for the tool');
  // 10 lookups a minute per caller network
  for (let i = 0; i < 10; i++) await get('https://bots.acme.com', '198.51.100.20');
  assert.equal((await get('https://bots.acme.com', '198.51.100.20')).status, 429);
  assert.equal((await get('https://bots.acme.com', '198.51.100.21')).status, 200, 'another network is unaffected');
});

test('the checker page verifies a real Web Bot Auth signature with the fetched directory, in the browser code', async () => {
  const { checkSignature } = await import('../../site/public/tools/web-bot-auth/check.js');
  const id = await generateIdentity();
  const url = 'https://shop.example/cart';
  const h = await signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: 'https://bots.acme.com' });
  const ok = await checkSignature({ method: 'GET', url, headers: h, directory: directory([id.publicJwk]) }, { verifyRequest });
  assert.equal(ok.ok, true, ok.text); assert.match(ok.text, /^SIGNATURE VALID/); assert.match(ok.text, /nonce was not checked/);
  const bad = await checkSignature({ method: 'GET', url: 'https://other.example/cart', headers: h, directory: directory([id.publicJwk]) }, { verifyRequest });
  assert.equal(bad.ok, false); assert.match(bad.text, /^NOT VALID/);
  assert.equal((await checkSignature({ method: 'GET', url, headers: {}, directory: { keys: [] } }, { verifyRequest })).ok, false);
});

test('a passkey that is already registered gets 409, not 500', async () => {
  const w = new World();
  const a = new Authenticator(ORIGIN, RP_ID);
  const b = await w.req('POST', '/v1/auth/register/begin', { body: { name: 'Dup' } });
  const cred = await a.create(b.body.options);
  w.env.DB.raw.prepare("INSERT INTO accounts (id, name, created_at) VALUES ('x', 'x', 1)").run();
  w.env.DB.raw.prepare("INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at) VALUES (?, 'x', -7, '{}', 0, 1)").run(cred.id);
  const f = await w.req('POST', '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: cred } });
  assert.equal(f.status, 409); assert.equal(f.body.error, 'passkey_exists');
});

test('IPv6 rate-limit buckets: the /64 is taken after expanding ::', async () => {
  const env = { IP_SALT: 'x' };
  const b = (ip) => ipBucket(env, new Request('https://x.test/', { headers: { 'cf-connecting-ip': ip } }), 'p');
  assert.equal(await b('2001:db8::1'), await b('2001:db8:0:0:ffff::2'));
  assert.equal(await b('2001:db8::1'), await b('2001:0db8:0000:0000:1:2:3:4'));
  assert.notEqual(await b('2001:db8::1'), await b('2001:db8:0:1::1'));
  assert.notEqual(await b('2001:db8::1'), await b('2001:db9::1'));
  assert.equal(await b('198.51.100.7'), await b('198.51.100.7'));
  assert.notEqual(await b('198.51.100.7'), await b('198.51.100.8'));
});

test('the SDK verifier is local by default: no third-party verify API is ever called unless one is named', async () => {
  const { verify } = await import('../../sdk/verifier.mjs');
  const id = await generateIdentity();
  const h = await signRequest({ url: 'https://shop.example/' }, { key: id.privateKey, keyid: id.keyid, agent: 'https://bots.acme.com' });
  let calls = 0;
  const r = await verify(new Request('https://shop.example/', { headers: h }), { fetchDirectory: async () => directory([id.publicJwk]), fetch: async () => { calls++; return Response.json({ verified: true }); } });
  assert.equal(r.verified, true, r.reason); assert.equal(calls, 0);
  void verifyRequest;
});
