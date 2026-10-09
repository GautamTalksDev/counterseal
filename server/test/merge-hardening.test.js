// Fixes from the adversarial review of the merged system (9 Oct 2026). Each test names its finding.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { signBrokerRequest, generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';

beforeEach(() => _resetMemoryBuckets());
const anon = { origin: null, xleash: false };

async function boundSetup(w) {
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'H'.repeat(36) } })).body.id;
  const jwk = await generateAgentKey(); const key = await importAgentKey(jwk);
  const b = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
  const ak = (await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b.challengeId, proof: await proveAgentKey(key, b.sign) } })).body;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, agentKeyId: ak.id } })).body.token;
  return { u, ak: { ...ak, key }, tok };
}

test('R1 (DoS of the log): reads that reach the Durable Object have a tighter limit than cached reads', async () => {
  // the limiter refills 2 tokens a second; hold the clock so a slow machine draining 120 tokens does not earn one back
  const real = Date.now, t0 = real();
  Date.now = () => t0;
  try { await r1(); } finally { Date.now = real; }
});
async function r1() {
  const w = new World();
  for (let i = 0; i < 120; i++) assert.equal((await w.req('GET', '/v1/log/entries?start=0&count=1', anon)).status, 200);
  const r = await w.req('GET', '/v1/log/entries?start=0&count=1', anon);
  assert.equal(r.status, 429); assert.equal(r.headers.get('access-control-allow-origin'), '*');
  assert.equal((await w.req('GET', '/v1/log/proof/consistency?first=1&second=1', anon)).status, 429, 'proofs share the limit');
  assert.equal((await w.req('GET', '/v1/stats', anon)).status, 200, 'the cached head is not limited by it');
  assert.equal((await w.req('GET', '/v1/log/entries?start=0&count=1', { ...anon, ip: '198.51.100.30' })).status, 200, 'per network');
  const u = await w.user('R', '198.51.100.31');
  for (let i = 0; i < 60; i++) await w.req('GET', '/v1/my/receipts', { cookie: u.cookie });
  assert.equal((await w.req('GET', '/v1/my/receipts', { cookie: u.cookie })).status, 429, 'your own receipts: 60 a minute');
  assert.equal((await w.req('GET', '/v1/holds', { cookie: u.cookie })).status, 200, 'other dashboard reads are unaffected');
}

test('R2 (signature binding): a signed request with a body must cover its content type, and an agent key\'s last use is written at most once a minute', async () => {
  const w = new World();
  const { ak, tok } = await boundSetup(w);
  const url = 'https://leash.test/p/github/repos/a/b/issues';
  const send = async (contentType, signed = contentType) => {
    const h = await signBrokerRequest({ method: 'POST', url, body: '{"x":1}', contentType: signed }, { key: ak.key, kid: ak.keyid });
    return w.req('POST', url, { bearer: tok, ...anon, raw: '{"x":1}', headers: { ...h, 'content-type': contentType } });
  };
  assert.equal((await send('application/json')).status, 200);
  assert.equal((await send('application/json', null)).body.reason, 'a request with a body must cover content-type');
  let updates = 0;
  const prep = w.env.DB.prepare;
  w.env.DB.prepare = (sql) => { if (/^UPDATE agent_keys SET last_used/.test(sql)) updates++; return prep(sql); };
  for (let i = 0; i < 3; i++) assert.equal((await w.req('GET', 'https://leash.test/p/github/repos/a/b', { bearer: tok, ...anon, headers: await signBrokerRequest({ method: 'GET', url: 'https://leash.test/p/github/repos/a/b' }, { key: ak.key, kid: ak.keyid }) })).status, 200);
  assert.equal(updates, 0, 'the key was used under a minute ago, so its last use is not written again');
  w.env.DB.raw.prepare('UPDATE agent_keys SET last_used = ?').run(Date.now() - 61_000);
  await w.req('GET', 'https://leash.test/p/github/repos/a/b', { bearer: tok, ...anon, headers: await signBrokerRequest({ method: 'GET', url: 'https://leash.test/p/github/repos/a/b' }, { key: ak.key, kid: ak.keyid }) });
  assert.equal(updates, 1);
  w.env.DB.prepare = prep;
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) n FROM agent_keys WHERE last_used IS NOT NULL').get().n, 1);
});

test('R3 (abuse): a phone alert test is limited to 3 a minute per account', async () => {
  const w = new World();
  const u = await w.user();
  for (let i = 0; i < 3; i++) assert.equal((await w.req('POST', '/v1/push/test', { cookie: u.cookie, body: {} })).status, 200);
  assert.equal((await w.req('POST', '/v1/push/test', { cookie: u.cookie, body: {} })).status, 429);
});

test('R4 (log integrity): the log never signs under a different name or key than it started with', async () => {
  const w = new World();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const send = () => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'b' } } });
  assert.equal((await send()).status, 200);
  w.env.LOG_ORIGIN = 'another.example/log';
  const r = await send();
  assert.equal(r.status, 503); assert.equal(r.body.error, 'log_key_changed');
  assert.equal(w.core.size(), 1);
  assert.equal(w.env.DB.raw.prepare('SELECT receipts FROM usage').get().receipts, 1, 'a refused append counts nothing');
  // and a private key that does not match its public part is refused before anything is signed
  w.env.LOG_ORIGIN = 'leash.test/log';
  const j = JSON.parse(w.env.LOG_KEY_JWK), other = JSON.parse(await (await import('./helpers.js')).logKeyJwk());
  w.env.LOG_KEY_JWK = JSON.stringify({ d: other.d, x: j.x });
  assert.equal((await w.req('GET', '/v1/log/key', anon)).body.error, 'log_key_invalid');
});

test('R5 (privacy): security log lines never carry a proxied path (repo or project names)', async () => {
  const w = new World();
  const lines = [];
  const orig = console.warn; console.warn = (...a) => lines.push(a.join(' '));
  try { await w.req('GET', '/p/github/repos/secret-org/secret-repo', { bearer: 'lsh_' + 'A'.repeat(43), ...anon }); } finally { console.warn = orig; }
  const text = lines.join('\n');
  assert.match(text, /"path":"\/p\/github\/\.\.\."/);
  assert.ok(!text.includes('secret-org') && !text.includes('secret-repo'), text);
});
