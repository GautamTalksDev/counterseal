// The joints between the three parts: a broker decision becomes a public receipt (Approve -> Record), an agent's own
// signature is required by a bound token (Prove who -> Approve), and the receipt names the agent key (Prove who ->
// Record). Plus forgery, replay across parts, signature downgrade, quota bypass and privacy of public receipts.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { verifyBundle } from '../../sdk/receipts.mjs';
import { signBrokerRequest, generateAgentKey, importAgentKey, keyid, proveAgentKey } from '../../cli/sign.mjs';
import { canonical } from '../src/receipts.js';
import { b64u } from '../src/util.js';

beforeEach(() => _resetMemoryBuckets());
const GH = 'ghp_' + 'Q'.repeat(36);
const anon = { origin: null, xleash: false };

async function account(w, name = 'Gautam', ip) {
  const u = await w.user(name, ip);
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH, label: 'prod' } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  return { ...u, cred: c.body.id, id: await w.accountId(u.cookie) };
}
async function token(w, u, extra = {}) {
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: u.cred, label: 'coding agent', ...extra } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return t.body;
}
async function approve(w, u, holdId) {
  const b = await w.req('POST', `/v1/holds/${holdId}/approve/begin`, { cookie: u.cookie, body: {} });
  return w.req('POST', `/v1/holds/${holdId}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
/** register an agent key with proof of possession; returns {id, keyid, jwk, key} */
async function agentKey(w, u, label = 'laptop agent') {
  const jwk = await generateAgentKey();
  const key = await importAgentKey(jwk);
  const b = await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const r = await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { label, publicKey: jwk.x, challengeId: b.body.challengeId, proof: await proveAgentKey(key, b.body.sign) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { ...r.body, jwk, key };
}
/** a proxied call, signed with the agent key when one is given */
async function call(w, tok, method, path, { body, ak, sign = {} } = {}) {
  const url = 'https://leash.test/p/github' + path;
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const headers = { ...(raw !== undefined ? { 'content-type': 'application/json' } : {}) };
  if (ak) Object.assign(headers, await signBrokerRequest({ method, url, body: raw }, { key: ak.key, kid: ak.keyid, ...sign }));
  return w.req(method, url, { bearer: tok, ...anon, raw, headers });
}
const publicEntries = async (w) => (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries;
const auditRows = (w, acct) => w.env.DB.raw.prepare('SELECT action, detail, hash, receipt FROM audit WHERE account_id = ? ORDER BY seq').all(acct);

test('Approve -> Record: every broker decision on a write is sealed as a public receipt that only the broker can make', async () => {
  const w = new World();
  const u = await account(w);
  const { token: t } = await token(w, u);
  assert.equal((await call(w, t, 'GET', '/repos/acme/app')).status, 200);
  assert.equal((await publicEntries(w)).length, 0, 'reads are not sealed');
  assert.equal((await call(w, t, 'POST', '/repos/acme/app/issues', { body: { title: 'x' } })).status, 200);
  const held = await call(w, t, 'DELETE', '/repos/acme/app');
  assert.equal(held.status, 428);
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/app')).status, 428, 'a retry reuses the hold and seals nothing new');
  assert.equal((await approve(w, u, held.body.hold_id)).status, 200);
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/app')).status, 200);
  const den = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: u.cred, policy: { deny: [{ path: '/orgs/**' }] } } });
  assert.equal((await call(w, den.body.token, 'POST', '/orgs/acme/x', { body: {} })).status, 403);
  const entries = await publicEntries(w);
  assert.deepEqual(entries.map((e) => e.entry.receipt.decision), ['allowed', 'held', 'approved', 'executed', 'denied'], 'no duplicate for the approved call');
  for (const { entry } of entries) {
    assert.equal(entry.source, 'broker'); assert.equal(entry.v, 2);
    assert.equal(entry.receipt.agent, 'broker');
    assert.match(entry.receipt.action, /^(POST|DELETE) api\.github\.com$/);
    assert.match(entry.receipt.parent, /^[0-9a-f]{64}$/);
    assert.match(entry.receipt.meta.map, /^\d{4}-\d{2}-\d{2}\.\d+$/);
  }
  assert.equal(entries[1].entry.receipt.meta.rule, 'gh.delete');
  assert.equal(entries[2].entry.receipt.meta.passkey, true, 'the approval was made with a passkey');
  // every receipt's parent is the hash of the owner's own audit entry, and the audit row points back at it
  const rows = auditRows(w, u.id).filter((r) => r.receipt !== null);
  assert.equal(rows.length, 5);
  for (const r of rows) assert.equal(entries.find((e) => e.index === r.receipt).entry.receipt.parent, r.hash);
  assert.equal(JSON.parse(rows.find((r) => r.action === 'approve').detail).passkey.length, 16, 'the audit entry names the approving passkey');
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true, 'the receipt column is outside the chain');
  // the owner gets verifiable bundles with an opening that proves the entry is theirs
  const mine = (await w.req('GET', '/v1/my/receipts', { cookie: u.cookie })).body.receipts;
  assert.equal(mine.length, 5);
  assert.equal(mine[0].opening.key_id, 'broker'); assert.equal(mine[0].opening.account_id, u.id);
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  const b = await w.req('GET', `/v1/my/receipts/${mine[0].index}/bundle`, { cookie: u.cookie });
  const v = await verifyBundle(b.body, vk);
  assert.equal(v.ok, true); assert.equal(v.broker, true); assert.equal(v.ownerProved, true);
  const me = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body;
  assert.deepEqual([me.receipts.on, me.receipts.usage, me.receipts.skipped], [true, 5, 0]);
});

test('Forgery: no receipts API key can make a broker entry, whatever the receipt says', async () => {
  const w = new World();
  const u = await account(w);
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  assert.match(key, /^lsr_/);
  const send = (receipt) => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt } });
  assert.equal((await send({ agent: 'broker', action: 'DELETE api.github.com', decision: 'approved', source: 'broker' })).body.error, 'unknown_field');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'b' }, source: 'broker', v: 3 } })).status, 200, 'extra top-level fields are ignored');
  const r = await send({ agent: 'broker', action: 'DELETE api.github.com', decision: 'approved', meta: { passkey: true, map: '2026-10-09.1' } });
  assert.equal(r.status, 200);
  for (const e of await publicEntries(w)) assert.equal(e.entry.source, undefined, 'reported receipts never carry source');
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  assert.equal((await verifyBundle(r.body.receipts[0], vk)).broker, false, 'verifiers tell a reported receipt from a broker one');
  // and a proxy token is not a receipts key, nor the reverse
  const { token: t } = await token(w, u);
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: t, ...anon, body: { receipt: { agent: 'a', action: 'b' } } })).body.error, 'api_key_required');
  assert.equal((await w.req('GET', '/p/github/user', { bearer: key, ...anon })).body.error, 'leash_token_required');
});

test('Privacy: public receipts carry no path, query, body, key, token, name, email, IP or account id', async () => {
  const w = new World();
  const u = await account(w, 'Jane Secretname');
  const { token: t, id: tokenId } = await token(w, u);
  const secretPath = '/repos/acme-private-client/secret-repo-name/issues';
  await call(w, t + '', 'POST', secretPath + '?q=jane@example.com', { body: { title: 'jane@example.com', token: 'sk_live_ZZZZ' } });
  await call(w, t, 'DELETE', '/repos/acme-private-client/secret-repo-name');
  const pubText = JSON.stringify(await publicEntries(w)) + JSON.stringify(w.sql.raw.prepare('SELECT entry FROM leaves').all());
  for (const s of ['acme-private-client', 'secret-repo-name', 'jane@example.com', 'sk_live', GH, t, tokenId, u.cred, u.id, 'Jane', 'Secretname', '203.0.113', 'ghp_']) {
    assert.ok(!pubText.includes(s), 'public log contains ' + s);
  }
  // receipts of one account cannot be grouped: no shared field links them
  const es = (await publicEntries(w)).map((e) => e.entry);
  assert.notEqual(es[0].submitter, es[1].submitter);
  assert.equal(new Set(es.map((e) => e.receipt.parent)).size, es.length);
});

test('Existing accounts keep receipts off; turning on is a web action, turning off needs a fresh passkey and is on the record', async () => {
  const w = new World();
  const u = await account(w);
  w.env.DB.raw.prepare('UPDATE accounts SET receipts = 0 WHERE id = ?').run(u.id); // an account made before receipts existed
  const { token: t } = await token(w, u);
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/app')).status, 428);
  assert.equal((await publicEntries(w)).length, 0, 'nothing is published for an account that has not turned receipts on');
  // a CLI session cannot change it
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const cli = (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon })).body.access_token;
  for (const p of ['/v1/me/receipts/on', '/v1/me/receipts/off/begin']) assert.equal((await w.req('POST', p, { bearer: cli, body: {}, ...anon })).body.error, 'passkey_required', p);
  assert.equal((await w.req('POST', '/v1/me/receipts/on', { cookie: u.cookie, body: {} })).body.on, true);
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/other')).status, 428);
  assert.equal((await publicEntries(w)).length, 1);
  // off: no ceremony, no change
  assert.equal((await w.req('POST', '/v1/me/receipts/off/finish', { cookie: u.cookie, body: {} })).status, 400);
  const b = await w.req('POST', '/v1/me/receipts/off/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/receipts/off/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } })).body.on, false);
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/third')).status, 428);
  assert.equal((await publicEntries(w)).length, 1, 'off means off');
  assert.deepEqual(auditRows(w, u.id).map((r) => r.action).filter((a) => a.startsWith('receipts_')), ['receipts_on', 'receipts_off']);
});

test('Quota bypass: broker receipts use the same quotas; when any is used up the decision still happens and is counted as skipped', async () => {
  const w = new World();
  w.env.FREE_LIMIT = '2';
  const u = await account(w);
  const { token: t } = await token(w, u);
  for (const p of ['/a', '/b', '/c']) assert.equal((await call(w, t, 'DELETE', '/repos/acme' + p)).status, 428, 'the broker never waits for the log');
  assert.equal((await publicEntries(w)).length, 2);
  let me = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.receipts;
  assert.deepEqual([me.usage, me.skipped], [2, 1]);
  // reported receipts cannot use what the broker could not
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'b' } } })).status, 402);
  // the log's global cap and the per-account daily cap apply to broker receipts too
  const v = new World();
  v.env.GLOBAL_DAILY_CAP = '1';
  const a = await account(v);
  const ta = (await token(v, a)).token;
  await call(v, ta, 'DELETE', '/repos/x/1'); await call(v, ta, 'DELETE', '/repos/x/2');
  assert.equal((await publicEntries(v)).length, 1);
  me = (await v.req('GET', '/v1/me', { cookie: a.cookie })).body.receipts;
  assert.equal(me.skipped, 1);
  const d = new World();
  d.env.ACCOUNT_DAILY_CAP = '1';
  const b = await account(d);
  const tb = (await token(d, b)).token;
  await call(d, tb, 'DELETE', '/repos/y/1'); await call(d, tb, 'DELETE', '/repos/y/2');
  assert.equal((await publicEntries(d)).length, 1);
  const kb = (await d.req('POST', '/v1/keys', { cookie: b.cookie, body: {} })).body.key;
  const r = await d.req('POST', '/v1/receipts', { bearer: kb, ...anon, body: { receipt: { agent: 'a', action: 'b' } } });
  assert.equal(r.status, 402); assert.equal(r.body.error, 'daily_quota');
});

test('A log that is misconfigured or down never blocks a decision', async () => {
  const w = new World();
  const u = await account(w);
  const { token: t } = await token(w, u);
  w.log.append = async () => { throw new Error('storage down'); };
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/app')).status, 428);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.receipts.skipped, 1);
  assert.equal(w.env.DB.raw.prepare('SELECT COALESCE(SUM(receipts),0) n FROM usage').get().n, 0, 'nothing counted for a failed append');
  delete w.env.LOG_KEY_JWK;
  assert.equal((await call(w, t, 'DELETE', '/repos/acme/b')).status, 428);
  assert.equal((await call(w, t, 'GET', '/repos/acme/b')).status, 200, 'the broker needs no log key');
});

test('Prove who: a token bound to an agent key works only on requests that key signed (no downgrade, no replay)', async () => {
  const w = new World();
  const u = await account(w);
  const ak = await agentKey(w, u);
  assert.equal(ak.keyid, await keyid(ak.jwk.x));
  const bound = await token(w, u, { agentKeyId: ak.id });
  assert.equal(bound.agentKey, ak.keyid);
  const t = bound.token;
  // the stolen-token case: the token alone is refused, before the policy and before its rate limit
  const bare = await call(w, t, 'GET', '/repos/acme/app');
  assert.equal(bare.status, 401); assert.equal(bare.body.error, 'agent_signature_required');
  assert.equal(w.upstream.length, 0);
  assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM ratelimits WHERE bucket LIKE 'tok:%'").get().n, 0, 'a bad request spends nothing of the agent\'s budget');
  const ok = await call(w, t, 'POST', '/repos/acme/app/issues', { body: { title: 'hi' }, ak });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(JSON.parse(auditRows(w, u.id).find((r) => r.action === 'proxy').detail).agent_key, ak.keyid, 'the audit entry names the agent key');
  assert.equal((await publicEntries(w)).at(-1).entry.receipt.meta.agent_key, true, 'the receipt records that a registered agent key signed it');
  // replay of the same signed request
  const url = 'https://leash.test/p/github/repos/acme/app';
  const h = await signBrokerRequest({ method: 'GET', url }, { key: ak.key, kid: ak.keyid });
  assert.equal((await w.req('GET', url, { bearer: t, ...anon, headers: h })).status, 200);
  const again = await w.req('GET', url, { bearer: t, ...anon, headers: h });
  assert.equal(again.status, 401); assert.equal(again.body.error, 'agent_signature_replayed');
  // a signature for another request, method, body or key; a too-long window; missing coverage
  const reason = async (r) => (await r).body.reason || (await r).body.error;
  assert.match(await reason(w.req('GET', url + '/pulls', { bearer: t, ...anon, headers: await signBrokerRequest({ method: 'GET', url }, { key: ak.key, kid: ak.keyid }) })), /does not verify/);
  assert.match(await reason(w.req('DELETE', url, { bearer: t, ...anon, headers: await signBrokerRequest({ method: 'GET', url }, { key: ak.key, kid: ak.keyid }) })), /does not verify/);
  const sb = await signBrokerRequest({ method: 'POST', url: url + '/issues', body: '{"title":"a"}' }, { key: ak.key, kid: ak.keyid });
  assert.match(await reason(w.req('POST', url + '/issues', { bearer: t, ...anon, raw: '{"title":"b"}', headers: { ...sb, 'content-type': 'application/json' } })), /Content-Digest does not match/);
  const other = await generateAgentKey();
  assert.match(await reason(w.req('GET', url, { bearer: t, ...anon, headers: await signBrokerRequest({ method: 'GET', url }, { key: await importAgentKey(other), kid: ak.keyid }) })), /does not verify/);
  assert.match(await reason(w.req('GET', url, { bearer: t, ...anon, headers: await signBrokerRequest({ method: 'GET', url }, { key: await importAgentKey(other), kid: await keyid(other.x) }) })), /keyid is not the agent key/);
  const old = Math.floor(Date.now() / 1000) - 400;
  assert.match(await reason(w.req('GET', url, { bearer: t, ...anon, headers: await signBrokerRequest({ method: 'GET', url }, { key: ak.key, kid: ak.keyid, now: old }) })), /expired/);
  // a body the signature does not cover
  const nb = await signBrokerRequest({ method: 'POST', url: url + '/issues' }, { key: ak.key, kid: ak.keyid });
  assert.match(await reason(w.req('POST', url + '/issues', { bearer: t, ...anon, raw: '{"title":"c"}', headers: { ...nb, 'content-type': 'application/json' } })), /must cover content-digest/);
  // revoking the key (web session only) breaks the token at once
  assert.equal((await w.req('GET', '/v1/agent-keys', { cookie: u.cookie })).body.agentKeys[0].tokens, 1);
  assert.equal((await w.req('DELETE', `/v1/agent-keys/${ak.id}`, { cookie: u.cookie })).status, 200);
  const after = await call(w, t, 'GET', '/repos/acme/app', { ak });
  assert.equal(after.status, 401); assert.equal(after.body.error, 'agent_key_revoked');
  // an unbound token is unaffected by signature headers
  const free = (await token(w, u)).token;
  assert.equal((await call(w, free, 'GET', '/repos/acme/app', { ak })).status, 200);
  assert.ok(auditRows(w, u.id).some((r) => r.action === 'agent_signature_failed'), 'the owner sees that a bound token was used without its key');
});

test('Prove who -> Approve -> Record: a held call from a signed agent is approved and retried with a fresh signature', async () => {
  const w = new World();
  const u = await account(w);
  const ak = await agentKey(w, u);
  const t = (await token(w, u, { agentKeyId: ak.id })).token;
  const h = await call(w, t, 'DELETE', '/repos/acme/app', { ak });
  assert.equal(h.status, 428);
  assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
  const r = await call(w, t, 'DELETE', '/repos/acme/app', { ak });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.headers.get('x-leash-decision'), 'approved');
  const es = (await publicEntries(w)).map((e) => e.entry.receipt);
  assert.deepEqual(es.map((x) => [x.decision, !!x.meta.agent_key]), [['held', true], ['approved', false], ['executed', true]]);
});

test('Signature downgrade and cross-protocol: a Web Bot Auth signature, a receipt signature or a key proof is never a broker signature', async () => {
  const w = new World();
  const u = await account(w);
  const ak = await agentKey(w, u);
  const t = (await token(w, u, { agentKeyId: ak.id })).token;
  const url = 'https://leash.test/p/github/repos/acme/app';
  // the same key signing a Web Bot Auth request (tag web-bot-auth, covering @authority and signature-agent)
  const { signRequest } = await import('../../sdk/websig.mjs');
  const wba = await signRequest({ method: 'GET', url }, { key: ak.key, keyid: ak.keyid, agent: 'https://bots.acme.example' });
  const r1 = await w.req('GET', url, { bearer: t, ...anon, headers: wba });
  assert.equal(r1.status, 401); assert.equal(r1.body.error, 'agent_signature_required');
  // relabel it as leash-pop: the covered components and the signed text are wrong for the profile
  const relabel = { ...wba, 'signature-input': wba['signature-input'].replace('tag="web-bot-auth"', 'tag="leash-pop"') };
  const r2 = await w.req('GET', url, { bearer: t, ...anon, headers: relabel });
  assert.equal(r2.status, 401); assert.match(r2.body.reason, /not allowed|must cover/);
  // the domain-separation prefixes: a key proof, a receipt and an RFC 9421 base never share their first bytes
  const proof = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: (await generateAgentKey()).x } })).body.sign;
  assert.ok(proof.startsWith('leash/agent-key-proof/v1\n'));
  assert.ok(canonical({ agent: 'a', action: 'b' }).startsWith('{'));
  assert.ok((await import('../src/receipts.js')).signerProofText('c', 'p', 'o', 'a').startsWith('witness/signer-proof/v2\n'));
  // an agent key proof signature cannot be passed off as a receipts signer proof for the same key
  const jwk = await generateAgentKey(), key = await importAgentKey(jwk);
  const ab = await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } });
  const agentProof = await proveAgentKey(key, ab.body.sign);
  const sb = await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: jwk.x } });
  const bind = await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { signerPublicKey: jwk.x, signerChallengeId: sb.body.challengeId, signerProof: agentProof } });
  assert.equal(bind.body.error, 'bad_signerProof');
  // but a registered agent key can be reused as a receipts signer without another proof
  const reuse = await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'signed by agent', agentKeyId: ak.id } });
  assert.equal(reuse.status, 200, JSON.stringify(reuse.body));
  const rc = { agent: 'laptop agent', action: 'deploy v2', ts: Date.now() };
  const sig = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, ak.key, new TextEncoder().encode(canonical(rc))));
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: reuse.body.key, ...anon, body: { receipt: { ...rc, sig: { alg: 'ed25519', value: sig } } } })).status, 200);
});

test('Agent key registration: proof of possession, public keys only, one account per key, no weak keys, revoke needs a web session', async () => {
  const w = new World();
  const u = await account(w), v = await account(w, 'Mallory', '198.51.100.9');
  const jwk = await generateAgentKey(), key = await importAgentKey(jwk);
  assert.equal((await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { jwk } })).body.error, 'private_key_sent');
  assert.equal((await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } })).body.error, 'bad_publicKey', 'the identity point (small order) is refused');
  const b = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } } })).body;
  assert.ok(b.sign.includes(u.id) && b.sign.includes('https://leash.test'), 'the proof names this server and the account');
  const wrong = await proveAgentKey(await importAgentKey(await generateAgentKey()), b.sign);
  assert.equal((await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b.challengeId, proof: wrong } })).body.error, 'bad_proof');
  const b2 = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
  assert.equal((await w.req('POST', '/v1/agent-keys', { cookie: v.cookie, body: { publicKey: jwk.x, challengeId: b2.challengeId, proof: await proveAgentKey(key, b2.sign) } })).body.error, 'challenge_expired', 'a challenge belongs to one account');
  const b3 = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
  const ok = await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b3.challengeId, proof: await proveAgentKey(key, b3.sign) } });
  assert.equal(ok.status, 200);
  assert.equal((await w.req('POST', '/v1/agent-keys/begin', { cookie: v.cookie, body: { publicKey: jwk.x } })).body.error, 'key_taken');
  assert.equal((await w.req('POST', '/v1/tokens', { cookie: v.cookie, body: { credentialId: v.cred, agentKeyId: ok.body.id } })).body.error, 'agent_key_not_found', 'cannot bind to another account\'s key');
  assert.equal((await w.req('DELETE', `/v1/agent-keys/${ok.body.id}`, { cookie: v.cookie })).status, 404);
  // a CLI session can register and bind, but not revoke
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const cli = (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon })).body.access_token;
  assert.equal((await w.req('POST', '/v1/tokens', { bearer: cli, ...anon, body: { credentialId: u.cred, agentKeyId: ok.body.id } })).status, 200);
  assert.equal((await w.req('DELETE', `/v1/agent-keys/${ok.body.id}`, { bearer: cli, ...anon })).body.error, 'passkey_required');
  assert.ok(!JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM agent_keys').all()).includes(jwk.d), 'only public keys are stored');
});

test('Limits: the busiest paths stay under 50 D1 queries per invocation', async () => {
  const w = new World();
  const u = await account(w);
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.env.__pushFetch = async () => new Response(null, { status: 201 });
  for (let i = 0; i < 10; i++) await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/d' + i } });
  const ak = await agentKey(w, u);
  const t = (await token(w, u, { agentKeyId: ak.id })).token;
  w.env.DB.cap = 50;
  const h = await call(w, t, 'DELETE', '/repos/acme/app', { ak });
  assert.equal(h.status, 428);
  assert.ok(h.queries <= 35, `${h.queries} queries for a signed, held call that wakes 10 devices and seals a receipt`);
  const a = await approve(w, u, h.body.hold_id);
  assert.equal(a.status, 200); assert.ok(a.queries <= 20, `${a.queries} queries to approve`);
  const r = await call(w, t, 'DELETE', '/repos/acme/app', { ak });
  assert.equal(r.status, 200); assert.ok(r.queries <= 25, `${r.queries} queries for the approved call`);
  const del = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  const fin = await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: del.body.challengeId, credential: await u.auth.get(del.body.options) } });
  assert.equal(fin.status, 200); assert.ok(fin.queries <= 30, `${fin.queries} queries to delete an account`);
});

test('Account deletion erases agent keys, receipts keys and counters, and unlinks the public log', async () => {
  const w = new World();
  const u = await account(w);
  const ak = await agentKey(w, u);
  const t = (await token(w, u, { agentKeyId: ak.id })).token;
  await call(w, t, 'DELETE', '/repos/acme/app', { ak });
  await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} });
  const del = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: del.body.challengeId, credential: await u.auth.get(del.body.options) } })).status, 200);
  const db = w.env.DB.raw;
  for (const tb of ['accounts', 'agent_keys', 'api_keys', 'usage', 'tokens', 'audit', 'holds', 'credentials']) assert.equal(db.prepare(`SELECT COUNT(*) n FROM ${tb}`).get().n, 0, tb);
  assert.equal(w.sql.raw.prepare('SELECT COUNT(*) n FROM leaves WHERE tenant = ? OR opening IS NOT NULL').get(u.id).n, 0, 'the log no longer says whose entries they were');
  assert.equal((await publicEntries(w)).length, 1, 'public entries stay by design');
});
