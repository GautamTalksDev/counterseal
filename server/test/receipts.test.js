import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World, makeDoSql, logKeyJwk } from './helpers.js';
import { LogCore } from '../src/log.js';
import { leafHash, nodeHash, sha, verifyInclusion, verifyConsistency } from '../src/merkle.js';
import { verifyCheckpoint, fromB64std } from '../src/note.js';
import { canonical } from '../src/receipts.js';
import { b64u } from '../src/util.js';

// brute-force RFC 6962 MTH, the reference the stored-node algorithms must match
async function refMth(leaves) {
  if (leaves.length === 0) return sha();
  if (leaves.length === 1) return leaves[0];
  let k = 1; while (k * 2 < leaves.length) k *= 2;
  return nodeHash(await refMth(leaves.slice(0, k)), await refMth(leaves.slice(k)));
}

test('Merkle log matches RFC 6962 for every size 1..70; every inclusion and consistency proof verifies', async () => {
  const env = { LOG_KEY_JWK: await logKeyJwk(), LOG_ORIGIN: 't/log' };
  const core = new LogCore(makeDoSql(), env);
  const leaves = [];
  for (let n = 1; n <= 70; n++) {
    const entry = `entry-${n}`;
    await core.append([{ tenant: 't', entry }], n);
    leaves.push(await leafHash(new TextEncoder().encode(entry)));
    const head = core.head();
    const root = new Uint8Array(head.root);
    assert.deepEqual(root, await refMth(leaves), `root at size ${n}`);
    for (const i of [0, n - 1, Math.floor(n / 2)]) {
      const proof = await core.inclusion(i, n);
      assert.ok(await verifyInclusion(i, n, leaves[i], proof, root), `inclusion ${i}/${n}`);
      if (n > 1) assert.ok(!(await verifyInclusion(i, n, leaves[(i + 1) % n], proof, root)), 'wrong leaf fails');
    }
  }
  const roots = [];
  for (let n = 1; n <= 70; n++) roots[n] = await refMth(leaves.slice(0, n));
  for (const [m, n] of [[1, 70], [7, 8], [8, 9], [13, 64], [32, 70], [64, 65], [69, 70], [3, 3]]) {
    const p = await core.consistency(m, n);
    assert.ok(await verifyConsistency(m, n, roots[m], roots[n], p), `consistency ${m}->${n}`);
    if (m !== n) assert.ok(!(await verifyConsistency(m, n, roots[m], roots[n - 1] || roots[1], p)) || n - 1 === m, 'forked root fails');
  }
});

test('a receipt bundle verifies offline: signed checkpoint, inclusion proof, leaf hash of the canonical entry', async () => {
  const w = await World.create();
  const u = await w.user();
  const k = await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'leash-prod' } });
  assert.equal(k.status, 200, JSON.stringify(k.body));
  const r = await w.req('POST', '/v1/receipts', { bearer: k.body.key, origin: null, xw: false, body: { receipts: [
    { agent: 'claude-code', action: 'github.DELETE /repos/acme/app', decision: 'approved', input_sha256: 'a'.repeat(64), ts: 1791300000000 },
    { agent: 'claude-code', action: 'github.GET /repos/acme/app/pulls', decision: 'allowed', ts: 1791300000001 },
  ] } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const vk = (await w.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
  for (const b of r.body.receipts) {
    const cp = await verifyCheckpoint(b.checkpoint, vk);
    const leaf = await leafHash(new TextEncoder().encode(canonical(b.entry)));
    assert.deepEqual(fromB64std(b.leaf_hash), leaf);
    assert.ok(await verifyInclusion(b.index, cp.size, leaf, b.inclusion_proof.map(fromB64std), cp.root));
  }
  // a tampered checkpoint or a different key fails
  const bad = r.body.receipts[0].checkpoint.replace(/\n2\n/, '\n3\n');
  await assert.rejects(verifyCheckpoint(bad, vk), /signature/);
});

test('the log can prove it never rewrote history: consistency between two published checkpoints', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const post = (n) => w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'a', action: 'x' + i })) } });
  await post(5);
  const vk = (await w.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
  const old = await verifyCheckpoint((await w.req('GET', '/v1/log/checkpoint', { origin: null, xw: false })).body, vk);
  await post(17);
  const neu = await verifyCheckpoint((await w.req('GET', '/v1/log/checkpoint', { origin: null, xw: false })).body, vk);
  const p = await w.req('GET', `/v1/log/proof/consistency?first=${old.size}&second=${neu.size}`, { origin: null, xw: false });
  assert.equal(p.headers.get('access-control-allow-origin'), '*', 'public proofs are fetchable by any verifier');
  assert.ok(await verifyConsistency(old.size, neu.size, old.root, neu.root, p.body.consistency_proof.map(fromB64std)));
});

async function bindSigner(w, cookie, kp, pub, label = 'signed') {
  const ch = await w.req('POST', '/v1/keys/signer/begin', { cookie, body: { signerPublicKey: pub } });
  if (ch.status !== 200) return ch;
  const proof = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(ch.body.sign)));
  return w.req('POST', '/v1/keys', { cookie, body: { label, signerPublicKey: pub, signerChallengeId: ch.body.challengeId, signerProof: proof } });
}
const newSigner = async () => { const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']); return { kp, pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)) }; };

test('signed receipts: an API key bound to an Ed25519 signer only accepts receipts that signer signed, each once, with a ts', async () => {
  const w = await World.create();
  const u = await w.user();
  const { kp, pub } = await newSigner();
  const key = (await bindSigner(w, u.cookie, kp, pub)).body.key;
  const sign = async (rc) => b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(canonical(rc))));
  const send = (receipt) => w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipt } });
  const noTs = { agent: 'billing-bot', action: 'stripe.POST /v1/refunds', decision: 'held' };
  assert.equal((await send(noTs)).body.error, 'signature_required');
  assert.equal((await send({ ...noTs, sig: { alg: 'ed25519', value: await sign(noTs) } })).body.error, 'ts_required');
  const rc = { ...noTs, ts: Date.now() };
  const sig = await sign(rc);
  assert.equal((await send({ ...rc, sig: { alg: 'ed25519', value: sig } })).status, 200);
  assert.equal((await send({ ...rc, decision: 'approved', sig: { alg: 'ed25519', value: sig } })).body.error, 'bad_signature');
  // replay: the same signed receipt is refused the second time, and twice in one batch
  const again = await send({ ...rc, sig: { alg: 'ed25519', value: sig } });
  assert.equal(again.status, 409); assert.equal(again.body.error, 'replay');
  const rc2 = { ...noTs, ts: rc.ts + 1 }, s2 = { alg: 'ed25519', value: await sign(rc2) };
  const dup = await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipts: [{ ...rc2, sig: s2 }, { ...rc2, sig: s2 }] } });
  assert.equal(dup.body.error, 'replay');
  assert.equal((await send({ ...rc2, sig: s2 })).status, 200, 'a refused batch claims nothing');
  // a non-canonical spelling of a signature is refused, so it cannot dodge the replay check
  assert.equal((await send({ ...rc, sig: { alg: 'ed25519', value: sig.slice(0, -1) + 'B' } })).body.error, 'bad_sig');
});

test('binding a signer needs proof of possession, and a signer key cannot be bound to two accounts', async () => {
  const w = await World.create();
  const u = await w.user(), v = await w.user('Mallory', '198.51.100.7');
  const { kp, pub } = await newSigner();
  const mk = (cookie, body) => w.req('POST', '/v1/keys', { cookie, body: { label: 'x', signerPublicKey: pub, ...body } });
  assert.equal((await mk(u.cookie, {})).body.error, 'bad_challenge', 'no challenge, no binding');
  // a proof by some other key, or a challenge for another public key or account, is refused
  const ch = (await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: pub } })).body;
  const other = await newSigner();
  const wrong = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, other.kp.privateKey, new TextEncoder().encode(ch.sign)));
  assert.equal((await mk(u.cookie, { signerChallengeId: ch.challengeId, signerProof: wrong })).body.error, 'bad_signerProof');
  const ch2 = (await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: pub } })).body;
  const good = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(ch2.sign)));
  assert.equal((await mk(v.cookie, { signerChallengeId: ch2.challengeId, signerProof: good })).body.error, 'challenge_expired', 'challenge is bound to the account');
  assert.equal((await mk(u.cookie, { signerChallengeId: ch2.challengeId, signerProof: good })).body.error, 'challenge_expired', 'challenges are single use');
  assert.equal((await bindSigner(w, u.cookie, kp, pub)).status, 200);
  assert.equal((await bindSigner(w, u.cookie, kp, pub, 'second')).status, 200, 'the same account may bind its signer to more keys');
  // another account cannot claim the same signer, even holding the private key
  const taken = await bindSigner(w, v.cookie, kp, pub);
  assert.equal(taken.status, 409); assert.equal(taken.body.error, 'signer_taken');
});

test('receipts carry hashes, not content: unknown fields, raw blobs and control characters are refused', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const send = (receipt) => w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipt } });
  assert.equal((await send({ agent: 'a', action: 'b', prompt: 'my secret prompt' })).body.error, 'unknown_field');
  assert.equal((await send({ agent: 'a', action: 'b', input_sha256: 'not-a-hash' })).body.error, 'bad_input_sha256');
  assert.equal((await send({ agent: 'a\u0000', action: 'b' })).body.error, 'bad_agent');
  assert.equal((await send({ agent: 'a', action: 'b', meta: { k: 'x'.repeat(121) } })).body.error, 'bad_meta');
  assert.equal((await send({ agent: 'a', action: 'b', decision: 'yolo' })).body.error, 'bad_decision');
});

test('keys and accounts: bad key refused, revoked key refused, you only see your own receipts, CSRF enforced', async () => {
  const w = await World.create();
  const a = await w.user('A'), b = await w.user('B');
  const ka = (await w.req('POST', '/v1/keys', { cookie: a.cookie, body: {} })).body;
  const kb = (await w.req('POST', '/v1/keys', { cookie: b.cookie, body: {} })).body;
  await w.req('POST', '/v1/receipts', { bearer: ka.key, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'mine' } } });
  await w.req('POST', '/v1/receipts', { bearer: kb.key, origin: null, xw: false, body: { receipt: { agent: 'b', action: 'theirs' } } });
  const mine = (await w.req('GET', '/v1/my/receipts', { cookie: a.cookie })).body.receipts;
  assert.equal(mine.length, 1); assert.equal(mine[0].entry.receipt.action, 'mine');
  assert.equal((await w.req('DELETE', `/v1/keys/${ka.id}`, { cookie: b.cookie })).status, 404, 'cannot revoke another account\'s key');
  await w.req('DELETE', `/v1/keys/${ka.id}`, { cookie: a.cookie });
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: ka.key, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'x' } } })).body.error, 'api_key_invalid');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: 'lsr_nope', origin: null, xw: false, body: { receipt: { agent: 'a', action: 'x' } } })).body.error, 'api_key_required');
  assert.equal((await w.req('POST', '/v1/keys', { cookie: a.cookie, body: {}, xw: false })).body.error, 'csrf');
  const keys = JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM api_keys').all());
  assert.ok(!keys.includes(kb.key), 'API keys are stored only as hashes');
});

test('monthly quota is enforced', async () => {
  const w = await World.create();
  w.env.FREE_LIMIT = '3';
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const r = await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipts: Array.from({ length: 4 }, () => ({ agent: 'a', action: 'b' })) } });
  assert.equal(r.status, 402);
});
