// Prove who: agent keys. An agent holds its own Ed25519 private key; its public key is registered here, with proof of
// possession. A proxy token bound to an agent key only works on requests that the agent signed with that key
// (RFC 9421 HTTP Message Signatures), so a stolen lsh_ token alone is useless, and every decision on such a request
// records which agent key made it.
//
// The broker signature profile (tag "leash-pop"):
//   Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type");created=...;expires=...;keyid="<JWK thumbprint>";alg="ed25519";nonce="...";tag="leash-pop"
//   Signature: sig1=:<base64 Ed25519 signature>:
//   Content-Digest: sha-256=:<base64 SHA-256 of the body>:      (RFC 9530; required when the request has a body)
// Rules: "@method" and "@target-uri" must be covered, and "content-digest" and "content-type" whenever there is a body
// (the approval hash binds both, and the upstream reads the body by its content type); only those four plus
// "@authority", "@path" and "@query" may be covered; window of 5 minutes at most; a nonce is
// required and accepted once per key; keyid is the RFC 7638 / RFC 8037 thumbprint of the registered key. A token bound
// to a key never falls back to unsigned requests, and a Web Bot Auth signature (tag "web-bot-auth") is never accepted
// here: the tag differs, and so does the signed text.
import { HttpError, fromB64u, b64u, randomId, now, str, sha256 } from './util.js';
import { parseDictionary, signatureBase, jwkThumbprint } from '../../sdk/websig.mjs';
import { signerKeyBytes } from './receipts.js';
import { newChallenge, takeChallenge, rp, sessionId } from './auth.js';
import { audit } from './audit.js';

export const POP_TAG = 'leash-pop';
export const POP_WINDOW = 300; // seconds
const REQUIRED = ['@method', '@target-uri'];
const ALLOWED = new Set(['@method', '@target-uri', '@authority', '@path', '@query', 'content-digest', 'content-type']);
const NONCE = /^[A-Za-z0-9+/=_-]{8,128}$/;
const MAX_KEYS = 20;

const bad = (reason) => new HttpError(401, 'bad_agent_signature', `Agent signature refused: ${reason}.`, { reason });

/** the text an agent key signs to prove possession when it is registered. It names this server and the account, and
 *  starts with its own prefix, so it can never be mistaken for a receipt, a checkpoint or an RFC 9421 signature base. */
export const agentKeyProofText = (origin, account, challenge, x) => `leash/agent-key-proof/v1\n${origin}\n${account}\n${challenge}\n${x}`;

/** a public Ed25519 key as base64url x, from {publicKey} or {jwk}; never a private key */
function publicX(body) {
  const j = body.jwk;
  if (j !== undefined) {
    if (!j || typeof j !== 'object') throw new HttpError(400, 'bad_jwk');
    if (j.d !== undefined) throw new HttpError(400, 'private_key_sent', 'That JWK contains a private key ("d"). Never send it anywhere; send only the public part.');
    if (j.kty !== 'OKP' || j.crv !== 'Ed25519') throw new HttpError(400, 'bad_jwk', 'Send the public Ed25519 JWK: {kty:"OKP", crv:"Ed25519", x}.');
    body = { publicKey: j.x };
  }
  const x = str(body.publicKey, 'publicKey', { max: 60, re: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/ });
  try { signerKeyBytes(x); } catch { throw new HttpError(400, 'bad_publicKey', 'Not a usable Ed25519 public key (small-order and non-canonical keys are refused).'); }
  return x;
}

async function notTakenElsewhere(env, accountId, x) {
  const other = await env.DB.prepare('SELECT 1 FROM agent_keys WHERE x = ? AND account_id != ? UNION ALL SELECT 1 FROM api_keys WHERE signer_pub = ? AND account_id != ? LIMIT 1').bind(x, accountId, x, accountId).first();
  if (other) throw new HttpError(409, 'key_taken', 'That public key is registered to another account.');
}

export async function registerBegin(env, sess, body) {
  const x = publicX(body);
  await notTakenElsewhere(env, sess.accountId, x);
  const { id, challenge } = await newChallenge(env, 'agentkey', sess.accountId, x);
  const origin = rp(env).origin;
  return { challengeId: id, challenge, origin, account: sess.accountId, sign: agentKeyProofText(origin, sess.accountId, challenge, x) };
}

export async function registerFinish(env, sess, body) {
  const x = publicX(body);
  const label = str(body.label ?? 'agent', 'label', { max: 60, re: /^[\p{L}\p{N} ._:/()-]+$/u });
  const ch = await takeChallenge(env, body.challengeId, 'agentkey');
  if (ch.account_id !== sess.accountId || ch.name !== x) throw new HttpError(400, 'challenge_expired', 'Start again.');
  const proof = str(body.proof, 'proof', { max: 100, re: /^[A-Za-z0-9_-]{85}[AQgw]$/ });
  const key = await crypto.subtle.importKey('raw', fromB64u(x), { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, fromB64u(proof), new TextEncoder().encode(agentKeyProofText(rp(env).origin, sess.accountId, ch.challenge, x))))) {
    throw new HttpError(400, 'bad_proof', 'The proof does not verify under that public key.');
  }
  await notTakenElsewhere(env, sess.accountId, x);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM agent_keys WHERE account_id = ? AND revoked_at IS NULL').bind(sess.accountId).first();
  if (n.n >= MAX_KEYS) throw new HttpError(409, 'too_many_agent_keys', `Up to ${MAX_KEYS} active agent keys. Revoke one first.`);
  const keyid = await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x });
  const id = randomId();
  // registered by a CLI session: revoking that session revokes this key too
  const cli = sess.kind === 'cli' ? await sessionId(sess.hash) : null;
  try {
    await env.DB.prepare('INSERT INTO agent_keys (id, account_id, label, keyid, x, created_at, session_id) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, sess.accountId, label, keyid, x, now(), cli).run();
  } catch (e) {
    if (/UNIQUE|constraint/i.test(String(e && e.message))) throw new HttpError(409, 'key_exists', 'That key is already registered.');
    throw e;
  }
  // a new key that can sign for this account is on the record (who made it: web or a CLI session)
  await audit(env, sess.accountId, sess.kind, 'agent_key_registered', { id, keyid, label, ...(cli ? { session: cli } : {}) });
  return { id, keyid, label };
}

export async function list(env, sess) {
  const r = await env.DB.prepare('SELECT k.id, k.label, k.keyid, k.x, k.created_at, k.revoked_at, k.last_used, (SELECT COUNT(*) FROM tokens t WHERE t.agent_key_id = k.id AND t.revoked = 0) AS tokens FROM agent_keys k WHERE k.account_id = ? ORDER BY k.created_at DESC').bind(sess.accountId).all();
  return { agentKeys: r.results };
}

export async function revoke(env, sess, id) {
  const r = await env.DB.prepare('UPDATE agent_keys SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL RETURNING keyid').bind(now(), id, sess.accountId).first();
  if (!r) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'agent_key_revoked', { id, keyid: r.keyid });
  return { ok: true, note: 'Tokens bound to this key stop working at once.' };
}

/** the agent key a new token is bound to: one of this account's own, active keys */
export async function ownActive(env, accountId, id) {
  const k = await env.DB.prepare('SELECT id, keyid FROM agent_keys WHERE id = ? AND account_id = ? AND revoked_at IS NULL').bind(str(id, 'agentKeyId', { max: 24, re: /^[0-9a-f]{24}$/ }), accountId).first();
  if (!k) throw new HttpError(404, 'agent_key_not_found', 'No active agent key with that id on this account.');
  return k;
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

/**
 * Verify the broker signature on a proxied request. key: {keyid, x}. body: the exact request bytes (or null).
 * seen(k, expiresMs) -> true if this nonce was already used. Returns {keyid}; throws 401 with a reason.
 */
export async function verifyAgentSignature(request, body, key, seen, nowS = Math.floor(Date.now() / 1000)) {
  const si = request.headers.get('signature-input'), sg = request.headers.get('signature');
  if (!si || !sg) throw new HttpError(401, 'agent_signature_required', 'This token is bound to an agent key, so every request must be signed with it (RFC 9421, tag "leash-pop").');
  if (si.length > 4096 || sg.length > 4096) throw bad('signature headers too long');
  let inputs, sigs;
  try { inputs = parseDictionary(si); sigs = parseDictionary(sg); } catch { throw bad('malformed Signature-Input or Signature'); }
  let found = null;
  for (const [label, input] of inputs) {
    if (input.params.tag !== POP_TAG) continue;
    if (found) throw bad('more than one leash-pop signature');
    found = [label, input];
  }
  if (!found) throw new HttpError(401, 'agent_signature_required', 'No signature with tag "leash-pop" on this request.');
  const [label, input] = found, p = input.params;
  const comps = input.list;
  if (!comps || !comps.length) throw bad('no covered components');
  const names = [];
  for (const c of comps) {
    if (typeof c.value !== 'string' || !ALLOWED.has(c.value) || Object.keys(c.params || {}).length) throw bad(`component ${JSON.stringify(String(c.value)).slice(0, 40)} is not allowed`);
    if (names.includes(c.value)) throw bad('a component is covered twice');
    names.push(c.value);
  }
  for (const r of REQUIRED) if (!names.includes(r)) throw bad(`must cover ${r}`);
  if (body && body.length && !names.includes('content-digest')) throw bad('a request with a body must cover content-digest');
  if (body && body.length && request.headers.get('content-type') && !names.includes('content-type')) throw bad('a request with a body must cover content-type');
  if (!Number.isInteger(p.created) || !Number.isInteger(p.expires)) throw bad('created and expires are required');
  if (p.expires <= p.created) throw bad('expires must be after created');
  if (p.expires - p.created > POP_WINDOW) throw bad(`window longer than ${POP_WINDOW} seconds`);
  if (p.created > nowS + 60) throw bad('created in the future');
  if (p.expires < nowS) throw bad('expired');
  if (p.alg !== undefined && p.alg !== 'ed25519') throw bad('alg must be ed25519');
  if (p.keyid !== key.keyid) throw bad('keyid is not the agent key bound to this token');
  if (typeof p.nonce !== 'string' || !NONCE.test(p.nonce)) throw bad('a nonce of 8 to 128 base64 characters is required');
  const s = sigs.get(label);
  if (!s || !s.value || typeof s.value.bytes !== 'string') throw bad('missing signature bytes');
  let base;
  try { base = signatureBase({ method: request.method, url: request.url, headers: request.headers }, comps.map((c) => ({ value: c.value, params: {} })), input.raw); }
  catch (e) { throw bad(String(e.message).slice(0, 80)); }
  let sigBytes;
  try { sigBytes = fromB64u(s.value.bytes); } catch { throw bad('signature is not base64'); }
  if (sigBytes.length !== 64) throw bad('signature must be 64 bytes');
  const pub = await crypto.subtle.importKey('raw', fromB64u(key.x), { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, pub, sigBytes, new TextEncoder().encode(base)))) throw bad('signature does not verify');
  if (names.includes('content-digest')) {
    let d;
    try { d = parseDictionary(request.headers.get('content-digest') || ''); } catch { throw bad('malformed Content-Digest'); }
    const m = d.get('sha-256');
    if (!m || !m.value || typeof m.value.bytes !== 'string') throw bad('Content-Digest must carry sha-256');
    let want;
    try { want = fromB64u(m.value.bytes); } catch { throw bad('malformed Content-Digest'); }
    const got = await sha256(body || new Uint8Array(0));
    if (b64(want) !== b64(got)) throw bad('Content-Digest does not match the body');
  }
  if (await seen(`${key.keyid} ${p.nonce}`, (p.expires + 60) * 1000)) throw new HttpError(401, 'agent_signature_replayed', 'This signature was already used. Sign each request with a fresh nonce.');
  return { keyid: key.keyid };
}

/** the nonce store for broker signatures: D1, atomic, one row per accepted signature until it expires */
export const d1Seen = (db) => async (k, expiresMs) => {
  const r = await db.prepare('INSERT INTO nonces (k, expires_at) VALUES (?, ?) ON CONFLICT(k) DO NOTHING').bind(k, expiresMs).run();
  return !r.meta.changes;
};

export const _b64u = b64u;
