// "Move to Counterseal": an account made on the old host (leash.gautamkhosla.com) adds a passkey on the product's host
// (counterseal.gautamkhosla.com). Passkeys are bound to the host they were made on, so the old one cannot sign in on
// the new host; this link carries the account across, once.
//
// 1. Signed in on the old host, with a fresh passkey check, the person asks for a link (POST /v1/me/move/begin, /finish).
//    The server makes a one-time token (32 random bytes), keeps only its SHA-256, bound to the account, for 10 minutes,
//    at most 3 a hour per account, and writes it to the audit log. The link is <new host>/app#move=<token>: the token is
//    in the fragment, so it is never sent in a request line, never logged, never in a Referer.
// 2. On the new host the page reads the fragment, removes it from the address bar, and registers a new passkey with the
//    token in the POST body (POST /v1/move/begin, /finish). The token is consumed atomically when the new passkey is
//    saved, for that account only. The new passkey uses the new host's RP ID; the old passkey keeps working on the old
//    host until its owner removes it.
import { HttpError, b64u, rand, sha256hex, now, str } from './util.js';
import { verifyRegistration } from './webauthn.js';
import { newChallenge, takeChallenge, checkAssertion, rp, hosts, startWebSession } from './auth.js';
import { audit } from './audit.js';
import { limit } from './ratelimit.js';

export const MOVE_TTL = 10 * 60_000, MOVES_PER_HOUR = 3;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

function onOldHost(env) {
  if (hosts(env).length < 2 || !rp(env).legacy) throw new HttpError(400, 'not_on_old_host', 'You are already on the new host.');
}
function onNewHost(env) {
  if (hosts(env).length < 2 || rp(env).legacy) throw new HttpError(403, 'csrf');
}

export async function linkBegin(env, sess) {
  onOldHost(env);
  const { id, challenge } = await newChallenge(env, 'move_link', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function linkFinish(env, sess, body) {
  onOldHost(env);
  const ch = await takeChallenge(env, body.challengeId, 'move_link');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess.accountId);
  await limit(env.DB, 'move:' + sess.accountId, MOVES_PER_HOUR, 3600_000, now());
  const token = b64u(rand(32));
  const expires = now() + MOVE_TTL;
  await env.DB.prepare('INSERT INTO move_links (hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)').bind(await sha256hex(token), sess.accountId, now(), expires).run();
  await audit(env, sess.accountId, 'web', 'move_link_created', { expires_at: expires });
  return { url: `${hosts(env)[0].origin}/app#move=${token}`, expiresAt: expires };
}

async function live(env, token) {
  const hash = await sha256hex(str(token, 'token', { re: TOKEN }));
  const row = await env.DB.prepare('SELECT m.account_id, a.name FROM move_links m JOIN accounts a ON a.id = m.account_id WHERE m.hash = ? AND m.used_at IS NULL AND m.expires_at > ?').bind(hash, now()).first();
  if (!row) throw new HttpError(400, 'move_link_invalid', 'This link was used, has expired, or is wrong. Make a new one on the old host.');
  return { hash, ...row };
}

/** on the new host: registration options for a passkey that will join the linked account */
export async function registerBegin(env, body) {
  onNewHost(env);
  const l = await live(env, body.token);
  const { id, challenge } = await newChallenge(env, 'move', l.account_id, l.hash);
  const r = rp(env);
  return {
    challengeId: id, name: l.name,
    options: {
      challenge, rp: { id: r.rpId, name: r.name }, user: { id: b64u(rand(16)), name: l.name, displayName: l.name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none', timeout: 300000,
    },
  };
}

export async function registerFinish(env, body) {
  onNewHost(env);
  const ch = await takeChallenge(env, body.challengeId, 'move');
  const hash = await sha256hex(str(body.token, 'token', { re: TOKEN }));
  // the challenge was issued for this token, and so for its account
  if (ch.name !== hash) throw new HttpError(400, 'move_link_invalid', 'This link does not match the sign-up you started. Start again.');
  const r = rp(env);
  const c = await verifyRegistration(body.credential || {}, { challenge: ch.challenge, origin: r.origin, rpId: r.rpId });
  if (await env.DB.prepare('SELECT 1 AS x FROM passkeys WHERE cred_id = ?').bind(c.credId).first()) throw new HttpError(409, 'passkey_exists', 'That passkey is already registered.');
  // consume the token, once, for the account it was made for
  const used = await env.DB.prepare('UPDATE move_links SET used_at = ? WHERE hash = ? AND account_id = ? AND used_at IS NULL AND expires_at > ? RETURNING account_id').bind(now(), hash, ch.account_id, now()).first();
  if (!used) throw new HttpError(400, 'move_link_invalid', 'This link was used, has expired, or is wrong. Make a new one on the old host.');
  await env.DB.prepare('INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at, rp_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(c.credId, used.account_id, c.alg, JSON.stringify(c.jwk), c.signCount, now(), r.rpId).run();
  await audit(env, used.account_id, 'web', 'passkey_added', { host: r.origin, via: 'move' });
  return startWebSession(env, used.account_id);
}

// ---- your passkeys: list them, and remove one you no longer use (never the last)
const pkId = async (credId) => (await sha256hex('passkey|' + credId)).slice(0, 24);
export async function listPasskeys(env, sess) {
  const rows = (await env.DB.prepare('SELECT cred_id, rp_id, created_at, last_used FROM passkeys WHERE account_id = ? ORDER BY created_at').bind(sess.accountId).all()).results;
  const { passkeyRpId } = await import('./auth.js');
  return { passkeys: await Promise.all(rows.map(async (p) => ({ id: await pkId(p.cred_id), host: hosts(env).find((h) => h.rpId === passkeyRpId(env, p))?.origin || null, created_at: p.created_at, last_used: p.last_used }))) };
}
export async function removePasskey(env, sess, id) {
  const rows = (await env.DB.prepare('SELECT cred_id FROM passkeys WHERE account_id = ?').bind(sess.accountId).all()).results;
  let target = null;
  for (const p of rows) if ((await pkId(p.cred_id)) === id) target = p.cred_id;
  if (!target) throw new HttpError(404, 'not_found');
  if (rows.length < 2) throw new HttpError(409, 'last_passkey', 'This is your only passkey. Add another one before you remove it.');
  await env.DB.prepare('DELETE FROM passkeys WHERE cred_id = ? AND account_id = ?').bind(target, sess.accountId).run();
  await audit(env, sess.accountId, 'web', 'passkey_removed', { passkey: id });
  return { ok: true };
}
