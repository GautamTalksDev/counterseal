// Accounts and sessions. Passkeys are the only way in; there are no passwords to phish or reuse.
// Web sessions: __Host- cookie (HttpOnly, Secure, SameSite=Strict) + a custom header on writes (CSRF), Origin checked.
// CLI sessions: bearer token from a device-code sign-in approved with a passkey. A CLI session can mint tokens and
// list holds but can never approve a hold or pre-approve irreversible operations: an agent on the same machine can
// read the CLI's file, so anything dangerous needs a human's passkey.
import { HttpError, b64u, rand, randomId, sha256hex, now, str } from './util.js';
import { verifyRegistration, verifyAssertion } from './webauthn.js';
import { audit } from './audit.js';

const WEB_TTL = 12 * 3600_000, CLI_TTL = 30 * 86400_000, CH_TTL = 5 * 60_000;

export function rp(env) {
  return { rpId: env.RP_ID || 'localhost', origin: env.ORIGIN || 'http://localhost:8787', name: 'LEASH' };
}

async function newChallenge(env, kind, accountId = null, name = null) {
  const id = randomId(), challenge = b64u(rand(32));
  await env.DB.prepare('INSERT INTO challenges (id, kind, account_id, challenge, name, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, kind, accountId, challenge, name, now() + CH_TTL).run();
  return { id, challenge };
}

/** single use: the row is deleted as it is read */
async function takeChallenge(env, id, kind) {
  str(id, 'challenge', { max: 64, re: /^[0-9a-f]+$/ });
  const row = await env.DB.prepare('DELETE FROM challenges WHERE id = ? RETURNING *').bind(id).first();
  if (!row || row.kind !== kind || row.expires_at < now()) throw new HttpError(400, 'challenge_expired', 'Start again.');
  return row;
}

export async function registerBegin(env, body) {
  const name = str(body.name, 'name', { max: 60, re: /^[\p{L}\p{N} ._'-]+$/u });
  const { id, challenge } = await newChallenge(env, 'register', null, name);
  const userId = b64u(rand(16));
  const r = rp(env);
  return {
    challengeId: id,
    options: {
      challenge, rp: { id: r.rpId, name: r.name }, user: { id: userId, name, displayName: name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none', timeout: 300000,
    },
  };
}

export async function registerFinish(env, body, request) {
  const ch = await takeChallenge(env, body.challengeId, 'register');
  const r = rp(env);
  const c = await verifyRegistration(body.credential || {}, { challenge: ch.challenge, origin: r.origin, rpId: r.rpId });
  const accountId = randomId();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO accounts (id, name, created_at) VALUES (?, ?, ?)').bind(accountId, ch.name, now()),
    env.DB.prepare('INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(c.credId, accountId, c.alg, JSON.stringify(c.jwk), c.signCount, now()),
  ]);
  await audit(env, accountId, 'web', 'signup', {});
  return startWebSession(env, accountId);
}

export async function loginBegin(env) {
  const { id, challenge } = await newChallenge(env, 'login');
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

/** verifies an assertion against a stored passkey; returns the account id */
export async function checkAssertion(env, cred, challenge, accountId = null) {
  if (!cred || typeof cred.id !== 'string') throw new HttpError(400, 'bad_credential');
  const pk = await env.DB.prepare('SELECT * FROM passkeys WHERE cred_id = ?').bind(str(cred.id, 'credential', { max: 1400 })).first();
  if (!pk || (accountId && pk.account_id !== accountId)) throw new HttpError(401, 'unknown_passkey', 'That passkey is not linked to this LEASH account. If you made more than one account, pick the passkey you created for the one you are signed in to.');
  const r = rp(env);
  const count = await verifyAssertion(cred, { challenge, origin: r.origin, rpId: r.rpId, alg: pk.alg, jwk: JSON.parse(pk.jwk), signCount: pk.sign_count });
  await env.DB.prepare('UPDATE passkeys SET sign_count = ?, last_used = ? WHERE cred_id = ?').bind(count, now(), pk.cred_id).run();
  return pk.account_id;
}

export async function loginFinish(env, body) {
  const ch = await takeChallenge(env, body.challengeId, 'login');
  const accountId = await checkAssertion(env, body.credential, ch.challenge);
  await audit(env, accountId, 'web', 'login', {});
  return startWebSession(env, accountId);
}

async function startWebSession(env, accountId) {
  const token = b64u(rand(32));
  await env.DB.prepare('INSERT INTO sessions (hash, account_id, kind, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256hex(token), accountId, 'web', now(), now() + WEB_TTL).run();
  return { body: { ok: true }, cookie: `__Host-leash=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${WEB_TTL / 1000}` };
}

export async function logout(env, sess) {
  await env.DB.prepare('DELETE FROM sessions WHERE hash = ?').bind(sess.hash).run();
  return { body: { ok: true }, cookie: '__Host-leash=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' };
}

/** {accountId, kind, hash} from cookie (web) or bearer (cli); writes from the web need Origin + x-leash header */
export async function session(env, request, write) {
  const authz = request.headers.get('authorization') || '';
  let token, kind;
  if (authz.startsWith('Bearer lsc_')) { token = authz.slice(7); kind = 'cli'; }
  else {
    const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)__Host-leash=([A-Za-z0-9_-]{20,100})/);
    if (m) { token = m[1]; kind = 'web'; }
  }
  if (!token) throw new HttpError(401, 'signed_out');
  if (kind === 'web' && write) {
    if (request.headers.get('origin') !== rp(env).origin || request.headers.get('x-leash') !== '1') throw new HttpError(403, 'csrf');
  }
  const hash = await sha256hex(token);
  const s = await env.DB.prepare('SELECT * FROM sessions WHERE hash = ? AND kind = ?').bind(hash, kind).first();
  if (!s || s.expires_at < now()) throw new HttpError(401, 'signed_out');
  return { accountId: s.account_id, kind, hash };
}

// ---- CLI sign-in: device code (RFC 8628 shape). The CLI never sees a passkey; the human approves in the browser.
const UC = 'BCDFGHJKLMNPQRSTVWXZ23456789';
export async function deviceStart(env) {
  const device = 'lsd_' + b64u(rand(32));
  const r = rand(8); let user = '';
  for (let i = 0; i < 8; i++) user += UC[r[i] % UC.length] + (i === 3 ? '-' : '');
  await env.DB.prepare('INSERT INTO device_codes (device_hash, user_code, expires_at) VALUES (?, ?, ?)').bind(await sha256hex(device), user, now() + 10 * 60_000).run();
  return { device_code: device, user_code: user, verification_uri: `${rp(env).origin}/app#device=${user}`, interval: 3, expires_in: 600 };
}

/** the browser approves a device code with a fresh passkey ceremony bound to that code */
export async function deviceApproveBegin(env, sess, body) {
  const code = str(body.user_code, 'user_code', { max: 9, re: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/ });
  const row = await env.DB.prepare('SELECT * FROM device_codes WHERE user_code = ?').bind(code).first();
  if (!row || row.status !== 'pending' || row.expires_at < now()) throw new HttpError(404, 'code_not_found', 'That code is wrong or expired.');
  const { id, challenge } = await newChallenge(env, 'device:' + code, sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function deviceApproveFinish(env, sess, body) {
  const code = str(body.user_code, 'user_code', { max: 9, re: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/ });
  const ch = await takeChallenge(env, body.challengeId, 'device:' + code);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess.accountId);
  const r = await env.DB.prepare("UPDATE device_codes SET account_id = ?, status = 'approved' WHERE user_code = ? AND status = 'pending' AND expires_at > ?")
    .bind(sess.accountId, code, now()).run();
  if (!r.meta.changes) throw new HttpError(404, 'code_not_found');
  await audit(env, sess.accountId, 'web', 'cli_signin_approved', { user_code: code });
  return { ok: true };
}

export async function devicePoll(env, body) {
  const device = str(body.device_code, 'device_code', { max: 80, re: /^lsd_[A-Za-z0-9_-]+$/ });
  const h = await sha256hex(device);
  const row = await env.DB.prepare('SELECT * FROM device_codes WHERE device_hash = ?').bind(h).first();
  if (!row || row.expires_at < now()) throw new HttpError(400, 'expired_token');
  if (row.status === 'pending') throw new HttpError(400, 'authorization_pending');
  const used = await env.DB.prepare("UPDATE device_codes SET status = 'used' WHERE device_hash = ? AND status = 'approved'").bind(h).run();
  if (!used.meta.changes) throw new HttpError(400, 'expired_token');
  const token = 'lsc_' + b64u(rand(32));
  await env.DB.prepare('INSERT INTO sessions (hash, account_id, kind, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256hex(token), row.account_id, 'cli', now(), now() + CLI_TTL).run();
  return { access_token: token, expires_in: CLI_TTL / 1000 };
}

export { newChallenge, takeChallenge };
