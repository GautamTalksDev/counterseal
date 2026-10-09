// Accounts and sessions. Passkeys are the only way in; there are no passwords to phish or reuse.
// Web sessions: __Host- cookie (HttpOnly, Secure, SameSite=Strict) + a custom header on writes (CSRF), Origin checked.
//
// Two hosts (the domain move, 9 Oct 2026): the product lives at ORIGIN (counterseal.gautamkhosla.com, RP ID RP_ID); the
// old host LEGACY_ORIGIN (leash.gautamkhosla.com, RP ID LEGACY_RP_ID) keeps its API, proxy and /app sign-in so existing
// passkeys and the published CLI keep working. Which host a request belongs to, and so which RP ID a WebAuthn ceremony
// uses, is chosen only by the request: its Origin header (browsers), else its own URL (CLI, agents), and only from that
// allow list of exactly two. A client never names an RP ID. Cookies are host-only (__Host-), so each host has its own
// sessions in the browser.
// CLI sessions: bearer token from a device-code sign-in approved with a passkey. A CLI session can mint tokens and
// list holds but can never approve a hold or pre-approve irreversible operations: an agent on the same machine can
// read the CLI's file, so anything dangerous needs a human's passkey.
import { HttpError, b64u, rand, randomId, sha256hex, now, str } from './util.js';
import { verifyRegistration, verifyAssertion } from './webauthn.js';
import { audit } from './audit.js';
import { BRAND } from './brand.js';
import { limit, callerKey } from './ratelimit.js';
import { notify } from './push.js';

// CLI sessions last 7 days (30 before 10 Oct 2026): a sign-in phished out of someone is a smaller prize, and nothing a
// CLI session makes outlives it (see broker.js mintToken). Device codes last 5 minutes (RFC 8628 says "short").
export const WEB_TTL = 12 * 3600_000, CLI_TTL = 7 * 86400_000, CH_TTL = 5 * 60_000, DEVICE_TTL = 5 * 60_000, DEVICE_INTERVAL = 5;

/** the allow list: the product's host first, then the old host if one is configured. Exactly these, nothing else. */
export function hosts(env) {
  const list = [{ origin: env.ORIGIN || 'http://localhost:8787', rpId: env.RP_ID || 'localhost', legacy: false }];
  if (env.LEGACY_ORIGIN && env.LEGACY_RP_ID) list.push({ origin: env.LEGACY_ORIGIN, rpId: env.LEGACY_RP_ID, legacy: true });
  return list;
}

/** the host entry this request belongs to: by its Origin header when it sends one (null if that Origin is not on the
 *  list), else by its own URL, else the product's host */
export function hostOf(env, request) {
  const list = hosts(env);
  const o = request.headers.get('origin');
  if (o) return list.find((h) => h.origin === o) || null;
  let u = null;
  try { u = new URL(request.url).origin; } catch { /* unreachable for a Request */ }
  return list.find((h) => h.origin === u) || list[0];
}

/** a browser write is same-origin and from one of the two hosts: the Origin header must be on the list and must be
 *  the origin of the URL it was sent to */
export function originAllowed(env, request) {
  const o = request.headers.get('origin');
  return !!o && o === new URL(request.url).origin && hosts(env).some((h) => h.origin === o);
}

/** the RP for this request (src/index.js sets env.__rp per request); without one, the product's host */
export function rp(env) {
  const h = env.__rp || hosts(env)[0];
  return { rpId: h.rpId, origin: h.origin, legacy: !!h.legacy, name: BRAND.name };
}

/** where a person signs in to approve: the product's host once the account has a passkey there, else the old host */
export async function appOrigin(env, accountId, known) {
  const list = hosts(env);
  if (list.length === 1) return list[0].origin;
  const hasNew = known ?? !!(await env.DB.prepare('SELECT 1 AS x FROM passkeys WHERE account_id = ? AND rp_id = ? LIMIT 1').bind(accountId, list[0].rpId).first());
  return hasNew ? list[0].origin : list[1].origin;
}

/** the RP ID a stored passkey belongs to: recorded since the move; before it, the host that was then the only one */
export const passkeyRpId = (env, pk) => pk.rp_id || (env.LEGACY_RP_ID && env.LEGACY_ORIGIN ? env.LEGACY_RP_ID : hosts(env)[0].rpId);

async function newChallenge(env, kind, accountId = null, name = null) {
  const id = randomId(), challenge = b64u(rand(32));
  await env.DB.prepare('INSERT INTO challenges (id, kind, account_id, challenge, name, expires_at, origin) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, kind, accountId, challenge, name, now() + CH_TTL, rp(env).origin).run();
  return { id, challenge };
}

/** single use: the row is deleted as it is read. A challenge issued on one host is refused on the other. */
async function takeChallenge(env, id, kind) {
  str(id, 'challenge', { max: 64, re: /^[0-9a-f]+$/ });
  const row = await env.DB.prepare('DELETE FROM challenges WHERE id = ? RETURNING *').bind(id).first();
  if (!row || row.kind !== kind || row.expires_at < now() || (row.origin && row.origin !== rp(env).origin)) throw new HttpError(400, 'challenge_expired', 'Start again.');
  return row;
}

export async function registerBegin(env, body) {
  // new accounts are made on the product's host only; the old host keeps sign-in for the passkeys it already has
  if (rp(env).legacy) throw new HttpError(403, 'register_on_new_host', `Create your account at ${hosts(env)[0].origin}/app.`);
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
  if (rp(env).legacy) throw new HttpError(403, 'register_on_new_host', `Create your account at ${hosts(env)[0].origin}/app.`);
  const ch = await takeChallenge(env, body.challengeId, 'register');
  const r = rp(env);
  const c = await verifyRegistration(body.credential || {}, { challenge: ch.challenge, origin: r.origin, rpId: r.rpId });
  const exists = () => new HttpError(409, 'passkey_exists', 'That passkey is already registered. Sign in instead.');
  if (await env.DB.prepare('SELECT 1 AS x FROM passkeys WHERE cred_id = ?').bind(c.credId).first()) throw exists();
  const accountId = randomId();
  // new accounts start with public receipts on (the sign-up page says so); accounts made before receipts existed keep
  // them off until their owner turns them on
  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO accounts (id, name, created_at, receipts, last_seen) VALUES (?, ?, ?, 1, ?)').bind(accountId, ch.name, now(), now()),
      env.DB.prepare('INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at, rp_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(c.credId, accountId, c.alg, JSON.stringify(c.jwk), c.signCount, now(), r.rpId),
    ]);
  } catch (e) {
    if (/UNIQUE|constraint/i.test(String(e && e.message))) throw exists();
    throw e;
  }
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
  if (!pk || (accountId && pk.account_id !== accountId)) throw new HttpError(401, 'unknown_passkey', `That passkey is not linked to this ${BRAND.name} account. If you made more than one account, pick the passkey you created for the one you are signed in to.`);
  const r = rp(env);
  // a passkey only ever works on the host (RP ID) it was made for; the authenticator data proves it too
  if (passkeyRpId(env, pk) !== r.rpId) throw new HttpError(401, 'unknown_passkey', `That passkey belongs to ${hosts(env).find((h) => h.rpId === passkeyRpId(env, pk))?.origin || 'another host'}. Sign in there.`);
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

export async function startWebSession(env, accountId) {
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
    if (!originAllowed(env, request) || request.headers.get('x-leash') !== '1') throw new HttpError(403, 'csrf');
  }
  const hash = await sha256hex(token);
  const s = await env.DB.prepare('SELECT * FROM sessions WHERE hash = ? AND kind = ?').bind(hash, kind).first();
  if (!s || s.expires_at < now()) throw new HttpError(401, 'signed_out');
  return { accountId: s.account_id, kind, hash, expiresAt: s.expires_at };
}

/** a session's public id: derived from its stored hash, so it can be listed and revoked without exposing the hash, and
 *  sessions made before this id existed have one too */
export const sessionId = async (hash) => (await sha256hex('session|' + hash)).slice(0, 24);

// ---- CLI sign-in: device code (RFC 8628 shape). The CLI never sees a passkey; the human approves in the browser.
//
// Device-code phishing (used at scale against other platforms in 2025): an attacker starts a sign-in, sends someone the
// code ("verify your account"), and if that person approves, the attacker's command line is in their account. So:
//  - the code is never put in a link: verification_uri is the plain page, and the page ignores a code in its address
//    (a link that carries one is shown as a warning). The person types the code from their own terminal;
//  - before the passkey, the page shows what is granted, when the sign-in started and from where (country and network,
//    from Cloudflare's request data, never an IP), next to where the person is now, and asks whether they ran it;
//  - the code lives 5 minutes, is used once, and starts, lookups and approvals are rate limited (RFC 8628 section 5.1);
//  - the session lasts 7 days, everything it makes ends with it, and the owner's devices are alerted at once
//    ("A command line was signed in") with a one-tap revoke that also revokes what it made.
const UC = 'BCDFGHJKLMNPQRSTVWXZ23456789'; // no vowels (no words), no 0/O or 1/I (RFC 8628 section 6.1)
export const DEVICE_STARTS_PER_HOUR = 10, DEVICE_LOOKUPS = 10, DEVICE_LOOKUP_WINDOW = 10 * 60_000, DEVICE_APPROVALS_PER_HOUR = 10;

/** the user code as typed: any case, spaces or dashes; always stored and shown as XXXX-XXXX */
function userCode(v) {
  const s = typeof v === 'string' && v.length <= 32 ? v.toUpperCase().replace(/[\s-]/g, '') : '';
  if (!/^[BCDFGHJKLMNPQRSTVWXZ2-9]{8}$/.test(s)) throw new HttpError(400, 'bad_user_code', 'Type the 8 characters shown in your terminal, like ABCD-2345.');
  return s.slice(0, 4) + '-' + s.slice(4);
}

/** 8 characters without modulo bias (a byte is used only below 252 = 9 x 28) */
function newUserCode() {
  let s = '';
  while (s.length < 8) for (const b of rand(16)) if (b < 252 && s.length < 8) s += UC[b % UC.length];
  return s.slice(0, 4) + '-' + s.slice(4);
}

const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/gu;
/** where a request came from, coarse, from Cloudflare's request.cf: country code, network name, network number. Never an
 *  IP. Missing outside Cloudflare (local dev). The network name is Cloudflare's, but it is still treated as untrusted text. */
export function whereFrom(cf) {
  if (!cf || typeof cf !== 'object') return { country: null, network: null, asn: null };
  const country = typeof cf.country === 'string' && /^[A-Z][A-Z0-9]$/.test(cf.country) && cf.country !== 'XX' ? cf.country : null;
  const network = typeof cf.asOrganization === 'string' ? cf.asOrganization.replace(UNSAFE_TEXT, '').trim().slice(0, 60) || null : null;
  const asn = Number.isSafeInteger(cf.asn) && cf.asn > 0 ? cf.asn : null;
  return { country, network, asn };
}

export async function deviceStart(env, request, from = whereFrom(null)) {
  // a phishing kit needs a fresh code for every person it targets: at most 10 starts an hour per network
  await limit(env.DB, 'devstart:' + (await callerKey(env, request)), DEVICE_STARTS_PER_HOUR, 3600_000, now());
  const device = 'lsd_' + b64u(rand(32));
  const user = newUserCode();
  await env.DB.prepare('INSERT INTO device_codes (device_hash, user_code, expires_at, created_at, country, network, asn) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256hex(device), user, now() + DEVICE_TTL, now(), from.country, from.network, from.asn).run();
  // verification_uri is the plain page: the code is typed there, never carried in a link (no verification_uri_complete)
  return { device_code: device, user_code: user, verification_uri: `${rp(env).origin}/app#device`, interval: DEVICE_INTERVAL, expires_in: DEVICE_TTL / 1000 };
}
async function pendingCode(env, code) {
  const row = await env.DB.prepare('SELECT * FROM device_codes WHERE user_code = ?').bind(code).first();
  if (!row || row.status !== 'pending' || row.expires_at < now()) throw new HttpError(404, 'code_not_found', 'That code is wrong or expired. Run leashcli login again and type the new code.');
  return row;
}

/** step 1 in the browser: what is this sign-in? When it started, where from, compared with where this browser is.
 *  Rate limited per account (with deny), so codes cannot be guessed or used to learn where other people sign in. */
export async function deviceLookup(env, sess, body, here = whereFrom(null)) {
  const code = userCode(body.user_code);
  await limit(env.DB, 'devlook:' + sess.accountId, DEVICE_LOOKUPS, DEVICE_LOOKUP_WINDOW, now());
  const row = await pendingCode(env, code);
  const same = (a, b) => (a && b ? a === b : null);
  return {
    user_code: code, started_at: row.created_at || null, expires_at: row.expires_at, now: now(),
    from: { country: row.country || null, network: row.network || null },
    here: { country: here.country, network: here.network },
    same: { country: same(row.country, here.country), network: same(row.asn, here.asn) },
    session_days: CLI_TTL / 86400_000,
  };
}

/** step 2: "No, I did not run it". The code is spent and the command line is told access_denied. */
export async function deviceDeny(env, sess, body) {
  const code = userCode(body.user_code);
  await limit(env.DB, 'devlook:' + sess.accountId, DEVICE_LOOKUPS, DEVICE_LOOKUP_WINDOW, now());
  const r = await env.DB.prepare("UPDATE device_codes SET status = 'denied' WHERE user_code = ? AND status = 'pending' AND expires_at > ? RETURNING country, network").bind(code, now()).first();
  if (!r) throw new HttpError(404, 'code_not_found', 'That code is wrong or expired.');
  await audit(env, sess.accountId, 'web', 'cli_signin_denied', { user_code: code, country: r.country || null, network: r.network || null });
  return { ok: true };
}

/** step 3: the browser approves a device code with a fresh passkey ceremony bound to that code */
export async function deviceApproveBegin(env, sess, body) {
  const code = userCode(body.user_code);
  await limit(env.DB, 'devappr:' + sess.accountId, DEVICE_APPROVALS_PER_HOUR, 3600_000, now());
  await pendingCode(env, code);
  const { id, challenge } = await newChallenge(env, 'device:' + code, sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function deviceApproveFinish(env, sess, body) {
  const code = userCode(body.user_code);
  const ch = await takeChallenge(env, body.challengeId, 'device:' + code);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess.accountId);
  const r = await env.DB.prepare("UPDATE device_codes SET account_id = ?, status = 'approved' WHERE user_code = ? AND status = 'pending' AND expires_at > ? RETURNING country, network")
    .bind(sess.accountId, code, now()).first();
  if (!r) throw new HttpError(404, 'code_not_found', 'That code is wrong or expired.');
  await audit(env, sess.accountId, 'web', 'cli_signin_approved', { user_code: code, country: r.country || null, network: r.network || null });
  return { ok: true };
}

export async function devicePoll(env, body) {
  const device = str(body.device_code, 'device_code', { max: 80, re: /^lsd_[A-Za-z0-9_-]+$/ });
  const h = await sha256hex(device);
  const row = await env.DB.prepare('SELECT * FROM device_codes WHERE device_hash = ?').bind(h).first();
  if (!row || row.expires_at < now()) throw new HttpError(400, 'expired_token');
  if (row.status === 'pending') throw new HttpError(400, 'authorization_pending');
  if (row.status === 'denied') throw new HttpError(400, 'access_denied', 'This sign-in was denied in the browser.');
  const used = await env.DB.prepare("UPDATE device_codes SET status = 'used' WHERE device_hash = ? AND status = 'approved'").bind(h).run();
  if (!used.meta.changes) throw new HttpError(400, 'expired_token');
  const token = 'lsc_' + b64u(rand(32)), hash = await sha256hex(token);
  await env.DB.prepare('INSERT INTO sessions (hash, account_id, kind, created_at, expires_at, country, network) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(hash, row.account_id, 'cli', now(), now() + CLI_TTL, row.country || null, row.network || null).run();
  // on the record, and every device with alerts on is told at once: "A command line was signed in", one tap to revoke
  const sid = await sessionId(hash);
  await audit(env, row.account_id, 'cli', 'cli_signed_in', { session: sid, country: row.country || null, network: row.network || null });
  const p = notify(env, row.account_id, env.__pushFetch || fetch).catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p); else await p;
  return { access_token: token, token_type: 'Bearer', expires_in: CLI_TTL / 1000 };
}

// ---- CLI sessions: list them, and revoke one with everything it made.
// The list comes from the audit log (every sign-in of the last 7 days), not only from live session rows: a phished
// command line that signs itself out at once (or a session that has expired) leaves its tokens, agent keys and receipts
// keys behind, and its owner must still be able to find it and revoke what it made.
const signinsSince = async (env, accountId, since, limit) => (await env.DB.prepare("SELECT at, detail FROM audit WHERE account_id = ? AND action = 'cli_signed_in' AND at > ? ORDER BY seq DESC LIMIT ?").bind(accountId, since, limit).all()).results
  .map((r) => { const d = JSON.parse(r.detail); return { id: String(d.session || ''), created_at: r.at, country: d.country || null, network: d.network || null }; })
  .filter((s) => /^[0-9a-f]{24}$/.test(s.id));

export async function listCliSessions(env, sess) {
  const t = now(), a = sess.accountId;
  const rows = (await env.DB.prepare("SELECT hash, created_at, expires_at, country, network FROM sessions WHERE account_id = ? AND kind = 'cli' AND expires_at > ? ORDER BY created_at DESC LIMIT 100").bind(a, t).all()).results;
  const live = new Map();
  for (const r of rows) live.set(await sessionId(r.hash), r);
  const revoked = new Set((await env.DB.prepare("SELECT detail FROM audit WHERE account_id = ? AND action = 'cli_session_revoked' AND at > ?").bind(a, t - CLI_TTL).all()).results.map((r) => JSON.parse(r.detail).session));
  const out = [];
  for (const s of await signinsSince(env, a, t - CLI_TTL, 100)) {
    const r = live.get(s.id);
    live.delete(s.id);
    out.push({ ...s, expires_at: r ? r.expires_at : null, status: r ? 'live' : revoked.has(s.id) ? 'revoked' : 'ended', current: !!r && r.hash === sess.hash });
  }
  // live sessions with no sign-in entry (made before migration 0005)
  for (const [id, r] of live) out.push({ id, created_at: r.created_at, expires_at: r.expires_at, country: r.country || null, network: r.network || null, status: 'live', current: r.hash === sess.hash });
  return { sessions: out };
}

/** the CLI sign-ins of the last 15 minutes, for the alert a phone shows after a push (from the audit log, so a sign-in
 *  that already signed itself out is still shown) */
export const recentCliSignins = (env, accountId) => signinsSince(env, accountId, now() - 15 * 60_000, 5);

/** web session only (a stolen CLI session must not sign out its owner's other machines). Ends the session if it is
 *  still live and revokes every token, agent key and receipts key it made, in one batch; this works after the session
 *  signed out or expired too. */
export async function revokeCliSession(env, sess, sid) {
  const rows = (await env.DB.prepare("SELECT hash FROM sessions WHERE account_id = ? AND kind = 'cli'").bind(sess.accountId).all()).results;
  let target = null;
  for (const r of rows) if ((await sessionId(r.hash)) === sid) { target = r.hash; break; }
  if (!target && !(await env.DB.prepare("SELECT 1 AS x FROM audit WHERE account_id = ? AND action = 'cli_signed_in' AND detail LIKE ? LIMIT 1").bind(sess.accountId, `%"session":"${sid}"%`).first())) throw new HttpError(404, 'not_found');
  const t = now(), a = sess.accountId;
  const [, tk, ak, rk] = await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE hash = ? AND account_id = ?').bind(target || '', a),
    env.DB.prepare('UPDATE tokens SET revoked = 1 WHERE account_id = ? AND session_id = ? AND revoked = 0').bind(a, sid),
    env.DB.prepare('UPDATE agent_keys SET revoked_at = ? WHERE account_id = ? AND session_id = ? AND revoked_at IS NULL').bind(t, a, sid),
    env.DB.prepare('UPDATE api_keys SET revoked = 1 WHERE account_id = ? AND session_id = ? AND revoked = 0').bind(a, sid),
  ]);
  const n = (r) => r?.meta?.changes || 0;
  await audit(env, a, 'web', 'cli_session_revoked', { session: sid, ended: !!target, tokens: n(tk), agent_keys: n(ak), receipts_keys: n(rk) });
  return { ok: true, ended: !!target, revoked: { tokens: n(tk), agentKeys: n(ak), receiptsKeys: n(rk) } };
}

export { newChallenge, takeChallenge };
