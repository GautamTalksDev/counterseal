// Your passkeys: list them, and remove one you no longer use (never the last). On a team, "your" means the signed-in
// person's own: nobody sees the ids of, or removes, another member's passkeys (an owner removes the member instead).
import { HttpError, sha256hex, now } from './util.js';
import { newChallenge, takeChallenge, checkAssertion, rp } from './auth.js';
import { audit } from './audit.js';

/** the host a stored passkey works on: this one when it was made for this RP ID, else none (for example one made on
 *  the retired leash.gautamkhosla.com, or before the RP ID was recorded) */
const hostOfPasskey = (env, p) => (p.rp_id === rp(env).rpId ? rp(env).origin : null);

/** passkeys added in the last 15 minutes (not the one the account was made with), for the alert a phone shows */
export async function recentPasskeys(env, accountId) {
  const rows = (await env.DB.prepare('SELECT p.cred_id, p.rp_id, p.created_at FROM passkeys p JOIN accounts a ON a.id = p.account_id WHERE p.account_id = ? AND p.created_at > ? AND p.created_at > a.created_at + 60000 ORDER BY p.created_at DESC LIMIT 5').bind(accountId, now() - 15 * 60_000).all()).results;
  return Promise.all(rows.map(async (p) => ({ id: await pkId(p.cred_id), host: hostOfPasskey(env, p), created_at: p.created_at })));
}

const pkId = async (credId) => (await sha256hex('passkey|' + credId)).slice(0, 24);
const OWN = 'account_id = ? AND COALESCE(member_id, account_id) = ?';
export async function listPasskeys(env, sess) {
  const rows = (await env.DB.prepare(`SELECT cred_id, rp_id, created_at, last_used FROM passkeys WHERE ${OWN} ORDER BY created_at`).bind(sess.accountId, sess.memberId).all()).results;
  return { passkeys: await Promise.all(rows.map(async (p) => ({ id: await pkId(p.cred_id), host: hostOfPasskey(env, p), created_at: p.created_at, last_used: p.last_used }))) };
}
async function removable(env, sess, id) {
  const rows = (await env.DB.prepare(`SELECT cred_id FROM passkeys WHERE ${OWN}`).bind(sess.accountId, sess.memberId).all()).results;
  let target = null;
  for (const p of rows) if ((await pkId(p.cred_id)) === id) target = p.cred_id;
  if (!target) throw new HttpError(404, 'not_found');
  if (rows.length < 2) throw new HttpError(409, 'last_passkey', 'This is your only passkey. Add another one before you remove it.');
  return target;
}
// Removing a passkey takes a sign-in method away from the owner, so, like deleting the account, it needs a fresh passkey
// ceremony: a stolen cookie alone cannot lock the owner out. It also signs out every other web session of the account,
// so a browser that signed in with the removed passkey (for example one a thief added) is out at once.
export async function removeBegin(env, sess, id) {
  await removable(env, sess, id);
  const { id: challengeId, challenge } = await newChallenge(env, 'passkey_remove:' + id, sess.accountId);
  return { challengeId, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
export async function removeFinish(env, sess, id, body) {
  const ch = await takeChallenge(env, body.challengeId, 'passkey_remove:' + id);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const target = await removable(env, sess, id);
  // signs out this person's other browsers (never another member's)
  const [, out] = await env.DB.batch([
    env.DB.prepare(`DELETE FROM passkeys WHERE cred_id = ? AND ${OWN}`).bind(target, sess.accountId, sess.memberId),
    env.DB.prepare(`DELETE FROM sessions WHERE ${OWN} AND kind = 'web' AND hash != ?`).bind(sess.accountId, sess.memberId, sess.hash),
  ]);
  const signedOut = out?.meta?.changes || 0;
  await audit(env, sess.accountId, 'web', 'passkey_removed', { passkey: id, signed_out: signedOut });
  return { ok: true, signedOut };
}
