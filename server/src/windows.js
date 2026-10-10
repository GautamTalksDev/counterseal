// Break-glass windows (two-person seal, part 2b). For the night when the second approver cannot be reached: an owner or an
// approver opens a window, with a passkey, for at most 60 minutes. While it is open, what the irreversible map would hold is
// let through for the tokens and guard keys it names (or every one of the account), sealed in the log like any call, flagged,
// and announced to every member's devices and every channel. It is one person loosening protection, so it is built to be
// seen and to be small:
//   - an owner or approver only, with a fresh passkey ceremony whose challenge carries exactly the minutes, the scope and
//     the reason; never a command line session; while one person cannot approve alone, not an approver whose seal does not
//     count yet (a stolen invite cannot open one)
//   - 5 to 60 minutes, one open at a time, at most 3 a day per account, and it cannot be extended (to go on, open another)
//   - it ends when closed (any member, any session), when it expires, when its opener stops being an owner or approver, or
//     when the account is frozen (a freeze stops every call whatever a window says)
//   - it never lets through what a brake holds (a tripped breaker, a rate limit or a money cap), never a deploy gate, and
//     with self-approval off never a call asked for by the person who opened it
//   - the calls it lets through carry the rule's id with ":breakglass" and the window's id in the owner's log, and the public
//     receipt says "breakglass" and nothing else about the window
import { HttpError, randomId, now, str, cleanText } from './util.js';
import { audit } from './audit.js';
import * as Team from './team.js';
import { frozenError } from './brakes.js';

export const MIN_MINUTES = 5, MAX_MINUTES = 60, PER_DAY = 3, MAX_REASON = 200;
const DAY = 86_400_000;
const ID24 = /^[0-9a-f]{24}$/;

/** a token's id or a guard key's id, as the id its holds carry (tokens: the id; guard keys: g:<id>) */
async function scopeOf(env, sess, id, t) {
  if (id === undefined || id === null) return null;
  const s = str(id, 'tokenId', { max: 24, re: ID24 });
  const tok = await env.DB.prepare('SELECT id, label, COALESCE(member_id, account_id) AS maker FROM tokens WHERE id = ? AND account_id = ? AND revoked = 0 AND expires_at > ?').bind(s, sess.accountId, t).first();
  if (tok) return { holdToken: tok.id, label: tok.label, maker: tok.maker };
  const gk = await env.DB.prepare('SELECT id, label, COALESCE(member_id, account_id) AS maker FROM guard_keys WHERE id = ? AND account_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)').bind(s, sess.accountId, t).first();
  if (gk) return { holdToken: 'g:' + gk.id, label: gk.label, maker: gk.maker };
  throw new HttpError(404, 'not_found', 'There is no such live token or guard key on this account.');
}

function params(body) {
  for (const k of Object.keys(body)) if (!['minutes', 'tokenId', 'reason', 'challengeId', 'credential'].includes(k)) throw new HttpError(400, 'bad_field', 'Unknown field. Send only: minutes, tokenId, reason.');
  if (!Number.isInteger(body.minutes) || body.minutes < MIN_MINUTES || body.minutes > MAX_MINUTES) throw new HttpError(400, 'bad_minutes', `A window lasts ${MIN_MINUTES} to ${MAX_MINUTES} minutes (a whole number). It cannot be extended.`);
  if (typeof body.reason !== 'string' || body.reason.length > MAX_REASON * 4) throw new HttpError(400, 'bad_reason', `Say why, in ${MAX_REASON} characters or fewer: the whole team is told a window is open.`);
  const reason = cleanText(body.reason).slice(0, MAX_REASON);
  if (reason.length < 3) throw new HttpError(400, 'bad_reason', 'Say why, in a few words: the whole team is told a window is open.');
  return { minutes: body.minutes, tokenId: body.tokenId ?? null, reason };
}

/** the checks before and after the passkey; they are the same, and the statement that inserts decides again */
async function checks(env, sess, p, t) {
  const a = await env.DB.prepare('SELECT frozen_at, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at FROM accounts WHERE id = ?').bind(sess.accountId).first();
  if (a?.frozen_at) throw frozenError();
  await Team.seasoned(env, sess);
  const scope = await scopeOf(env, sess, p.tokenId, t);
  // with self-approval off, the person who made a token cannot open a window for what it asks
  if (scope && !Team.effective(a, t).selfApprove && scope.maker === sess.memberId) throw new HttpError(403, 'own_request', 'Your team requires someone other than the maker to let this through, so you cannot open a window for your own token or guard key.');
  const r = await env.DB.prepare('SELECT (SELECT COUNT(*) FROM windows WHERE account_id = ?1 AND closed_at IS NULL AND expires_at > ?2) AS open, (SELECT COUNT(*) FROM windows WHERE account_id = ?1 AND opened_at > ?3) AS today').bind(sess.accountId, t, t - DAY).first();
  if (r.open) throw new HttpError(409, 'window_open', 'A window is already open. Close it, or wait for it to end; a window cannot be extended.');
  if (r.today >= PER_DAY) throw new HttpError(429, 'too_many_windows', `At most ${PER_DAY} windows in 24 hours. Approve the held actions one by one instead.`);
  return scope;
}

export async function openBegin(env, sess, body) {
  const p = params(body);
  await checks(env, sess, p, now());
  // what the passkey approves is exactly this window
  return Team.ceremony(env, 'breakglass', sess.accountId, JSON.stringify({ minutes: p.minutes, token: p.tokenId, reason: p.reason }));
}

export async function openFinish(env, sess, body) {
  const ch = await Team.confirm(env, sess, body, 'breakglass');
  const p = (() => { const w = JSON.parse(ch.name); return { minutes: w.minutes, tokenId: w.token, reason: w.reason }; })();
  const t = now();
  const scope = await checks(env, sess, p, t);
  const id = randomId();
  // one statement decides: still no window open, fewer than 3 today, the account not frozen, the opener still an owner or approver
  const ins = await env.DB.prepare(`INSERT INTO windows (id, account_id, token_id, opened_by, reason, opened_at, expires_at)
    SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
    WHERE NOT EXISTS (SELECT 1 FROM windows WHERE account_id = ?2 AND closed_at IS NULL AND expires_at > ?6)
      AND (SELECT COUNT(*) FROM windows WHERE account_id = ?2 AND opened_at > ?6 - ${DAY}) < ?8
      AND NOT EXISTS (SELECT 1 FROM accounts WHERE id = ?2 AND frozen_at IS NOT NULL)
      AND ${Team.ROLE_OF('?4', '?2')} IN ('owner','approver')`)
    .bind(id, sess.accountId, scope ? scope.holdToken : null, sess.memberId, p.reason, t, t + p.minutes * 60_000, PER_DAY).run();
  if (!ins.meta.changes) throw new HttpError(409, 'try_again', 'The team or the account changed while you confirmed. Look again and retry.');
  await audit(env, sess.accountId, 'web', 'breakglass_opened', { id, by: sess.memberId, minutes: p.minutes, scope: scope ? scope.holdToken : 'all', reason: p.reason });
  // everyone else is told at once, with no rate limit (each took a passkey, and the daily cap bounds them), and so is every channel
  await Team.alertTeam(env, sess.accountId, sess.memberId, { channel: 'Counterseal: break glass is open. Held actions are being let through for up to ' + p.minutes + ' minutes, and every call it lets through is on the record. Review it in the app.' });
  return { id, expires_at: t + p.minutes * 60_000, scope: scope ? { token_id: scope.holdToken, label: scope.label } : null };
}

/** closing only tightens: any member, any session */
export async function close(env, sess, id) {
  const t = now();
  const r = await env.DB.prepare('UPDATE windows SET closed_at = ?3, closed_by = ?4 WHERE id = ?1 AND account_id = ?2 AND closed_at IS NULL AND expires_at > ?3').bind(id, sess.accountId, t, sess.memberId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'breakglass_closed', { id, by: sess.memberId });
  await Team.alertTeam(env, sess.accountId, sess.memberId, { channel: 'Counterseal: break glass was closed. Held actions wait for approval again.' });
  return { ok: true };
}

/** the open windows, for the team page and the banner on every page */
export async function listOpen(env, accountId, t = now()) {
  const r = await env.DB.prepare(`SELECT w.id, w.token_id, w.opened_by, w.reason, w.opened_at, w.expires_at,
      COALESCE((SELECT name FROM members WHERE id = w.opened_by AND account_id = w.account_id), (SELECT name FROM accounts WHERE id = w.opened_by)) AS opened_by_name,
      COALESCE((SELECT label FROM tokens WHERE id = w.token_id AND account_id = w.account_id), (SELECT label FROM guard_keys WHERE 'g:' || id = w.token_id AND account_id = w.account_id)) AS scope_label
    FROM windows w WHERE w.account_id = ? AND w.closed_at IS NULL AND w.expires_at > ? ORDER BY w.opened_at DESC LIMIT 1`).bind(accountId, t).all();
  return r.results.map((w) => ({ ...w, scope: w.token_id ? { token_id: w.token_id, label: w.scope_label || null } : null, token_id: undefined, scope_label: undefined }));
}

/** is a window open for this hold's token (a token's id, or g:<guard key id>)? Called only when the map would hold, so it costs
 *  a held call one read and every other call nothing. The opener must still be an owner or approver, and with self-approval
 *  off the window does not cover what the opener's own token or key asks for. */
export async function matching(env, accountId, holdToken, requestedBy, selfApprove, t = now()) {
  const w = await env.DB.prepare(`SELECT w.id, w.opened_by FROM windows w WHERE w.account_id = ?1 AND w.closed_at IS NULL AND w.expires_at > ?2 AND (w.token_id IS NULL OR w.token_id = ?3)
      AND ${Team.ROLE_OF('w.opened_by', 'w.account_id')} IN ('owner','approver') LIMIT 1`).bind(accountId, t, holdToken).first();
  if (!w) return null;
  if (!selfApprove && requestedBy && requestedBy === w.opened_by) return null;
  return w;
}
