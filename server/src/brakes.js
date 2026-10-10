// Brakes: money caps on Stripe refunds and payouts, a circuit breaker per token, and Freeze.
//
// Order of decisions on a proxied call (src/broker.js calls apply() after policy.js decides):
//   1. account frozen            -> 423 for every method, before anything else is read or written (broker.js)
//   2. policy deny, read-only    -> 403, unchanged
//   3. token tripped             -> a write that would have been allowed is held with rule brake.tripped; reads pass
//   4. money caps                -> a Stripe refund or payout the irreversible map holds may pass if it is readable, in the
//                                   token's currency, under the per-call cap, and the day's total stays under the per-day
//                                   cap (reserved with one conditional statement, so concurrent calls cannot both pass)
//   5. breaker counters          -> a write that would go upstream is counted; too many in an hour, or the same exact
//                                   request too many times in 5 minutes, trips the token and this write is held
// Anything these cannot read with certainty is held, never allowed. Everything here only ever adds holds, except the
// money caps in step 4, which loosen a hold; they are set only by a passkey ceremony (policy.js) and only ever apply to
// calls the rest of the token's policy would allow.
//
// Workers Free: a token without `limits` or `money` costs nothing extra. `limits` adds one statement and two row writes
// to a write that goes upstream; a capped refund or payout adds one Stripe lookup (a subrequest, no D1) and one statement.
import { HttpError, now, sha256hex, readCapped } from './util.js';
import { allow } from './ratelimit.js';
import { newChallenge, takeChallenge, checkAssertion, rp } from './auth.js';
import { seasoned } from './team.js';
import { audit } from './audit.js';
import { notify } from './push.js';
import { afterMap } from './policy.js';
import { moneyKind, readMoneyCall, storedMoney, storedLimits, fmtMoney, utcDay } from './money.js';
import { BRAND } from './brand.js';

const HOUR = 3600_000, FIVE_MIN = 300_000;

// ---------------------------------------------------------------- Freeze
export const frozenError = () => new HttpError(423, 'account_frozen', `This ${BRAND.name} account is frozen: every agent token and every coding-agent approval is stopped. Its owner can unfreeze it with a passkey in the app.`);

// A frozen account answers every call from its tokens with 423 and writes nothing, so a looping agent cannot burn the
// database's daily row budget. The first refused call of each token is noted in the owner's audit log, at most once per
// token every 10 minutes per isolate (the same rule as a bound token used without its key).
const blocked = new Map();
export function noteFrozenBlock(env, tok, method, host) {
  const t = now(), last = blocked.get(tok.id) || 0;
  if (t - last < 10 * 60_000) return;
  if (blocked.size > 10_000) blocked.clear();
  blocked.set(tok.id, t);
  const p = audit(env, tok.account_id, 'token:' + tok.id, 'frozen_block', { method, host }).catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p);
}
export const _resetBrakeMemory = () => blocked.clear();

/** for code that decides for an account without a proxy token (approvals and gates on other branches): true while frozen */
export async function isFrozen(env, accountId) {
  return !!(await env.DB.prepare('SELECT frozen_at FROM accounts WHERE id = ?').bind(accountId).first())?.frozen_at;
}

/** any signed-in session, the command line included: stopping is always safe, so it never needs a passkey */
export async function freeze(env, sess) {
  const t = now();
  const r = await env.DB.prepare('UPDATE accounts SET frozen_at = ? WHERE id = ? AND frozen_at IS NULL RETURNING frozen_at').bind(t, sess.accountId).first();
  if (!r) {
    const a = await env.DB.prepare('SELECT frozen_at FROM accounts WHERE id = ?').bind(sess.accountId).first();
    return { ok: true, frozen: true, frozen_at: a ? a.frozen_at : null, already: true };
  }
  // approvals nobody has used yet are void: nothing a human said yes to earlier fires after the freeze ends. On a team
  // (src/team.js) that includes the seals already on waiting holds: they are dropped, and sealing starts again after
  // the unfreeze.
  const [v, s] = await env.DB.batch([
    env.DB.prepare("UPDATE holds SET status = 'expired' WHERE account_id = ? AND status = 'approved'").bind(sess.accountId),
    env.DB.prepare('DELETE FROM hold_votes WHERE account_id = ?1 AND hold_id IN (SELECT id FROM holds WHERE account_id = ?1 AND status = \'pending\')').bind(sess.accountId),
  ]);
  await audit(env, sess.accountId, sess.kind, 'freeze', { by: sess.kind, voided_approvals: v.meta.changes, ...(s.meta.changes ? { dropped_seals: s.meta.changes } : {}), ...(sess.memberId && sess.memberId !== sess.accountId ? { member: sess.memberId } : {}) });
  // every device is woken (the push has no content; the alert then says the account is frozen). Freezing again takes a
  // passkey in between, so this is at most one alert per human decision; the minute's limit is a seatbelt.
  const p = (async () => { if (await allow(env.DB, 'pushfreeze:' + sess.accountId, 1, 60_000, now())) await notify(env, sess.accountId, env.__pushFetch || fetch); })().catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p); else await p;
  return { ok: true, frozen: true, frozen_at: t, voided_approvals: v.meta.changes };
}

/** web session and a fresh passkey ceremony: starting again is what a stolen command line session must never be able to do */
export async function unfreezeBegin(env, sess) {
  const a = await env.DB.prepare('SELECT frozen_at FROM accounts WHERE id = ?').bind(sess.accountId).first();
  if (!a || !a.frozen_at) throw new HttpError(409, 'not_frozen', 'This account is not frozen.');
  await seasoned(env, sess); // on a team: not by an approver whose seal does not count yet (src/team.js)
  const { id, challenge } = await newChallenge(env, 'unfreeze', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
export async function unfreezeFinish(env, sess, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  const ch = await takeChallenge(env, body.challengeId, 'unfreeze');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess); // the signed-in person's own passkey (on a team too)
  await seasoned(env, sess);
  const r = await env.DB.prepare('UPDATE accounts SET frozen_at = NULL WHERE id = ? AND frozen_at IS NOT NULL RETURNING id').bind(sess.accountId).first();
  if (!r) throw new HttpError(409, 'not_frozen', 'This account is not frozen.');
  await audit(env, sess.accountId, 'web', 'unfreeze', { passkey: (await sha256hex(String(body.credential.id))).slice(0, 16), ...(sess.memberId && sess.memberId !== sess.accountId ? { member: sess.memberId } : {}) });
  return { ok: true, frozen: false };
}

// ---------------------------------------------------------------- the breaker's reset (a passkey, never a CLI session)
export async function resetBegin(env, sess, tokenId) {
  const t = await env.DB.prepare('SELECT tripped_at FROM tokens WHERE id = ? AND account_id = ?').bind(tokenId, sess.accountId).first();
  if (!t) throw new HttpError(404, 'not_found');
  if (!t.tripped_at) throw new HttpError(409, 'not_tripped', 'This token has not tripped.');
  await seasoned(env, sess);
  const { id, challenge } = await newChallenge(env, 'brake_reset:' + tokenId, sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
export async function resetFinish(env, sess, tokenId, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  const ch = await takeChallenge(env, body.challengeId, 'brake_reset:' + tokenId);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess); // the signed-in person's own passkey (on a team too)
  await seasoned(env, sess);
  const r = await env.DB.prepare('UPDATE tokens SET tripped_at = NULL, tripped_why = NULL WHERE id = ? AND account_id = ? AND tripped_at IS NOT NULL RETURNING id').bind(tokenId, sess.accountId).first();
  if (!r) throw new HttpError(409, 'not_tripped', 'This token has not tripped.');
  // a fresh start: the old windows go (or the next write would trip it again at once), and the writes that waited because
  // of the trip are closed (the agent just retries)
  await env.DB.batch([
    env.DB.prepare('DELETE FROM counters WHERE k = ?1 OR (k >= ?2 AND k < ?3)').bind('w:' + tokenId, `r:${tokenId}:`, `r:${tokenId};`),
    env.DB.prepare("UPDATE holds SET status = 'expired' WHERE token_id = ? AND account_id = ? AND rule = 'brake.tripped' AND status = 'pending'").bind(tokenId, sess.accountId),
  ]);
  await audit(env, sess.accountId, 'web', 'brake_reset', { token: tokenId, passkey: (await sha256hex(String(body.credential.id))).slice(0, 16), ...(sess.memberId && sess.memberId !== sess.accountId ? { member: sess.memberId } : {}) });
  return { ok: true };
}

// ---------------------------------------------------------------- what the dashboard shows
/** what each token's money caps let through today: {token id: {currency: amount}} */
export async function spentToday(env, accountId, t = now()) {
  const rows = (await env.DB.prepare('SELECT s.token_id, s.currency, s.amount FROM spend s JOIN tokens k ON k.id = s.token_id WHERE k.account_id = ? AND s.day = ?').bind(accountId, utcDay(t)).all()).results;
  const out = {};
  for (const r of rows) (out[r.token_id] ||= {})[r.currency] = r.amount;
  return out;
}

const HEADLINE = /^(Refund|Payout) [0-9][0-9,]*(\.[0-9]+)? [A-Z]{3}$/;
const MONEY_HOLD = /^brake\.money-(per-call|per-day|currency)$/;
/** The amount of a held refund or payout, for large type. Only the holds a money cap made have it: their preview starts
 * with a line Counterseal wrote itself. On any other hold the preview starts with the agent's own text, which must never
 * be shown as a heading (a body that begins "Refund 0.01 USD" is the agent talking, not the broker). */
export function headlineOf(preview, rule) {
  if (!MONEY_HOLD.test(String(rule))) return null;
  const first = typeof preview === 'string' ? preview.split('\n', 1)[0] : '';
  return HEADLINE.test(first) ? first : null;
}

// ---------------------------------------------------------------- cleanup
/** part of the sweep (src/index.js): expired windows, and daily totals older than 35 days */
export const sweepStatements = (db, t) => [
  db.prepare('DELETE FROM counters WHERE expires_at < ?').bind(t),
  db.prepare('DELETE FROM spend WHERE day < ?').bind(utcDay(t - 35 * 86_400_000)),
];
/** part of deleting an account: its tokens' totals and windows (before the tokens go) */
export const deleteStatements = (db, accountId) => [
  db.prepare('DELETE FROM spend WHERE token_id IN (SELECT id FROM tokens WHERE account_id = ?)').bind(accountId),
  db.prepare('DELETE FROM counters WHERE substr(k, 3, 24) IN (SELECT id FROM tokens WHERE account_id = ?)').bind(accountId),
];

// ---------------------------------------------------------------- the decision
const TRIP_WHY = {
  writes_per_hour: 'This token made more writes in an hour than its limit allows',
  repeat: 'This token sent the same request more times in 5 minutes than its limit allows',
};
/** the hold for a write while the breaker is tripped */
const trippedHold = (reason) => ({
  decision: 'hold', rule: 'brake.tripped',
  why: `${TRIP_WHY[reason] || 'This token went past a limit'}, so its breaker tripped. Its writes wait until you reset it with your passkey; reads still pass.`,
});

/**
 * Brakes for one proxied call that policy.js has not denied. x: {d, tok, policy, provider, method, canon, bodyText,
 * search, contentType, reqHash, P, fetcher, secretOf}. Returns {d, lines, reserved, money, tripped}:
 *   d        the decision to act on (allow or hold; never looser than the map unless a money cap let it through)
 *   lines    lead lines for the hold's preview (what the approver reads first)
 *   reserved what a money cap reserved for this call, to hand back if it fails (release())
 *   money    {kind, amount, currency, target} of a call a cap let through, for the owner's audit entry
 *   tripped  true when this very call tripped the breaker (the one call that wakes the owner's devices)
 */
export async function apply(env, x) {
  const { tok, policy, provider, method, canon } = x;
  const st = { d: x.d, lines: [], reserved: null, money: null, tripped: false };
  if (method === 'GET' || method === 'HEAD') return st; // brakes are for writes
  if (tok.tripped_at) {
    if (st.d.decision === 'allow') st.d = trippedHold(tok.tripped_why);
    return st; // a hold stays the hold it was; nothing is reserved or counted while tripped
  }

  // ---- money caps
  const kind = moneyKind(provider, method, canon);
  const cfg = kind ? storedMoney(policy) : null;
  const viaMap = st.d.decision === 'hold' && st.d.rule === 'st.money';
  const viaPre = st.d.decision === 'allow' && st.d.rule === 'st.money:preapproved';
  if (kind && cfg !== null && (viaMap || viaPre)) {
    if (cfg === undefined) { // stored caps that do not parse: fail closed
      if (viaPre) st.d = { decision: 'hold', rule: 'brake.money-unreadable', why: `This token's money caps could not be read, so the ${kind} waits for you.` };
    // a cap only ever turns a map hold into an allow when the rest of the token's own policy (hold rules, allow list,
    // default) already allows the call; a preapproved call is already allowed and the cap can only hold it
    } else if (!viaMap || afterMap(policy, provider, method, canon).decision === 'allow') {
      await moneyStep(env, x, cfg, kind, st);
    }
  }

  // ---- the breaker
  const limits = storedLimits(policy);
  if (limits && st.d.decision === 'allow') {
    let hit;
    try { hit = await countWrite(env, tok, limits, x.reqHash, now()); } catch (e) { await release(env, st.reserved).catch(() => {}); throw e; }
    if (hit) {
      await release(env, st.reserved);
      st.reserved = null; st.money = null; st.lines = [];
      st.tripped = await trip(env, tok, hit);
      st.d = trippedHold(hit.why);
    }
  }
  return st;
}

// ---- money
async function moneyStep(env, x, cfg, kind, st) {
  const { tok } = x;
  const NAME = kind === 'refund' ? 'Refund' : 'Payout';
  const hold = (rule, text, lines = []) => { st.d = { decision: 'hold', rule, why: text }; st.lines = lines; };
  const call = readMoneyCall(kind, x.contentType, x.bodyText, x.search);
  if (!call.ok) return hold('brake.money-unreadable', `${BRAND.name} could not read this ${kind} with certainty (${call.why}), so it waits for you.`, [`${NAME}: amount not read`, `Not read: ${call.why}.`]);

  let currency, amount = call.amount, target = null, refundable = null;
  if (kind === 'payout') currency = call.currency;
  else {
    target = call.target;
    const info = await lookup(x, target);
    if (!info) return hold('brake.money-unreadable', `${BRAND.name} could not look up that ${target.type.replace('_', ' ')} at Stripe, so the ${kind} waits for you.`, [`${NAME}: amount not read`, `Stripe did not return ${target.type.replace('_', ' ')} ${target.id} in a form that can be trusted.`]);
    currency = info.currency; refundable = info;
    amount ??= info.refundable; // no amount: Stripe refunds everything that is left
  }
  const head = `${NAME} ${fmtMoney(amount, currency)}`;
  const scope = kind === 'refund' && (call.amount === undefined ? 'everything left' : amount >= refundable.refundable ? 'all of it' : 'part of it');
  const what = kind === 'refund'
    ? `Stripe refund of ${target.type.replace('_', ' ')} ${target.id}: ${scope}; ${fmtMoney(refundable.refundable, currency)} ${refundable.exact ? 'refundable' : 'received'}.`
    : `Stripe payout in ${currency.toUpperCase()}.`;
  if (!(amount >= 1)) return hold('brake.money-unreadable', `There is nothing left to ${kind}, so Stripe would refuse it; it waits for you.`, [head, what]);
  if (currency !== cfg.currency) return hold('brake.money-currency', `This ${kind} is in ${currency.toUpperCase()} and this token's caps are in ${cfg.currency.toUpperCase()}, so it waits for you.`, [head, what, `Currency ${currency.toUpperCase()}, caps in ${cfg.currency.toUpperCase()}.`]);
  if (amount > cfg.perCall) return hold('brake.money-per-call', `${NAME} of ${fmtMoney(amount, currency)} is over this token's cap of ${fmtMoney(cfg.perCall, currency)} a call.`, [head, what, `Over the per-call cap of ${fmtMoney(cfg.perCall, currency)}.`]);

  const day = utcDay(now());
  const total = await reserve(env.DB, tok.id, day, currency, amount, cfg.perDay);
  if (total === null) {
    const so = (await env.DB.prepare('SELECT amount FROM spend WHERE token_id = ? AND day = ? AND currency = ?').bind(tok.id, day, currency).first())?.amount || 0;
    return hold('brake.money-per-day', `${NAME} of ${fmtMoney(amount, currency)} would take today's total to ${fmtMoney(so + amount, currency)}, over this token's cap of ${fmtMoney(cfg.perDay, currency)} a day (UTC).`,
      [head, what, `Today (UTC): ${fmtMoney(so, currency)} already let through + ${fmtMoney(amount, currency)} = ${fmtMoney(so + amount, currency)}, over the daily cap of ${fmtMoney(cfg.perDay, currency)}.`]);
  }
  st.reserved = { tokenId: tok.id, day, currency, amount };
  st.money = { kind, amount, currency, ...(target ? { [target.type]: target.id } : {}) };
  st.d = { decision: 'allow', rule: 'st.money:capped', why: '' };
}

/** the one conditional statement: add to today's total only if it stays within the cap, in a single atomic step, so
 * concurrent calls cannot both pass. Returns the new total, or null when it would not fit (nothing is written). */
export async function reserve(db, tokenId, day, currency, amount, max) {
  const r = await db.prepare(`INSERT INTO spend (token_id, day, currency, amount) SELECT ?1, ?2, ?3, ?4 WHERE ?4 <= ?5
    ON CONFLICT (token_id, day, currency) DO UPDATE SET amount = amount + ?4 WHERE amount + ?4 <= ?5 RETURNING amount`).bind(tokenId, day, currency, amount, max).first();
  return r ? r.amount : null;
}
/** hand a reservation back (the call did not happen) */
export async function release(env, r) {
  if (!r) return;
  await env.DB.prepare('UPDATE spend SET amount = MAX(0, amount - ?) WHERE token_id = ? AND day = ? AND currency = ?').bind(r.amount, r.tokenId, r.day, r.currency).run();
}
/** After the upstream answered: a definite refusal (4xx and the like) gives the reservation back; a 2xx keeps it, and so
 * does a 5xx or a call that never got an answer, because Stripe may have done it (the cap stays on the safe side). */
export const definitelyNotDone = (status) => status < 500 && !(status >= 200 && status < 300);

/** what Stripe says about the charge or payment intent a refund names: its currency, and what can still be refunded.
 * A charge: what was captured (or the amount, if not captured) less what was refunded. A payment intent has no refunded
 * total, so what it received is an upper bound. Anything else (a failed call, another id, a field that is not a whole
 * number) is null, and the refund is held. */
async function lookup(x, target) {
  try {
    const { P, fetcher } = x;
    const h = new Headers(P.auth(await x.secretOf()));
    h.set('accept', 'application/json'); h.set('user-agent', 'leash-proxy');
    const res = await fetcher(`https://${P.host}${P.base}/v1/${target.type === 'charge' ? 'charges' : 'payment_intents'}/${target.id}`, { method: 'GET', headers: h, redirect: 'manual', signal: AbortSignal.timeout(4000) });
    if (res.status !== 200) return null;
    const o = JSON.parse(new TextDecoder().decode(await readCapped(res.body, 262144)));
    const whole = (v) => Number.isSafeInteger(v) && v >= 0;
    if (!o || typeof o !== 'object' || o.id !== target.id || typeof o.currency !== 'string' || !/^[a-z]{3}$/.test(o.currency)) return null;
    if (target.type === 'charge') {
      const base = o.captured === true ? o.amount_captured : o.amount;
      if (o.object !== 'charge' || !whole(base) || !whole(o.amount_refunded)) return null;
      return { currency: o.currency, refundable: Math.max(0, base - o.amount_refunded), exact: true };
    }
    if (o.object !== 'payment_intent' || !whole(o.amount_received)) return null;
    return { currency: o.currency, refundable: o.amount_received, exact: false };
  } catch { return null; }
}

// ---- the breaker
/**
 * Count one write that would go upstream: the token's writes in its current hour, and this exact request in its current
 * 5 minutes, in one statement (a window starts at the first write and its row is reused once it has expired). Returns
 * {why, n, max} if a limit is exceeded (the call that makes it n > max is the first held), else null. Only the counts of
 * the limits the token set are kept: a token without limits costs nothing.
 */
export async function countWrite(env, tok, limits, reqHash, t) {
  const rows = [];
  if (limits.writesPerHour) rows.push([`w:${tok.id}`, HOUR, 'writes_per_hour', limits.writesPerHour]);
  if (limits.repeatsPer5Min) rows.push([`r:${tok.id}:${reqHash.slice(0, 12)}`, FIVE_MIN, 'repeat', limits.repeatsPer5Min]);
  if (!rows.length) return null;
  const args = rows.flatMap(([k, ms]) => [k, t + ms]);
  const cur = `?${args.length + 1}`;
  const got = await env.DB.prepare(`INSERT INTO counters (k, n, expires_at) VALUES ${rows.map((_, i) => `(?${2 * i + 1}, 1, ?${2 * i + 2})`).join(', ')}
    ON CONFLICT (k) DO UPDATE SET n = CASE WHEN counters.expires_at <= ${cur} THEN 1 ELSE counters.n + 1 END,
      expires_at = CASE WHEN counters.expires_at <= ${cur} THEN excluded.expires_at ELSE counters.expires_at END RETURNING k, n`).bind(...args, t).all();
  const n = Object.fromEntries(got.results.map((r) => [r.k, r.n]));
  for (const [k, , reason, max] of [...rows].reverse()) if (n[k] > max) return { why: reason, n: n[k], max }; // a repeat is the sharper finding
  return null;
}

/** trip the token. True only for the one call that did it (a concurrent call finds it already tripped), so the owner is
 * told once. */
async function trip(env, tok, hit) {
  const r = await env.DB.prepare('UPDATE tokens SET tripped_at = ?, tripped_why = ? WHERE id = ? AND account_id = ? AND tripped_at IS NULL RETURNING id').bind(now(), hit.why, tok.id, tok.account_id).first();
  if (!r) return false;
  await audit(env, tok.account_id, 'token:' + tok.id, 'brake_tripped', { token: tok.id, why: hit.why, count: hit.n, limit: hit.max });
  return true;
}
