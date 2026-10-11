// Budget seal: hard spend caps on the AI model calls that go through Counterseal (the state; src/metered.js is the pure
// half: providers, prices, reading usage).
//
// What it caps: spend that flows through Counterseal's proxy to a metered provider, per agent (one token), per key (one
// vaulted credential) and per account, for the UTC day and the UTC month. What it cannot cap: anything that does not go
// through Counterseal (another key, the provider's console, a cloud bill). See docs/BUDGET_SEAL.md.
//
// One call, in order (src/broker.js calls before() once the map, the brakes and break-glass have allowed it):
//   1. a write that is free at the provider (count tokens, files, deletes the map already holds) passes, unmetered;
//   2. a write the meter cannot price (an unknown model, an image, a batch) counts against the token's unpriced calls for
//      the day; past them it is held (rule budget.unpriced) until a passkey approves that exact request;
//   3. the runaway detector: more calls, or more estimated spend, in a few minutes than the account allows trips the
//      token's breaker (src/brakes.js), and every write of it waits for a passkey reset;
//   4. the reservation: the call's estimate is added to all six totals it touches (agent, key, account; day, month) in
//      ONE statement. A CHECK on the table makes the statement fail as a whole if any total would pass its cap, so two
//      calls near a cap cannot both pass (SQLite runs one statement at a time; D1 is one SQLite database);
//   5. at a cap: 402 budget_exhausted with what is left and when it resets, and nothing is sent. In "ask me" mode the
//      call is held instead (rule budget.cap): a passkey approval raises that period's cap once, by one cap;
//   6. "ask me" mode at 80%: the first call past 80% of a cap is held (rule budget.ask); approving it lets the period
//      run on to the cap;
//   7. after the answer: the real cost (usage times the price table) replaces the estimate (settle()). A refusal (4xx)
//      gives the reservation back; an answer whose usage cannot be read keeps the estimate (the safe side).
// The owner's devices are woken at 50%, 80% and 100% of a cap (an empty push, as for holds; the app shows the numbers).
//
// Workers Free: a call to a metered provider costs one read of the budgets, one reservation and one settlement (3 D1
// queries), plus one statement when the runaway detector is on. No cron: old totals go in the sweep (src/index.js).
import { HttpError, now, sha256hex } from './util.js';
import { allow } from './ratelimit.js';
import { newChallenge, takeChallenge, checkAssertion, rp } from './auth.js';
import { seasoned } from './team.js';
import { audit } from './audit.js';
import { notify } from './push.js';
import { utcDay } from './money.js';
import { trip, trippedHold } from './brakes.js';
import { jsonView } from './providers.js';
import { meterKind, readRequest, readUsage, costOf, priceOf, PRICES, PRICES_DATE, PRICE_SOURCES, UNPRICED_DEFAULT } from './metered.js';
import { BRAND } from './brand.js';

export const MICRO = 1_000_000;
/** the cap stored for a total that has none: larger than any real spend, small enough to stay an exact integer */
export const NO_CAP = 1e15;
/** the largest cap that can be set: 1,000,000 USD */
export const MAX_CAP_CENTS = 100_000_000;
const ID = /^[0-9a-f]{24}$/;
const THRESHOLDS = [50, 80, 100];

// ---------------------------------------------------------------- periods (UTC)
export const periodsOf = (t) => { const d = utcDay(t); return { day: 'd:' + d, month: 'm:' + d.slice(0, 7) }; };
/** when a day or month total starts again from zero: the next UTC midnight, the first of the next UTC month */
export function resetsOf(t) {
  const d = new Date(t);
  return { day: Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1), month: Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) };
}
const usd = (micros) => '$' + (Math.max(0, micros) / MICRO).toFixed(2);
/** the key a total is kept under: the account's own scope names the account, so totals of two accounts never meet */
const spendKey = (accountId, scope) => (scope === 'account' ? 'acct:' + accountId : scope);

// ---------------------------------------------------------------- settings (a passkey ceremony, always)
const whole = (v, lo, hi, name) => {
  if (v === null || v === undefined) return null;
  if (!Number.isSafeInteger(v) || v < lo || v > hi) throw new HttpError(400, 'bad_budget', `${name} must be a whole number from ${lo} to ${hi}, or null.`);
  return v;
};
const FIELDS = ['scope', 'dailyCents', 'monthlyCents', 'ask', 'runaway', 'unpricedPerDay'];
/** the settings a passkey approves, validated strictly: unknown fields, wrong types and out-of-range values are refused,
 * never defaulted (a typo must not silently leave an agent without its cap) */
export function normaliseSettings(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new HttpError(400, 'bad_budget', 'Send the budget as an object.');
  const bad = Object.keys(b).find((k) => !FIELDS.includes(k) && !['challengeId', 'credential'].includes(k));
  if (bad !== undefined) throw new HttpError(400, 'bad_budget', `A budget has no field "${String(bad).slice(0, 40)}". Fields: ${FIELDS.join(', ')}.`);
  const scope = b.scope;
  if (typeof scope !== 'string' || !(scope === 'account' || /^(cred|tok):[0-9a-f]{24}$/.test(scope))) throw new HttpError(400, 'bad_budget', 'scope is "account", "cred:<key id>" or "tok:<token id>".');
  const s = {
    scope,
    daily: whole(b.dailyCents, 1, MAX_CAP_CENTS, 'dailyCents'),
    monthly: whole(b.monthlyCents, 1, MAX_CAP_CENTS, 'monthlyCents'),
    ask: b.ask === undefined ? false : b.ask,
    runaway: null,
    unpricedPerDay: null,
  };
  if (typeof s.ask !== 'boolean') throw new HttpError(400, 'bad_budget', 'ask is true or false.');
  if (s.daily && s.monthly && s.monthly < s.daily) throw new HttpError(400, 'bad_budget', 'monthlyCents must be at least dailyCents.');
  if (s.ask && !s.daily && !s.monthly) throw new HttpError(400, 'bad_budget', '"Ask me" mode needs a daily or monthly cap to ask about.');
  if (b.runaway !== undefined && b.runaway !== null) {
    if (scope !== 'account') throw new HttpError(400, 'bad_budget', 'The runaway detector is set for the whole account (scope "account").');
    const r = b.runaway;
    if (!r || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).some((k) => !['calls', 'cents', 'minutes'].includes(k))) throw new HttpError(400, 'bad_budget', 'runaway is {calls, cents, minutes}.');
    s.runaway = { calls: whole(r.calls, 1, 100_000, 'runaway.calls'), cents: whole(r.cents, 1, MAX_CAP_CENTS, 'runaway.cents'), minutes: whole(r.minutes, 1, 60, 'runaway.minutes') };
    if (!s.runaway.minutes || (!s.runaway.calls && !s.runaway.cents)) throw new HttpError(400, 'bad_budget', 'runaway needs minutes and at least one of calls or cents.');
  }
  if (b.unpricedPerDay !== undefined && b.unpricedPerDay !== null) {
    if (scope !== 'account') throw new HttpError(400, 'bad_budget', 'unpricedPerDay is set for the whole account (scope "account").');
    s.unpricedPerDay = whole(b.unpricedPerDay, 0, 1000, 'unpricedPerDay');
  }
  return s;
}
/** the challenge names the exact settings, so the passkey approves those and nothing else */
const kindOf = async (accountId, s) => 'budget:' + (await sha256hex(JSON.stringify([accountId, s]))).slice(0, 40);

async function checkScope(env, accountId, scope) {
  if (scope === 'account') return;
  const [k, id] = scope.split(':');
  const row = await env.DB.prepare(`SELECT id FROM ${k === 'cred' ? 'credentials' : 'tokens'} WHERE id = ? AND account_id = ?`).bind(id, accountId).first();
  if (!row) throw new HttpError(404, 'not_found', `No ${k === 'cred' ? 'key' : 'token'} with that id in this account.`);
}

export async function setBegin(env, sess, body) {
  const s = normaliseSettings(body);
  await checkScope(env, sess.accountId, s.scope);
  await seasoned(env, sess); // on a team: not by an approver whose seal does not count yet
  const { id, challenge } = await newChallenge(env, await kindOf(sess.accountId, s), sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
/** raising, lowering or removing a cap all take a passkey: a stolen command line session can neither lift a cap nor
 * quietly change what the owner sees */
export async function setFinish(env, sess, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  const s = normaliseSettings(body);
  const ch = await takeChallenge(env, body.challengeId, await kindOf(sess.accountId, s));
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  await seasoned(env, sess);
  await checkScope(env, sess.accountId, s.scope);
  const t = now();
  const empty = !s.daily && !s.monthly && !s.runaway && s.unpricedPerDay === null;
  if (empty) await env.DB.prepare('DELETE FROM budgets WHERE account_id = ? AND scope = ?').bind(sess.accountId, s.scope).run();
  else {
    await env.DB.prepare(`INSERT INTO budgets (account_id, scope, daily, monthly, ask, runaway_calls, runaway_micros, runaway_minutes, unpriced_per_day, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
      ON CONFLICT (account_id, scope) DO UPDATE SET daily = ?3, monthly = ?4, ask = ?5, runaway_calls = ?6, runaway_micros = ?7, runaway_minutes = ?8, unpriced_per_day = ?9, updated_at = ?10`)
      .bind(sess.accountId, s.scope, s.daily && s.daily * 10_000, s.monthly && s.monthly * 10_000, s.ask ? 1 : 0, s.runaway?.calls ?? null, s.runaway?.cents ? s.runaway.cents * 10_000 : null, s.runaway?.minutes ?? null, s.unpricedPerDay, t).run();
  }
  await audit(env, sess.accountId, 'web', 'budget_set', {
    scope: s.scope, daily_cents: s.daily, monthly_cents: s.monthly, ask: s.ask, ...(s.runaway ? { runaway: s.runaway } : {}), ...(s.unpricedPerDay !== null ? { unpriced_per_day: s.unpricedPerDay } : {}),
    passkey: (await sha256hex(String(body.credential.id))).slice(0, 16), ...(sess.memberId && sess.memberId !== sess.accountId ? { member: sess.memberId } : {}),
  });
  return { ok: true, budget: s, removed: empty };
}

// ---------------------------------------------------------------- the live view
/** every budget and every total of this UTC day and month, with what is left and when it resets */
export async function view(env, sess, t = now()) {
  const { day, month } = periodsOf(t);
  const rows = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).all()).results;
  const budgets = await rows('SELECT scope, daily, monthly, ask, runaway_calls, runaway_micros, runaway_minutes, unpriced_per_day FROM budgets WHERE account_id = ?', sess.accountId);
  const spend = await rows('SELECT scope, period, amount, over, extra, asked FROM budget_spend WHERE account_id = ? AND period IN (?, ?)', sess.accountId, day, month);
  const tokens = await rows("SELECT t.id, t.label, c.provider FROM tokens t JOIN credentials c ON c.id = t.credential_id WHERE t.account_id = ? AND c.provider IN ('openai', 'anthropic') AND t.revoked = 0 AND t.expires_at > ? ORDER BY t.created_at DESC LIMIT 200", sess.accountId, t);
  const keys = await rows("SELECT id, label, provider FROM credentials WHERE account_id = ? AND provider IN ('openai', 'anthropic') ORDER BY created_at DESC", sess.accountId);
  const bud = Object.fromEntries(budgets.map((r) => [r.scope, r]));
  const tot = (scope, period) => spend.find((r) => r.scope === spendKey(sess.accountId, scope) && r.period === period);
  const resets = resetsOf(t);
  const one = (scope, label, provider) => {
    const r = bud[scope] || {};
    const per = (period, cap, resetAt) => {
      const x = tot(scope, period);
      const spent = x ? x.amount + x.over : 0, extra = x ? x.extra : 0;
      return { spent, cap: cap ?? null, extra, remaining: cap ? Math.max(0, cap + extra - spent) : null, pct: cap ? Math.min(999, Math.floor((spent * 100) / cap)) : null, resetsAt: resetAt, asked: !!x?.asked };
    };
    return { scope, label, ...(provider ? { provider } : {}), ask: !!r.ask, day: per(day, r.daily, resets.day), month: per(month, r.monthly, resets.month) };
  };
  const acct = bud.account || {};
  return {
    unit: 'micro USD (1 USD = 1,000,000)',
    prices: { date: PRICES_DATE, sources: PRICE_SOURCES, models: Object.fromEntries(Object.entries(PRICES).map(([p, t]) => [p, Object.keys(t)])) },
    runaway: acct.runaway_minutes ? { calls: acct.runaway_calls, micros: acct.runaway_micros, minutes: acct.runaway_minutes } : null,
    unpricedPerDay: acct.unpriced_per_day ?? UNPRICED_DEFAULT,
    scopes: [one('account', 'Whole account'), ...keys.map((k) => one('cred:' + k.id, k.label, k.provider)), ...tokens.map((k) => one('tok:' + k.id, k.label, k.provider))],
  };
}

/** for the phone after an empty push: the totals at or past 50% of a cap right now */
export async function alertsOf(env, accountId, t = now()) {
  const { day, month } = periodsOf(t);
  const r = (await env.DB.prepare(`SELECT s.scope, s.period, s.amount + s.over AS spent, CASE WHEN s.period LIKE 'd:%' THEN b.daily ELSE b.monthly END AS cap
    FROM budget_spend s JOIN budgets b ON b.account_id = s.account_id AND (b.scope = s.scope OR (b.scope = 'account' AND s.scope = 'acct:' || s.account_id))
    WHERE s.account_id = ? AND s.period IN (?, ?)`).bind(accountId, day, month).all()).results;
  return r.filter((x) => x.cap && x.spent * 2 >= x.cap).map((x) => ({ scope: x.scope.startsWith('acct:') ? 'account' : x.scope, period: x.period.startsWith('d:') ? 'day' : 'month', spent: x.spent, cap: x.cap, pct: Math.floor((x.spent * 100) / x.cap) }));
}

// ---------------------------------------------------------------- the decision for one call
const memo = new Map(); // the first refused call of each token, noted in the owner's log at most every 10 minutes
export const _resetBudgetMemory = () => memo.clear();
function noteBlock(env, tok, detail) {
  const t = now(), last = memo.get(tok.id) || 0;
  if (t - last < 10 * 60_000) return;
  if (memo.size > 10_000) memo.clear();
  memo.set(tok.id, t);
  const p = audit(env, tok.account_id, 'token:' + tok.id, 'budget_block', detail).catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p);
}

const hold = (rule, why, ctx) => ({ d: { decision: 'hold', rule, why }, ctx });

/**
 * The Budget seal for one call the rest of the broker has allowed. x: {tok, provider, method, canon, bodyText}.
 * opts.approved: this exact request was approved by a passkey after a hold (it is still metered and still stops at a
 * hard cap, but is not asked about again). Returns null (no meter), or {d?, ctx?, meter?}:
 *   d     a hold to make instead of forwarding (with ctx, the budget it is about, kept on the hold for the approval)
 *   meter what was reserved, for settle() or release() after the answer
 * Throws 402 at a hard cap.
 */
export async function before(env, x, opts = {}) {
  const { tok, provider, method, canon } = x;
  const kind = meterKind(provider, method, canon);
  if (!kind || kind === 'free') return null;
  const t = now();
  const { day, month } = periodsOf(t);
  const scopes = ['tok:' + tok.id, 'cred:' + tok.credential_id, 'account'];
  const conf = (await env.DB.prepare('SELECT scope, daily, monthly, ask, runaway_calls, runaway_micros, runaway_minutes, unpriced_per_day FROM budgets WHERE account_id = ? AND scope IN (?, ?, ?)')
    .bind(tok.account_id, ...scopes).all()).results;
  const by = Object.fromEntries(conf.map((r) => [r.scope, r]));
  const acct = by.account || {};

  const req = kind === 'metered' ? readRequest(provider, x.bodyText, jsonView) : { model: null, price: null };
  if (!req.price) {
    // unpriced: never guessed. A few a day per token; past that, each one waits for a passkey
    const allowance = acct.unpriced_per_day ?? UNPRICED_DEFAULT;
    const n = (await env.DB.prepare(`INSERT INTO counters (k, n, expires_at) VALUES (?1, 1, ?2) ON CONFLICT (k) DO UPDATE SET
      n = CASE WHEN counters.expires_at <= ?3 THEN 1 ELSE counters.n + 1 END, expires_at = CASE WHEN counters.expires_at <= ?3 THEN ?2 ELSE counters.expires_at END RETURNING n`)
      .bind(`p:${tok.id}:u`, resetsOf(t).day, t).first()).n;
    if (n > allowance && !opts.approved) {
      const what = kind === 'unpriced' ? `this ${provider === 'openai' ? 'OpenAI' : 'Anthropic'} call is not one the meter can price` : req.model ? `the model "${String(req.model).slice(0, 60)}" is not in the price table (${PRICES_DATE})` : 'the request does not name a model the meter can read';
      return hold('budget.unpriced', `${BRAND.name} cannot price this call: ${what}. This token has used its ${allowance} unpriced calls for today (UTC), so it waits for you.`, null);
    }
    return { meter: null };
  }

  // the runaway detector (the account's setting, per token): calls and estimated spend in a short window
  if (acct.runaway_minutes && (acct.runaway_calls || acct.runaway_micros)) {
    const win = acct.runaway_minutes * 60_000;
    const got = (await env.DB.prepare(`INSERT INTO counters (k, n, expires_at) VALUES (?1, 1, ?3), (?2, ?4, ?3) ON CONFLICT (k) DO UPDATE SET
      n = CASE WHEN counters.expires_at <= ?5 THEN excluded.n ELSE counters.n + excluded.n END,
      expires_at = CASE WHEN counters.expires_at <= ?5 THEN excluded.expires_at ELSE counters.expires_at END RETURNING k, n`)
      .bind(`b:${tok.id}:n`, `b:${tok.id}:u`, t + win, req.estimate, t).all()).results;
    const n = Object.fromEntries(got.map((r) => [r.k.slice(-1), r.n]));
    const hit = acct.runaway_calls && n.n > acct.runaway_calls ? { n: n.n, max: acct.runaway_calls } : acct.runaway_micros && n.u > acct.runaway_micros ? { n: n.u, max: acct.runaway_micros } : null;
    if (hit) {
      const tripped = await trip(env, tok, { why: 'runaway', ...hit });
      return { d: trippedHold('runaway'), ctx: null, tripped };
    }
  }

  // the reservation: all six totals in one statement, or none
  const caps = (scope) => ({ d: by[scope]?.daily || NO_CAP, m: by[scope]?.monthly || NO_CAP });
  const rows = scopes.flatMap((s) => [[spendKey(tok.account_id, s), day, caps(s).d, s, 'day'], [spendKey(tok.account_id, s), month, caps(s).m, s, 'month']]);
  let got;
  try {
    got = (await env.DB.prepare(`INSERT INTO budget_spend (account_id, scope, period, amount, cap) VALUES ${rows.map((_, i) => `(?1, ?${3 * i + 3}, ?${3 * i + 4}, ?2, ?${3 * i + 5})`).join(', ')}
      ON CONFLICT (scope, period) DO UPDATE SET amount = budget_spend.amount + excluded.amount, cap = excluded.cap RETURNING scope, period, amount, over, cap, extra, asked`)
      .bind(tok.account_id, req.estimate, ...rows.flatMap(([k, p, c]) => [k, p, c])).all()).results;
  } catch (e) {
    if (!/CHECK|constraint/i.test(String(e?.message || e))) throw e; // anything else: fail closed (the call is not sent)
    return atCap(env, x, rows, by, req, t, opts);
  }
  const meter = { accountId: tok.account_id, keys: rows.map((r) => r[0]).filter((k, i, a) => a.indexOf(k) === i), periods: [day, month], estimate: req.estimate, price: req.price, model: req.model, provider };

  // "ask me" at 80%: the first call past it this period waits for a passkey
  if (!opts.approved) {
    for (const [key, period, , scope, which] of rows) {
      const b = by[scope], cap = b && (which === 'day' ? b.daily : b.monthly);
      const r = got.find((g) => g.scope === key && g.period === period);
      if (b?.ask && cap && r && !r.asked && r.amount + r.over > cap * 0.8) {
        await release(env, meter);
        return hold('budget.ask', `This call would take ${label(scope)} to ${usd(r.amount + r.over)} of its ${usd(cap)} ${which === 'day' ? 'daily (UTC)' : 'monthly (UTC)'} budget, past 80%. Approve to let it run on to the cap.`, { scope, period });
      }
    }
  }
  crossings(env, tok.account_id, rows, by, got, req.estimate);
  return { meter };
}

const label = (scope) => (scope === 'account' ? 'the account' : scope.startsWith('cred:') ? 'this key' : 'this agent');

/** the reservation did not fit: find which total is full, and answer 402 (or, in "ask me" mode, hold) */
async function atCap(env, x, rows, by, req, t, opts) {
  const { tok } = x;
  const cur = (await env.DB.prepare(`SELECT scope, period, amount, over, extra FROM budget_spend WHERE scope IN (${rows.map(() => '?').join(', ')}) AND period IN (?, ?)`)
    .bind(...rows.map((r) => r[0]), rows[0][1], rows[1][1]).all()).results;
  const resets = resetsOf(t);
  for (const [key, period, , scope, which] of rows) {
    const b = by[scope], cap = b && (which === 'day' ? b.daily : b.monthly);
    if (!cap) continue;
    const r = cur.find((c) => c.scope === key && c.period === period) || { amount: 0, over: 0, extra: 0 };
    if (r.amount + req.estimate <= cap + r.extra) continue;
    const spent = r.amount + r.over, left = Math.max(0, cap + r.extra - spent);
    const detail = { scope, period: which, cap, extra: r.extra, spent, remaining: left, estimate: req.estimate, resets_at: which === 'day' ? resets.day : resets.month };
    if (b.ask && !opts.approved) return hold('budget.cap', `${label(scope)[0].toUpperCase() + label(scope).slice(1)} has ${usd(left)} left of its ${usd(cap + r.extra)} ${which === 'day' ? 'daily (UTC)' : 'monthly (UTC)'} budget and this call may cost up to ${usd(req.estimate)}. Approve to raise the cap once, to ${usd(cap * 2 + r.extra)}, for this ${which}.`, { scope, period });
    noteBlock(env, tok, { scope, period: which, cap, spent });
    throw new HttpError(402, 'budget_exhausted', `${BRAND.name} stopped this call before it was sent: ${label(scope)} has ${usd(left)} left of its ${usd(cap + r.extra)} ${which === 'day' ? 'daily' : 'monthly'} budget (UTC), and this call may cost up to ${usd(req.estimate)}. It starts again at ${new Date(detail.resets_at).toISOString()}. Stop and tell your human; only they can raise the budget, with a passkey.`, { budget: detail });
  }
  // nothing is full now (a concurrent call gave its reservation back in between): the caller may simply retry
  throw new HttpError(409, 'budget_busy', 'The budget changed while this call was checked. Retry it once.');
}

/** give a reservation back (the call was not sent, or the provider refused it) */
export async function release(env, m) {
  if (!m) return;
  await adjust(env, m, -m.estimate);
}
/** add delta (micro dollars) to every total of a reservation, in one statement. Up: the true total goes on past the cap
 * if the real cost was higher than the estimate (kept in `over`: the call was already let through). Down: never below 0.
 * Returns the rows. */
async function adjust(env, m, delta) {
  if (!delta) return [];
  return (await env.DB.prepare(`UPDATE budget_spend SET
      over = over + MAX(0, amount + ?1 - cap - extra),
      amount = MAX(0, MIN(amount + ?1, cap + extra))
    WHERE scope IN (${m.keys.map((_, i) => `?${i + 4}`).join(', ')}) AND period IN (?2, ?3) RETURNING scope, period, amount, over, cap, extra`)
    .bind(delta, m.periods[0], m.periods[1], ...m.keys).all()).results;
}

/** After the answer came back (2xx): read the usage and replace the estimate with the real cost. Text: the answer's
 * body. When the usage cannot be read, the estimate stays (it is the dear side). */
export async function settle(env, m, contentType, text) {
  if (!m) return null;
  const u = readUsage(m.provider, contentType, text);
  if (!u) return { cost: m.estimate, read: false };
  // the provider says which model it ran: if that one is priced and dearer, it is the one charged
  const said = priceOf(m.provider, u.model);
  const cost = Math.max(costOf(m.price, u.usage), said ? costOf(said, u.usage) : 0);
  const got = await adjust(env, m, cost - m.estimate);
  if (cost > m.estimate && got.length) {
    const by = Object.fromEntries((await env.DB.prepare('SELECT scope, daily, monthly FROM budgets WHERE account_id = ?').bind(m.accountId).all()).results.map((r) => [r.scope, r]));
    const rows = got.map((r) => [r.scope, r.period, 0, r.scope.startsWith('acct:') ? 'account' : r.scope, r.period.startsWith('d:') ? 'day' : 'month']);
    crossings(env, m.accountId, rows, by, got, cost - m.estimate);
  }
  return { cost, read: true };
}

/** 50%, 80% and 100% of a cap: wake the owner's devices (an empty push; the app shows the numbers), at most once a
 * minute per account. Each crossing is seen by exactly one call: the one whose single statement moved the total past it. */
function crossings(env, accountId, rows, by, got, added) {
  const hits = [];
  for (const [key, period, , scope, which] of rows) {
    const b = by[scope], cap = b && (which === 'day' ? b.daily : b.monthly);
    const r = got.find((g) => g.scope === key && g.period === period);
    if (!cap || !r) continue;
    const after = r.amount + r.over, before = after - added;
    const pct = THRESHOLDS.filter((p) => before * 100 < cap * p && after * 100 >= cap * p).pop();
    if (pct) hits.push({ scope, period: which, pct });
  }
  if (!hits.length) return;
  const p = (async () => {
    await audit(env, accountId, 'broker', 'budget_alert', { alerts: hits });
    if (await allow(env.DB, 'pushbudget:' + accountId, 1, 60_000, now())) await notify(env, accountId, env.__pushFetch || fetch);
  })().catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p);
}

// ---------------------------------------------------------------- an approved budget hold
/** A passkey approved a budget hold (the quorum, on a team): "ask me" at 80% marks the period as asked, at the cap it
 * raises that period's cap once, by one cap. The approval is used up by this (it is not also a grant for one request). */
export async function onApproved(env, accountId, h) {
  let c; try { c = JSON.parse(h.context || 'null'); } catch { c = null; }
  if (!c || typeof c.scope !== 'string' || typeof c.period !== 'string' || !/^(d:\d{4}-\d{2}-\d{2}|m:\d{4}-\d{2})$/.test(c.period)) return null;
  const key = spendKey(accountId, c.scope);
  if (h.rule === 'budget.ask') {
    await env.DB.prepare('UPDATE budget_spend SET asked = 1 WHERE scope = ? AND period = ? AND account_id = ?').bind(key, c.period, accountId).run();
  } else if (h.rule === 'budget.cap') {
    const b = await env.DB.prepare('SELECT daily, monthly FROM budgets WHERE account_id = ? AND scope = ?').bind(accountId, c.scope).first();
    const cap = b && (c.period.startsWith('d:') ? b.daily : b.monthly);
    if (!cap) return null;
    await env.DB.prepare('UPDATE budget_spend SET extra = extra + ?, asked = 1 WHERE scope = ? AND period = ? AND account_id = ?').bind(cap, key, c.period, accountId).run();
  } else return null;
  await env.DB.prepare("UPDATE holds SET status = 'used' WHERE id = ? AND account_id = ? AND status = 'approved'").bind(h.id, accountId).run();
  return c;
}

// ---------------------------------------------------------------- cleanup
/** part of the sweep: day totals older than 35 days, month totals older than 13 months */
export const sweepStatements = (db, t) => [
  db.prepare("DELETE FROM budget_spend WHERE (period LIKE 'd:%' AND period < ?) OR (period LIKE 'm:%' AND period < ?)").bind('d:' + utcDay(t - 35 * 86_400_000), 'm:' + utcDay(t - 400 * 86_400_000).slice(0, 7)),
];
/** part of deleting an account (its caps go with the account by their foreign key: ON DELETE CASCADE) */
export const deleteStatements = (db, accountId) => [
  db.prepare('DELETE FROM budget_spend WHERE account_id = ?').bind(accountId),
];
