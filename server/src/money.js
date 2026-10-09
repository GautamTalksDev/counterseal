// Money, the pure half of Brakes (src/brakes.js keeps the state): what a token's `limits` and `money` policy may say,
// which Stripe calls a money cap can ever let through, how their amounts are read, and how an amount is shown.
//
// A money cap lets a Stripe refund or payout through unattended when it is under the token's per-call and per-day
// caps. That loosens a hold, so it is set in a passkey ceremony only (policy.js). It is deliberately narrow:
//  - only POST /v1/refunds and POST /v1/payouts, spelled exactly so (no other case, no format suffix, nothing after);
//    every other money call (charges, transfers, top-ups, confirms and captures, application fee refunds) stays held;
//  - only a plain form body (Stripe's own format) with no copy of any parameter in the query string, read through the
//    same strict parser the map uses (providers.js strictForm): repeated, oddly spelled or ambiguous parameters are
//    unreadable, and unreadable means held;
//  - an amount is a plain whole number written the one canonical way (no sign, no zeros in front, no fraction, no
//    exponent); a currency is three lower case letters, exactly as Stripe asks for it.
import { HttpError } from './util.js';
import { strictForm } from './providers.js';

/** twelve digits: the most Stripe takes for a card payment (docs.stripe.com/currencies) */
export const MAX_MINOR = 999_999_999_999;
const AMOUNT = /^[1-9][0-9]{0,11}$/;
const CURRENCY = /^[a-z]{3}$/;
export const LIMIT_RANGE = { writesPerHour: [1, 5000], repeatsPer5Min: [2, 100] };

const whole = (v, lo, hi, name) => {
  if (!Number.isSafeInteger(v) || v < lo || v > hi) throw new HttpError(400, 'bad_policy', `${name} must be a whole number from ${lo} to ${hi}.`);
  return v;
};
const only = (o, keys, name) => {
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw new HttpError(400, 'bad_policy', `${name} must be an object.`);
  const bad = Object.keys(o).find((k) => !keys.includes(k));
  if (bad !== undefined) throw new HttpError(400, 'bad_policy', `${name} has no field "${String(bad).slice(0, 40)}". Fields: ${keys.join(', ')}.`);
};

/** `limits` and `money` of a policy, validated strictly (a typo here would silently leave a token without its brake, so
 * unknown fields and out-of-range values are refused, not defaulted). `money` needs a passkey ceremony. */
export function normaliseBrakes(p, byPasskey) {
  let limits = null, money = null;
  if (p.limits !== undefined && p.limits !== null) {
    only(p.limits, Object.keys(LIMIT_RANGE), 'limits');
    const l = {};
    for (const [k, [lo, hi]] of Object.entries(LIMIT_RANGE)) if (p.limits[k] !== undefined) l[k] = whole(p.limits[k], lo, hi, `limits.${k}`);
    if (Object.keys(l).length) limits = l;
  }
  if (p.money !== undefined && p.money !== null) {
    only(p.money, ['currency', 'perCall', 'perDay'], 'money');
    if (typeof p.money.currency !== 'string' || !CURRENCY.test(p.money.currency)) throw new HttpError(400, 'bad_policy', 'money.currency must be three lower case letters, like usd.');
    money = {
      currency: p.money.currency,
      perCall: whole(p.money.perCall, 1, MAX_MINOR, 'money.perCall'),
      perDay: whole(p.money.perDay, 1, MAX_MINOR, 'money.perDay'),
    };
    if (money.perDay < money.perCall) throw new HttpError(400, 'bad_policy', 'money.perDay must be at least money.perCall.');
    if (!byPasskey) throw new HttpError(403, 'passkey_required', 'Only a passkey holder can let money calls through without approval.');
  }
  return { limits, money };
}

/** a stored policy's caps, re-checked when used: a malformed stored value reads as `undefined`, which the broker treats as
 * "caps that cannot be trusted" and holds. `null` is "no caps". */
export function storedMoney(policy) {
  const m = policy && policy.money;
  if (m === undefined || m === null) return null;
  try { return normaliseBrakes({ money: m }, true).money; } catch { return undefined; }
}
export function storedLimits(policy) {
  const l = policy && policy.limits;
  if (l === undefined || l === null) return null;
  try { return normaliseBrakes({ limits: l }, false).limits; } catch { return null; }
}

// ---------------------------------------------------------------- which calls, and how they are read
/** 'refund' or 'payout' for the two calls a money cap can ever let through, else null. `canon` is the canonical path. */
export function moneyKind(provider, method, canon) {
  if (provider !== 'stripe' || method !== 'POST') return null;
  return canon === '/v1/refunds' ? 'refund' : canon === '/v1/payouts' ? 'payout' : null;
}

const CHARGE = /^(ch|py)_[A-Za-z0-9]{8,64}$/, INTENT = /^pi_[A-Za-z0-9]{8,64}$/;
const bad = (why) => ({ ok: false, why });

/** What a refund or payout asks for, or {ok: false, why}. Refund: {kind, amount?, target: {type, id}} (no amount means
 * "everything left", which the broker looks up). Payout: {kind, amount, currency}. */
export function readMoneyCall(kind, contentType, bodyText, search) {
  if (!/^application\/x-www-form-urlencoded\s*(;|$)/i.test(contentType || '')) return bad('the body is not a plain form (application/x-www-form-urlencoded)');
  if (search) return bad('the request has a query string');
  if (bodyText.length > 4096) return bad('the body is unusually large');
  const f = strictForm(bodyText, search, kind === 'refund' ? ['amount', 'charge', 'payment_intent', 'origin'] : ['amount', 'currency']);
  if (!f) return bad('the parameters could not be read one way (repeated, oddly spelled or not a plain form)');
  let amount;
  if (f.amount !== undefined) {
    if (!AMOUNT.test(f.amount)) return bad('the amount is not a plain whole number');
    amount = Number(f.amount);
  }
  if (kind === 'payout') {
    if (amount === undefined) return bad('the payout has no amount');
    if (f.currency === undefined || !CURRENCY.test(f.currency)) return bad('the payout has no currency in lower case letters');
    return { ok: true, kind, amount, currency: f.currency };
  }
  if (f.origin !== undefined) return bad('the refund comes from a customer balance');
  const charge = f.charge, intent = f.payment_intent;
  if ((charge === undefined) === (intent === undefined)) return bad('a refund must name exactly one of charge and payment_intent');
  if (charge !== undefined && !CHARGE.test(charge)) return bad('the charge id is not in the usual form');
  if (intent !== undefined && !INTENT.test(intent)) return bad('the payment intent id is not in the usual form');
  return { ok: true, kind, amount, target: charge !== undefined ? { type: 'charge', id: charge } : { type: 'payment_intent', id: intent } };
}

// ---------------------------------------------------------------- amounts for people
// Stripe's amounts are whole numbers of the currency's smallest unit (docs.stripe.com/currencies): none for the
// zero-decimal currencies, three for the three-decimal ones, two for the rest. ISK and UGX are zero-decimal currencies
// that Stripe still takes with two decimals (500 is 5 ISK), so they stay at two. The table is for display; the caps
// themselves are plain integers in whatever unit Stripe uses for that currency.
const ZERO = new Set('bif clp djf gnf jpy kmf krw mga pyg rwf vnd vuv xaf xof xpf'.split(' '));
const THREE = new Set('bhd jod kwd omr tnd'.split(' '));
export const exponent = (currency) => (ZERO.has(currency) ? 0 : THREE.has(currency) ? 3 : 2);
export const EXPONENTS = { zero: [...ZERO], three: [...THREE] };

/** 124000 usd -> "1,240.00 USD" (integers only; never a float) */
export function fmtMoney(amount, currency) {
  const e = exponent(currency);
  const s = String(amount).padStart(e + 1, '0');
  const w = (e ? s.slice(0, -e) : s).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${w}${e ? '.' + s.slice(-e) : ''} ${currency.toUpperCase()}`;
}

export const utcDay = (t) => new Date(t).toISOString().slice(0, 10);
