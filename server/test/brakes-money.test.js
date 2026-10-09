// Brakes, money caps: a Stripe refund or payout under a token's per-call and per-day caps passes without asking; anything
// over, unreadable, in another currency or not one of those two calls waits for a passkey. Amounts are read exactly as the
// map reads them (the strict form parser), the day's total is reserved with one conditional statement, and caps loosen a
// hold, so only a passkey ceremony can set them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { readMoneyCall, normaliseBrakes, fmtMoney, exponent, moneyKind, MAX_MINOR } from '../src/money.js';
import { reserve, release } from '../src/brakes.js';
import { irreversibleRule } from '../src/providers.js';
import { canonPath } from '../src/broker.js';
import {
  anon, FORM, SK, CH, PI, MONEY, charge, intent, stripeWorld, account, mintPre, mint, refund, payout, stripe, posts, lookups,
  approve, cliSession, withVapid, subscribe, db, spend, auditRows, publicEntries, today,
} from './brakes-helpers.js';

const CT = 'application/x-www-form-urlencoded';
const read = (kind, body, o = {}) => readMoneyCall(kind, o.ct ?? CT, body, o.search ?? '');

// ---------------------------------------------------------------- policy: who may set what
test('limits narrow, so any session sets them; money loosens, so only a passkey ceremony does; both are validated strictly', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const mk = (policy, o = {}) => w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: u.cred, policy }, ...o });
  const ok = await mk({ limits: { writesPerHour: 100, repeatsPer5Min: 3 } });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const listed = (await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens.find((t) => t.id === ok.body.id);
  assert.deepEqual(listed.policy.limits, { writesPerHour: 100, repeatsPer5Min: 3 });
  assert.equal(listed.policy.money, null);
  const none = await mk({ limits: {} });
  assert.equal((await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens.find((t) => t.id === none.body.id).policy.limits, null, 'an empty limits object is no limits');
  // a typo or an out-of-range value is refused, not silently ignored (a token without its brake would look protected)
  for (const bad of [{ writesPerHour: 0 }, { writesPerHour: 5001 }, { writesPerHour: 1.5 }, { writesPerHour: '10' }, { writesPerHour: null }, { writesPerHour: -1 }, { repeatsPer5Min: 1 }, { repeatsPer5Min: 101 }, { writesPerHr: 5 }, { writesPerHour: 5, extra: true }, [], 'x', 7]) {
    const r = await mk({ limits: bad });
    assert.equal(r.body.error, 'bad_policy', JSON.stringify(bad));
    assert.equal(r.status, 400);
  }
  // money: a plain web session and a command line session are refused, the passkey ceremony is not
  const money = { currency: 'usd', perCall: 5000, perDay: 20000 };
  const plain = await mk({ money });
  assert.equal(plain.status, 403); assert.equal(plain.body.error, 'passkey_required');
  const cli = await cliSession(w, u);
  const viaCli = await w.req('POST', '/v1/tokens', { bearer: cli, ...anon, body: { credentialId: u.cred, policy: { money } } });
  assert.equal(viaCli.status, 403); assert.equal(viaCli.body.error, 'passkey_required');
  const viaCliBegin = await w.req('POST', '/v1/tokens/passkey/begin', { bearer: cli, ...anon, body: {} });
  assert.equal(viaCliBegin.body.error, 'passkey_required', 'the passkey route is for a web session');
  const pre = await mintPre(w, u, { money });
  assert.deepEqual((await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens.find((t) => t.id === pre.id).policy.money, money);
  assert.equal(db(w).prepare('SELECT minted_by FROM tokens WHERE id = ?').get(pre.id).minted_by, 'passkey');
  // money is validated before the passkey question, and a bad value is a 400 even in a ceremony
  const badMoney = [
    { currency: 'USD', perCall: 1, perDay: 1 }, { currency: 'us', perCall: 1, perDay: 1 }, { currency: 'usdx', perCall: 1, perDay: 1 }, { currency: 'u$d', perCall: 1, perDay: 1 },
    { currency: 'usd', perCall: 0, perDay: 10 }, { currency: 'usd', perCall: 50.5, perDay: 100 }, { currency: 'usd', perCall: '50', perDay: 100 }, { currency: 'usd', perCall: 50 },
    { currency: 'usd', perCall: 100, perDay: 50 }, { currency: 'usd', perCall: 1, perDay: MAX_MINOR + 1 }, { currency: 'usd', perCall: 1, perDay: 5, extra: 1 }, { perCall: 1, perDay: 5 },
    { currency: 'usd', perCall: -5, perDay: 5 }, { currency: 'usd', perCall: 1e21, perDay: 1e21 }, [], 'usd',
  ];
  for (const m of badMoney) {
    assert.equal((await mk({ money: m })).body.error, 'bad_policy', 'plain ' + JSON.stringify(m));
    const b = await w.req('POST', '/v1/tokens/passkey/begin', { cookie: u.cookie, body: {} });
    const r = await w.req('POST', '/v1/tokens/passkey/finish', { cookie: u.cookie, body: { credentialId: u.cred, policy: { money: m }, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
    assert.equal(r.body.error, 'bad_policy', 'passkey ' + JSON.stringify(m));
  }
  // the same rules, without a server
  assert.throws(() => normaliseBrakes({ money }, false), /Only a passkey holder/);
  assert.deepEqual(normaliseBrakes({ money }, true).money, money);
  assert.deepEqual(normaliseBrakes({}, false), { limits: null, money: null });
});

// ---------------------------------------------------------------- reading an amount exactly as Stripe's form parser does
test('amount tricks: a refund or payout is read only when every reading of the request agrees; anything else is unreadable', () => {
  const C = 'ch_3NabcdefGHIJ';
  const ok = read('refund', `charge=${C}&amount=2500`);
  assert.deepEqual(ok, { ok: true, kind: 'refund', amount: 2500, target: { type: 'charge', id: C } });
  assert.deepEqual(read('refund', `payment_intent=${PI}`), { ok: true, kind: 'refund', amount: undefined, target: { type: 'payment_intent', id: PI } });
  assert.ok(read('refund', `charge=${C}&amount=2500&reason=duplicate&metadata[order]=77&refund_application_fee=true&reverse_transfer=false`).ok, 'other parameters are Stripe\'s business');
  assert.ok(read('refund', `charge=${C}&amount=2500`, { ct: 'application/x-www-form-urlencoded; charset=UTF-8' }).ok);
  assert.ok(read('refund', `charge=${C}&amount=2500`, { ct: 'Application/X-WWW-Form-Urlencoded' }).ok);
  assert.deepEqual(read('payout', 'amount=5000&currency=usd'), { ok: true, kind: 'payout', amount: 5000, currency: 'usd' });
  assert.ok(read('payout', 'amount=5000&currency=usd&method=instant&destination=ba_1&metadata[a]=b').ok);
  assert.equal(read('refund', `charge=${C}&amount=999999999999`).amount, 999999999999);

  const unreadable = (kind, body, o, why = '') => { const r = read(kind, body, o); assert.equal(r.ok, false, `${kind} ${JSON.stringify(body)} ${JSON.stringify(o || {})}`); if (why) assert.match(r.why, why); };
  // a repeated amount, anywhere a parser might split it (Rack keeps the last copy, others the first)
  for (const body of [`charge=${C}&amount=100&amount=9000`, `charge=${C}&amount=9000&amount=100`, `charge=${C}&amount=100&amount=100`, `charge=${C}&amount=100;amount=9000`,
    `charge=${C}&amount=100;x=1`, `charge=${C}&amount=100%3Bamount=9000&amount=100`, `charge=${C}&amount[]=100`, `charge=${C}&amount[x]=100`, `charge=${C}&[amount]=100`, `charge=${C}& amount=100`,
    `charge=${C}&Amount=100`, `charge=${C}&AMOUNT=100`, `charge=${C}&%61mount=100&amount=100`, `charge=${C}&am%6Funt=100&%61mount=9000`, `charge=${C}&amount=+100`])
    unreadable('refund', body);
  // an escaped letter or digit is the same character to Stripe and to the broker, so it reads as what it is
  assert.equal(read('refund', `charge=${C}&amount=1%300`).amount, 100);
  assert.equal(read('refund', `charge=${C}&%61mount=100`).amount, 100);
  // the amount itself: one canonical spelling, a whole number from 1 up to twelve digits
  for (const a of ['0', '', '00', '0100', '+100', '-100', '100.0', '100.', '.5', '1e3', '1E3', '0x10', '100 ', ' 100', '100abc', '1,000', '١٢٣', '１２３', '1'.repeat(13), '9007199254740993', 'NaN', 'Infinity', 'null', 'true'])
    unreadable('refund', `charge=${C}&amount=${encodeURIComponent(a)}`, {}, /amount/);
  unreadable('refund', `charge=${C}&amount=100%20`, {}, /amount/);
  // a query string copy, a JSON body, multipart, a bigger body, another content type
  unreadable('refund', `charge=${C}&amount=100`, { search: '?amount=9000' }, /query string/);
  unreadable('refund', `charge=${C}&amount=100`, { search: '?x=1' }, /query string/);
  unreadable('refund', JSON.stringify({ charge: C, amount: 100 }), {}, /one way/);
  unreadable('refund', JSON.stringify({ charge: C, amount: 100, Amount: 9000 }), {}, /one way/);
  unreadable('refund', `--x\r\nContent-Disposition: form-data; name="amount"\r\n\r\n100\r\n--x--`, {}, /one way/);
  unreadable('refund', `charge=${C}&amount=100&pad=${'x'.repeat(5000)}`, {}, /large/);
  for (const ct of ['application/json', 'multipart/form-data; boundary=x', 'text/plain', '', 'application/x-www-form-urlencoded, application/json', 'application/x-www-form-urlencodedx'])
    unreadable('refund', `charge=${C}&amount=100`, { ct }, /plain form/);
  // what is refunded: exactly one of charge and payment_intent, in the usual id form, not from a customer balance
  unreadable('refund', `charge=${C}&payment_intent=${PI}&amount=100`, {}, /exactly one/);
  unreadable('refund', 'amount=100', {}, /exactly one/);
  unreadable('refund', `charge=${C}&charge=${C}`, {});
  unreadable('refund', `charge=${C}&origin=customer_balance&amount=100`, {}, /customer balance/);
  unreadable('refund', 'amount=100&origin=customer_balance', {}, /customer balance/);
  for (const id of ['ch_short', 'ch_', 'ch_abc defgh123', 'ch_../v1/payouts12', 'ch_abc%2Fdef12345', 'xx_3Nabcdef123', PI, 'ch_3Nabcdef123/', `ch_${'a'.repeat(65)}`, 'ch_ünicodeabcde'])
    unreadable('refund', `charge=${encodeURIComponent(id)}&amount=100`, {}, /charge id/);
  unreadable('refund', `payment_intent=${C}&amount=100`, {}, /payment intent id/);
  // a payout needs an amount and a currency in lower case letters, once
  unreadable('payout', 'currency=usd', {}, /no amount/);
  unreadable('payout', 'amount=5000', {}, /currency/);
  unreadable('payout', 'amount=5000&currency=USD', {}, /currency/);
  unreadable('payout', 'amount=5000&currency=usdx', {}, /currency/);
  unreadable('payout', 'amount=5000&currency=usd&currency=eur', {});
  unreadable('payout', 'amount=5000&currency=usd&currency=usd', {});
  unreadable('payout', 'amount=5000&currency[]=usd', {});
  unreadable('payout', 'amount=5000&amount=1&currency=usd', {});
});

test('only POST /v1/refunds and POST /v1/payouts, spelled exactly so, are calls a cap can ever let through', () => {
  assert.equal(moneyKind('stripe', 'POST', '/v1/refunds'), 'refund');
  assert.equal(moneyKind('stripe', 'POST', '/v1/payouts'), 'payout');
  for (const [p, m, path] of [['stripe', 'GET', '/v1/refunds'], ['stripe', 'POST', '/v1/Refunds'], ['stripe', 'POST', '/v1/refunds.json'], ['stripe', 'POST', '/v1/refunds/re_1'], ['stripe', 'POST', '/v1/transfers'], ['stripe', 'POST', '/v1/charges'],
    ['stripe', 'POST', '/v1/topups'], ['stripe', 'POST', '/v1/charges/ch_1/refund'], ['stripe', 'POST', '/v1/application_fees/fee_1/refunds'], ['stripe', 'POST', '/v1/payment_intents/pi_1/capture'], ['stripe', 'POST', '/v1/payouts/po_1/cancel'],
    ['github', 'POST', '/v1/refunds'], ['stripe', 'PUT', '/v1/payouts']]) assert.equal(moneyKind(p, m, path), null, `${p} ${m} ${path}`);
});

// ---------------------------------------------------------------- the flow
test('a refund under the caps passes: the amount is read, Stripe is asked what the charge is, the day\'s total is kept, the call is recorded without the amount in public', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const t = await mintPre(w, u, { money: MONEY });
  const r = await refund(w, t.token, `charge=${CH}&amount=2500`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.headers.get('x-leash-decision'), 'allowed');
  assert.deepEqual(w.upstream.map((x) => [x.method, new URL(x.url).pathname]), [['GET', `/v1/charges/${CH}`], ['POST', '/v1/refunds']], 'one lookup, then the refund');
  assert.equal(w.upstream[0].headers.authorization, 'Bearer ' + SK, 'the lookup uses the vaulted key');
  assert.equal(w.upstream[1].body, `charge=${CH}&amount=2500`, 'the refund goes upstream byte for byte');
  assert.deepEqual(spend(w), [{ token_id: t.id, day: today(), currency: 'usd', amount: 2500 }]);
  const last = auditRows(w, u.id).filter((a) => a.action === 'proxy').at(-1);
  assert.equal(last.detail.rule, 'st.money:capped');
  assert.deepEqual(last.detail.money, { kind: 'refund', amount: 2500, currency: 'usd', charge: CH }, 'the owner\'s audit log says what it was');
  const es = (await publicEntries(w)).map((e) => e.entry.receipt);
  assert.deepEqual(es.map((e) => [e.action, e.decision, e.meta.rule]), [['POST api.stripe.com', 'allowed', 'st.money:capped']]);
  // at the cap exactly is fine; one over is held
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=5000`)).status, 200);
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=5001`)).body.rule, 'brake.money-per-call');
  assert.equal(spend(w)[0].amount, 7500);
});

test('over the per-call cap: held with the amount in large type and the arithmetic in the preview; an approval lets that exact call through once and is not counted', async () => {
  const w = stripeWorld();
  await withVapid(w);
  const u = await account(w);
  await subscribe(w, u);
  w.charges[CH] = charge(CH, { amount: 124000 });
  const t = await mintPre(w, u, { money: MONEY });
  const body = `charge=${CH}&amount=124000`;
  const r = await refund(w, t.token, body);
  assert.equal(r.status, 428, JSON.stringify(r.body));
  assert.equal(r.body.rule, 'brake.money-per-call');
  assert.match(r.body.message, /held this request: Refund of 1,240\.00 USD is over this token's cap of 50\.00 USD a call\./);
  assert.ok(!/cannot be undone/.test(r.body.message));
  assert.deepEqual(posts(w), [], 'nothing reached Stripe but the lookup');
  assert.deepEqual(spend(w), [], 'a held call reserves nothing');
  assert.equal(w.pushes.length, 1, 'the owner is woken');
  const h = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0];
  assert.equal(h.headline, 'Refund 1,240.00 USD');
  assert.equal(h.rule, 'brake.money-per-call');
  assert.ok(h.preview.startsWith(`Refund 1,240.00 USD\nStripe refund of charge ${CH}: all of it; 1,240.00 USD refundable.\nOver the per-call cap of 50.00 USD.\n`), h.preview);
  assert.match(h.preview, new RegExp(`charge=${CH}&amount=124000`), 'the raw request is still shown');
  // a retry reuses the hold: no second push
  assert.equal((await refund(w, t.token, body)).body.hold_id, r.body.hold_id);
  assert.equal(w.pushes.length, 1);
  // a different amount is not covered by the approval
  assert.equal((await approve(w, u, r.body.hold_id)).status, 200);
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=124001`)).status, 428);
  const ok = await refund(w, t.token, body);
  assert.equal(ok.status, 200); assert.equal(ok.headers.get('x-leash-decision'), 'approved');
  assert.equal(posts(w).length, 1);
  assert.deepEqual(spend(w), [], 'what you approved is yours: it is not counted against the day\'s cap');
  assert.equal((await refund(w, t.token, body)).status, 428, 'once');
  const es = (await publicEntries(w)).map((e) => e.entry.receipt.decision);
  assert.deepEqual(es, ['held', 'approved', 'held', 'executed', 'held']);
});

test('a refund without an amount refunds everything left, so the lookup decides; a payment intent is looked up too', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: MONEY });
  w.charges[CH] = charge(CH, { amount: 8000 });
  const big = await refund(w, t.token, `charge=${CH}`);
  assert.equal(big.body.rule, 'brake.money-per-call', 'a full refund of 80.00 is over a 50.00 cap');
  assert.equal((await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0].headline, 'Refund 80.00 USD');
  w.charges[CH] = charge(CH, { amount: 8000, amount_refunded: 3000 });
  const rest = await refund(w, t.token, `charge=${CH}`);
  assert.equal(rest.status, 200, JSON.stringify(rest.body));
  assert.equal(spend(w)[0].amount, 5000, 'what was left, not the original amount');
  // a charge that was only partly captured: what was captured, less what was refunded
  w.charges['ch_3NpartlyCaptured001'] = charge('ch_3NpartlyCaptured001', { amount: 9000, amount_captured: 4000, amount_refunded: 500 });
  assert.equal((await refund(w, t.token, 'charge=ch_3NpartlyCaptured001')).status, 200);
  assert.equal(spend(w)[0].amount, 5000 + 3500);
  // a charge with nothing left cannot be refunded: held, not counted as a zero
  w.charges['ch_3NallRefunded0001'] = charge('ch_3NallRefunded0001', { amount: 800, amount_refunded: 800 });
  const none = await refund(w, t.token, 'charge=ch_3NallRefunded0001');
  assert.equal(none.body.rule, 'brake.money-unreadable'); assert.match(none.body.message, /nothing left/);
  // payment intents: what the intent received bounds a full refund
  w.intents[PI] = intent(PI, { amount_received: 3000 });
  const pi = await refund(w, t.token, `payment_intent=${PI}`);
  assert.equal(pi.status, 200, JSON.stringify(pi.body));
  assert.equal(lookups(w).at(-1).url, `https://api.stripe.com/v1/payment_intents/${PI}`);
  assert.equal(spend(w)[0].amount, 5000 + 3500 + 3000);
  w.intents[PI] = intent(PI, { amount_received: 0 });
  assert.equal((await refund(w, t.token, `payment_intent=${PI}`)).body.rule, 'brake.money-unreadable');
});

test('a lookup that fails, answers oddly or names another object holds the refund: nothing is guessed', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: MONEY });
  const odd = (v) => () => new Response(v, { status: 200, headers: { 'content-type': 'application/json' } });
  const cases = {
    missing: undefined, notJson: odd('<html>'), array: odd('[]'), nullBody: odd('null'),
    server500: () => new Response('{}', { status: 500 }), redirect: () => new Response(null, { status: 302, headers: { location: 'https://evil.example/' } }),
    otherId: charge('ch_3NsomethingElse0001'), wrongObject: charge(CH, { object: 'refund' }), upperCurrency: charge(CH, { currency: 'USD' }), noCurrency: charge(CH, { currency: undefined }),
    floatAmount: charge(CH, { amount: 80.5, amount_captured: 80.5 }), stringAmount: charge(CH, { amount: '8000', amount_captured: '8000' }), negativeRefunded: charge(CH, { amount_refunded: -5 }),
    noRefunded: charge(CH, { amount_refunded: undefined }), hugeAmount: charge(CH, { amount: 2 ** 60, amount_captured: 2 ** 60 }),
  };
  for (const [name, c] of Object.entries(cases)) {
    w.charges[CH] = c; if (c === undefined) delete w.charges[CH];
    const r = await refund(w, t.token, `charge=${CH}&amount=100`);
    assert.equal(r.status, 428, name);
    assert.equal(r.body.rule, 'brake.money-unreadable', name);
  }
  assert.deepEqual(posts(w), []); assert.deepEqual(spend(w), []);
  // the lookup is bounded: a charge whose answer is far bigger than any charge is not read
  w.charges[CH] = odd(JSON.stringify(charge(CH)) + ' '.repeat(300_000));
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=100`)).body.rule, 'brake.money-unreadable');
});

test('currency mismatch: a refund in another currency, a payout in another currency, and a currency spelled any other way are held', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: MONEY });
  w.charges[CH] = charge(CH, { currency: 'eur' });
  const r = await refund(w, t.token, `charge=${CH}&amount=100`);
  assert.equal(r.body.rule, 'brake.money-currency');
  assert.match(r.body.message, /in EUR and this token's caps are in USD/);
  assert.equal((await payout(w, t.token, 'amount=100&currency=eur')).body.rule, 'brake.money-currency');
  assert.equal((await payout(w, t.token, 'amount=100&currency=USD')).body.rule, 'brake.money-unreadable');
  assert.equal((await payout(w, t.token, 'amount=100&currency=usd')).status, 200);
  assert.equal((await payout(w, t.token, 'amount=100&currency=usd')).status, 200);
  assert.deepEqual(spend(w).map((s) => [s.currency, s.amount]), [['usd', 200]], 'only the token\'s currency is ever counted');
  // a euro amount is never compared with a dollar cap: 49.99 EUR is not 49.99 USD
  w.charges[CH] = charge(CH, { currency: 'eur', amount: 100 });
  assert.equal((await refund(w, t.token, `charge=${CH}`)).body.rule, 'brake.money-currency');
});

test('payouts: capped like refunds, held when over, unreadable, or in the wrong currency', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: MONEY });
  assert.equal((await payout(w, t.token, 'amount=5000&currency=usd')).status, 200);
  assert.deepEqual(lookups(w), [], 'a payout needs no lookup');
  const over = await payout(w, t.token, 'amount=5001&currency=usd');
  assert.equal(over.body.rule, 'brake.money-per-call');
  assert.equal((await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0].headline, 'Payout 50.01 USD');
  for (const bad of ['amount=100', 'currency=usd', 'amount=100&currency=usd&amount=200', 'amount=1e2&currency=usd', 'amount=0&currency=usd', 'amount=-5&currency=usd'])
    assert.equal((await payout(w, t.token, bad)).body.rule, 'brake.money-unreadable', bad);
  assert.equal(posts(w).length, 1);
});

test('the daily cap: the Nth call that fits passes, the one that does not waits with today\'s arithmetic, the exact fit passes, a new UTC day starts again', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: { currency: 'usd', perCall: 5000, perDay: 10000 } });
  for (let i = 0; i < 2; i++) { w.charges[`${CH}${i}`] = charge(`${CH}${i}`); assert.equal((await refund(w, t.token, `charge=${CH}${i}&amount=4000`)).status, 200); }
  w.charges[`${CH}x`] = charge(`${CH}x`);
  const over = await refund(w, t.token, `charge=${CH}x&amount=4000`);
  assert.equal(over.body.rule, 'brake.money-per-day');
  assert.match(over.body.message, /would take today's total to 120\.00 USD, over this token's cap of 100\.00 USD a day \(UTC\)/);
  const h = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0];
  assert.match(h.preview, /Today \(UTC\): 80\.00 USD already let through \+ 40\.00 USD = 120\.00 USD, over the daily cap of 100\.00 USD\./);
  assert.equal(h.headline, 'Refund 40.00 USD');
  assert.equal(spend(w)[0].amount, 8000, 'a refused call writes nothing');
  assert.equal((await refund(w, t.token, `charge=${CH}x&amount=2000`)).status, 200, 'exactly the cap');
  assert.equal(spend(w)[0].amount, 10000);
  assert.equal((await refund(w, t.token, `charge=${CH}x&amount=1`)).body.rule, 'brake.money-per-day', 'one more unit is over');
  // yesterday\'s total does not count today (and the sweep removes totals older than 35 days)
  db(w).prepare("UPDATE spend SET day = '2020-01-01'").run();
  assert.equal((await refund(w, t.token, `charge=${CH}x&amount=5000`)).status, 200);
  assert.deepEqual(spend(w).map((s) => [s.day, s.amount]), [['2020-01-01', 10000], [today(), 5000]]);
  const { sweep } = await import('../src/index.js');
  await sweep(w.env);
  assert.deepEqual(spend(w).map((s) => s.day), [today()]);
});

test('concurrent calls race the daily cap: exactly as many pass as fit, and the total never goes over', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: { currency: 'usd', perCall: 1000, perDay: 5000 } });
  const ids = Array.from({ length: 8 }, (_, i) => `ch_3Nrace${String(i).padStart(2, '0')}abcdefgh`);
  for (const id of ids) w.charges[id] = charge(id, { amount: 1000 });
  const rs = await Promise.all(ids.map((id) => refund(w, t.token, `charge=${id}&amount=1000`)));
  assert.equal(rs.filter((r) => r.status === 200).length, 5);
  assert.deepEqual([...new Set(rs.filter((r) => r.status !== 200).map((r) => r.body.rule))], ['brake.money-per-day']);
  assert.equal(spend(w)[0].amount, 5000);
  assert.equal(posts(w).length, 5, 'only five refunds reached Stripe');
  // the statement itself, raced directly
  const d = new World().env.DB;
  const got = await Promise.all(Array.from({ length: 30 }, () => reserve(d, 'tok', '2026-10-09', 'usd', 300, 1000)));
  assert.equal(got.filter((x) => x !== null).length, 3);
  assert.equal(d.raw.prepare('SELECT amount FROM spend').get().amount, 900);
  assert.equal(await reserve(d, 'tok', '2026-10-09', 'usd', 100, 1000), 1000);
  assert.equal(await reserve(d, 'tok', '2026-10-09', 'usd', 1, 1000), null);
  // a call bigger than the whole cap writes no row at all
  assert.equal(await reserve(d, 'other', '2026-10-09', 'usd', 1001, 1000), null);
  assert.equal(d.raw.prepare("SELECT COUNT(*) n FROM spend WHERE token_id = 'other'").get().n, 0);
  await release({ DB: d }, { tokenId: 'tok', day: '2026-10-09', currency: 'usd', amount: 400 });
  assert.equal(d.raw.prepare("SELECT amount FROM spend WHERE token_id = 'tok'").get().amount, 600);
  await release({ DB: d }, { tokenId: 'tok', day: '2026-10-09', currency: 'usd', amount: 99999 });
  assert.equal(d.raw.prepare("SELECT amount FROM spend WHERE token_id = 'tok'").get().amount, 0, 'never below zero');
});

test('a refusal from Stripe gives the reservation back; a server error or no answer keeps it (the money may have moved)', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: MONEY });
  w.charges[CH] = charge(CH);
  w.postStatus = 400;
  const r = await refund(w, t.token, `charge=${CH}&amount=2500`);
  assert.equal(r.status, 400, 'Stripe\'s answer is passed through');
  assert.equal(spend(w)[0].amount, 0, 'handed back');
  assert.equal(auditRows(w, u.id).filter((a) => a.action === 'proxy').at(-1).detail.released, true);
  w.postStatus = 402; await refund(w, t.token, `charge=${CH}&amount=2500`); assert.equal(spend(w)[0].amount, 0);
  w.postStatus = 429; await refund(w, t.token, `charge=${CH}&amount=2500`); assert.equal(spend(w)[0].amount, 0);
  w.postStatus = 500;
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=2500`)).status, 500);
  assert.equal(spend(w)[0].amount, 2500, 'Stripe may have refunded before failing');
  w.postStatus = 'throw';
  const gone = await refund(w, t.token, `charge=${CH}&amount=1000`);
  assert.equal(gone.status, 502); assert.equal(gone.body.error, 'upstream_unreachable');
  assert.equal(spend(w)[0].amount, 3500, 'no answer: it stays counted');
  w.postStatus = 200;
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=1000`)).status, 200);
  assert.equal(spend(w)[0].amount, 4500);
});

test('a preapproved refund is still capped; a cap never overrides the token\'s own hold rules, allow list or default', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH, { amount: 9000 });
  const pre = await mintPre(w, u, { money: MONEY, unattendedIrreversible: [{ method: 'POST', path: '/v1/refunds' }] });
  assert.equal((await refund(w, pre.token, `charge=${CH}&amount=2000`)).status, 200);
  const over = await refund(w, pre.token, `charge=${CH}&amount=9000`);
  assert.equal(over.status, 428, 'the cap holds what the preapproval would have let through');
  assert.equal(over.body.rule, 'brake.money-per-call');
  assert.equal((await refund(w, pre.token, `charge=${CH}&amount=2000&amount=1`)).body.rule, 'brake.money-unreadable', 'and so does an unreadable one');
  // without caps a preapproval is exactly what it was
  const only = await mintPre(w, u, { unattendedIrreversible: [{ method: 'POST', path: '/v1/refunds' }] });
  assert.equal((await refund(w, only.token, `charge=${CH}&amount=9000&amount=1`)).status, 200);
  const before = w.upstream.length;
  // an allow list that leaves refunds out, a hold rule, a default of hold: the refund stays held for the map, with no lookup
  for (const [name, policy] of [
    ['allow list', { allow: [{ method: 'GET', path: '/v1/**' }] }],
    ['hold rule', { hold: [{ method: 'POST', path: '/v1/refunds' }] }],
    ['default hold', { default: 'hold' }],
  ]) {
    const t = await mintPre(w, u, { ...policy, money: MONEY });
    const r = await refund(w, t.token, `charge=${CH}&amount=100`);
    assert.equal(r.status, 428, name); assert.equal(r.body.rule, 'st.money', name);
  }
  assert.equal(w.upstream.length, before, 'no lookup, no refund');
  // an allow list that includes it lets the cap work
  const al = await mintPre(w, u, { allow: [{ method: 'POST', path: '/v1/refunds' }], money: MONEY });
  assert.equal((await refund(w, al.token, `charge=${CH}&amount=100`)).status, 200);
  // a read-only token is denied, caps or not
  const ro = await mintPre(w, u, { readOnly: true, money: MONEY });
  assert.equal((await refund(w, ro.token, `charge=${CH}&amount=100`)).body.error, 'leash_denied');
});

test('every other money call stays held with its own map rule, caps or not: transfers, charges, top-ups, confirms, captures, fee refunds, spelling variants, method overrides', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const t = await mintPre(w, u, { money: MONEY });
  const held = async (path, raw, rule) => {
    const r = await stripe(w, t.token, path, raw);
    assert.equal(r.status, 428, `${path} ${raw}`); assert.equal(r.body.rule, rule, `${path} ${raw}`);
  };
  await held('/v1/transfers', 'amount=100&currency=usd&destination=acct_1', 'st.money');
  await held('/v1/charges', 'amount=100&currency=usd&source=tok_visa', 'st.money');
  await held('/v1/topups', 'amount=100&currency=usd', 'st.money');
  await held(`/v1/charges/${CH}/refund`, 'amount=100', 'st.refund');
  await held(`/v1/charges/${CH}/refunds`, 'amount=100', 'st.refund');
  await held('/v1/application_fees/fee_1/refunds', 'amount=100', 'st.refund');
  await held('/v1/payment_intents/pi_1/capture', 'amount_to_capture=100', 'st.money2');
  await held('/v1/payment_intents/pi_1/confirm', '', 'st.money2');
  await held('/v1/payment_intents', 'amount=100&currency=usd&confirm=true', 'st.pi-confirm');
  await held('/v1/Refunds', `charge=${CH}&amount=100`, 'st.money');
  await held('/v1/REFUNDS', `charge=${CH}&amount=100`, 'st.money');
  await held('/v1/refunds.json', `charge=${CH}&amount=100`, 'st.money');
  await held('/v1/payouts.json', 'amount=100&currency=usd', 'st.money');
  await held('/v1/refunds', `charge=${CH}&amount=100&_method=DELETE`, 'any.method-override');
  await held('/v1/payouts', 'amount=100&currency=usd&_method=get', 'any.method-override');
  assert.equal(w.upstream.length, 0, 'no lookup, nothing upstream');
  assert.deepEqual(spend(w), []);
  // DELETE is held by the map and never touched
  const del = await w.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon });
  assert.equal(del.body.rule, 'st.delete');
  // trailing slash and an escaped unreserved letter are the same path to the broker and to Stripe, so they are capped like it
  w.upstream.length = 0;
  assert.equal(canonPath('/v1/%72efunds/'), '/v1/refunds');
  assert.equal((await stripe(w, t.token, '/v1/%72efunds/', `charge=${CH}&amount=100`)).status, 200);
  assert.equal(w.upstream.at(-1).url, 'https://api.stripe.com/v1/refunds', 'sent upstream in the canonical form that was checked');
  assert.equal(irreversibleRule('stripe', 'POST', '/v1/refunds', '')?.id, 'st.money');
});

test('another token\'s caps and totals are its own; a token without caps behaves exactly as before', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const a = await mintPre(w, u, { money: { currency: 'usd', perCall: 5000, perDay: 5000 } }, 'a');
  const b = await mintPre(w, u, { money: { currency: 'usd', perCall: 5000, perDay: 5000 } }, 'b');
  assert.equal((await refund(w, a.token, `charge=${CH}&amount=5000`)).status, 200);
  assert.equal((await refund(w, a.token, `charge=${CH}&amount=1`)).body.rule, 'brake.money-per-day');
  assert.equal((await refund(w, b.token, `charge=${CH}&amount=5000`)).status, 200, 'b has its own day');
  assert.deepEqual(spend(w).map((s) => s.amount), [5000, 5000]);
  const plain = await mint(w, u, {});
  const r = await refund(w, plain.token, `charge=${CH}&amount=100`);
  assert.equal(r.status, 428); assert.equal(r.body.rule, 'st.money');
  assert.match(r.body.message, /cannot be undone/, 'the map\'s own wording is unchanged');
  // the token list says what each token has let through today
  const list = (await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens;
  assert.deepEqual(list.find((t) => t.id === a.id).spent_today, { usd: 5000 });
  assert.equal(list.find((t) => t.id === plain.id).spent_today, undefined);
});

test('caps that cannot be read from the stored policy fail closed', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const t = await mintPre(w, u, { money: MONEY, unattendedIrreversible: [{ method: 'POST', path: '/v1/refunds' }] });
  db(w).prepare("UPDATE tokens SET policy = json_set(policy, '$.money', json('{\"currency\":\"USD\",\"perCall\":\"x\",\"perDay\":1}')) WHERE id = ?").run(t.id);
  const r = await refund(w, t.token, `charge=${CH}&amount=100`);
  assert.equal(r.status, 428); assert.equal(r.body.rule, 'brake.money-unreadable', 'a preapproval does not run on caps nobody can read');
  const t2 = await mintPre(w, u, { money: MONEY });
  db(w).prepare("UPDATE tokens SET policy = json_set(policy, '$.money', json('{\"currency\":\"usd\",\"perCall\":5,\"perDay\":1}')) WHERE id = ?").run(t2.id);
  assert.equal((await refund(w, t2.token, `charge=${CH}&amount=1`)).body.rule, 'st.money', 'the map holds it and no cap lets it through');
  assert.deepEqual(spend(w), []);
});

test('amounts are shown with the currency\'s own decimals: JPY none, USD two, KWD three', async () => {
  assert.deepEqual(['jpy', 'usd', 'kwd', 'eur', 'bhd', 'isk', 'ugx', 'zzz'].map(exponent), [0, 2, 3, 2, 3, 2, 2, 2]);
  assert.equal(fmtMoney(124000, 'usd'), '1,240.00 USD');
  assert.equal(fmtMoney(5, 'usd'), '0.05 USD');
  assert.equal(fmtMoney(50000, 'jpy'), '50,000 JPY');
  assert.equal(fmtMoney(12345, 'kwd'), '12.345 KWD');
  assert.equal(fmtMoney(7, 'kwd'), '0.007 KWD');
  assert.equal(fmtMoney(999999999999, 'usd'), '9,999,999,999.99 USD');
  assert.equal(fmtMoney(1000, 'jpy'), '1,000 JPY');
  const w = stripeWorld();
  const u = await account(w);
  const t = await mintPre(w, u, { money: { currency: 'jpy', perCall: 50000, perDay: 200000 } });
  w.charges[CH] = charge(CH, { currency: 'jpy', amount: 60000, amount_captured: 60000 });
  assert.equal((await refund(w, t.token, `charge=${CH}&amount=30000`)).status, 200);
  assert.equal((await refund(w, t.token, `charge=${CH}`)).body.rule, 'brake.money-per-call');
  assert.equal((await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds[0].headline, 'Refund 60,000 JPY');
  const k = await mintPre(w, u, { money: { currency: 'kwd', perCall: 50000, perDay: 200000 } });
  w.charges['ch_3NkuwaitCharge0001'] = charge('ch_3NkuwaitCharge0001', { currency: 'kwd', amount: 62345, amount_captured: 62345 });
  assert.equal((await refund(w, k.token, 'charge=ch_3NkuwaitCharge0001')).body.rule, 'brake.money-per-call');
  assert.ok((await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.some((h) => h.headline === 'Refund 62.345 KWD'));
});

test('privacy: a capped call puts no amount, currency, charge id or key in the public log', async () => {
  const w = stripeWorld();
  const u = await account(w, { name: 'Jane Secretname' });
  const AMT = 31415926, ID = 'ch_3NprivateCharge77aabb';
  w.charges[ID] = charge(ID, { amount: AMT, amount_captured: AMT });
  const t = await mintPre(w, u, { money: { currency: 'usd', perCall: 99999999, perDay: 99999999 } });
  assert.equal((await refund(w, t.token, `charge=${ID}&amount=${AMT}`)).status, 200);
  const over = await refund(w, t.token, `charge=${ID}&amount=${AMT}&reason=duplicate`);
  assert.equal(over.status, 200);
  w.charges[ID] = charge(ID, { amount: 99999999 + 5, amount_captured: 99999999 + 5 });
  assert.equal((await refund(w, t.token, `charge=${ID}`)).status, 428);
  const pub = JSON.stringify(await publicEntries(w)) + JSON.stringify(w.sql.raw.prepare('SELECT entry FROM leaves').all());
  for (const s of [String(AMT), '99999999', ID, 'usd', 'USD', 'refund', 'charge', 'Jane', 'Secretname', u.id, t.id, t.token, SK, 'sk_test', '203.0.113']) assert.ok(!pub.includes(s), 'public log contains ' + s);
  const es = (await publicEntries(w)).map((e) => e.entry.receipt);
  assert.deepEqual(es.map((e) => [e.decision, e.meta.rule]), [['allowed', 'st.money:capped'], ['allowed', 'st.money:capped'], ['held', 'brake.money-per-call']]);
  for (const e of es) assert.deepEqual(Object.keys(e).sort(), ['action', 'agent', 'decision', 'meta', 'parent', 'ts']);
  // the owner's private audit log does say what it was
  assert.ok(JSON.stringify(auditRows(w, u.id)).includes(String(AMT)));
});

test('the busiest money path stays inside the D1 budget: a capped refund is one lookup, one statement more, and well under 50 queries', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH);
  const t = await mintPre(w, u, { money: MONEY, limits: { writesPerHour: 100, repeatsPer5Min: 5 } });
  const plain = await mint(w, u, {}); // for the baseline: an allowed Stripe write with no brakes at all
  w.env.DB.cap = 50;
  const customers = () => w.req('POST', '/p/stripe/v1/customers', { bearer: plain.token, ...anon, headers: FORM, raw: 'email=a%40b.c' });
  await customers(); // the first call of an account also marks it active; measure the second
  const base = await customers();
  assert.equal(base.status, 200);
  const r = await refund(w, t.token, `charge=${CH}&amount=100`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  // lookups are subrequests, not D1: +1 statement for the reservation, +1 for the two breaker counters
  assert.equal(r.queries - base.queries, 2, `${r.queries} queries against ${base.queries} for the same write without brakes`);
  assert.equal(r.writes - base.writes, 2, `${r.writes} write statements against ${base.writes}: a reservation and the counters`);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM counters').get().n + db(w).prepare('SELECT COUNT(*) n FROM spend').get().n, 3, 'three rows: the two breaker windows and the day\'s total');
  assert.ok(r.queries <= 20);
  const held = await refund(w, t.token, `charge=${CH}&amount=9000`);
  assert.equal(held.status, 428);
  assert.ok(held.queries <= 30, `${held.queries} queries for a held, over-cap refund`);
  const o = await customers();
  assert.equal(o.queries, base.queries); assert.equal(o.writes, base.writes, 'a token without brakes costs exactly what it did');
});
