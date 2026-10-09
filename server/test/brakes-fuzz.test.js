// A differential fuzz of the amount reader. Servers read the same form body in different ways (first copy or last copy
// wins, ";" splits, names matched without case, brackets read as nesting, spaces trimmed, escapes decoded or not). The
// reader is allowed to say "unreadable" (that is a hold) but when it does read a refund or payout, every one of those
// readings must agree with it on the amount, the currency and what is refunded. 60,000 generated bodies, fixed seed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readMoneyCall } from '../src/money.js';

let seed = 0x9e3779b9;
const rnd = (n) => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
const pick = (a) => a[rnd(a.length)];

// ---- other readings of a form body: name -> [values in order], by how a server might see the names
const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };
function reading(body, { seps = /&/, trim = false, fold = false, brackets = false, decode = true }) {
  const out = {};
  for (const part of body.split(seps)) {
    if (!part) continue;
    const i = part.indexOf('=');
    let k = i < 0 ? part : part.slice(0, i), v = i < 0 ? '' : part.slice(i + 1);
    if (decode) { k = dec(k); v = dec(v); }
    if (trim) { k = k.trim(); v = v.trim(); }
    if (brackets) k = k.replace(/^[\s[\]]+/, '').replace(/\[.*$/, '');
    if (fold) k = k.toLowerCase();
    (out[k] ||= []).push(v);
  }
  return out;
}
const READINGS = [
  {}, { seps: /[&;]/ }, { trim: true }, { fold: true }, { brackets: true }, { seps: /[&;]/, trim: true, fold: true, brackets: true }, { decode: false },
];
/** every value any reading could take for `name`: the first copy, the last copy, and whether there is more than one */
function seen(body, name) {
  const vals = new Set();
  for (const r of READINGS) {
    const l = reading(body, r)[name];
    vals.add(l === undefined ? '<none>' : l[0]); vals.add(l === undefined ? '<none>' : l.at(-1));
    if (l && l.length > 1) vals.add('<many>');
  }
  return vals;
}

// ---- generated bodies
const NAMES = { amount: ['amount', 'amount', 'amount', 'Amount', ' amount', 'amount ', '%61mount', 'amount[]', 'amount[x]', '[amount]', 'AMOUNT'], charge: ['charge', 'charge', 'charge', 'Charge', ' charge', 'charge[]'], payment_intent: ['payment_intent', 'payment_intent', 'Payment_Intent'], currency: ['currency', 'currency', 'Currency'], other: ['reason', 'metadata[order]', 'metadata[amount]', 'x', 'refund_application_fee', 'origin', 'expand[]'] };
const AMOUNTS = ['100', '2500', '0', '', '007', '+100', '-5', '1e3', '12.5', ' 100', '100 ', '%31%30%30', '1%300', '999999999999', '9999999999999', '٣٠٠', '100;amount=9', '100&amount=9', '1 00', '0x64', '%20100', '100%00'];
const CHARGES = ['ch_3NabcdefGHIJKLMNOP01', 'ch_3Nabcdef', 'ch_', 'ch_3Nabcdef%20x', 'py_3NabcdefGHIJKLMNOP01', 'pi_3NabcdefGHIJKLMNOP02', 'ch_3NabcdefGHIJKLMNOP01;amount=5', 'CH_3NabcdefGHIJKLMNOP01'];
const CURS = ['usd', 'USD', 'usd ', 'us', 'usdx', 'eur', 'usd;currency=eur', ''];
function body(kind) {
  const parts = [];
  const add = (set, val) => parts.push(`${pick(NAMES[set])}=${val}`);
  if (kind === 'refund') { add('charge', pick(CHARGES)); if (rnd(4) === 0) add('payment_intent', 'pi_3NabcdefGHIJKLMNOP02'); }
  else add('currency', pick(CURS));
  if (rnd(6) !== 0) add('amount', pick(AMOUNTS));
  for (let i = rnd(3); i > 0; i--) { const set = pick(['amount', 'charge', 'currency', 'other', 'other']); add(set, set === 'amount' ? pick(AMOUNTS) : set === 'charge' ? pick(CHARGES) : set === 'currency' ? pick(CURS) : 'v' + rnd(9)); }
  for (let i = parts.length - 1; i > 0; i--) { const j = rnd(i + 1); [parts[i], parts[j]] = [parts[j], parts[i]]; }
  return parts.join(pick(['&', '&', '&', ';', '&&', '& ']));
}

test('whenever the reader reads a refund or payout, every other way of reading the body agrees with it', () => {
  let read = 0, held = 0;
  for (let i = 0; i < 60_000; i++) {
    const kind = i % 2 ? 'refund' : 'payout';
    const b = body(kind);
    const r = readMoneyCall(kind, 'application/x-www-form-urlencoded', b, '');
    if (!r.ok) { held++; continue; }
    read++;
    const one = (name, want) => assert.deepEqual([...seen(b, name)], [want], `${kind} ${JSON.stringify(b)}: ${name}`);
    one('amount', r.amount === undefined ? '<none>' : String(r.amount));
    if (kind === 'payout') one('currency', r.currency);
    else {
      one(r.target.type, r.target.id);
      one(r.target.type === 'charge' ? 'payment_intent' : 'charge', '<none>');
      one('origin', '<none>');
    }
  }
  assert.ok(read > 300, `${read} bodies read`); // the generator hits the readable shapes often enough to mean something
  assert.ok(held > 3000, `${held} bodies held`);
});

test('the reader never accepts what a differently reading server could take for something else (hand picked)', () => {
  const C = 'ch_3NabcdefGHIJKLMNOP01';
  for (const b of [`charge=${C}&amount=100;amount=999999`, `charge=${C}&amount=100&amount=999999`, `charge=${C}&amount=100&AMOUNT=999999`, `charge=${C}&amount=100&amount[]=999999`,
    `charge=${C}&amount=100&%61mount=999999`, `charge=${C}&amount=100&amount%5B%5D=999999`, `charge=${C}&amount=100&amount[x]=999999`, `charge=${C};amount=100&amount=999999`,
    `charge=${C}&amount=100&payment_intent=pi_3NabcdefGHIJKLMNOP02`, `charge=${C}&amount=100&origin=customer_balance`, `charge=${C}&amount=100%26amount=999999`.replace('%26', '&')])
    assert.equal(readMoneyCall('refund', 'application/x-www-form-urlencoded', b, '').ok, false, b);
  // an escaped ampersand inside a value is one value, not another parameter: read as the garbage it is, and refused as an amount
  assert.equal(readMoneyCall('refund', 'application/x-www-form-urlencoded', `charge=${C}&amount=100%26amount%3D999999`, '').ok, false);
});
