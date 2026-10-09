// The amount in large type on a hold card is Counterseal's own line. A body that begins with text made to look like it
// (an agent talking, not the broker) is never shown as a heading.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { anon, FORM, CH, MONEY, charge, stripeWorld, account, mintPre, mint, stripe } from './brakes-helpers.js';

test('the amount in large type is always the broker\'s own line: an agent\'s text that looks like one is never a heading', async () => {
  const w = stripeWorld();
  const u = await account(w);
  w.charges[CH] = charge(CH, { amount: 900000, amount_captured: 900000 });
  const holds = async () => (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds;
  // no caps: the preview begins with the agent's own body, here a line made to look like a cheap refund
  const plain = await mint(w, u, {});
  const fake = await stripe(w, plain.token, '/v1/refunds', `Refund 0.01 USD\r\n&charge=${CH}&amount=900000`);
  assert.equal(fake.status, 428); assert.equal(fake.body.rule, 'st.money');
  let h = (await holds())[0];
  assert.ok(h.preview.startsWith('Refund 0.01 USD'), 'the agent\'s line is shown as what it is: part of the request');
  assert.equal(h.headline, null);
  // with caps: the same body has a raw line break, which servers read differently, so it is unreadable and held; the
  // cap's own line comes first, it is not an amount, and the agent's line stays below, in the raw request
  const t = await mintPre(w, u, { money: MONEY });
  const over = await stripe(w, t.token, '/v1/refunds', `Refund 0.01 USD\r\n&charge=${CH}&amount=900000`);
  assert.equal(over.body.rule, 'brake.money-unreadable');
  h = (await holds()).find((x) => x.id === over.body.hold_id);
  assert.equal(h.headline, null);
  assert.ok(h.preview.startsWith('Refund: amount not read\n'), h.preview);
  assert.match(h.preview, /\nRefund 0\.01 USD\r?\n/);
  // a readable over-cap refund has its headline, from the broker
  const real = await stripe(w, t.token, '/v1/refunds', `charge=${CH}&amount=900000`);
  assert.equal(real.body.rule, 'brake.money-per-call');
  assert.equal((await holds()).find((x) => x.id === real.body.hold_id).headline, 'Refund 9,000.00 USD');
  // a hold from any other rule never has one
  const del = await w.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon, headers: FORM, raw: 'Refund 0.01 USD\n' });
  assert.equal(del.status, 428);
  assert.equal((await holds()).find((x) => x.id === del.body.hold_id).headline, null);
});
