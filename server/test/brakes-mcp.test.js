// The MCP tool could only send JSON, which Stripe's v1 API refuses, so a Stripe refund could not be made through it at
// all (held or not). It now takes `form` for APIs that want a form, which is also what money caps read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { serve } from './helpers.js';
import { stripeWorld, account, mintPre, charge, CH, MONEY, spend, posts } from './brakes-helpers.js';

const CLI = fileURLToPath(new URL('../../cli/leash.mjs', import.meta.url));
function mcpCall(env, calls) {
  return new Promise((done) => {
    const p = spawn(process.execPath, [CLI, 'mcp'], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; let buf = '';
    p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { out.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); if (out.length === calls.length) p.kill(); } });
    const timer = setTimeout(() => p.kill(), 15000);
    p.on('exit', () => { clearTimeout(timer); done(out.sort((a, b) => a.id - b.id)); });
    for (const c of calls) p.stdin.write(JSON.stringify(c) + '\n');
  });
}
const call = (id, args) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'leash_request', arguments: { provider: 'stripe', ...args } } });
const text = (r) => r.result.content[0].text;

test('the MCP tool sends a form to Stripe: a refund under the caps goes through, one over them is held, and mistakes are refused before anything is sent', async () => {
  const w = stripeWorld();
  const srv = await serve(w);
  try {
    const u = await account(w);
    w.charges[CH] = charge(CH);
    const t = await mintPre(w, u, { money: MONEY });
    const env = { LEASH_URL: w.base, LEASH_TOKENS: `stripe=${t.token}` };
    const [ok, over, both, odd, nested, list, json] = await mcpCall(env, [
      call(1, { method: 'POST', path: '/v1/refunds', form: { charge: CH, amount: 2500, reason: 'duplicate' } }),
      call(2, { method: 'POST', path: '/v1/refunds', form: { charge: CH, amount: 9000 } }),
      call(3, { method: 'POST', path: '/v1/refunds', form: { charge: CH }, body: { charge: CH } }),
      call(4, { method: 'POST', path: '/v1/refunds', form: { 'charge&amount': CH } }),
      call(5, { method: 'POST', path: '/v1/customers', form: { email: 'a b@example.com', metadata: { order: '77', note: 'x&y=z' }, balance: 0, flag: true, none: null } }),
      call(6, { method: 'POST', path: '/v1/customers', form: { 'expand': ['a', 'b'] } }),
      call(7, { method: 'POST', path: '/v1/customers', body: { email: 'j@example.com' } }),
    ]);
    assert.match(text(ok), /^HTTP 200/);
    assert.match(text(over), /^HTTP 428[\s\S]*held_for_approval[\s\S]*brake\.money-per-call/);
    assert.equal(text(both), 'Send body (JSON) or form, not both.');
    assert.match(text(odd), /not a plain word/);
    assert.deepEqual(spend(w).map((s) => s.amount), [2500]);
    // the calls run side by side, so find each by what it sent
    const sent = posts(w).map((p) => ({ path: new URL(p.url).pathname, ctype: p.headers['content-type'], body: p.body }));
    assert.equal(sent.length, 4, 'the refund and three customers: nothing for the held, refused or doubled calls');
    const find = (f) => sent.find(f);
    assert.deepEqual(find((x) => x.path === '/v1/refunds'), { path: '/v1/refunds', ctype: 'application/x-www-form-urlencoded', body: `charge=${CH}&amount=2500&reason=duplicate` }, 'the refund goes out as the form it was');
    assert.equal(find((x) => x.body.startsWith('email=')).body, 'email=a+b%40example.com&metadata%5Border%5D=77&metadata%5Bnote%5D=x%26y%3Dz&balance=0&flag=true', 'nested fields are name[key], and no value can start another field');
    assert.equal(find((x) => x.body.startsWith('expand')).body, 'expand%5B0%5D=a&expand%5B1%5D=b');
    assert.deepEqual(find((x) => x.ctype === 'application/json'), { path: '/v1/customers', ctype: 'application/json', body: '{"email":"j@example.com"}' }, 'a JSON body is exactly what it was');
    assert.match(text(list), /^HTTP 200/);
    assert.match(text(json), /^HTTP 200/);
    assert.match(text(nested), /^HTTP 200/);
  } finally { srv.close(); }
});
