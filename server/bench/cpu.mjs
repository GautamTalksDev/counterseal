// CPU of the hot paths, measured in Node (node bench/cpu.mjs). Workers Free allows 10 ms of CPU per invocation.
// In Workers, D1 and Durable Object storage calls are I/O, not CPU of this Worker, so time spent inside node:sqlite is
// measured separately and subtracted ("worker" below). The log append runs in the Durable Object, a separate
// invocation with its own CPU limit; it is reported on its own line. These are Node numbers, not a load test on Workers.
import { World } from '../test/helpers.js';
import { handle } from '../src/index.js';
import { signBrokerRequest, generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';
import { canonical } from '../src/receipts.js';
import { b64u } from '../src/util.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';

const N = Number(process.argv[2]) || 60;
let sqlNs = 0n;
function timeSql(raw) { // wrap node:sqlite statements so their time can be taken out
  const prep = raw.prepare.bind(raw);
  raw.prepare = (sql) => {
    const st = prep(sql);
    const wrap = (fn) => (...a) => { const t = process.hrtime.bigint(); try { return fn.apply(st, a); } finally { sqlNs += process.hrtime.bigint() - t; } };
    return { get: wrap(st.get), all: wrap(st.all), run: wrap(st.run) };
  };
  const ex = raw.exec.bind(raw);
  raw.exec = (s) => { const t = process.hrtime.bigint(); try { return ex(s); } finally { sqlNs += process.hrtime.bigint() - t; } };
}
const median = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const p95 = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length * 0.95)]; };

const w = new World();
w.env.UNLIMITED = '1'; w.env.GLOBAL_DAILY_CAP = '100000000'; // measure CPU, not quotas
timeSql(w.env.DB.raw); timeSql(w.sql.raw);
const u = await w.user();
const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'B'.repeat(36) } })).body.id;
const jwk = await generateAgentKey(), key = await importAgentKey(jwk);
const b = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
const ak = (await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b.challengeId, proof: await proveAgentKey(key, b.sign) } })).body;
const plain = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, policy: { perMinute: 600 } } })).body.token;
const bound = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, agentKeyId: ak.id, policy: { perMinute: 600 } } })).body.token;
const rkey = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
const skp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const spub = b64u(await crypto.subtle.exportKey('raw', skp.publicKey));
const sch = (await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: spub } })).body;
const skey = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { signerPublicKey: spub, signerChallengeId: sch.challengeId, signerProof: b64u(await crypto.subtle.sign({ name: 'Ed25519' }, skp.privateKey, new TextEncoder().encode(sch.sign))) } })).body.key;

// the log append alone (Durable Object side)
const realAppend = w.log.append;
let doNs = 0n;
w.log.append = async (i, n) => { const c0 = process.cpuUsage(); const s0 = sqlNs; try { return await realAppend(i, n); } finally { const c = process.cpuUsage(c0); doNs += BigInt((c.user + c.system) * 1000) - (sqlNs - s0); } };

const anon = { origin: null, xleash: false };
/** a request as the Worker gets it: built outside the measurement; only handle() and its waitUntil work are timed */
function request(method, path, { bearer, cookie, body, raw, headers = {} } = {}) {
  const h = { 'cf-connecting-ip': '203.0.113.7', ...headers };
  if (bearer) h.authorization = 'Bearer ' + bearer;
  if (cookie) { h.cookie = cookie; h.origin = 'https://leash.test'; h['x-leash'] = '1'; }
  const b = raw ?? (body !== undefined ? JSON.stringify(body) : undefined);
  if (b !== undefined && !h['content-type']) h['content-type'] = 'application/json';
  return new Request(path.startsWith('http') ? path : 'https://leash.test' + path, { method, headers: h, body: b });
}
async function measure(name, make, ok = (s) => s < 300) {
  const worker = [], dobj = [];
  for (let i = 0; i < N; i++) {
    _resetMemoryBuckets();
    const req = await make(i);
    const pending = [];
    sqlNs = 0n; doNs = 0n;
    const c0 = process.cpuUsage();
    const r = await handle(req, w.env, { fetcher: w.fetcher, log: w.log, ctx: { waitUntil: (p) => pending.push(p) } });
    for (let j = 0; j < pending.length; j++) await pending[j];
    const c = process.cpuUsage(c0);
    if (!ok(r.status)) throw new Error(name + ' failed: ' + r.status + ' ' + (await r.text()).slice(0, 300));
    const total = (c.user + c.system) * 1000; // ns
    worker.push(Number(BigInt(total) - sqlNs - doNs) / 1e6);
    dobj.push(Number(doNs) / 1e6);
  }
  console.log(`${name.padEnd(58)} worker median ${median(worker).toFixed(2)} ms, p95 ${p95(worker).toFixed(2)} ms${median(dobj) > 0 ? `; log append (Durable Object) median ${median(dobj).toFixed(2)} ms` : ''}`);
}
const url = (p) => 'https://leash.test/p/github' + p;
await measure('proxy GET, unbound token (allowed, not sealed)', () => request('GET', url('/repos/a/b'), { bearer: plain }));
await measure('proxy GET, bound token (RFC 9421 verify + nonce)', async () => { const h = await signBrokerRequest({ method: 'GET', url: url('/repos/a/b') }, { key, kid: ak.keyid }); return request('GET', url('/repos/a/b'), { bearer: bound, headers: h }); });
await measure('proxy POST, bound token, 1 KB body (allowed + sealed)', async (i) => { const body = JSON.stringify({ title: 'x'.repeat(1000), i }); const h = await signBrokerRequest({ method: 'POST', url: url('/repos/a/b/issues'), body, contentType: 'application/json' }, { key, kid: ak.keyid }); return request('POST', url('/repos/a/b/issues'), { bearer: bound, raw: body, headers: { ...h, 'content-type': 'application/json' } }); });
// a token may have 20 requests waiting (approval fatigue cap): close earlier holds outside the measurement
await measure('proxy DELETE, bound token (held + push check + sealed)', async (i) => { w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); const h =await signBrokerRequest({ method: 'DELETE', url: url('/repos/a/r' + i) }, { key, kid: ak.keyid }); return request('DELETE', url('/repos/a/r' + i), { bearer: bound, headers: h }); }, (st) => st === 428);
// map 2026-10-10: Shopify reads its mutations from the GraphQL document (every rule asks the same memoised classifier), and
// a store address is checked on every call
const shCred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'shopify', secret: 'shpat_' + 'S'.repeat(32), host: 'bench-store.myshopify.com' } })).body.id;
const shTok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: shCred, policy: { perMinute: 600 } } })).body.token;
const shUrl = 'https://leash.test/p/shopify/admin/api/2026-07/graphql.json';
const rwCred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'railway', secret: 'rw_' + 'R'.repeat(30) } })).body.id;
const rwTok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: rwCred, policy: { perMinute: 600 } } })).body.token;
const shQuery = (q) => request('POST', shUrl, { bearer: shTok, body: { query: q } });
await measure('proxy Shopify GraphQL query (POST, allowed + sealed)', () => shQuery('query { products(first: 10) { edges { node { id title variants(first: 5) { edges { node { id sku } } } } } } }'));
await measure('proxy Shopify GraphQL mutation, plain (productUpdate)', () => shQuery('mutation { productUpdate(input: {id: "gid://shopify/Product/1", title: "t"}) { product { id } } }'));
await measure('proxy Shopify GraphQL delete (held + push check + sealed)', async (i) => { w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); return shQuery(`mutation { productDelete(input: {id: "gid://shopify/Product/${i}"}) { deletedProductId } }`); }, (s) => s === 428);
await measure('proxy Shopify GraphQL, 200 KB document (worst case, held)', async (i) => { w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); return shQuery('query { shop { name } } '.repeat(8000) + `mutation { refundCreate(input: {orderId: "${i}"}) { refund { id } } }`); }, (s) => s === 428);
// the same 200 KB document on GitHub (map 2026-10-09, unchanged): a baseline for the Shopify line above
await measure('proxy GitHub GraphQL, 200 KB document (worst case, held)', async (i) => { w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); return request('POST', url('/graphql'), { bearer: plain, body: { query: 'query { viewer { login } } '.repeat(8000) + `mutation { deleteRepository(input: {repositoryId: "${i}"}) { clientMutationId } }` } }); }, (s) => s === 428);
// work limits (providers.js LIMITS): the worst a GraphQL request can cost is bounded before anything is parsed
const heldDoc = (kb) => 'query { viewer { login } } '.repeat(Math.floor(kb * 1024 / 28)) + 'mutation { deleteRepository(input: {repositoryId: "R"}) { clientMutationId } }';
const closeHolds = () => w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run();
await measure('GitHub GraphQL, 30 KB document, just inside the limits (held)', async () => { closeHolds(); return request('POST', url('/graphql'), { bearer: plain, body: { query: heldDoc(30) } }); }, (s) => s === 428);
await measure('GitHub GraphQL, 120 KB body (5 KB query + 115 KB variable), inside the limits', async () => { closeHolds(); return request('POST', url('/graphql'), { bearer: plain, body: { query: 'mutation($v: String) { updateIssue(input: {body: $v}) { clientMutationId } }', variables: { v: 'x'.repeat(115000) } } }); }, (s) => s === 428);
await measure('GitHub GraphQL, 1 MB of "a&a&..." (worst case for the form reading)', async () => { closeHolds(); return request('POST', url('/graphql'), { bearer: plain, raw: 'a&'.repeat(500000), headers: { 'content-type': 'application/x-www-form-urlencoded' } }); }, (s) => s === 428);
await measure('Railway GraphQL, 1 MB body (held unread)', async () => { closeHolds(); return request('POST', 'https://leash.test/p/railway/', { bearer: rwTok, body: { query: heldDoc(1000) } }); }, (s) => s === 428);
await measure('approve a hold (passkey verify + sealed)', async (i) => {
  const h = await w.req('DELETE', url('/repos/z/q' + i), { bearer: plain, ...anon });
  const bb = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  const credential = await u.auth.get(bb.body.options);
  return request('POST', `/v1/holds/${h.body.hold_id}/approve/finish`, { cookie: u.cookie, body: { challengeId: bb.body.challengeId, credential } });
});
// approvals for a coding agent's commands (guard keys, lsg_): ask, poll, approve, use
const gkey = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'bench guard' } })).body.key;
// outside the timing: close earlier holds and reset the per-key create limit, so the caps (20 waiting, 60 an hour) do not stop the bench
const fresh = () => { w.env.DB.raw.prepare("UPDATE holds SET status = 'expired' WHERE status = 'pending'").run(); w.env.DB.raw.prepare("DELETE FROM ratelimits WHERE bucket LIKE 'gcreate:%' OR bucket LIKE 'pushhold:%' OR bucket LIKE 'acct:%'").run(); };
const askBody = (i) => ({ kind: 'shell', agent: 'claude-code', rule: 'sh.terraform-destroy', why: 'Destroys every resource in the state.', summary: 'terraform destroy', detail: `terraform destroy -auto-approve -target=module.m${i} ` + 'x'.repeat(3000), context: { cwd: 'infra', session: 's1' }, map: '2026-10-10.1' });
await measure('POST /v1/approvals, 3 KB command (held + push check + sealed)', (i) => { fresh(); return request('POST', '/v1/approvals', { bearer: gkey, body: askBody(i) }); }, (st) => st === 202);
fresh();
const pending = (await w.req('POST', '/v1/approvals', { bearer: gkey, body: askBody('poll'), origin: null, xleash: false })).body;
await measure('GET /v1/approvals/:id (poll, no wait)', () => request('GET', `/v1/approvals/${pending.id}`, { bearer: gkey }));
// a full 20 s long poll on a pending hold: 11 reads; the 2 s timer is stubbed (waiting costs no CPU on Workers)
w.env.__sleep = async () => {};
await measure('GET /v1/approvals/:id?wait=20 (11 reads, timer stubbed)', () => request('GET', `/v1/approvals/${pending.id}?wait=20`, { bearer: gkey }));
delete w.env.__sleep;
await measure('approve a guard hold (passkey verify + sealed)', async (i) => {
  fresh();
  const h = (await w.req('POST', '/v1/approvals', { bearer: gkey, body: askBody('a' + i), origin: null, xleash: false })).body;
  const bb = await w.req('POST', `/v1/holds/${h.id}/approve/begin`, { cookie: u.cookie, body: {} });
  const credential = await u.auth.get(bb.body.options);
  return request('POST', `/v1/holds/${h.id}/approve/finish`, { cookie: u.cookie, body: { challengeId: bb.body.challengeId, credential } });
});
await measure('POST /v1/approvals/:id/use (atomic use + sealed)', async (i) => {
  fresh();
  const h = (await w.req('POST', '/v1/approvals', { bearer: gkey, body: askBody('u' + i), origin: null, xleash: false })).body;
  const bb = await w.req('POST', `/v1/holds/${h.id}/approve/begin`, { cookie: u.cookie, body: {} });
  const ok = await w.req('POST', `/v1/holds/${h.id}/approve/finish`, { cookie: u.cookie, body: { challengeId: bb.body.challengeId, credential: await u.auth.get(bb.body.options) } });
  if (ok.status !== 200) throw new Error('approve failed: ' + JSON.stringify([h, bb.body, ok.body]).slice(0, 500));
  return request('POST', `/v1/approvals/${h.id}/use`, { bearer: gkey, body: { hash: h.hash } });
});
await measure('POST /v1/holds/:id/deny with a reason (sealed)', async (i) => {
  fresh();
  const h = (await w.req('POST', '/v1/approvals', { bearer: gkey, body: askBody('d' + i), origin: null, xleash: false })).body;
  return request('POST', `/v1/holds/${h.id}/deny`, { cookie: u.cookie, body: { reason: 'Not today: use the staging workspace.' } });
});
const { LIMITS } = await import('../src/receipts.js');
await measure(`POST /v1/receipts, ${LIMITS.MAX_BATCH} unsigned (the cap)`, (i) => request('POST', '/v1/receipts', { bearer: rkey, body: { receipts: Array.from({ length: LIMITS.MAX_BATCH }, (_, j) => ({ agent: 'a', action: `x${i}.${j}`, input_sha256: 'a'.repeat(64) })) } }));
await measure(`POST /v1/receipts, ${LIMITS.MAX_SIGNED_BATCH} signed (the cap)`, async (i) => {
  const rs = await Promise.all(Array.from({ length: LIMITS.MAX_SIGNED_BATCH }, async (_, j) => { const rc = { agent: 'a', action: `s${i}.${j}`, ts: Date.now() + j }; return { ...rc, sig: { alg: 'ed25519', value: b64u(await crypto.subtle.sign({ name: 'Ed25519' }, skp.privateKey, new TextEncoder().encode(canonical(rc)))) } }; }));
  return request('POST', '/v1/receipts', { bearer: skey, body: { receipts: rs } });
});
await measure('POST /v1/receipts, 1 unsigned', (i) => request('POST', '/v1/receipts', { bearer: rkey, body: { receipt: { agent: 'a', action: 'one ' + i } } }));
await measure('GET /v1/stats (cached head)', () => request('GET', '/v1/stats'));
await measure('GET /v1/log/proof/inclusion', () => request('GET', '/v1/log/proof/inclusion?index=3'));

// ---- Deploy Gate: GitHub's OIDC token (RS256, WebCrypto) and the gate's own paths. The stand-in issuer signs real RSA-2048
// tokens outside the timing; the Worker's fetch of GitHub's key set is a stub (no network), as in the tests.
const { makeGithub } = await import('../test/gh.js');
const { audienceFor } = await import('../src/gates.js');
const { verifyGithubToken, _resetOidc } = await import('../src/oidc.js');
const gh = await makeGithub();
w.env.__oidcFetch = gh.fetch;
{
  // the signature and claims check alone, with GitHub's key already imported (the steady state: once per isolate and key)
  const aud = 'https://leash.test/gate/gate_bench';
  const toks = []; for (let i = 0; i < N; i++) toks.push(await gh.token(gh.claims({ aud, run_id: String(i) })));
  const time = async (fn) => { const c0 = process.cpuUsage(); await fn(); const c = process.cpuUsage(c0); return (c.user + c.system) / 1000; };
  _resetOidc(); await verifyGithubToken(w.env, toks[0], { audience: aud });
  const warm = []; for (const t of toks) warm.push(await time(() => verifyGithubToken(w.env, t, { audience: aud })));
  console.log(`${'verify a GitHub OIDC token (RS256, claims; key cached)'.padEnd(58)} worker median ${median(warm).toFixed(2)} ms, p95 ${p95(warm).toFixed(2)} ms`);
  // the first token of an isolate: key set fetched (a stub here) and the RSA key imported, then verified
  const cold = []; for (let i = 0; i < Math.min(N, 30); i++) { _resetOidc(); cold.push(await time(() => verifyGithubToken(w.env, toks[i], { audience: aud }))); }
  console.log(`${'verify the first token (key set parsed, RSA key imported)'.padEnd(58)} worker median ${median(cold).toFixed(2)} ms, p95 ${p95(cold).toFixed(2)} ms`);
  // WebCrypto's RSASSA-PKCS1-v1_5 verify by itself, for comparison
  const k = [...gh.keys.values()][0];
  const pub = await crypto.subtle.importKey('jwk', k.jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const [h, p, s] = toks[0].split('.'), sig = Uint8Array.from(Buffer.from(s, 'base64url')), msg = new TextEncoder().encode(`${h}.${p}`);
  const raw = []; for (let i = 0; i < N; i++) raw.push(await time(() => crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pub, sig, msg)));
  console.log(`${'crypto.subtle.verify, RSA-2048 PKCS1 v1.5, alone'.padEnd(58)} worker median ${median(raw).toFixed(2)} ms, p95 ${p95(raw).toFixed(2)} ms`);
}
_resetOidc();
const mkGate = async (over = {}) => {
  const b = await w.req('POST', '/v1/gates/passkey/begin', { cookie: u.cookie, body: {} });
  const r = await w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options), label: 'bench gate', repository: 'acme/app', workflows: ['.github/workflows/deploy.yml'], refs: ['refs/heads/main'], ...over } });
  if (r.status !== 200) throw new Error('gate: ' + JSON.stringify(r.body));
  return r.body.id;
};
const gate1 = await mkGate(), gate2 = await mkGate({ credentialId: cred, policy: { perMinute: 600 } });
const jwtFor = async (g, over = {}) => gh.token(gh.claims({ aud: audienceFor(w.env, g), ...over }));
// outside the timing: close earlier holds and reset the limits (10 waiting a gate, 30 new holds an hour a gate)
const clearGate = () => { w.env.DB.raw.prepare("UPDATE holds SET status = 'expired' WHERE status = 'pending'").run(); w.env.DB.raw.prepare("DELETE FROM ratelimits WHERE bucket LIKE 'gate:%' OR bucket LIKE 'pushhold:%' OR bucket LIKE 'acct:%'").run(); };
const askGate = async (g, over, extra = {}) => request('POST', '/v1/gate/request', { bearer: await jwtFor(g, over), body: { gate: g, summary: 'deploy to production', ...extra } });
await measure('POST /v1/gate/request, new hold (verify + jti + held + push check + sealed)', (i) => { clearGate(); return askGate(gate1, { run_id: String(10_000 + i) }); }, (st) => st === 202);
clearGate();
const waiting = (await w.req('POST', '/v1/gate/request', { bearer: await jwtFor(gate1, { run_id: '99' }), origin: null, xleash: false, body: { gate: gate1 } })).body;
await measure('POST /v1/gate/request, the same run asked again (verify + jti + poll secret)', () => askGate(gate1, { run_id: '99' }), (st) => st === 202);
await measure('GET /v1/gate/status/:id (poll, no wait)', () => request('GET', `/v1/gate/status/${waiting.id}`, { bearer: waiting.poll }));
// a full 20 s long poll: 11 reads; the 2 s timer is stubbed (waiting costs no CPU on Workers)
w.env.__sleep = async () => {};
await measure('GET /v1/gate/status/:id?wait=20 (11 reads, timer stubbed)', () => request('GET', `/v1/gate/status/${waiting.id}?wait=20`, { bearer: waiting.poll }));
delete w.env.__sleep;
const approvedGate = async (g, i) => {
  clearGate();
  const r = (await w.req('POST', '/v1/gate/request', { bearer: await jwtFor(g, { run_id: String(50_000 + i) }), origin: null, xleash: false, body: { gate: g } })).body;
  const bb = await w.req('POST', `/v1/holds/${r.id}/approve/begin`, { cookie: u.cookie, body: {} });
  const ok = await w.req('POST', `/v1/holds/${r.id}/approve/finish`, { cookie: u.cookie, body: { challengeId: bb.body.challengeId, credential: await u.auth.get(bb.body.options) } });
  if (ok.status !== 200) throw new Error('approve failed: ' + JSON.stringify([r, ok.body]).slice(0, 400));
  return r;
};
await measure('GET /v1/gate/status/:id, approved (spend once + bind + sealed)', async (i) => { const r = await approvedGate(gate1, i); return request('GET', `/v1/gate/status/${r.id}`, { bearer: r.poll }); });
await measure('GET /v1/gate/status/:id, approved, phase 2 (+ a 15 minute token)', async (i) => { const r = await approvedGate(gate2, 100_000 + i); return request('GET', `/v1/gate/status/${r.id}`, { bearer: r.poll }); });
await measure('POST /v1/gate/cancel/:id', async (i) => { clearGate(); const r = (await w.req('POST', '/v1/gate/request', { bearer: await jwtFor(gate1, { run_id: String(70_000 + i) }), origin: null, xleash: false, body: { gate: gate1 } })).body; return request('POST', `/v1/gate/cancel/${r.id}`, { bearer: r.poll, body: {} }); });
clearGate();

// ---- Brakes: the breaker's counters, money caps (a Stripe lookup stub, no network), Freeze and a reset
const stripeCred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'stripe', secret: 'sk_test_' + 'B'.repeat(24) } })).body.id;
const CHG = 'ch_3NbenchChargeABCDEF01';
w.reply = (to, init) => {
  const j = (o) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json' } });
  return init.method === 'GET' && to.includes('/v1/charges/') ? j({ id: CHG, object: 'charge', amount: 900000, amount_captured: 900000, amount_refunded: 0, captured: true, currency: 'usd' }) : j({ ok: true });
};
const ceremony = async (begin, finish, body = {}) => { const b = await w.req('POST', begin, { cookie: u.cookie, body }); return w.req('POST', finish, { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } }); };
const mintFor = async (credentialId, policy) => (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId, policy } })).body.token;
const limited = await mintFor(cred, { perMinute: 600, limits: { writesPerHour: 5000, repeatsPer5Min: 100 } });
const capped = (await ceremony('/v1/tokens/passkey/begin', '/v1/tokens/passkey/finish', { credentialId: stripeCred, label: 'support agent', policy: { perMinute: 600, money: { currency: 'usd', perCall: 100000, perDay: 99999999999 }, limits: { writesPerHour: 5000, repeatsPer5Min: 100 } } })).body.token;
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
// (named apart from the approvals section's fresh(): two branches each declared one, and the merged file did not parse)
const clearLimits = () => w.env.DB.raw.prepare('DELETE FROM ratelimits').run(); // the account limit (300 writes a minute) is not what is measured
await measure('proxy POST, both breaker limits (counted + allowed + sealed)', (i) => request('POST', url('/repos/a/b/issues'), { bearer: limited, body: { title: 'brakes', i } }));
await measure('proxy POST /v1/refunds, under the caps (lookup, reserve, count, sealed)', (i) => request('POST', 'https://leash.test/p/stripe/v1/refunds', { bearer: capped, raw: `charge=${CHG}&amount=${100 + i}`, headers: FORM }));
await measure('proxy POST /v1/refunds, over the cap (lookup + held + push check + sealed)', (i) => { w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); return request('POST', 'https://leash.test/p/stripe/v1/refunds', { bearer: capped, raw: `charge=${CHG}&amount=${200000 + i}`, headers: FORM }); }, (st) => st === 428);
await measure('freeze (any signed-in session)', async () => { clearLimits(); if (w.env.DB.raw.prepare('SELECT frozen_at FROM accounts').get().frozen_at) await ceremony('/v1/me/unfreeze/begin', '/v1/me/unfreeze/finish'); return request('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} }); });
await measure('proxy GET, frozen account (423, nothing else read or written)', () => request('GET', url('/repos/a/b'), { bearer: plain }), (st) => st === 423);
await measure('unfreeze (passkey verify)', async () => {
  clearLimits();
  await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} });
  const b = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {} });
  return request('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
});
await measure('reset a tripped token (passkey verify)', async (i) => {
  clearLimits();
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'trips ' + i, policy: { limits: { writesPerHour: 1 } } } });
  await w.req('POST', '/p/github/repos/a/b/issues', { bearer: t.body.token, ...anon, body: { n: 1 } });
  await w.req('POST', '/p/github/repos/a/b/issues', { bearer: t.body.token, ...anon, body: { n: 2 } }); // trips it
  const b = await w.req('POST', `/v1/tokens/${t.body.id}/reset/begin`, { cookie: u.cookie, body: {} });
  return request('POST', `/v1/tokens/${t.body.id}/reset/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
});

// the two-person seal (team): a second approver joins through an invite and the quorum goes to 2. The setup of each
// sample (a fresh hold, the first seal, a fresh invite) is outside the measurement.
const { Authenticator, ORIGIN, RP_ID } = await import('../test/helpers.js');
const inviteFor = async (name) => {
  clearLimits();
  const ib = await w.req('POST', '/v1/team/invites/begin', { cookie: u.cookie, body: { role: 'approver', label: 'bench' } });
  const inv = await w.req('POST', '/v1/team/invites/finish', { cookie: u.cookie, body: { challengeId: ib.body.challengeId, credential: await u.auth.get(ib.body.options) } });
  const token = inv.body.url.split('#invite=')[1], auth = new Authenticator(ORIGIN, RP_ID);
  const jb = await w.req('POST', '/v1/invites/begin', { body: { token, name } });
  return { token, auth, jb };
};
const first = await inviteFor('Bench Approver');
const joined = await w.req('POST', '/v1/invites/finish', { body: { token: first.token, challengeId: first.jb.body.challengeId, credential: await first.auth.create(first.jb.body.options) } });
const second = { cookie: joined.headers.get('set-cookie').split(';')[0], auth: first.auth };
await ceremony('/v1/team/quorum/begin', '/v1/team/quorum/finish', { quorum: 2, selfApprove: true });
await measure('GET /v1/team (members, passkeys, invites)', () => request('GET', '/v1/team', { cookie: u.cookie }));
const heldNow = async (i) => { clearLimits(); w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run(); return (await w.req('DELETE', url('/repos/seal/r' + i), { bearer: plain, ...anon })).body.hold_id; };
const sealStep = async (who, id) => { const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: who.cookie, body: {} }); return { challengeId: b.body.challengeId, credential: await who.auth.get(b.body.options) }; };
await measure('approve, two seals: the first (passkey verify, seal, nudge check)', async (i) => {
  const id = await heldNow('a' + i);
  return request('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: await sealStep(u, id) });
});
await measure('approve, two seals: the second (passkey verify, seal, approved + sealed)', async (i) => {
  const id = await heldNow('b' + i);
  await w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: await sealStep(u, id) });
  return request('POST', `/v1/holds/${id}/approve/finish`, { cookie: second.cookie, body: await sealStep(second, id) });
});
await measure('join a team (registration verify, invite used, member + passkey, alert check)', async (i) => {
  w.env.DB.raw.prepare("UPDATE members SET removed_at = 1 WHERE name LIKE 'Joiner%'").run(); // keep the team under 10 people
  const j = await inviteFor('Joiner ' + i);
  return request('POST', '/v1/invites/finish', { body: { token: j.token, challengeId: j.jb.body.challengeId, credential: await j.auth.create(j.jb.body.options) }, headers: { origin: 'https://leash.test' } });
});

// break glass and alert channels (two-person seal, part 2b). The stand-in for the chat services answers at once, so this is
// our own CPU (building the message, unsealing the address, checking it), not the services' time.
w.env.__channelFetch = async () => new Response('ok');
await measure('open a break-glass window (passkey verify, insert, team alert)', async () => {
  clearLimits(); w.env.DB.raw.prepare('DELETE FROM windows').run();
  const b = await w.req('POST', '/v1/team/breakglass/begin', { cookie: u.cookie, body: { minutes: 30, reason: 'bench' } });
  return request('POST', '/v1/team/breakglass/finish', { cookie: u.cookie, body: { minutes: 30, reason: 'bench', challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
});
await measure('proxy DELETE the map would hold, let through by an open window (+ sealed)', async (i) => { clearLimits(); return request('DELETE', url('/repos/bg/r' + i), { bearer: plain }); });
w.env.DB.raw.prepare('UPDATE windows SET closed_at = 1').run();
const chAdd = await ceremony('/v1/team/channels/begin', '/v1/team/channels/finish', { kind: 'slack', label: 'bench', url: 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678' });
if (chAdd.status !== 200) throw new Error('channel: ' + JSON.stringify(chAdd.body));
await measure('add an alert channel (passkey verify, seal the address, insert)', async () => {
  clearLimits(); w.env.DB.raw.prepare('DELETE FROM channels').run();
  const body = { kind: 'slack', label: 'bench', url: 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678' };
  const b = await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body });
  return request('POST', '/v1/team/channels/finish', { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
});
await measure('proxy DELETE held, with one alert channel (hold + push check + unseal + post stubbed)', async (i) => {
  clearLimits(); w.env.DB.raw.prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run();
  return request('DELETE', url('/repos/bg/h' + i), { bearer: plain });
}, (s) => s === 428);
