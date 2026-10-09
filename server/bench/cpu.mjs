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
