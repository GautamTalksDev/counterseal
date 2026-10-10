// The Deploy Gate action (action/deploy-gate), run as GitHub runs it: a child process with INPUT_* variables, an OIDC
// token endpoint (a stub that signs like GitHub) and the real Worker code behind a real HTTP server. What it prints, what it
// outputs, how it ends, and that no secret ever reaches the log.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handle } from '../src/index.js';
import { BRAND } from '../src/brand.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { audienceFor } from '../src/gates.js';
import { readInputs, DEFAULT_SERVER, Stop } from '../../action/deploy-gate/index.mjs';
import { anon, world, gateId, approve, db } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });
const ACTION = fileURLToPath(new URL('../../action/deploy-gate/index.mjs', import.meta.url));
const RUNNER_TOKEN = 'runner-request-token-xyz';
const until = async (fn, ms = 10_000) => { const t0 = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) assert.fail('timed out waiting: ' + fn); await new Promise((r) => setTimeout(r, 25)); } };

/** the Worker over real HTTP; `before(req)` may answer a request itself (to simulate an outage or a redirect) */
async function serveWith(w, before) {
  const srv = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    w.served = (w.served || []); w.served.push(`${req.method} ${req.url}`);
    const early = before && before(req);
    if (early) { res.writeHead(early.status, { 'content-type': 'application/json', ...(early.headers || {}) }); return res.end(JSON.stringify(early.body ?? {})); }
    const h = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') h.set(k, v);
    h.set('cf-connecting-ip', '127.0.0.1');
    const pending = [];
    const r = await handle(new Request(w.base + req.url, { method: req.method, headers: h, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), w.env, { fetcher: w.fetcher, log: w.log, ctx: { waitUntil: (p) => pending.push(p) } });
    await Promise.allSettled(pending);
    res.writeHead(r.status, Object.fromEntries(r.headers)); res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  w.base = `http://127.0.0.1:${srv.address().port}`;
  return srv;
}

/** GitHub's token endpoint for a job: answers with a token signed like GitHub's for the audience asked for, as long as the
 *  runner's request token is presented. over: claims to change; mode: how to misbehave */
async function tokenStub(w, gh) {
  const stub = { requests: [], over: {}, mode: null, jwts: [] };
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    stub.requests.push({ audience: u.searchParams.get('audience'), auth: req.headers.authorization, accept: req.headers.accept });
    if (req.headers.authorization !== `Bearer ${RUNNER_TOKEN}`) { res.writeHead(401); return res.end('{}'); }
    if (stub.mode === 'error') { res.writeHead(500); return res.end('{}'); }
    if (stub.mode === 'junk') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"value":"not a token"}'); }
    const aud = u.searchParams.get('audience') || '';
    const id = /\/gate\/(gate_[0-9a-f]{24})$/.exec(aud)?.[1] || 'gate_x';
    // the Worker's audience is its own host; the action's is the server it was given (a loopback port here), so the stub
    // signs for the Worker's and the test checks separately that the action asked for the right string
    const jwt = await gh.token(gh.claims({ aud: audienceFor(w.env, id), ...stub.over }));
    stub.jwts.push(jwt);
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ count: jwt.length, value: jwt }));
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  stub.url = `http://127.0.0.1:${srv.address().port}/token?api-version=2.0`;
  stub.close = () => srv.close();
  return stub;
}

function parseOutput(text) {
  const out = {}; const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^([a-z-]+)<<(\S+)$/.exec(lines[i]); if (!m) continue;
    const val = []; i++;
    while (i < lines.length && lines[i] !== m[2]) val.push(lines[i++]);
    out[m[1]] = val.join('\n');
  }
  return out;
}

/** start the action; returns { child, done } where done resolves with { code, out, err, outputs, summary } */
function start(env, dir) {
  const files = { GITHUB_OUTPUT: join(dir, 'output'), GITHUB_STEP_SUMMARY: join(dir, 'summary') };
  writeFileSync(files.GITHUB_OUTPUT, ''); writeFileSync(files.GITHUB_STEP_SUMMARY, '');
  const child = spawn(process.execPath, [ACTION], { env: { PATH: process.env.PATH, ...files, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', (d) => (out += d)); child.stderr.on('data', (d) => (err += d));
  const done = new Promise((ok) => child.on('exit', (code, signal) => ok({ code, signal, out, err, outputs: parseOutput(readFileSync(files.GITHUB_OUTPUT, 'utf8')), summary: readFileSync(files.GITHUB_STEP_SUMMARY, 'utf8') })));
  return { child, done };
}

/** a world, a user, a gate, the stub and the server, ready to run the action against */
async function rig(over = {}, gateOver = {}) {
  const { w, gh } = await world();
  w.env.__sleep = () => new Promise((r) => setTimeout(r, 40)); // the Worker's 2 second re-read, shortened
  const u = await w.user();
  const g = await gateId(w, u, gateOver);
  const srv = await serveWith(w, over.before);
  const stub = await tokenStub(w, gh);
  const dir = mkdtempSync(join(tmpdir(), 'gate-'));
  const env = (extra = {}) => ({ INPUT_GATE: g, INPUT_SERVER: w.base, INPUT_SUMMARY: 'deploy to production', 'INPUT_TIMEOUT-MINUTES': '5', ACTIONS_ID_TOKEN_REQUEST_URL: stub.url, ACTIONS_ID_TOKEN_REQUEST_TOKEN: RUNNER_TOKEN, ...extra });
  const run = (extra) => start(env(extra), dir);
  const hold = () => until(() => db(w).prepare("SELECT id FROM holds WHERE kind = 'deploy' AND status = 'pending' ORDER BY created_at DESC").get());
  const close = () => { srv.close(); stub.close(); rmSync(dir, { recursive: true, force: true }); };
  return { w, gh, u, g, srv, stub, run, hold, close, dir };
}

const COMMANDS = /^::(add-mask|notice|error|warning)\b/;
/** nothing the action prints can be read by the runner as a command except the ones it means: masks, a notice, an error */
function onlyOwnCommands(out) { for (const l of out.split('\n')) if (l.startsWith('::')) assert.match(l, COMMANDS, 'unexpected workflow command: ' + l.slice(0, 80)); }
/** the secrets appear in the log only as masks */
function secretsOnlyAsMasks(out, secrets) {
  for (const s of secrets) {
    const lines = out.split('\n').filter((l) => l.includes(s));
    assert.ok(lines.every((l) => l === `::add-mask::${s}`), `a secret was printed: ${s.slice(0, 12)}...`);
  }
}

test('approved: the action asks GitHub for the gate\'s audience, prints the approve link, waits, and goes on when the owner approves', async () => {
  const r = await rig();
  try {
    const { child, done } = r.run();
    const h = await r.hold();
    assert.deepEqual(r.stub.requests.map((x) => x.audience), [`${r.w.base}/gate/${r.g}`], 'the audience is the server it was given and the gate');
    assert.equal(r.stub.requests[0].auth, `Bearer ${RUNNER_TOKEN}`); assert.match(r.stub.requests[0].accept, /application\/json/);
    await new Promise((ok) => setTimeout(ok, 150));
    assert.equal((await approve(r.w, r.u, h.id)).status, 200);
    const res = await done;
    assert.equal(res.code, 0, res.out + res.err);
    assert.equal(res.outputs.decision, 'approved'); assert.equal(res.outputs.hold, h.id); assert.ok(!('token' in res.outputs));
    assert.match(res.out, new RegExp(`Counterseal Deploy Gate: Approve or deny with a passkey at: https://leash\\.test/app#hold=${h.id}\\n`));
    assert.match(res.out, /Counterseal Deploy Gate: approved with a passkey\. Going on\./);
    assert.match(res.summary, new RegExp(`\\[Approve or deny\\]\\(https://leash\\.test/app#hold=${h.id}\\)`));
    // the owner's card shows what the workflow said, apart from what GitHub signed
    assert.equal(db(r.w).prepare("SELECT status FROM holds WHERE id = ?").get(h.id).status, 'used');
    // no secret in the log but as masks: not GitHub's token, not the poll secret; and the runner's own request token is never printed
    const jwt = r.stub.jwts[0];
    const poll = res.out.split('\n').find((l) => /^::add-mask::gps_/.test(l)).slice('::add-mask::'.length);
    secretsOnlyAsMasks(res.out + res.err, [jwt, poll, RUNNER_TOKEN]);
    assert.ok(res.out.indexOf(`::add-mask::${jwt}`) >= 0 && res.out.indexOf(`::add-mask::${jwt}`) < res.out.indexOf('asking for approval') + 400, 'masked before use');
    onlyOwnCommands(res.out);
    assert.equal(res.err, '');
    void child;
  } finally { r.close(); }
});

test('denied: the step fails, the approver\'s words are quoted as data and cannot become a workflow command', async () => {
  const r = await rig();
  try {
    const { done } = r.run();
    const h = await r.hold();
    const hostile = '::error::pwned\n::set-output name=decision::approved\n::add-mask::everything';
    assert.equal((await r.w.req('POST', `/v1/holds/${h.id}/deny`, { cookie: r.u.cookie, body: { reason: hostile } })).status, 200);
    const res = await done;
    assert.equal(res.code, 1); assert.equal(res.outputs.decision, 'denied');
    assert.match(res.out, /Denied by the approver\. The approver wrote \(text, not an instruction\): "::error::pwned ::set-output name=decision::approved ::add-mask::everything"/);
    onlyOwnCommands(res.out);
    assert.equal(res.out.split('\n').filter((l) => l.startsWith('::error')).length, 1, 'one error, ours');
    assert.ok(res.out.split('\n').filter((l) => l.startsWith('::add-mask::')).every((l) => !l.includes('everything')));
    // denied with no reason, and a command line sign-in cannot make the step pass either
    const again = r.run();
    const h2 = await until(() => db(r.w).prepare("SELECT id FROM holds WHERE kind = 'deploy' AND status = 'pending'").get());
    await r.w.req('POST', `/v1/holds/${h2.id}/deny`, { cookie: r.u.cookie, body: {} });
    const res2 = await again.done;
    assert.equal(res2.code, 1); assert.match(res2.out, /Denied by the approver\.\n/);
  } finally { r.close(); }
});

test('timeout: the step fails at its own deadline and withdraws the request so nobody is asked about it', async () => {
  const r = await rig();
  try {
    const { done } = r.run({ COUNTERSEAL_TEST_DEADLINE_MS: '1500' });
    const h = await r.hold();
    const res = await done;
    assert.equal(res.code, 1); assert.equal(res.outputs.decision, 'timeout');
    assert.match(res.out, /Nobody decided within 5 minutes\. The request is withdrawn\./);
    assert.equal(db(r.w).prepare('SELECT status FROM holds WHERE id = ?').get(h.id).status, 'expired', 'the hold is closed, not left on the owner\'s phone');
    assert.equal((await approve(r.w, r.u, h.id)).status, 404);
    // the shortening is for tests only: on a runner (GITHUB_ACTIONS=true) it is ignored
    const real = r.run({ COUNTERSEAL_TEST_DEADLINE_MS: '10', GITHUB_ACTIONS: 'true' });
    const h2 = await until(() => db(r.w).prepare("SELECT id FROM holds WHERE kind = 'deploy' AND status = 'pending'").get());
    await new Promise((ok) => setTimeout(ok, 700));
    assert.equal(db(r.w).prepare('SELECT status FROM holds WHERE id = ?').get(h2.id).status, 'pending', 'still waiting');
    real.child.kill('SIGTERM');
    const end = await real.done;
    assert.equal(end.code, 1); assert.equal(end.outputs.decision, 'cancelled');
    assert.equal(db(r.w).prepare('SELECT status FROM holds WHERE id = ?').get(h2.id).status, 'expired', 'a cancelled job withdraws its request');
  } finally { r.close(); }
});

test('refused: a run the gate does not accept fails with the reason, and nothing is held', async () => {
  const r = await rig();
  try {
    r.stub.over = { ref: 'refs/heads/feature' };
    const a = await r.run().done;
    assert.equal(a.code, 1); assert.equal(a.outputs.decision, 'refused');
    assert.match(a.out, /Refused\. This branch or tag is not one the gate accepts\. The ref refs\/heads\/feature is not on this gate's list\./);
    r.stub.over = { repository: 'evil/app', repository_id: '666', repository_owner: 'evil', repository_owner_id: '6', workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main' };
    const b = await r.run().done;
    assert.equal(b.code, 1); assert.match(b.out, /Refused\. This repository is not the one the gate belongs to\./);
    assert.ok(!/acme/.test(b.out), 'and it names nothing of the gate\'s repository');
    r.stub.over = {};
    const c = await r.run({ INPUT_GATE: 'gate_' + '0'.repeat(24) }).done;
    assert.equal(c.code, 1); assert.match(c.out, /There is no such gate, or it was revoked/);
    assert.equal(db(r.w).prepare("SELECT COUNT(*) n FROM holds WHERE kind = 'deploy'").get().n, 0);
    for (const x of [a, b, c]) onlyOwnCommands(x.out);
  } finally { r.close(); }
});

test('inputs and permissions are checked before anything is sent: the gate id, the timeout, the server, and id-token: write', async () => {
  const r = await rig();
  try {
    const bad = [
      [{ INPUT_GATE: '' }, /gate input is not a gate id/], [{ INPUT_GATE: 'gate_xyz' }, /gate input is not a gate id/], [{ INPUT_GATE: r.g.toUpperCase() }, /gate input is not a gate id/],
      [{ 'INPUT_TIMEOUT-MINUTES': '0' }, /timeout-minutes/], [{ 'INPUT_TIMEOUT-MINUTES': '61' }, /timeout-minutes/], [{ 'INPUT_TIMEOUT-MINUTES': '1.5' }, /timeout-minutes/], [{ 'INPUT_TIMEOUT-MINUTES': 'x' }, /timeout-minutes/], [{ 'INPUT_TIMEOUT-MINUTES': '-5' }, /timeout-minutes/],
      [{ INPUT_SERVER: 'http://example.com' }, /must be an https address/], [{ INPUT_SERVER: 'https://u:p@example.com' }, /must be an https address/], [{ INPUT_SERVER: 'https://example.com/path' }, /must be an https address/],
      [{ INPUT_SERVER: 'https://example.com/?x=1' }, /must be an https address/], [{ INPUT_SERVER: 'ftp://example.com' }, /must be an https address/], [{ INPUT_SERVER: 'not a url' }, /not a web address/],
    ];
    for (const [extra, re] of bad) { const x = await r.run(extra).done; assert.equal(x.code, 1, JSON.stringify(extra)); assert.match(x.out, re, JSON.stringify(extra)); assert.equal(x.outputs.decision, 'refused'); }
    // no OIDC address (the job lacks id-token: write, or is a pull request from a fork): the fix is named
    const noPerm = await r.run({ ACTIONS_ID_TOKEN_REQUEST_URL: '', ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }).done;
    assert.equal(noPerm.code, 1); assert.match(noPerm.out, /permissions: id-token: write/);
    // an OIDC address that is not https (outside loopback), or that GitHub does not answer, or that answers with something else
    assert.match((await r.run({ ACTIONS_ID_TOKEN_REQUEST_URL: 'http://example.com/token?x=1' }).done).out, /not https/);
    r.stub.mode = 'error'; assert.match((await r.run().done).out, /would not give this job an OIDC token \(HTTP 500\)/);
    r.stub.mode = 'junk'; assert.match((await r.run().done).out, /would not give this job an OIDC token/);
    r.stub.mode = null;
    assert.match((await r.run({ ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'wrong' }).done).out, /would not give this job an OIDC token \(HTTP 401\)/);
    assert.equal(db(r.w).prepare("SELECT COUNT(*) n FROM holds WHERE kind = 'deploy'").get().n, 0);
    assert.deepEqual(r.w.served || [], [], 'none of that reached Counterseal');
  } finally { r.close(); }
});

test('the summary is trimmed to 120 characters and cleaned; the default server is the product\'s host', async () => {
  const r = await rig();
  try {
    const long = 'deploy ' + 'x'.repeat(300) + '\n::error::injected';
    const { done } = r.run({ INPUT_SUMMARY: long });
    const h = await r.hold();
    const card = JSON.parse(db(r.w).prepare('SELECT context FROM holds WHERE id = ?').get(h.id).context).gate;
    assert.ok(card.summary.length <= 120); assert.ok(!card.summary.includes('\n'));
    await r.w.req('POST', `/v1/holds/${h.id}/deny`, { cookie: r.u.cookie, body: {} });
    await done;
  } finally { r.close(); }
  assert.equal(DEFAULT_SERVER, BRAND.origin);
  assert.ok(readFileSync(new URL('../../action/deploy-gate/action.yml', import.meta.url), 'utf8').includes(`default: '${BRAND.origin}'`), 'the action defaults to the product origin');
  const ok = readInputs({ INPUT_GATE: 'gate_' + 'a'.repeat(24) });
  assert.deepEqual(ok, { gate: 'gate_' + 'a'.repeat(24), origin: BRAND.origin, minutes: 15, summary: '' });
  assert.equal(readInputs({ INPUT_GATE: 'gate_' + 'a'.repeat(24), INPUT_SERVER: 'https://counterseal.example/' }).origin, 'https://counterseal.example');
  assert.equal(readInputs({ INPUT_GATE: 'gate_' + 'a'.repeat(24), INPUT_SERVER: 'http://localhost:8787' }).origin, 'http://localhost:8787');
  assert.throws(() => readInputs({ INPUT_GATE: 'x' }), Stop);
});

test('a frozen account stops it: asking answers 423, and a freeze while it waits ends the wait', async () => {
  const r = await rig();
  try {
    const acct = await r.w.accountId(r.u.cookie);
    const { done } = r.run();
    const h = await r.hold();
    await new Promise((ok) => setTimeout(ok, 150));
    db(r.w).prepare('UPDATE accounts SET frozen_at = ? WHERE id = ?').run(Date.now(), acct);
    const mid = await done;
    assert.equal(mid.code, 1); assert.match(mid.out, /The account was frozen while this job waited/);
    assert.equal(db(r.w).prepare('SELECT status FROM holds WHERE id = ?').get(h.id).status, 'expired', 'and it withdrew its request');
    const asking = await r.run().done;
    assert.equal(asking.code, 1); assert.match(asking.out, /The account is frozen, so nothing is approved/);
    assert.equal(asking.outputs.decision, 'refused');
  } finally { r.close(); }
});

test('an outage is retried with a fresh GitHub token each time; a redirect is never followed', async () => {
  let fails = 2, redirected = 0;
  const r = await rig({ before: (req) => (req.method === 'POST' && req.url === '/v1/gate/request' && fails-- > 0 ? { status: 503, body: { error: 'oidc_keys_unavailable', message: 'try again' } } : null) });
  try {
    const { done } = r.run();
    const h = await r.hold();
    assert.equal(r.stub.requests.length, 3, 'one GitHub token per try');
    assert.equal(new Set(r.stub.jwts).size, 3);
    assert.equal((await approve(r.w, r.u, h.id)).status, 200);
    assert.equal((await done).code, 0);
  } finally { r.close(); }
  const r2 = await rig({ before: (req) => (req.url === '/v1/gate/request' ? { status: 302, headers: { location: 'http://127.0.0.1:1/steal' }, body: {} } : null) });
  try {
    const x = await r2.run().done;
    assert.equal(x.code, 1); assert.match(x.out, /Counterseal refused the request \(302\)/);
    redirected = (r2.w.served || []).filter((s) => s.includes('/steal')).length;
    assert.equal(redirected, 0);
  } finally { r2.close(); }
});

test('two jobs with the same claims share one hold; one approval lets one of them through', async () => {
  const r = await rig();
  try {
    const a = r.run(), b = r.run();
    await until(() => db(r.w).prepare("SELECT COUNT(*) n FROM gate_polls").get().n >= 2);
    assert.equal(db(r.w).prepare("SELECT COUNT(*) n FROM holds WHERE kind = 'deploy'").get().n, 1);
    const h = await r.hold();
    assert.equal((await approve(r.w, r.u, h.id)).status, 200);
    const [x, y] = await Promise.all([a.done, b.done]);
    assert.deepEqual([x.code, y.code].sort(), [0, 1], 'exactly one went on');
    assert.match((x.code ? x : y).out, /ended as "used" and was not approved/);
  } finally { r.close(); }
});

test('phase 2: the token for the gate\'s key is masked before it is written, and it is the only place the key is', async () => {
  const { w, gh } = await world();
  w.env.__sleep = () => new Promise((r) => setTimeout(r, 40));
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'K'.repeat(36), label: 'deploy key' } })).body.id;
  const g = await gateId(w, u, { credentialId: cred, policy: { allow: [{ method: 'GET', path: '/repos/acme/**' }] } });
  const srv = await serveWith(w), stub = await tokenStub(w, gh), dir = mkdtempSync(join(tmpdir(), 'gate-'));
  try {
    const { done } = start({ INPUT_GATE: g, INPUT_SERVER: w.base, 'INPUT_TIMEOUT-MINUTES': '5', ACTIONS_ID_TOKEN_REQUEST_URL: stub.url, ACTIONS_ID_TOKEN_REQUEST_TOKEN: RUNNER_TOKEN }, dir);
    const h = await until(() => db(w).prepare("SELECT id FROM holds WHERE kind = 'deploy' AND status = 'pending'").get());
    assert.equal(db(w).prepare("SELECT COUNT(*) n FROM tokens WHERE minted_by = 'gate'").get().n, 0, 'before the approval there is no key');
    assert.equal((await approve(w, u, h.id)).status, 200);
    const res = await done;
    assert.equal(res.code, 0, res.out + res.err);
    const token = res.outputs.token;
    assert.match(token, /^lsh_[A-Za-z0-9_-]{43}$/);
    assert.equal(res.outputs.provider, 'github'); assert.equal(res.outputs['base-url'], 'https://leash.test/p/github');
    assert.ok(Math.abs(Number(res.outputs['token-expires-at']) - (Date.now() + 15 * 60_000)) < 60_000);
    secretsOnlyAsMasks(res.out + res.err, [token, stub.jwts[0]]);
    assert.ok(res.out.includes(`::add-mask::${token}`));
    assert.match(res.out, /A token for the gate's key \(valid 15 minutes\) is in the token output\./);
    // and it works, through the proxy, for what the gate's policy allows
    assert.equal((await w.req('GET', '/p/github/repos/acme/app/pulls', { bearer: token, ...anon })).status, 200);
    assert.equal((await w.req('PUT', '/p/github/user/starred/acme/app', { bearer: token, ...anon })).status, 403, 'outside the gate\'s policy');
    assert.equal((await w.req('DELETE', '/p/github/repos/acme/app/releases/1', { bearer: token, ...anon })).status, 428, 'irreversible and not pre-approved: held for a human');
    assert.ok(!res.out.includes('ghp_'), 'the real key was never anywhere near the job');
    onlyOwnCommands(res.out);
  } finally { srv.close(); stub.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('the action has no dependencies, no package, no dash in user-facing text, and names the node runtime', () => {
  const src = readFileSync(new URL('../../action/deploy-gate/index.mjs', import.meta.url), 'utf8');
  const imports = [...src.matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1]);
  assert.deepEqual(imports.sort(), ['node:crypto', 'node:fs', 'node:url'], 'only Node\'s own modules');
  assert.ok(!existsSync(new URL('../../action/deploy-gate/package.json', import.meta.url)));
  const yml = readFileSync(new URL('../../action/deploy-gate/action.yml', import.meta.url), 'utf8');
  assert.match(yml, /using: node24\n\s+main: index\.mjs/);
  for (const f of ['action.yml', 'index.mjs', 'examples/deploy.yml', 'examples/deploy-with-key.yml']) {
    const text = readFileSync(new URL('../../action/deploy-gate/' + f, import.meta.url), 'utf8');
    assert.ok(!new RegExp('[' + String.fromCharCode(0x2013, 0x2014) + ']').test(text), f + ' has an en or em dash');
    assert.ok(!/\b(LEASH|WITNESS|SIGIL|Leash|Witness|Sigil)\b(?![_-])/.test(text.replace(/GautamTalksDev\/(leash|counterseal)/g, '')), f + ' has an old product name');
  }
  const wf = readFileSync(new URL('../../action/deploy-gate/examples/deploy.yml', import.meta.url), 'utf8');
  assert.match(wf, /id-token: write/); assert.match(wf, /needs: approve/);
  assert.ok(!/@(main|master|v\d)\b/.test(wf.replace(/#.*$/gm, '')), 'the sample pins by commit, never by a moving name');
});
