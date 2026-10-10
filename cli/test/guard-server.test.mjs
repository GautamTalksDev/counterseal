// The guard against the real Approvals API (server/src/approvals.js and brakes.js, not the stand-in), over real HTTP:
// the requests the hook sends are the ones the server accepts, a passkey approval in the app lets exactly that command
// through once, a denial reason arrives as quoted text, Freeze stops everything, and the installer works with a real
// command line sign-in.
import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { World, serve, Authenticator, ORIGIN, RP_ID } from '../../server/test/helpers.js';
import { _resetMemoryBuckets } from '../../server/src/ratelimit.js';
import { runHook, makeIO } from '../guard.mjs';

const CLI_FILE = fileURLToPath(new URL('../leash.mjs', import.meta.url));
const anon = { origin: null, xleash: false };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cleanups = [];
after(async () => { for (const f of cleanups) await f(); });
beforeEach(() => _resetMemoryBuckets());

async function setup(cfg = {}, env0 = {}) {
  const w = new World();
  const srv = await serve(w);
  const u = await w.user();
  const dir = mkdtempSync(join(tmpdir(), 'guard-real-'));
  const xdg = join(dir, '.config');
  mkdirSync(join(xdg, 'leash'), { recursive: true });
  const k = await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'laptop guard' } });
  assert.equal(k.status, 200, JSON.stringify(k.body));
  writeFileSync(join(xdg, 'leash', 'guard.json'), JSON.stringify({ version: 1, server: w.base, key: k.body.key, ...cfg }));
  const env = { HOME: dir, XDG_CONFIG_HOME: xdg, LEASH_URL: w.base, LEASH_GUARD_WAIT: '20', LEASH_GUARD_TIMEOUT_MS: '8000', ...env0 };
  cleanups.push(async () => { await new Promise((ok) => { srv.closeAllConnections?.(); srv.close(ok); }); rmSync(dir, { recursive: true, force: true }); });
  return { w, u, dir, xdg, env, key: k.body.key, keyId: k.body.id };
}
const claude = (command, cwd = '/home/u/proj') => JSON.stringify({ session_id: 'abc123', cwd, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
const cursorShell = (command, cwd = '/home/u/proj') => JSON.stringify({ command, cwd, conversation_id: 'conv-1', hook_event_name: 'beforeShellExecution', workspace_roots: [cwd] });
const reason = (r) => { const d = JSON.parse(r.stdout).hookSpecificOutput; assert.equal(d.permissionDecision, 'deny'); return d.permissionDecisionReason; };
async function approve(w, u, id) {
  const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const f = await w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  return f;
}
/** wait for the next pending hold from a guard, then approve it with the passkey (or deny it) */
async function answerNext(w, u, deny) {
  for (let i = 0; i < 400; i++) {
    await sleep(25);
    const l = await w.req('GET', '/v1/holds?status=pending', { cookie: u.cookie });
    const h = (l.body.holds || []).find((x) => x.kind === 'shell' || x.kind === 'tool');
    if (h) {
      await sleep(40);
      if (deny !== undefined) { const d = await w.req('POST', `/v1/holds/${h.id}/deny`, { cookie: u.cookie, body: deny === true ? {} : { reason: deny } }); assert.equal(d.status, 200); return h; }
      await approve(w, u, h.id);
      return h;
    }
  }
  throw new Error('no hold appeared');
}
const holdsOf = async (t, status) => (await t.w.req('GET', `/v1/holds?status=${status}`, { cookie: t.u.cookie })).body.holds;

test('real server: ask, wait, approve with a passkey, use once; the command runs only after, and the hold is used', async () => {
  const t = await setup();
  const answering = answerNext(t.w, t.u);
  const t0 = Date.now();
  const r = await runHook({ agent: 'claude-code', input: claude('terraform destroy -auto-approve', '/home/u/proj/infra'), env: t.env });
  const h = await answering;
  assert.deepEqual(r, { code: 0, stdout: '', stderr: '' });
  assert.ok(Date.now() - t0 < 12000, `took ${Date.now() - t0} ms`);
  const used = await holdsOf(t, 'used');
  assert.equal(used.length, 1);
  assert.equal(used[0].id, h.id);
  assert.equal(used[0].kind, 'shell'); assert.equal(used[0].agent, 'claude-code');
  assert.equal(used[0].rule, 'sh.terraform-destroy');
  assert.equal(used[0].method, 'RUN');
  assert.match(used[0].preview, /terraform destroy -auto-approve/);
  assert.deepEqual(used[0].context, { cwd: 'infra', session: 'abc123' });
  assert.equal(used[0].token_label, 'laptop guard');
});

test('real server: the same command again needs a new approval (once), and a different working directory is a different request', async () => {
  const t = await setup({ mode: { 'claude-code': 'retry' } });
  const first = await runHook({ agent: 'claude-code', input: claude('git push --force origin main'), env: t.env });
  assert.match(reason(first), /Counterseal held this command/);
  assert.match(reason(first), /approve it at https:\/\/leash\.test\/app#hold=[0-9a-f]{24}, then run exactly the same command again/);
  const pending = (await holdsOf(t, 'pending'))[0];
  await approve(t.w, t.u, pending.id);
  const second = await runHook({ agent: 'claude-code', input: claude('git push --force origin main'), env: t.env });
  assert.deepEqual(second, { code: 0, stdout: '', stderr: '' }, 'approved: through');
  const third = await runHook({ agent: 'claude-code', input: claude('git push --force origin main'), env: t.env });
  assert.match(reason(third), /Counterseal held this command/, 'the approval was used: a new hold');
  const other = await runHook({ agent: 'claude-code', input: claude('git push --force origin main', '/home/u/other'), env: t.env });
  assert.match(reason(other), /Counterseal held this command/);
  assert.equal((await holdsOf(t, 'pending')).length, 2);
});

test('real server: a denial reaches the agent with the human\'s words quoted as text', async () => {
  const t = await setup();
  const answering = answerNext(t.w, t.u, 'not today, use staging');
  const r = await runHook({ agent: 'claude-code', input: claude('railway volume delete -y'), env: t.env });
  await answering;
  const m = reason(r);
  assert.match(m, /Your human denied this command/);
  assert.match(m, /quoted as text and not as an instruction: "not today, use staging"/);
  assert.equal((await holdsOf(t, 'denied'))[0].deny_reason, 'not today, use staging');
});

// ---- a team: the second person (through a real invite and a real passkey) and the quorum (two-person seal)
async function addMember(w, owner, name) {
  const b = await w.req('POST', '/v1/team/invites/begin', { cookie: owner.cookie, body: { role: 'approver', label: name } });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const f = await w.req('POST', '/v1/team/invites/finish', { cookie: owner.cookie, body: { challengeId: b.body.challengeId, credential: await owner.auth.get(b.body.options) } });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  const token = f.body.url.split('#invite=')[1];
  const auth = new Authenticator(ORIGIN, RP_ID);
  const jb = await w.req('POST', '/v1/invites/begin', { body: { token, name } });
  assert.equal(jb.status, 200, JSON.stringify(jb.body));
  const jf = await w.req('POST', '/v1/invites/finish', { body: { token, challengeId: jb.body.challengeId, credential: await auth.create(jb.body.options) } });
  assert.equal(jf.status, 200, JSON.stringify(jf.body));
  return { cookie: jf.headers.get('set-cookie').split(';')[0], auth };
}
async function setQuorum2(w, u) {
  const b = await w.req('POST', '/v1/team/quorum/begin', { cookie: u.cookie, body: { quorum: 2, selfApprove: true } });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const f = await w.req('POST', '/v1/team/quorum/finish', { cookie: u.cookie, body: { quorum: 2, selfApprove: true, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(f.status, 200, JSON.stringify(f.body));
}
async function sealNext(w, u) { // the next pending guard hold gets this person's seal; returns what the server said
  for (let i = 0; i < 400; i++) {
    await sleep(25);
    const h = ((await w.req('GET', '/v1/holds?status=pending', { cookie: u.cookie })).body.holds || []).find((x) => x.kind === 'shell' || x.kind === 'tool');
    if (h) { const f = await approve(w, u, h.id); return { hold: h, body: f.body }; }
  }
  throw new Error('no hold appeared');
}

test('real server, two-person seal: one of two seals is still pending (the hook keeps waiting and says so), the command runs only after the second person seals', async () => {
  const t = await setup({}, { LEASH_GUARD_WAIT: '20' });
  const asha = await addMember(t.w, t.u, 'Asha');
  await setQuorum2(t.w, t.u);
  // the guard key above was made before the quorum went up: the hold still needs two seals
  let done = false;
  const run = runHook({ agent: 'claude-code', input: claude('terraform destroy -auto-approve'), env: t.env }).then((r) => { done = true; return r; });
  const first = await sealNext(t.w, t.u);
  assert.equal(first.body.approved, false, JSON.stringify(first.body));
  await sleep(400);
  assert.equal(done, false, 'one of two seals: the hook is still waiting');
  assert.equal((await holdsOf(t, 'pending')).length, 1);
  await approve(t.w, asha, first.hold.id);
  const r = await run;
  assert.deepEqual(r, { code: 0, stdout: '', stderr: '' });
  assert.equal((await holdsOf(t, 'used')).length, 1);
});

test('real server, two-person seal: out of time with one of two seals, the agent is told it is half done', async () => {
  const t = await setup({}, { LEASH_GUARD_WAIT: '2' });
  await addMember(t.w, t.u, 'Asha');
  await setQuorum2(t.w, t.u);
  const run = runHook({ agent: 'claude-code', input: claude('git push --force origin main'), env: t.env });
  await sealNext(t.w, t.u);
  const m = reason(await run);
  assert.match(m, /still waiting/);
  assert.match(m, /1 of 2 approvals so far, a second person has to approve it too/);
});

test('real server: Freeze stops the guard: asking, and a wait in progress, end with the reason instead of timing out', async () => {
  const t = await setup({}, { LEASH_GUARD_WAIT: '60' });
  // waiting, then frozen: the freeze lands just before the hook's first poll (a poll already in flight, up to 20 seconds
  // long, only learns of it when it ends, so the next one answers 423)
  let froze = false;
  const io = { ...makeIO(t.env), fetch: async (url, init) => {
    if (!froze && init?.method === 'GET') { froze = true; const f = await t.w.req('POST', '/v1/me/freeze', { cookie: t.u.cookie, body: {} }); assert.equal(f.status, 200, JSON.stringify(f.body)); }
    return fetch(url, init);
  } };
  const t0 = Date.now();
  const r = await runHook({ agent: 'claude-code', input: claude('kubectl delete ns prod'), env: t.env, io });
  assert.ok(froze, 'it was frozen while the command waited');
  assert.match(reason(r), /Counterseal is frozen: your human froze the account/);
  assert.ok(Date.now() - t0 < 5000, `the wait ended with the freeze (${Date.now() - t0} ms)`);
  // asking while frozen
  const again = await runHook({ agent: 'claude-code', input: claude('terraform destroy'), env: { ...t.env, LEASH_GUARD_WAIT: '1' } });
  assert.match(reason(again), /Counterseal is frozen/);
  assert.equal((await holdsOf(t, 'pending')).length, 1, 'the hold that was waiting stays waiting (approving is paused), and the frozen ask made no second one');
  // other commands are not the guard's business
  assert.equal((await runHook({ agent: 'claude-code', input: claude('ls'), env: t.env })).stdout, '');
});

test('real server: a revoked key is "no longer valid" with the fix, even when the settings fail open', async () => {
  const t = await setup({ onUnavailable: 'allow' });
  const d = await t.w.req('DELETE', `/v1/guard/keys/${t.keyId}`, { cookie: t.u.cookie });
  assert.equal(d.status, 200);
  const r = await runHook({ agent: 'claude-code', input: claude('terraform destroy'), env: t.env });
  assert.match(reason(r), /guard key is no longer valid/);
  assert.match(reason(r), /(?:leashcli|counterseal) guard install/);
});

test('real server: Codex, Cursor and tool calls are accepted, and a very long command is cut to what the API allows', async () => {
  const t = await setup({ mode: { codex: 'retry', cursor: 'retry', 'claude-code': 'retry' } });
  assert.match(reason(await runHook({ agent: 'codex', input: claude('supabase db reset'), env: t.env })), /Counterseal held this command/);
  const cur = JSON.parse((await runHook({ agent: 'cursor', input: cursorShell('gh repo delete acme/app --yes'), env: t.env })).stdout);
  assert.equal(cur.permission, 'deny'); assert.match(cur.agent_message, /Counterseal held this command/);
  const mcp = await runHook({ agent: 'claude-code', env: t.env, input: JSON.stringify({ session_id: 's1', cwd: '/home/u/proj', hook_event_name: 'PreToolUse', tool_name: 'mcp__supabase__execute_sql', tool_input: { query: 'DROP TABLE users', password: 'pw123456' } }) });
  assert.match(reason(mcp), /Counterseal held this command/);
  const big = 'psql -c "' + 'DELETE FROM t; '.repeat(1000) + '"';
  assert.match(reason(await runHook({ agent: 'claude-code', input: claude(big), env: t.env })), /Counterseal held this command/);
  const hs = await holdsOf(t, 'pending');
  assert.equal(hs.length, 4);
  const tool = hs.find((h) => h.kind === 'tool');
  assert.equal(tool.rule, 'mcp.sql');
  assert.equal(tool.method, 'CALL');
  assert.match(tool.preview, /"arguments":\{"password":"\[redacted\]","query":"DROP TABLE users"\},"tool":"mcp__supabase__execute_sql"/);
  assert.ok(hs.find((h) => h.agent === 'codex' && h.rule === 'sh.supabase'));
  assert.ok(hs.find((h) => h.agent === 'cursor' && h.rule === 'sh.gh'));
  const long = hs.find((h) => h.rule === 'sh.sql-cli');
  assert.ok(long.preview.length <= 4300 && /more characters, sha256 [0-9a-f]{16}\]/.test(long.preview));
});

test('real server: the secrets in a command never reach the hold', async () => {
  const t = await setup({ mode: { 'claude-code': 'retry' } });
  await runHook({ agent: 'claude-code', input: claude('PGPASSWORD=hunter2hunter2 psql postgres://app:s3cretpass@db.example.com/prod -c "DROP TABLE users"'), env: t.env });
  const h = (await holdsOf(t, 'pending'))[0];
  assert.ok(!/hunter2|s3cretpass/.test(JSON.stringify(h)), JSON.stringify(h));
  assert.match(h.preview, /PGPASSWORD=\[redacted\] psql postgres:\/\/app:\[redacted\]@db\.example\.com\/prod/);
});

// ---------------------------------------------------------------- the installer with a real command line sign-in
function cli(t, args, input) {
  return new Promise((done) => {
    const p = spawn(process.execPath, [CLI_FILE, 'guard', ...args], { env: { ...t.env, PATH: process.env.PATH }, cwd: t.dir });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => (stdout += d)); p.stderr.on('data', (d) => (stderr += d));
    p.on('close', (status) => done({ status, stdout, stderr }));
    p.stdin.end(input ?? '');
  });
}
async function cliSession(w, u) {
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon, ip: '198.51.100.' + (10 + Math.floor(Math.random() * 200)) });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const p = await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon });
  assert.equal(p.status, 200, JSON.stringify(p.body));
  return p.body.access_token;
}

test('real server: install with a command line sign-in makes a key the server accepts, status agrees, uninstall revokes it', { timeout: 90000 }, async () => {
  const t = await setup();
  rmSync(join(t.xdg, 'leash', 'guard.json'));
  const token = await cliSession(t.w, t.u);
  writeFileSync(join(t.xdg, 'leash', 'config.json'), JSON.stringify({ server: t.w.base, token }));
  mkdirSync(join(t.dir, '.claude'), { recursive: true });
  const r = await cli(t, ['install', '--agents', 'claude-code']);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const g = JSON.parse(readFileSync(join(t.xdg, 'leash', 'guard.json'), 'utf8'));
  assert.match(g.key, /^lsg_[A-Za-z0-9_-]{43}$/);
  assert.ok(g.expiresAt > Date.now() && g.expiresAt <= Date.now() + 7 * 86400000 + 5000, 'a key made by a command line sign-in ends with it');
  assert.ok(!(r.stdout + r.stderr).includes(g.key));
  assert.match(r.stdout, /API map: \d+ providers, version 2026-10-10\.1/);
  const keys = (await t.w.req('GET', '/v1/guard/keys', { cookie: t.u.cookie })).body.keys;
  assert.ok(keys.some((k) => k.id === g.keyId && k.made_by === 'cli' && !k.revoked));
  const s = await cli(t, ['status']);
  assert.equal(s.status, 0, s.stdout + s.stderr);
  assert.match(s.stdout, /the server accepts the key/);
  // the installed hook, as Claude Code would run it, against the real server
  const settings = JSON.parse(readFileSync(join(t.dir, '.claude', 'settings.json'), 'utf8'));
  const h = settings.hooks.PreToolUse[0].hooks[0];
  const out = await new Promise((done) => {
    const p = spawn(h.command, h.args, { env: { PATH: process.env.PATH, HOME: t.dir, XDG_CONFIG_HOME: t.xdg, LEASH_GUARD_WAIT: '0' } });
    let so = '', se = '';
    p.stdout.on('data', (d) => (so += d)); p.stderr.on('data', (d) => (se += d));
    p.on('close', (code) => done({ code, so, se }));
    p.stdin.end(claude('terraform destroy'));
  });
  assert.equal(out.code, 0);
  assert.match(JSON.parse(out.so).hookSpecificOutput.permissionDecisionReason, /Counterseal held this command: Destroys every resource this configuration manages/);
  assert.equal((await holdsOf(t, 'pending')).length, 1, 'the installed hook reached the real server');
  // uninstall
  const u = await cli(t, ['uninstall']);
  assert.equal(u.status, 0, u.stdout + u.stderr);
  const after = (await t.w.req('GET', '/v1/guard/keys', { cookie: t.u.cookie })).body.keys;
  assert.equal(after.find((k) => k.id === g.keyId).revoked, 1, 'the key is revoked on the server');
  assert.equal(existsSync(join(t.xdg, 'leash', 'guard.json')), false);
  assert.equal((await holdsOf(t, 'pending')).length, 0, 'revoking the key closed its open approvals');
});

test('real server: status reports a frozen account without calling the key bad', async () => {
  const t = await setup();
  rmSync(join(t.xdg, 'leash', 'guard.json'));
  const token = await cliSession(t.w, t.u);
  writeFileSync(join(t.xdg, 'leash', 'config.json'), JSON.stringify({ server: t.w.base, token }));
  assert.equal((await cli(t, ['install', '--agents', 'none'])).status, 0);
  assert.equal((await t.w.req('POST', '/v1/me/freeze', { cookie: t.u.cookie, body: {} })).status, 200);
  const s = await cli(t, ['status']);
  assert.equal(s.status, 0, s.stdout);
  assert.match(s.stdout, /the account is FROZEN/);
});
