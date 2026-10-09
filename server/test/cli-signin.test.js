// CLI sign-in against device-code phishing (RFC 8628 section 5.4; the IETF cross-device flows BCP): an attacker starts
// leashcli login and sends someone the code. The code is never in a link, the approval screen says what is granted and
// where the sign-in started next to where you are, the code lives 5 minutes, the session 7 days, everything a CLI
// session makes ends with it, every device is alerted, one tap revokes it all, and starts, lookups and approvals are
// rate limited. The published leashcli 0.1.1 still signs in.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { World, serve } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';

beforeEach(() => _resetMemoryBuckets());
const DE = { country: 'DE', asOrganization: 'Hetzner Online GmbH', asn: 24940 };
const CA = { country: 'CA', asOrganization: 'Rogers Communications Canada Inc.', asn: 812 };
const CA2 = { country: 'CA', asOrganization: 'Bell Canada', asn: 577 };
const CODE = /^[BCDFGHJKLMNPQRSTVWXZ2-9]{4}-[BCDFGHJKLMNPQRSTVWXZ2-9]{4}$/;
const cliReq = { origin: null, xleash: false };
const start = (w, o = {}) => w.req('POST', '/v1/device/start', { ...cliReq, body: {}, ...o });
const poll = (w, d) => w.req('POST', '/v1/device/poll', { ...cliReq, body: { device_code: d.device_code } });
async function approve(w, u, code, o = {}) {
  const b = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: code }, ...o });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: code, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) }, ...o });
}
async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url, init) => { w.pushes.push({ url, init }); return new Response(null, { status: 201 }); };
}

test('the code is never in a link, lives 5 minutes, and where the sign-in started is kept coarse (never the IP)', async () => {
  const w = new World();
  const d = await start(w, { cf: DE });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(d.body.verification_uri, 'https://leash.test/app#device', 'the plain page: the code is typed, not carried');
  assert.ok(!('verification_uri_complete' in d.body));
  assert.ok(!d.body.verification_uri.includes(d.body.user_code));
  assert.equal(d.body.expires_in, 300); assert.equal(d.body.interval, 5);
  assert.match(d.body.user_code, CODE);
  const rows = w.env.DB.raw.prepare('SELECT * FROM device_codes').all();
  assert.equal(rows[0].country, 'DE'); assert.equal(rows[0].network, 'Hetzner Online GmbH'); assert.equal(rows[0].asn, 24940);
  assert.ok(!JSON.stringify(rows).includes('203.0.113'), 'no IP address is stored');
  // codes are spread over the whole alphabet (no modulo bias toward the first letters)
  const seen = new Set();
  for (let i = 0; i < 9; i++) { _resetMemoryBuckets(); for (const ch of (await start(w, { ip: '198.51.100.' + i })).body.user_code.replace('-', '')) seen.add(ch); }
  assert.ok(seen.size > 20, 'codes use the 28-character alphabet');
  // after 5 minutes the code is gone for both sides
  const u = await w.user('Late', '192.0.2.50');
  await timeShift(5 * 60_000 + 1000, async () => {
    assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: d.body.user_code } })).body.error, 'code_not_found');
    assert.equal((await poll(w, d.body)).body.error, 'expired_token');
  });
  // Cloudflare's network name is untrusted text: control and direction characters are dropped, length capped
  const odd = await start(w, { ip: '192.0.2.99', cf: { country: 'xx', asOrganization: 'Evil‮Corp\u0000' + 'x'.repeat(100), asn: -1 } });
  const r = w.env.DB.raw.prepare('SELECT country, network, asn FROM device_codes WHERE user_code = ?').get(odd.body.user_code);
  assert.equal(r.country, null); assert.equal(r.asn, null); assert.ok(!/[‮\u0000]/.test(r.network)); assert.equal(r.network.length, 60);
});

test('the approval screen: when and where the sign-in started next to where you are; web session only; typed codes are normalised', async () => {
  const w = new World();
  const u = await w.user();
  const d = (await start(w, { cf: DE })).body;
  // typed in lower case, with a space instead of the dash
  const look = await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, cf: CA, body: { user_code: d.user_code.toLowerCase().replace('-', ' ') } });
  assert.equal(look.status, 200, JSON.stringify(look.body));
  assert.equal(look.body.user_code, d.user_code);
  assert.deepEqual(look.body.from, { country: 'DE', network: 'Hetzner Online GmbH' });
  assert.deepEqual(look.body.here, { country: 'CA', network: 'Rogers Communications Canada Inc.' });
  assert.deepEqual(look.body.same, { country: false, network: false }, 'a different country and network is flagged');
  assert.equal(look.body.session_days, 7);
  assert.ok(look.body.started_at <= look.body.now && look.body.now - look.body.started_at < 60_000);
  // the same network: no flag
  const d2 = (await start(w, { cf: CA, ip: '198.51.100.20' })).body;
  assert.deepEqual((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, cf: CA, body: { user_code: d2.user_code } })).body.same, { country: true, network: true });
  assert.deepEqual((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, cf: CA2, body: { user_code: d2.user_code } })).body.same, { country: true, network: false });
  // unknown on either side: no claim either way
  assert.deepEqual((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: d2.user_code } })).body.same, { country: null, network: null });
  // a CLI session (an agent on the laptop can read it) can never look up, deny or approve a sign-in
  const cli = await signIn(w, u);
  for (const p of ['/v1/device/lookup', '/v1/device/deny', '/v1/device/approve/begin']) {
    assert.equal((await w.req('POST', p, { bearer: cli, ...cliReq, body: { user_code: d.user_code } })).body.error, 'passkey_required', p);
  }
  // not a code at all, or a code nobody started
  assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: 'ABCD-EF01' } })).body.error, 'bad_user_code');
  assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: 'BBBB-2222' } })).body.error, 'code_not_found');
  assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: {} })).body.error, 'bad_user_code');
});

/** a full sign-in for u; returns the CLI bearer */
async function signIn(w, u, cf) {
  _resetMemoryBuckets();
  const d = (await start(w, { cf, ip: '198.51.100.' + Math.floor(Math.random() * 200) })).body;
  const a = await approve(w, u, d.user_code);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  const p = await poll(w, d);
  assert.equal(p.status, 200, JSON.stringify(p.body));
  return p.body.access_token;
}

test('"No, deny it": the command line gets access_denied, nothing is signed in, and the denial is on the record', async () => {
  const w = new World();
  const u = await w.user();
  const d = (await start(w, { cf: DE })).body;
  assert.equal((await poll(w, d)).body.error, 'authorization_pending');
  const no = await w.req('POST', '/v1/device/deny', { cookie: u.cookie, body: { user_code: d.user_code } });
  assert.equal(no.status, 200, JSON.stringify(no.body));
  assert.equal((await poll(w, d)).body.error, 'access_denied');
  assert.equal((await approve(w, u, d.user_code)).body.error, 'code_not_found', 'a denied code cannot be approved after all');
  assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM sessions WHERE kind = 'cli'").get().n, 0);
  const e = w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'cli_signin_denied'").get();
  assert.deepEqual(JSON.parse(e.detail), { user_code: d.user_code, country: 'DE', network: 'Hetzner Online GmbH' });
});

test('an approved sign-in: 7 days, on the record, every device alerted, listed with where it started; one tap revokes it and all it made', async () => {
  const w = new World();
  await withVapid(w);
  const u = await w.user();
  const id = await w.accountId(u.cookie);
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } })).status, 200);
  const d = (await start(w, { cf: DE })).body;
  assert.equal((await approve(w, u, d.user_code)).status, 200);
  assert.equal(w.pushes.length, 0, 'nothing is signed in yet');
  const p = await poll(w, d);
  assert.equal(p.status, 200);
  const cli = p.body.access_token;
  assert.equal(p.body.expires_in, 7 * 86400, 'a CLI session lasts 7 days');
  assert.equal(w.pushes.length, 1, 'every device with alerts on is woken at once');
  assert.equal(w.pushes[0].init.body, '', 'the alert carries nothing; the phone fetches it over its own session');
  const signedIn = JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'cli_signed_in' AND account_id = ?").get(id).detail);
  assert.equal(signedIn.country, 'DE'); assert.match(signedIn.session, /^[0-9a-f]{24}$/);
  // what the phone shows: a recent sign-in, with its id for the one-tap revoke
  const al = await w.req('GET', '/v1/alerts', { cookie: u.cookie });
  assert.equal(al.body.signins[0].id, signedIn.session); assert.equal(al.body.signins[0].network, 'Hetzner Online GmbH');
  assert.deepEqual(al.body.holds, []);
  const list = (await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions;
  assert.equal(list.length, 1); assert.equal(list[0].id, signedIn.session); assert.equal(list[0].country, 'DE');
  assert.ok(Math.abs(list[0].expires_at - (Date.now() + 7 * 86400_000)) < 60_000);
  assert.ok(!JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM sessions').all()).includes(cli), 'only a hash of the session is kept');
  assert.equal((await w.req('GET', '/v1/sessions', { bearer: cli, ...cliReq })).body.sessions[0].current, true);

  // what the CLI session makes: a token (capped at the session's end), an agent key, a receipts key
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'S'.repeat(36) } })).body.id;
  const t = await w.req('POST', '/v1/tokens', { bearer: cli, ...cliReq, body: { credentialId: cred, ttlHours: 24 * 90 } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  assert.ok(t.body.expiresAt <= list[0].expires_at, 'a CLI-minted token never outlives its session');
  assert.match(t.body.note, /ends with this command line sign-in/);
  const short = await w.req('POST', '/v1/tokens', { bearer: cli, ...cliReq, body: { credentialId: cred, ttlHours: 2 } });
  assert.ok(Math.abs(short.body.expiresAt - (Date.now() + 2 * 3600_000)) < 60_000, 'a shorter token keeps its own expiry');
  const web = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, ttlHours: 24 * 90 } })).body;
  assert.ok(web.expiresAt > list[0].expires_at, 'the app can still mint long-lived tokens');
  const jwk = await generateAgentKey(); const key = await importAgentKey(jwk);
  const kb = (await w.req('POST', '/v1/agent-keys/begin', { bearer: cli, ...cliReq, body: { publicKey: jwk.x } })).body;
  const ak = await w.req('POST', '/v1/agent-keys', { bearer: cli, ...cliReq, body: { publicKey: jwk.x, challengeId: kb.challengeId, proof: await proveAgentKey(key, kb.sign) } });
  assert.equal(ak.status, 200, JSON.stringify(ak.body));
  const rk = (await w.req('POST', '/v1/keys', { bearer: cli, ...cliReq, body: { label: 'cli' } })).body;
  assert.match(rk.key, /^lsr_/);
  // and a guard key (approvals for a coding agent's commands): it never outlives the session either
  const gk = await w.req('POST', '/v1/guard/keys', { bearer: cli, ...cliReq, body: { label: 'laptop guard' } });
  assert.equal(gk.status, 200, JSON.stringify(gk.body));
  assert.equal(gk.body.expiresAt, list[0].expires_at, 'a CLI-made guard key ends with its session');
  const sid = signedIn.session;
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) n FROM tokens WHERE session_id = ?').get(sid).n, 2);
  assert.equal(w.env.DB.raw.prepare('SELECT session_id FROM agent_keys').get().session_id, sid);
  assert.equal(w.env.DB.raw.prepare('SELECT session_id FROM api_keys').get().session_id, sid);
  assert.equal(w.env.DB.raw.prepare('SELECT session_id FROM guard_keys').get().session_id, sid);

  // revoking: never by a CLI session, never another account's
  assert.equal((await w.req('DELETE', `/v1/sessions/${sid}`, { bearer: cli, ...cliReq })).body.error, 'passkey_required');
  const eve = await w.user('Eve', '192.0.2.77');
  assert.equal((await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: eve.cookie })).status, 404);
  assert.equal((await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: u.cookie, xleash: false })).body.error, 'csrf');
  const rv = await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: u.cookie });
  assert.equal(rv.status, 200, JSON.stringify(rv.body));
  assert.deepEqual(rv.body.revoked, { tokens: 2, agentKeys: 1, receiptsKeys: 1, guardKeys: 1 });
  assert.equal((await w.req('GET', `/v1/approvals/${'0'.repeat(24)}`, { bearer: gk.body.key, ...cliReq })).body.error, 'guard_key_invalid', 'its guard key is revoked with it');
  assert.equal((await w.req('GET', '/v1/tokens', { bearer: cli, ...cliReq })).body.error, 'signed_out');
  assert.equal((await w.req('GET', '/p/github/user', { bearer: t.body.token, ...cliReq })).body.error, 'token_invalid');
  assert.equal((await w.req('GET', '/p/github/user', { bearer: web.token, ...cliReq })).status, 200, 'what the web session made is untouched');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: rk.key, ...cliReq, body: { receipt: { agent: 'a', action: 'b' } } })).body.error, 'api_key_invalid');
  assert.ok(w.env.DB.raw.prepare('SELECT revoked_at FROM agent_keys').get().revoked_at);
  assert.deepEqual((await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions.map((s) => [s.id, s.status]), [[sid, 'revoked']]);
  assert.ok(w.env.DB.raw.prepare("SELECT 1 FROM audit WHERE action = 'cli_session_revoked' AND account_id = ?").get(id));
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
});

test('a phished command line that signs itself out cannot hide: the alert and the list still show it, and revoking it revokes what it made', async () => {
  const w = new World();
  await withVapid(w);
  const u = await w.user();
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } });
  const cli = await signIn(w, u, DE);
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'H'.repeat(36) } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { bearer: cli, ...cliReq, body: { credentialId: cred } })).body.token;
  const rk = (await w.req('POST', '/v1/keys', { bearer: cli, ...cliReq, body: { label: 'quiet' } })).body;
  assert.ok(rk.expiresAt <= Date.now() + 7 * 86400_000 + 60_000, 'a receipts key made by a CLI session ends with it');
  // and a guard key, with an approval waiting (a phisher's guard could keep asking)
  const gk = (await w.req('POST', '/v1/guard/keys', { bearer: cli, ...cliReq, body: { label: 'quiet guard' } })).body;
  const ask = await w.req('POST', '/v1/approvals', { bearer: gk.key, ...cliReq, body: { kind: 'shell', agent: 'codex', rule: 'sh.rm', why: 'Deletes the home folder.', summary: 'rm -rf ~', detail: 'rm -rf ~' } });
  assert.equal(ask.status, 202, JSON.stringify(ask.body));
  // it signs itself out at once
  assert.equal((await w.req('POST', '/v1/auth/logout', { bearer: cli, ...cliReq, body: {} })).status, 200);
  assert.equal((await w.req('GET', '/v1/tokens', { bearer: cli, ...cliReq })).body.error, 'signed_out');
  // the phone still says so, and the list still has it, as ended
  const al = (await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.signins;
  assert.equal(al.length, 1); assert.equal(al[0].country, 'DE');
  const s = (await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions;
  assert.deepEqual(s.map((x) => [x.id, x.status]), [[al[0].id, 'ended']]);
  assert.equal((await w.req('GET', '/p/github/user', { bearer: tok, ...cliReq })).status, 200, 'what it made still works until revoked');
  const rv = await w.req('DELETE', `/v1/sessions/${al[0].id}`, { cookie: u.cookie });
  assert.equal(rv.status, 200, JSON.stringify(rv.body));
  assert.equal(rv.body.ended, false); assert.deepEqual(rv.body.revoked, { tokens: 1, agentKeys: 0, receiptsKeys: 1, guardKeys: 1 });
  assert.equal((await w.req('GET', `/v1/approvals/${ask.body.id}`, { bearer: gk.key, ...cliReq })).body.error, 'guard_key_invalid');
  assert.equal(w.env.DB.raw.prepare('SELECT status FROM holds WHERE id = ?').get(ask.body.id).status, 'expired', 'its waiting approval is closed');
  assert.equal((await w.req('GET', '/p/github/user', { bearer: tok, ...cliReq })).body.error, 'token_invalid');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: rk.key, ...cliReq, body: { receipt: { agent: 'a', action: 'b' } } })).body.error, 'api_key_invalid');
  assert.equal((await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions[0].status, 'revoked');
  // an id that never signed in to this account is not found
  assert.equal((await w.req('DELETE', `/v1/sessions/${'0'.repeat(24)}`, { cookie: u.cookie })).status, 404);
  const eve = await w.user('Eve', '192.0.2.88');
  assert.equal((await w.req('DELETE', `/v1/sessions/${al[0].id}`, { cookie: eve.cookie })).status, 404);
  // and a receipts key made by a CLI session stops when the session's 7 days end, even if nobody revokes anything
  const cli2 = await signIn(w, u, DE);
  const rk2 = (await w.req('POST', '/v1/keys', { bearer: cli2, ...cliReq, body: { label: 'later' } })).body;
  await timeShift(7 * 86400_000 + 60_000, async () => {
    assert.equal((await w.req('POST', '/v1/receipts', { bearer: rk2.key, ...cliReq, body: { receipt: { agent: 'a', action: 'b' } } })).body.error, 'api_key_invalid');
  });
});

test('rate limits: 10 sign-in starts an hour per network, 10 lookups per 10 minutes and 10 approvals an hour per account', async () => {
  const w = new World();
  for (let i = 0; i < 10; i++) assert.equal((await start(w)).status, 200, 'start ' + i);
  const over = await start(w);
  assert.equal(over.status, 429); assert.equal(over.body.error, 'slow_down');
  assert.equal((await start(w, { ip: '198.51.100.9' })).status, 200, 'another network is not affected');
  const u = await w.user('A', '192.0.2.1'), v = await w.user('B', '192.0.2.2');
  for (let i = 0; i < 10; i++) assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: 'BBBB-2222' } })).status, 404);
  assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: 'BBBB-2222' } })).status, 429, 'codes cannot be guessed');
  assert.equal((await w.req('POST', '/v1/device/deny', { cookie: u.cookie, body: { user_code: 'BBBB-2222' } })).status, 429, 'deny shares the budget');
  assert.equal((await w.req('POST', '/v1/device/lookup', { cookie: v.cookie, body: { user_code: 'BBBB-2222' } })).status, 404, 'per account');
  const codes = [];
  for (let i = 0; i < 11; i++) codes.push((await start(w, { ip: '203.0.113.' + (100 + i) })).body.user_code);
  for (let i = 0; i < 10; i++) assert.equal((await w.req('POST', '/v1/device/approve/begin', { cookie: v.cookie, body: { user_code: codes[i] } })).status, 200);
  assert.equal((await w.req('POST', '/v1/device/approve/begin', { cookie: v.cookie, body: { user_code: codes[10] } })).status, 429);
});

// ---- the CLIs, end to end over HTTP
const CLI_NEW = fileURLToPath(new URL('../../cli/leash.mjs', import.meta.url));
const CLI_OLD = fileURLToPath(new URL('./fixtures/leashcli-0.1.1/leash.mjs', import.meta.url));
function runCli(file, args, env) {
  const p = spawn(process.execPath, [file, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const io = { out: '', err: '' };
  p.stdout.on('data', (d) => { io.out += d; });
  p.stderr.on('data', (d) => { io.err += d; });
  const kill = setTimeout(() => p.kill(), 30_000);
  const done = new Promise((ok) => p.on('exit', (code) => { clearTimeout(kill); ok({ code, ...io }); }));
  const code = new Promise((ok, fail) => {
    const t = setInterval(() => { const m = /([BCDFGHJKLMNPQRSTVWXZ2-9]{4}-[BCDFGHJKLMNPQRSTVWXZ2-9]{4})/.exec(io.err); if (m) { clearInterval(t); ok(m[1]); } }, 50);
    done.then(() => { clearInterval(t); fail(new Error('CLI exited without a code: ' + io.err)); });
  });
  code.catch(() => {}); // commands without a sign-in code (logout) never print one
  return { code, done, io };
}

test('the published leashcli 0.1.1 still signs in: it prints verification_uri and user_code, the person types the code, it polls', async () => {
  const w = new World();
  const srv = await serve(w);
  const dir = mkdtempSync(join(tmpdir(), 'cli011-'));
  try {
    const u = await w.user();
    const run = runCli(CLI_OLD, ['login'], { LEASH_URL: w.base, XDG_CONFIG_HOME: dir });
    const code = await run.code;
    assert.match(run.io.err, /Open https:\/\/leash\.test\/app#device\nand confirm the code [A-Z0-9-]{9} with your passkey/);
    assert.equal((await approve(w, u, code)).status, 200);
    const r = await run.done;
    assert.equal(r.code, 0, r.err); assert.match(r.out, /Signed in\./);
    const token = JSON.parse(readFileSync(join(dir, 'leash', 'config.json'), 'utf8')).token;
    assert.equal((await w.req('GET', '/v1/tokens', { bearer: token, ...cliReq })).status, 200);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('leashcli 0.2.1: prints the guidance, says whose account it signed in to, stops on a denial, logs out on the server', async () => {
  const w = new World();
  const srv = await serve(w);
  const dir = mkdtempSync(join(tmpdir(), 'cli021-'));
  try {
    const u = await w.user('Ada');
    const env = { LEASH_URL: w.base, XDG_CONFIG_HOME: dir };
    const run = runCli(CLI_NEW, ['login'], env);
    const code = await run.code;
    assert.match(run.io.err, /Type this code: [A-Z0-9-]{9}/);
    assert.match(run.io.err, /Never send it to anyone, and never type a code\nsomeone sent you/);
    assert.ok(!run.io.err.includes('#device='), 'no code in the link it prints');
    assert.equal((await approve(w, u, code)).status, 200);
    const r = await run.done;
    assert.equal(r.code, 0, r.err); assert.match(r.out, /Signed in to the account of Ada, for 7 days/);
    assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM sessions WHERE kind = 'cli'").get().n, 1);
    // leash logout ends the session on the server, not only on this machine
    const out = await runCli(CLI_NEW, ['logout'], env).done;
    assert.equal(out.code, 0, out.err);
    assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) n FROM sessions WHERE kind = 'cli'").get().n, 0);
    // a denial stops it at once
    const run2 = runCli(CLI_NEW, ['login'], env);
    assert.equal((await w.req('POST', '/v1/device/deny', { cookie: u.cookie, body: { user_code: await run2.code } })).status, 200);
    const r2 = await run2.done;
    assert.equal(r2.code, 1); assert.match(r2.err, /denied in the browser/);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('the page never takes a sign-in code from a link, and the phone alert can show a command line sign-in', () => {
  const app = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8');
  assert.ok(!/#device=\(\[/.test(app), 'no code is read out of the address');
  for (const m of app.matchAll(/\$\('devCode'\)\.value\s*=\s*([^;]+);/g)) assert.equal(m[1].trim(), "''", 'the code box is only ever cleared');
  assert.match(app, /devLinkWarn/);
  const sw = readFileSync(new URL('../../site/public/sw.js', import.meta.url), 'utf8');
  assert.match(sw, /fetch\('\/v1\/alerts'/);
  assert.match(sw, /'\/app#cli=' \+ s\.id/);
});
