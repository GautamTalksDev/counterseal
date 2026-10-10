// Approvals for actions the broker does not proxy: a coding agent's shell command or an MCP tool call. A hook on the
// agent's machine (counterseal guard) holds a guard key (lsg_), asks here, and waits; the human approves in the app with a
// passkey, exactly as for a held API call (the same holds table, alerts, approve and deny routes, and public receipts).
//
// What a guard key can do: ask for an approval and read and use its own. Never approve (every approve route needs a web
// session and a fresh passkey ceremony), never see another key's holds, never touch the vault. A key made by a CLI
// session ends with that session and is revoked with it (the device-code phishing rule, see auth.js).
//
// The guard runs on the agent's machine: a seatbelt, not a sandbox. Only brokered keys are enforced on the server.
//
// Workers Free: waiting for a decision writes nothing to D1 (the poll's rate limit is in memory, the key's last use is
// written only when a hold is created or used), and a long poll is at most 12 D1 reads.
import { HttpError, json, b64u, rand, randomId, sha256hex, now, str, cleanText } from './util.js';
import { audit } from './audit.js';
import { appOrigin, sessionId } from './auth.js';
import { limit, readLimit, allow } from './ratelimit.js';
import { notify } from './push.js';
import { preview, PENDING_PER_ACCOUNT } from './broker.js';
import { markSeen } from './admin.js';
import { frozenError } from './brakes.js';
import { int } from './ledger.js';
import { BRAND } from './brand.js';
import * as Team from './team.js';
import * as Windows from './windows.js';
import * as Channels from './channels.js';
import { markLater } from './trust.js';

export const AGENTS = ['claude-code', 'codex', 'cursor', 'copilot', 'gemini', 'antigravity', 'mcp'];
/** the kinds a guard key may ask for, and the method word their holds and public receipts carry */
export const KINDS = { shell: 'RUN', tool: 'CALL' };
// waiting holds: 20 per guard key, like a token; the account's 100 is shared with brokered calls (broker.js)
export const HOLD_TTL = 30 * 60_000, MAX_KEYS = 20, CREATES_PER_HOUR = 60, PENDING_PER_KEY = 20;
export const POLLS_PER_MINUTE = 30, USES_PER_MINUTE = 30, WAIT_MAX = 20, WAIT_STEP = 2000, WAIT_READS = 10;
export const MAX_DETAIL = 4096, MAX_SUMMARY = 200, MAX_WHY = 300, MAX_PREVIEW = 3 * MAX_DETAIL;
const KEY = /^Bearer (lsg_[A-Za-z0-9_-]{43})$/;
const LABEL = /^[\p{L}\p{N} ._:/()-]+$/u;
const RULE = /^[a-z0-9._:-]{1,64}$/;
const MAPV = /^\d{4}-\d{2}-\d{2}\.\d{1,3}$/;
const FIELDS = new Set(['kind', 'agent', 'rule', 'why', 'summary', 'detail', 'context', 'map']);
// a folder name, never a path: no separators, no control, format or line-break characters, not "." or ".."
const CWD = /^(?!\.{1,2}$)[^/\\\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,80}$/u;
const SESSION = /^[A-Za-z0-9._:-]{1,64}$/;
const guardTokenId = (id) => 'g:' + id;

/** the hash an approval is bound to: the kind, the agent, the exact command or tool call, and the folder it runs in */
export const approvalHash = (kind, agent, detail, cwd = '') => sha256hex(JSON.stringify(['v1', kind, agent, detail, cwd || '']));

/** C0 and C1 control characters (other than newline and tab) made visible, so an escape sequence or a carriage return
 *  cannot hide part of a command on the approval card; the invisible and direction characters are handled by preview() */
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const shown = (t) => t.replace(CONTROL, (c) => `<U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);

/** status as the agent should read it: a pending or approved hold past its time is expired, whatever the sweep did */
const statusOf = (h, t = now()) => (['pending', 'approved'].includes(h.status) && h.expires_at <= t ? 'expired' : h.status);

const sleep = (env, ms) => (env.__sleep ? env.__sleep(ms) : globalThis.scheduler?.wait ? globalThis.scheduler.wait(ms) : new Promise((ok) => setTimeout(ok, ms)));

// ---------------------------------------------------------------- guard keys (managed from the app or the CLI)
export async function createKey(env, sess, body) {
  const label = body.label === undefined ? 'guard' : str(body.label, 'label', { max: 60, re: LABEL });
  const t = now();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM guard_keys WHERE account_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)').bind(sess.accountId, t).first();
  if (n.n >= MAX_KEYS) throw new HttpError(409, 'too_many_guard_keys',`Up to ${MAX_KEYS} active guard keys. Revoke one first.`);
  // made by a CLI session: it never outlives that session, and revoking the session revokes it
  const cli = sess.kind === 'cli' ? await sessionId(sess.hash) : null;
  const expiresAt = cli ? sess.expiresAt : null;
  const key = 'lsg_' + b64u(rand(32));
  const id = randomId();
  // member_id: who made it (with self-approval off, they cannot seal what it asks for; removing them revokes it)
  await env.DB.prepare('INSERT INTO guard_keys (id, account_id, hash, label, session_id, expires_at, created_at, member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, sess.accountId, await sha256hex(key), label, cli, expiresAt, t, sess.memberId || null).run();
  await audit(env, sess.accountId, sess.kind, 'guard_key_created', { id, label, ...(cli ? { session: cli, expires_at: expiresAt } : {}) });
  return {
    id, key, label, expiresAt,
    note: `Shown once. ${BRAND.name} keeps only a hash. This key can ask for approvals, never give them.${cli ? ' It ends with this command line sign-in; make a lasting one in the app.' : ''}`,
  };
}

export async function listKeys(env, sess) {
  const r = await env.DB.prepare('SELECT id, label, created_at, last_used, expires_at, revoked, session_id, COALESCE(member_id, account_id) AS member_id FROM guard_keys WHERE account_id = ? ORDER BY created_at DESC LIMIT 100').bind(sess.accountId).all();
  return { keys: r.results.map(({ session_id, ...k }) => ({ ...k, made_by: session_id ? 'cli' : 'web' })) };
}

/** revoking only tightens: its maker or an owner may (src/team.js; anyone else freezes the account); the key's open
 *  holds are closed in the same batch, only once the key is revoked */
export async function revokeKey(env, sess, id) {
  const [k, h] = await env.DB.batch([
    env.DB.prepare(`UPDATE guard_keys SET revoked = 1 WHERE id = ? AND account_id = ? AND revoked = 0 ${Team.MAKER_OR_OWNER}`).bind(id, sess.accountId, ...Team.makerOrOwner(sess)),
    env.DB.prepare("UPDATE holds SET status = 'expired' WHERE account_id = ? AND token_id = ? AND status IN ('pending','approved') AND EXISTS (SELECT 1 FROM guard_keys WHERE id = ? AND account_id = ? AND revoked = 1)").bind(sess.accountId, guardTokenId(id), id, sess.accountId),
  ]);
  if (!k.meta.changes) throw await Team.notRevoked(env, sess, 'guard_keys', id);
  await audit(env, sess.accountId, sess.kind, 'guard_key_revoked', { id, closed: h.meta.changes });
  return { ok: true, closed: h.meta.changes };
}

/** the guard key in the Authorization header, with whether its account has public receipts on, is frozen, and its
 *  quorum settings (one query) */
export async function guardKey(env, request) {
  const m = (request.headers.get('authorization') || '').match(KEY);
  if (!m) throw new HttpError(401, 'guard_key_required', `Send your ${BRAND.name} guard key as: Authorization: Bearer lsg_...`);
  const k = await env.DB.prepare('SELECT g.id, g.account_id, g.revoked, g.expires_at, g.last_used, g.member_id, a.receipts AS receipts_on, a.frozen_at, a.quorum, a.self_approve, a.quorum_pending, a.self_approve_pending, a.quorum_effective_at, EXISTS (SELECT 1 FROM windows w WHERE w.account_id = g.account_id AND w.closed_at IS NULL AND w.expires_at > ' + Date.now() + ') AS window_open FROM guard_keys g JOIN accounts a ON a.id = g.account_id WHERE g.hash = ?')
    .bind(await sha256hex(m[1])).first();
  if (!k || k.revoked || (k.expires_at !== null && k.expires_at <= now())) throw new HttpError(401, 'guard_key_invalid', 'This guard key was revoked or has ended. Make a new one in the app, or run counterseal guard install again.');
  return k;
}

/** the key's last use, written at most once a minute and never by a poll */
function touch(env, k, t, waitUntil) {
  if (k.last_used > t - 60_000) return;
  waitUntil(env.DB.prepare('UPDATE guard_keys SET last_used = ? WHERE id = ?').bind(t, k.id).run());
}

// ---------------------------------------------------------------- the request body
function text(v, name, max) {
  if (typeof v !== 'string' || v.length > max) throw new HttpError(400, 'bad_' + name, `${name} is text of ${max} characters at most.`);
  const s = cleanText(v);
  if (!s) throw new HttpError(400, 'bad_' + name, `${name} is empty.`);
  return s;
}
function readRequest(b) {
  for (const k of Object.keys(b)) if (!FIELDS.has(k)) throw new HttpError(400, 'bad_field', `Unknown field. Send only: ${[...FIELDS].join(', ')}.`);
  if (typeof b.kind !== 'string' || !Object.hasOwn(KINDS, b.kind)) throw new HttpError(400, 'bad_kind', 'kind is shell or tool.');
  if (!AGENTS.includes(b.agent)) throw new HttpError(400, 'bad_agent', `agent is one of ${AGENTS.join(', ')}.`);
  const rule = str(b.rule, 'rule', { max: 64, re: RULE });
  const why = text(b.why, 'why', MAX_WHY);
  const summary = text(b.summary, 'summary', MAX_SUMMARY);
  // the exact command or tool call, kept as sent (the hash covers it); NUL and lone surrogates read differently in
  // different places, so they are refused rather than guessed
  const detail = str(b.detail, 'detail', { max: MAX_DETAIL });
  if (/[\u0000]|\p{Cs}/u.test(detail)) throw new HttpError(400, 'bad_detail', 'detail has a NUL or an unpaired surrogate.');
  let cwd = null, session = null;
  if (b.context !== undefined && b.context !== null) {
    const c = b.context;
    if (typeof c !== 'object' || Array.isArray(c) || Object.keys(c).some((k) => k !== 'cwd' && k !== 'session')) throw new HttpError(400, 'bad_context', 'context takes cwd and session only.');
    if (c.cwd !== undefined) cwd = str(c.cwd, 'context', { max: 80, re: CWD });
    if (c.session !== undefined) session = str(c.session, 'context', { max: 64, re: SESSION });
  }
  const map = b.map === undefined ? null : str(b.map, 'map', { max: 16, re: MAPV });
  return { kind: b.kind, agent: b.agent, rule, why, summary, detail, cwd, session, map };
}

// ---------------------------------------------------------------- the guard key's routes
/** POST /v1/approvals: ask once per exact command. An approved one comes back approved (then use it); a pending one
 *  comes back as it is (no second hold, no second alert); otherwise a new hold, an audit entry and an alert. */
export async function create(c) {
  const k = c.g, env = c.env, t = now();
  if (k.frozen_at) throw frozenError(); // Freeze: nothing new is asked, held or alerted while the account is frozen
  const r = readRequest(c.body);
  // the approver sees the exact command, never truncated: preview() makes invisible and direction characters visible.
  // Each hidden character becomes 8 visible ones, so a command made mostly of them is refused (before anything is
  // written) rather than shown at up to 32 KB on every phone and dashboard refresh; no real command needs that many.
  const pv = preview('', shown(r.detail), 64 * 1024);
  if (pv.length > MAX_PREVIEW) throw new HttpError(400, 'bad_detail', 'detail has too many invisible or control characters to show.');
  const tokenId = guardTokenId(k.id);
  const hash = await approvalHash(r.kind, r.agent, r.detail, r.cwd);
  const url = async (id) => `${await appOrigin(env, k.account_id)}/app#hold=${id}`;
  const found = await env.DB.prepare("SELECT id, status, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status IN ('approved','pending') AND expires_at > ? ORDER BY status = 'approved' DESC, created_at DESC LIMIT 1")
    .bind(tokenId, hash, t).first();
  if (found) {
    const body = { id: found.id, status: found.status, hash, approve_url: await url(found.id), expires_at: found.expires_at };
    return found.status === 'approved' ? json(body, 200) : json({ ...body, created: false }, 202);
  }
  // asking is cheap for the agent and costly for the human: 60 new holds an hour per key, 20 waiting per key, 100 per account
  await limit(env.DB, 'gcreate:' + k.id, CREATES_PER_HOUR, 3600_000, t);
  const n = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM holds WHERE token_id = ?1 AND status = 'pending' AND expires_at > ?3) AS mine, (SELECT COUNT(*) FROM holds WHERE account_id = ?2 AND status = 'pending' AND expires_at > ?3) AS acct")
    .bind(tokenId, k.account_id, t).first();
  if (n.mine >= PENDING_PER_KEY || n.acct >= PENDING_PER_ACCOUNT) {
    throw new HttpError(429, 'too_many_holds', `${n.mine >= PENDING_PER_KEY ? `${n.mine} approvals from this guard key are` : `${n.acct} requests are`} already waiting, so this one was not held or sent. Stop and ask your human to review the waiting ones first.`);
  }
  // Break-glass (src/windows.js): while a window is open for this key, what the map holds is approved at once (one use, within
  // 10 minutes, like any approval), on the record with the window's id; with self-approval off, never for the opener's own key.
  const bg = k.window_open ? await Windows.matching(env, k.account_id, tokenId, Team.memberOf(k), Team.effective(k, t).selfApprove, t) : null;
  const id = randomId(), expiresAt = t + (bg ? Team.GRANT_TTL : HOLD_TTL), method = KINDS[r.kind];
  const context = JSON.stringify({ ...(r.cwd ? { cwd: r.cwd } : {}), ...(r.session ? { session: r.session } : {}), ...(r.map ? { map: r.map } : {}), ...(bg ? { breakglass: bg.id } : {}) });
  // the seals the team requires now (two-person seal), and who made this guard key (separation of duties)
  const needs = Team.effective(k, t).quorum, requestedBy = Team.memberOf(k);
  // one statement: two hooks asking for the same command at the same moment make one hold, not two
  const ins = await env.DB.prepare(`INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at, preview, kind, agent, context, needs, requested_by, status, decided_at)
    SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19 WHERE NOT EXISTS (SELECT 1 FROM holds WHERE token_id = ?3 AND req_hash = ?4 AND status = 'pending' AND expires_at > ?10)`)
    .bind(id, k.account_id, tokenId, hash, method, r.agent, r.summary, r.rule, r.why, t, expiresAt, pv, r.kind, r.agent, context === '{}' ? null : context, needs, requestedBy, bg ? 'approved' : 'pending', bg ? t : null).run();
  if (!ins.meta.changes) {
    const p = await env.DB.prepare("SELECT id, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1").bind(tokenId, hash).first();
    if (p) return json({ id: p.id, status: 'pending', hash, approve_url: await url(p.id), expires_at: p.expires_at, created: false }, 202);
    throw new HttpError(409, 'try_again', 'Another request for the same command was decided just now. Ask again.');
  }
  await audit(env, k.account_id, 'guard:' + k.id, 'hold', { method, host: r.agent, rule: r.rule, hold: id, kind: r.kind, agent: r.agent, preview_sha256: await sha256hex(pv || ''), ...(r.map ? { map: r.map } : {}), ...(bg ? { breakglass: bg.id } : {}) }, { receipts: !!k.receipts_on && !bg });
  touch(env, k, t, c.waitUntil);
  markLater(env, k.account_id, 'call'); // the launch funnel's "first protected call"
  const seen = markSeen(env, k.account_id);
  if (seen) c.waitUntil(seen);
  // a window approved it: nobody is asked (the team was told when the window opened), and the answer is the approval
  if (bg) return json({ id, status: 'approved', hash, approve_url: await url(id), expires_at: expiresAt, created: true, breakglass: true }, 200);
  // wake the owner's devices after responding; the push carries nothing. At most one alert a minute per account for
  // held requests (the alert says how many are waiting), so a flood of holds is one buzz, not hundreds.
  // (the same bucket as held API calls, so a guard and a token together still make one buzz a minute)
  c.waitUntil((async () => {
    if (await allow(env.DB, 'pushhold:' + k.account_id, 1, 60_000, now())) {
      await notify(env, k.account_id, env.__pushFetch || fetch);
      await Channels.holdAlert(env, k.account_id, { who: r.agent, rule: r.rule, needs, holdId: id });
    }
  })());
  return json({ id, status: 'pending', hash, approve_url: await url(id), expires_at: expiresAt, created: true }, 202);
}

// with the seals it has so far and the seals it needs (two-person seal: a hook can say "1 of 2 seals")
const readHold = (env, k, id) => env.DB.prepare("SELECT id, status, deny_reason, expires_at, req_hash, needs, (SELECT COUNT(*) FROM hold_votes v WHERE v.hold_id = holds.id AND v.req_hash = holds.req_hash) AS seals FROM holds WHERE id = ? AND token_id = ? AND kind IN ('shell','tool')").bind(id, guardTokenId(k.id)).first();

/** GET /v1/approvals/:id?wait=N: the decision, waiting up to N seconds for one. No D1 writes at all. */
export async function status(c, id) {
  const k = c.g, env = c.env, t0 = now();
  if (k.frozen_at) throw frozenError(); // a freeze ends every wait at once: the guard learns why instead of timing out
  const w = c.url.searchParams.get('wait');
  const wait = w === null ? 0 : int(w, 'wait', WAIT_MAX);
  await readLimit(env, 'gpoll:' + k.id, POLLS_PER_MINUTE, t0);
  let h = await readHold(env, k, id);
  if (!h) throw new HttpError(404, 'not_found');
  const deadline = t0 + wait * 1000;
  for (let i = 0; i < WAIT_READS && statusOf(h) === 'pending' && now() < deadline; i++) {
    await sleep(env, Math.min(WAIT_STEP, deadline - now()));
    h = await readHold(env, k, id);
    if (!h) throw new HttpError(404, 'not_found');
  }
  const st = statusOf(h);
  return { id: h.id, status: st, deny_reason: st === 'denied' ? h.deny_reason || null : null, expires_at: h.expires_at, hash: h.req_hash, seals: h.seals || 0, needs: Math.max(h.needs || 1, Team.effective(k).quorum) };
}

/** POST /v1/approvals/:id/use {hash}: an approval is spent once, on exactly the command it was given for */
export async function use(c, id) {
  const k = c.g, env = c.env, t = now();
  if (k.frozen_at) throw frozenError();
  await readLimit(env, 'guse:' + k.id, USES_PER_MINUTE, t);
  const hash = str(c.body.hash, 'hash', { max: 64, re: /^[0-9a-f]{64}$/ });
  const u = await env.DB.prepare("UPDATE holds SET status = 'used' WHERE id = ? AND token_id = ? AND req_hash = ? AND status = 'approved' AND expires_at > ? AND kind IN ('shell','tool') RETURNING method, host, rule, kind, context")
    .bind(id, guardTokenId(k.id), hash, t).first();
  if (!u) {
    const h = await readHold(env, k, id);
    if (!h) throw new HttpError(404, 'not_found');
    const st = statusOf(h, t);
    if (st === 'expired') throw new HttpError(410, 'expired', 'This approval has expired. Ask again.');
    if (st === 'denied') throw new HttpError(403, 'denied', 'Your human denied this.', { deny_reason: h.deny_reason || null });
    if (st === 'used') throw new HttpError(409, 'already_used', 'This approval was already used. Ask again.');
    if (st === 'pending') throw new HttpError(409, 'not_approved', 'Not approved yet.');
    throw new HttpError(409, 'hash_mismatch', 'This approval is for a different command. Ask again for this one.');
  }
  const map = mapOf(u.context);
  await audit(env, k.account_id, 'guard:' + k.id, 'run_approved', { method: u.method, host: u.host, rule: u.rule, hold: id, kind: u.kind, ...(map ? { map } : {}), ...(breakglassOf(u.context) ? { breakglass: breakglassOf(u.context) } : {}) }, { receipts: !!k.receipts_on });
  touch(env, k, t, c.waitUntil);
  return { ok: true, id, status: 'used' };
}

/** the break-glass window that approved a guard hold, from its context */
export function breakglassOf(context) {
  if (!context) return null;
  try { const b = JSON.parse(context).breakglass; return typeof b === 'string' && /^[0-9a-f]{24}$/.test(b) ? b : null; } catch { return null; }
}

/** the shell map version a guard hold was made under (for its receipts), from the hold's context */
export function mapOf(context) {
  if (!context) return null;
  try { const m = JSON.parse(context).map; return typeof m === 'string' && MAPV.test(m) ? m : null; } catch { return null; }
}
