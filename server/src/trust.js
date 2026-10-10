// The app, the first run and the privacy center (branch feat/app-trust).
//
//   Launch funnel markers: the first token, the first protected call, the first demo, the app installed, alerts on. Each
//   is one UPDATE that only matches while its column is NULL, sent at most once per account per isolate, so a busy agent
//   adds no D1 writes. /v1/admin/stats reads them as aggregate counts only.
//   The demo: "Try a held call" makes a hold against a built-in demo provider. Nothing is proxied, no key is used, no
//   upstream is called and nothing is sealed in the public log (it is audited as demo_hold, demo_approved, demo_denied
//   and demo_executed, none of which is a public decision). Approving it is the real passkey ceremony, so a new person
//   sees exactly what an approval feels like in under a minute.
//   Your data: an owner downloads everything Counterseal keeps about the account as JSON, after a fresh passkey ceremony,
//   3 times an hour, on the record. Never a secret: no vaulted key or any part of it, no token, key, session or invite
//   hash, no passkey public key, no push address.
//   Evidence pack: the audit log with its hash chain, page by page, with the log's latest signed checkpoint and verifier
//   key, for the browser to verify (the server never re-hashes a whole log: Workers Free allows 10 ms of CPU).
//   Retention: closed holds are deleted after 30, 90 or 365 days (365 unless the owner picks less).
import { HttpError, randomId, sha256hex, now, str } from './util.js';
import { audit } from './audit.js';
import { newChallenge, takeChallenge, checkAssertion, rp, appOrigin } from './auth.js';
import { limit, readLimit, allow } from './ratelimit.js';
import { notify } from './push.js';
import { frozenError } from './brakes.js';
import { cachedHead, logOf, int } from './ledger.js';
import { logKey } from './note.js';
import { MAP_VERSION } from './providers.js';
import { BRAND } from './brand.js';
import * as Team from './team.js';

const DAY = 86_400_000;

// ---------------------------------------------------------------- funnel markers
export const MARKERS = { token: 'first_token_at', call: 'first_call_at', demo: 'demo_at', installed: 'installed_at', alerts: 'alerts_at' };
const marked = new Map();
/** set an account's first-time marker once. Returns the statement's promise, or null when this isolate already sent it. */
export function markFirst(env, accountId, kind) {
  const col = MARKERS[kind];
  if (!col || !accountId) return null;
  const k = kind + ':' + accountId;
  if (marked.has(k)) return null;
  if (marked.size > 50_000) marked.clear(); // bounded memory; a reset only means one more no-op UPDATE
  marked.set(k, 1);
  return env.DB.prepare(`UPDATE accounts SET ${col} = ? WHERE id = ? AND ${col} IS NULL`).bind(now(), accountId).run();
}
/** after the response on Workers; inline in tests and local dev */
export function markLater(env, accountId, kind) {
  const p = markFirst(env, accountId, kind);
  if (!p) return null;
  const q = p.catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(q);
  return q;
}
export const _resetMarks = () => marked.clear();

/** POST /v1/me/installed: the app reports, once, that it was opened installed (standalone). Writes one row at most. */
export async function installed(env, sess) {
  await markFirst(env, sess.accountId, 'installed');
  return { ok: true };
}

// ---------------------------------------------------------------- the demo ("Try a held call")
export const DEMO_TTL = 10 * 60_000, DEMOS_PER_HOUR = 10;
export const DEMO = {
  method: 'DELETE', host: 'demo', path: '/repos/you/practice-repo', rule: 'demo.delete',
  why: 'Demo: on a real API, deleting a repository cannot be undone. This one is pretend: nothing is called, no key is used, and nothing goes to the public log.',
};
const demoToken = (s) => 'demo:' + (s.memberId || s.accountId);

/** POST /v1/demo/call: the built-in demo agent asks to delete a pretend repository and is held; with {hold}, it retries
 *  after you approved, once. Any signed-in browser; never a command line session (it is a dashboard lesson). */
export async function demoCall(c) {
  const env = c.env, s = c.s, t = now();
  if (Object.keys(c.body).some((k) => k !== 'hold')) throw new HttpError(400, 'bad_field', 'Send {} to start the demo, or {"hold": id} to retry it.');
  if (c.body.hold !== undefined) return demoRetry(env, s, str(c.body.hold, 'hold', { max: 24, re: /^[0-9a-f]{24}$/ }));
  if (Object.keys(c.body).length) throw new HttpError(400, 'bad_field', 'Send {} to start the demo, or {"hold": id} to retry it.');
  const a = await env.DB.prepare('SELECT frozen_at, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at FROM accounts WHERE id = ?').bind(s.accountId).first();
  if (!a) throw new HttpError(401, 'signed_out');
  if (a.frozen_at) throw frozenError();
  const tokenId = demoToken(s);
  const open = await env.DB.prepare("SELECT id, expires_at FROM holds WHERE token_id = ? AND account_id = ? AND kind = 'demo' AND status = 'pending' AND expires_at > ? LIMIT 1").bind(tokenId, s.accountId, t).first();
  const url = async (id) => `${await appOrigin(env, s.accountId)}/app#hold=${id}`;
  if (open) return { hold_id: open.id, status: 'pending', approve_url: await url(open.id), expires_at: open.expires_at, created: false, demo: true };
  await limit(env.DB, 'demo:' + s.accountId, DEMOS_PER_HOUR, 3600_000, t);
  const id = randomId(), expiresAt = t + DEMO_TTL;
  const preview = [
    'DEMO. The built-in demo provider made this hold so you can see an approval.',
    'Nothing is proxied and no key is used. Approving it calls no API and writes no public receipt.',
    '',
    'DELETE /repos/you/practice-repo',
  ].join('\n');
  // the seals your team requires now (on a two-seal team the demo needs two people too); nobody "made" it, so the
  // separation-of-duties rule never blocks your own demo
  const needs = Team.effective(a, t).quorum;
  await env.DB.prepare('INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at, preview, kind, needs, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)')
    .bind(id, s.accountId, tokenId, await sha256hex('demo|' + id), DEMO.method, DEMO.host, DEMO.path, DEMO.rule, DEMO.why, t, expiresAt, preview, 'demo', needs).run();
  await audit(env, s.accountId, s.kind, 'demo_hold', { hold: id, ...(s.memberId !== s.accountId ? { member: s.memberId } : {}) });
  markLater(env, s.accountId, 'demo');
  // your devices buzz as they would for a real hold (one alert a minute per account, shared with real holds)
  c.waitUntil((async () => { if (await allow(env.DB, 'pushhold:' + s.accountId, 1, 60_000, now())) await notify(env, s.accountId, env.__pushFetch || fetch); })());
  return { hold_id: id, status: 'pending', approve_url: await url(id), expires_at: expiresAt, created: true, demo: true };
}

/** the demo agent's retry: an approved demo hold is used once, like a real grant; the demo provider "answers" */
async function demoRetry(env, s, id) {
  const t = now();
  const u = await env.DB.prepare("UPDATE holds SET status = 'used' WHERE id = ? AND account_id = ? AND kind = 'demo' AND status = 'approved' AND expires_at > ? RETURNING id").bind(id, s.accountId, t).first();
  if (!u) {
    const h = await env.DB.prepare("SELECT status, expires_at FROM holds WHERE id = ? AND account_id = ? AND kind = 'demo'").bind(id, s.accountId).first();
    if (!h) throw new HttpError(404, 'not_found');
    const st = ['pending', 'approved'].includes(h.status) && h.expires_at <= t ? 'expired' : h.status;
    if (st === 'pending') throw new HttpError(409, 'not_approved', 'Not approved yet. Approve it with your passkey first.', { status: st });
    if (st === 'denied') throw new HttpError(403, 'denied', 'You denied it, so the demo agent stops here. That is what an agent sees.', { status: st });
    if (st === 'used') throw new HttpError(409, 'already_used', 'This approval was used once already. An approval works once.', { status: st });
    throw new HttpError(410, 'expired', 'This demo hold expired. Start a new one.', { status: st });
  }
  await audit(env, s.accountId, s.kind, 'demo_executed', { hold: id });
  return { status: 'executed', demo: true, response: { status: 204, provider: 'demo', note: 'The demo provider pretended to delete practice-repo. Nothing real happened, and the approval is now used up: the same request again would be held again.' } };
}

// ---------------------------------------------------------------- retention
export const HOLD_DAYS = [30, 90, 365], HOLD_DAYS_DEFAULT = 365;
export const holdDaysOf = (v) => (HOLD_DAYS.includes(v) ? v : HOLD_DAYS_DEFAULT);
/** POST /v1/me/retention {holdDays}: an owner, in the app. Shorter deletes sooner (at the next cleanup); longer keeps
 *  what is still there. On the record. */
export async function setRetention(env, sess, body) {
  const d = body.holdDays;
  if (!HOLD_DAYS.includes(d)) throw new HttpError(400, 'bad_holdDays', `holdDays is one of ${HOLD_DAYS.join(', ')}.`);
  const prev = await env.DB.prepare('UPDATE accounts SET hold_days = ? WHERE id = ? RETURNING hold_days').bind(d, sess.accountId).first();
  if (!prev) throw new HttpError(401, 'signed_out');
  await audit(env, sess.accountId, 'web', 'retention_changed', { hold_days: d, ...(sess.memberId !== sess.accountId ? { member: sess.memberId } : {}) });
  return { ok: true, holdDays: d };
}
/** part of the cleanup batch: closed holds older than the account's choice (365 days unless it picked less) */
export const retentionStatements = (db, t) => [
  db.prepare(`DELETE FROM holds WHERE status NOT IN ('pending','approved') AND expires_at < ?1 - ${DAY} * COALESCE((SELECT hold_days FROM accounts a WHERE a.id = holds.account_id AND a.hold_days IN (${HOLD_DAYS.join(',')})), ${HOLD_DAYS_DEFAULT})`).bind(t),
];

/** the retention facts the app and the privacy center show: what the product deletes by itself, and when */
export const RETENTION = [
  ['Closed held requests and commands (what was asked, the preview, a deny reason)', 'Deleted 365 days after they close, or 30 or 90 if the owner chooses. The preview text itself is dropped 1 day after a hold closes.'],
  ['Seals on a held action (who sealed, which passkey fingerprint, when)', 'Deleted 2 days after the seal; the audit log keeps the approval.'],
  ['Audit log (hash-chained)', 'Kept while the account exists, because the chain proves nothing was removed. Deleted with the account. Export it (evidence pack) to keep your own copy.'],
  ['Web sessions', '12 hours at most, and 1 hour without an action of yours.'],
  ['Command line sessions', '7 days at most; what they made ends with them.'],
  ['Sign-in challenges and command line sign-in codes', '5 minutes.'],
  ['Money cap daily totals', '35 days.'],
  ['Breaker counts', 'The current hour and 5 minutes.'],
  ['Rate limit counters', 'Until their window ends (at most a day), and deleted with the account.'],
  ['Alert devices (push addresses)', 'Until you turn alerts off, the push service says the device is gone, or the account is deleted.'],
  ['Team invites', '1 day after they expire.'],
  ['Public log entries', 'Kept forever by design (append-only). They never hold a name, path, body, key or IP; after account deletion nothing on our side links them to you.'],
];

// ---------------------------------------------------------------- your data (owner, passkey)
export const EXPORTS_PER_HOUR = 3;
export async function exportBegin(env, sess) {
  await limit(env.DB, 'export:' + sess.accountId, EXPORTS_PER_HOUR, 3600_000, now());
  const { id, challenge } = await newChallenge(env, 'export', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

// Each query names its columns: a new secret column can never leak into the export by being added to a table.
const Q = {
  account: 'SELECT id, name, created_at, receipts, plan, last_seen, frozen_at, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at, first_token_at, first_call_at, demo_at, installed_at, alerts_at, hold_days FROM accounts WHERE id = ?',
  members: 'SELECT id, name, label, role, created_at, invited_by, votes_from, removed_at FROM members WHERE account_id = ?',
  passkeys: 'SELECT cred_id, created_at, last_used, rp_id, COALESCE(member_id, account_id) AS member_id FROM passkeys WHERE account_id = ?',
  sessions: 'SELECT kind, created_at, expires_at, country, network, COALESCE(member_id, account_id) AS member_id FROM sessions WHERE account_id = ?',
  credentials: 'SELECT id, provider, label, host, created_at, last_used FROM credentials WHERE account_id = ?',
  tokens: 'SELECT id, credential_id, label, policy, minted_by, expires_at, revoked, created_at, last_used, agent_key_id, session_id, tripped_at, tripped_why, COALESCE(member_id, account_id) AS member_id FROM tokens WHERE account_id = ?',
  agentKeys: 'SELECT id, label, keyid, x AS public_key, created_at, revoked_at, last_used, session_id, COALESCE(member_id, account_id) AS member_id FROM agent_keys WHERE account_id = ?',
  receiptsKeys: 'SELECT id, label, signer_pub, revoked, created_at, last_used, expires_at, session_id, COALESCE(member_id, account_id) AS member_id FROM api_keys WHERE account_id = ?',
  guardKeys: 'SELECT id, label, session_id, expires_at, created_at, last_used, revoked, COALESCE(member_id, account_id) AS member_id FROM guard_keys WHERE account_id = ?',
  seals: 'SELECT hold_id, member_id, passkey, at FROM hold_votes WHERE account_id = ?',
  invites: 'SELECT id, role, label, created_by, created_at, expires_at, used_at, used_by, revoked_at FROM invites WHERE account_id = ?',
  alertDevices: 'SELECT id, endpoint, created_at, last_ok_at, COALESCE(member_id, account_id) AS member_id FROM push_subs WHERE account_id = ?',
  receiptsUsage: 'SELECT month, receipts, day, day_receipts, skipped FROM usage WHERE account_id = ?',
  moneyTotals: 'SELECT s.token_id, s.day, s.currency, s.amount FROM spend s JOIN tokens t ON t.id = s.token_id WHERE t.account_id = ?',
  moveLinks: 'SELECT created_at, expires_at, used_at FROM move_links WHERE account_id = ?',
};
/** a push address is a capability (anyone holding it can wake your device): only the push service's name leaves */
const pushService = (e) => { try { return new URL(e).hostname; } catch { return null; } };

export async function exportFinish(env, sess, body) {
  const ch = await takeChallenge(env, body.challengeId, 'export');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const a = sess.accountId, db = env.DB;
  const names = Object.keys(Q);
  const rows = await Promise.all(names.map((k) => (k === 'account' ? db.prepare(Q[k]).bind(a).first() : db.prepare(Q[k]).bind(a).all().then((r) => r.results))));
  const d = Object.fromEntries(names.map((k, i) => [k, rows[i]]));
  // passkeys: an id fingerprint (as the audit log records them), never the public key; tokens: the policy is yours
  const out = {
    format: 'counterseal-data-export/1',
    generated_at: now(),
    service: BRAND.name,
    controller_note: `${BRAND.name} processes this data for the account's owner. Questions: ${BRAND.privacy}.`,
    never_included: [
      'vaulted API keys, or any part of them (not even the last 4 characters)',
      'the vault\'s encryption material (ciphertext, IVs, wrapped keys)',
      'agent token, guard key, receipts key, session, invite and move-link hashes',
      'passkey public keys and signature counters',
      'push addresses (only the push service\'s name)',
      'public receipts\' openings and salts',
    ],
    account: d.account ? { ...d.account, hold_days: holdDaysOf(d.account.hold_days) } : null,
    members: d.members,
    passkeys: await Promise.all(d.passkeys.map(async ({ cred_id, ...p }) => ({ fingerprint: (await sha256hex(String(cred_id))).slice(0, 16), ...p }))),
    sessions: d.sessions,
    credentials: d.credentials,
    tokens: d.tokens.map((t) => ({ ...t, policy: safeJson(t.policy) })),
    agent_keys: d.agentKeys,
    receipts_keys: d.receiptsKeys,
    guard_keys: d.guardKeys,
    // held requests and commands can be many (a busy account, 365 days): also added by the app, page by page
    holds: { entries: [], complete: false, pages_from: '/v1/export/holds' },
    seals: d.seals,
    invites: d.invites,
    alert_devices: d.alertDevices.map(({ endpoint, ...x }) => ({ ...x, service: pushService(endpoint) })),
    receipts_usage: d.receiptsUsage,
    money_totals: d.moneyTotals,
    move_links: d.moveLinks,
    // the audit log can be long: it is not in this response (Workers Free allows 10 ms of CPU). The app adds every entry,
    // page by page, from GET /v1/export/evidence (the same rows, as stored, with their hash chain).
    audit: { entries: [], complete: false, pages_from: '/v1/export/evidence', note: 'The app adds every audit entry here, page by page.' },
    retention: RETENTION.map(([what, rule]) => ({ what, rule })),
  };
  await audit(env, a, 'web', 'data_export', { ...(sess.memberId !== a ? { member: sess.memberId } : {}) });
  return out;
}
const safeJson = (s) => { if (s === null || s === undefined) return null; try { return JSON.parse(s); } catch { return null; } };

// ---------------------------------------------------------------- evidence pack (audit chain + log checkpoint)
export const EVIDENCE_PAGE = 250, EVIDENCE_RPM = 120, EVIDENCE_SCAN = 1000;
/** GET /v1/export/evidence?from=&to=&after=: a page of audit entries as stored, oldest first, so the browser can
 *  recompute every hash and link; the first page also carries the log's latest signed checkpoint and verifier key. */
export async function evidence(c) {
  const env = c.env, s = c.s, q = c.url.searchParams, t = now();
  await readLimit(env, 'evidence:' + s.accountId, EVIDENCE_RPM, t);
  const from = q.get('from') === null ? 0 : int(q.get('from'), 'from');
  const to = q.get('to') === null ? Number.MAX_SAFE_INTEGER : int(q.get('to'), 'to');
  const after = q.get('after') === null ? 0 : int(q.get('after'), 'after');
  if (to < from) throw new HttpError(400, 'bad_range', 'to is before from.');
  // A page looks at most EVIDENCE_SCAN entries (the index is by account and seq, not by time): a range that matches nothing
  // must not make one request read the account's whole log (Workers Free: 5 million rows read a day for every tenant).
  // When the look ends before a full page is found, the page is short and next_after says where to go on.
  const rows = (await env.DB.prepare(`SELECT seq, at, actor, action, detail, prev_hash, hash, receipt FROM (SELECT seq, at, actor, action, detail, prev_hash, hash, receipt FROM audit
      WHERE account_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?5) WHERE at >= ?3 AND at <= ?4 ORDER BY seq LIMIT ?6`)
    .bind(s.accountId, after, from, to, EVIDENCE_SCAN, EVIDENCE_PAGE + 1).all()).results;
  let done = rows.length <= EVIDENCE_PAGE, entries = rows.slice(0, EVIDENCE_PAGE), next = done ? null : entries[entries.length - 1].seq;
  if (done) {
    // fewer than a page matched: was the look cut short? (it then looked at a full EVIDENCE_SCAN entries; go on after the
    // last one, unless that one is already past the range: times only grow along the chain, give or take a clock step)
    const last = await env.DB.prepare('SELECT seq, at FROM audit WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT 1 OFFSET ?').bind(s.accountId, after, EVIDENCE_SCAN - 1).first();
    if (last && last.at <= to) { done = false; next = last.seq; }
  }
  const out = { account_id: s.accountId, entries, done, next_after: next };
  if (!after) {
    // the first page: whether the range starts at the account's first entry (then the chain must start at zero), and
    // the public log's head, so receipts in the range can be checked against a signed checkpoint
    const first = await env.DB.prepare('SELECT MIN(seq) AS seq FROM audit WHERE account_id = ?').bind(s.accountId).first();
    let log = null;
    try {
      const key = await logKey(env);
      await readLimit(env, 'do:' + s.accountId, 60, t);
      const head = await cachedHead({ key, log: logOf(env) });
      log = { origin: key.name, verifier_key: key.vkey, checkpoint: head?.note || null, tree_size: head?.size || 0 };
    } catch { /* the log is optional for the chain */ }
    Object.assign(out, { from_start: !!first && entries.length > 0 && entries[0].seq === first.seq, generated_at: t, map_version: MAP_VERSION, log, range: { from, to: to === Number.MAX_SAFE_INTEGER ? null : to } });
  }
  return out;
}

// ---------------------------------------------------------------- account deletion, the rest
/** rate limit rows that name the account (they expire by themselves within a day; deleting the account removes them now) */
export const deleteStatements = (db, id) => [db.prepare("DELETE FROM ratelimits WHERE bucket LIKE '%:' || ?").bind(id)];


/** GET /v1/export/holds?after=: every hold the account still has (retention decides how long), oldest first, 200 a page.
 *  For the data export: an owner, in the app. */
export const HOLDS_PAGE = 200;
export async function exportHolds(c) {
  const env = c.env, s = c.s;
  await readLimit(env, 'export-holds:' + s.accountId, 120, now());
  const after = c.url.searchParams.get('after') === null ? 0 : int(c.url.searchParams.get('after'), 'after');
  const rows = (await env.DB.prepare('SELECT rowid AS n, id, token_id, method, host, path, rule, why, status, created_at, decided_at, expires_at, preview, kind, agent, deny_reason, context, needs, requested_by FROM holds WHERE account_id = ? AND rowid > ? ORDER BY rowid LIMIT ?')
    .bind(s.accountId, after, HOLDS_PAGE + 1).all()).results;
  const done = rows.length <= HOLDS_PAGE;
  const page = rows.slice(0, HOLDS_PAGE);
  return { entries: page.map(({ n, ...h }) => ({ ...h, context: safeJson(h.context) })), done, next_after: done ? null : page[page.length - 1].n };
}
