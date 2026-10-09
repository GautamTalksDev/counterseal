// Record: the public transparency log (RFC 6962 Merkle tree in the ReceiptLog Durable Object, C2SP signed-note
// checkpoints), the receipts API for agents that log their own actions, and the broker's own receipts.
//
// Two kinds of entry, both {v: 2, submitter, received_at, receipt}:
//  - reported: sent by an agent with an lsr_ API key (POST /v1/receipts). The receipt says what the agent claims.
//  - broker: written by the broker itself for every decision it makes on a proxied call (allowed write, held, denied,
//    approved, executed after approval). These carry source: "broker" at the entry level, outside the receipt, so no
//    API key holder can ever make one: the receipts API only fills the inner receipt.
// Everything in an entry is public and permanent, so a broker receipt holds only: the method and the provider's API host
// (fixed per provider), the decision, the rule id, the map version, whether the call was signed by a registered agent
// key, the time, and `parent`, the SHA-256 of the account's own audit entry for that decision. Never a path, query,
// body, key, token, name, email or IP. The owner can open a receipt with their audit log (the parent hash) and the
// opening (account id and salt), and so prove what happened, which agent key made the call and who approved it.
import { HttpError, json, API_HEADERS, b64u, rand, randomId, sha256hex, now, str } from './util.js';
import { validate, canonical, checkSignature, checkSignerProof, signerProofText, signerKeyBytes, importSigner, LIMITS, SIGNED_KEEP_MS } from './receipts.js';
import { logKey, b64std } from './note.js';
import * as A from './auth.js';
import { audit } from './audit.js';

// a non-negative integer from a default (number) or a query parameter (plain decimal only: no "", "0x1", "1e3", " 1", "01");
// a missing required parameter (null) is refused, never read as 0
export const int = (v, name, max = Number.MAX_SAFE_INTEGER) => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(v) ? Number(v) : NaN;
  if (!Number.isSafeInteger(n) || n < 0 || n > max) throw new HttpError(400, 'bad_' + name);
  return n;
};
const month = (t) => new Date(t).toISOString().slice(0, 7);
const day = (t) => new Date(t).toISOString().slice(0, 10);
export const PUBLIC_PATH = /^\/v1\/(log|stats)(\/|$)/;
export const MAX_RECEIPTS_KEYS = 20;
export const CORS = { 'access-control-allow-origin': '*' };
// same security headers as JSON responses (HSTS, CSP, CORP, nosniff, no-store); CORS stays open for public reads
const text = (body, status = 200) => new Response(body, { status, headers: { ...API_HEADERS, 'content-type': 'text/plain; charset=utf-8', ...CORS } });
const pub = (data) => json(data, 200, CORS);

/** monthly receipts per account during the public beta */
export const quotaFor = (env) => (env.UNLIMITED ? Number.MAX_SAFE_INTEGER : Number(env.FREE_LIMIT) || LIMITS.FREE);
/** receipts per account per UTC day, so one account cannot fill the whole log for a day */
export const dayCapFor = (env) => (env.UNLIMITED ? Number.MAX_SAFE_INTEGER : Number(env.ACCOUNT_DAILY_CAP) || LIMITS.DAY);
/** total appends per UTC day across all accounts (abuse and cost guard). Sized for the Workers Free plan, where D1 and
 *  Durable Object SQLite each allow 100,000 rows written a day. See docs/DEPLOY.md. */
export const globalCap = (env) => Number(env.GLOBAL_DAILY_CAP) || 10_000;

// Per isolate: requests that are certain to be refused (the day's capacity or an account's quota is used up) are
// refused from memory, before any D1 write. Set only when D1 itself said the counter is full.
const full = new Map();
const isFull = (k, t) => (full.get(k) || 0) > t;
const markFull = (k, until) => { if (full.size > 10_000) full.clear(); full.set(k, until); };
const nextDay = (t) => Date.UTC(new Date(t).getUTCFullYear(), new Date(t).getUTCMonth(), new Date(t).getUTCDate() + 1);
const nextMonth = (t) => Date.UTC(new Date(t).getUTCFullYear(), new Date(t).getUTCMonth() + 1, 1);

// Per isolate: the log head (size, root, signed checkpoint) for HEAD_TTL, so the verify page, /v1/stats and
// /v1/log/checkpoint do not call the Durable Object on every view (Workers Free: 100k DO requests a day). An append
// made through this isolate replaces it at once.
const HEAD_TTL = 10_000;
const heads = new Map();
export async function cachedHead(c) {
  const hit = heads.get(c.key.vkey), t = now();
  if (hit && t - hit.at < HEAD_TTL) return hit.head;
  const head = await c.log.head();
  if (heads.size > 100) heads.clear();
  heads.set(c.key.vkey, { at: t, head });
  return head;
}

/** tests: forget this isolate's memory of full counters and the cached head (each test world is a new log) */
export function _resetLedgerMemory() { full.clear(); heads.clear(); lastPrune = 0; }

/** the log's Durable Object (tests pass their own in-memory one) */
export const logOf = (env) => env.__log || env.LOG.get(env.LOG.idFromName('main'));

// Public entries never carry the account id or API key id. Each entry has a salted commitment instead:
//   submitter = hex(SHA-256("witness/submitter/v2\n" || account_id || "\n" || key_id || "\n" || salt))
// key_id is the API key id for reported receipts and "broker" for the broker's own. The salt (the "opening") is kept
// server-side and shown only to the owner, who can use it to prove an entry is theirs.
export const submitterCommitment = (account, key, salt) => sha256hex(`witness/submitter/v2\n${account}\n${key}\n${salt}`);
const opening = (accountId, raw) => { if (!raw) return undefined; const o = JSON.parse(raw); return { account_id: accountId, key_id: o.key, salt: o.salt }; };

function bundle(c, e, size, note, entry, open) {
  const b = { index: e.index, leaf_hash: b64std(e.leaf), tree_size: size, inclusion_proof: e.proof.map(b64std), checkpoint: note, entry, log: c.key.vkey };
  if (open) b.opening = open;
  return b;
}

export async function apiKey(env, request) {
  const m = (request.headers.get('authorization') || '').match(/^Bearer (lsr_[A-Za-z0-9_-]{43})$/);
  if (!m) throw new HttpError(401, 'api_key_required', 'Send your receipts API key as: Authorization: Bearer lsr_...');
  const k = await env.DB.prepare('SELECT * FROM api_keys WHERE hash = ?').bind(await sha256hex(m[1])).first();
  // a receipts key made by a CLI session ends with it (expires_at); others have none
  if (!k || k.revoked || (k.expires_at && k.expires_at < now())) throw new HttpError(401, 'api_key_invalid');
  return k;
}

/** atomically reserve n units in a counter row, only if the total stays within max; returns false if it would not.
 *  One statement (D1 counts queries per invocation), and a refused reservation writes no row. */
async function reserve(db, table, keyCols, keyVals, n, max) {
  const cols = keyCols.join(', ');
  const r = await db.prepare(`INSERT INTO ${table} (${cols}, receipts) SELECT ${keyCols.map(() => '?').join(', ')}, ? WHERE ? <= ?
    ON CONFLICT (${cols}) DO UPDATE SET receipts = receipts + excluded.receipts WHERE receipts + excluded.receipts <= ? RETURNING receipts`).bind(...keyVals, n, n, max, max).first();
  return !!r;
}
const release = (db, table, keyCols, keyVals, n) =>
  db.prepare(`UPDATE ${table} SET receipts = MAX(0, receipts - ?) WHERE ${keyCols.map((k) => `${k} = ?`).join(' AND ')}`).bind(n, ...keyVals).run();

/** the account's month and day counters in one row and one statement: both must stay within their caps */
async function reserveUsage(db, acct, t, n, quota, dayCap) {
  const r = await db.prepare(`INSERT INTO usage (account_id, month, receipts, day, day_receipts) SELECT ?1, ?2, ?3, ?4, ?3 WHERE ?3 <= ?5 AND ?3 <= ?6
    ON CONFLICT (account_id, month) DO UPDATE SET receipts = receipts + ?3, day_receipts = CASE WHEN day = ?4 THEN day_receipts + ?3 ELSE ?3 END, day = ?4
    WHERE receipts + ?3 <= ?5 AND (CASE WHEN day = ?4 THEN day_receipts + ?3 ELSE ?3 END) <= ?6 RETURNING receipts`).bind(acct, month(t), n, day(t), quota, dayCap).first();
  return !!r;
}
const releaseUsage = (db, acct, t, n) => db.prepare('UPDATE usage SET receipts = MAX(0, receipts - ?1), day_receipts = CASE WHEN day = ?2 THEN MAX(0, day_receipts - ?1) ELSE day_receipts END WHERE account_id = ?3 AND month = ?4').bind(n, day(t), acct, month(t)).run();

/** replay records whose receipts are past the freshness window */
export const pruneSigned = (db, t) => db.prepare('DELETE FROM signed_receipts WHERE at < ?').bind(t - SIGNED_KEEP_MS);
let lastPrune = 0; // per isolate: at most one opportunistic prune every 5 minutes

/** the deletes that keep the receipts tables small; part of the broker's sweep (src/index.js) */
export const cleanupStatements = (db, t) => [
  db.prepare('DELETE FROM global_usage WHERE day < ?').bind(day(t - 40 * 86_400_000)),
  db.prepare('DELETE FROM usage WHERE month < ?').bind(month(t - 400 * 86_400_000)),
  db.prepare('DELETE FROM usage WHERE account_id NOT IN (SELECT id FROM accounts)'),
  pruneSigned(db, t),
];

// a log that changed its name or key refuses to sign (src/log.js); the Durable Object's error crosses RPC as a plain Error
const logChanged = (e) => /log name or signing key differs/.test(String(e && e.message));

/** reserve the account's counters and the global day, append, and undo everything if any step fails. Throws HttpError
 *  402 (quota), 503 (capacity) or the append's own error. */
async function reserveAndAppend(c, { t, acct, items, signerClaim }) {
  const db = c.env.DB, n = items.length;
  const quota = quotaFor(c.env), dayCap = dayCapFor(c.env);
  const capKey = `cap:${c.key.vkey}:${day(t)}`, quotaKey = `quota:${acct}:${month(t)}`, dayKey = `dayq:${acct}:${day(t)}`;
  if (isFull(capKey, t)) throw new HttpError(503, 'log_at_capacity', 'The public log reached its daily capacity. Nothing was recorded. Try again after 00:00 UTC.');
  if (isFull(quotaKey, t)) throw new HttpError(402, 'quota', `Monthly quota is ${quota} receipts and all are used, so nothing was recorded.`, { quota, used: quota, remaining: 0 });
  if (isFull(dayKey, t)) throw new HttpError(402, 'daily_quota', `An account can record up to ${dayCap} receipts a day and today's are used, so nothing was recorded. Try again after 00:00 UTC.`, { dayCap, remaining: 0 });
  const held = [];
  try {
    if (!(await reserveUsage(db, acct, t, n, quota, dayCap))) {
      const u = await db.prepare('SELECT receipts, day, day_receipts FROM usage WHERE account_id = ? AND month = ?').bind(acct, month(t)).first();
      const used = u?.receipts || 0, usedToday = u && u.day === day(t) ? u.day_receipts : 0;
      if (used + n > quota) {
        if (used >= quota) markFull(quotaKey, nextMonth(t));
        throw new HttpError(402, 'quota', `Monthly quota is ${quota} receipts and ${used} are used. This batch of ${n} would exceed it, so nothing was recorded.`, { quota, used, remaining: Math.max(0, quota - used) });
      }
      if (usedToday >= dayCap) markFull(dayKey, nextDay(t));
      throw new HttpError(402, 'daily_quota', `An account can record up to ${dayCap} receipts a day and ${usedToday} are used today. This batch of ${n} would exceed it, so nothing was recorded.`, { dayCap, usedToday, remaining: Math.max(0, dayCap - usedToday) });
    }
    held.push(() => releaseUsage(db, acct, t, n));
    const cap = globalCap(c.env), G = ['day'], gk = [day(t)];
    if (!(await reserve(db, 'global_usage', G, gk, n, cap))) {
      const used = (await db.prepare('SELECT receipts FROM global_usage WHERE day = ?').bind(...gk).first())?.receipts || 0;
      if (used >= cap) markFull(capKey, nextDay(t));
      throw new HttpError(503, 'log_at_capacity', 'The public log reached its daily capacity. Nothing was recorded. Try again after 00:00 UTC.');
    }
    held.push(() => release(db, 'global_usage', G, gk, n));
    const res = await c.log.append(items, t).catch((e) => { throw logChanged(e) ? new HttpError(503, 'log_key_changed', 'The log is misconfigured. Nothing was recorded.') : e; });
    heads.set(c.key.vkey, { at: now(), head: { size: res.size, root: res.root, note: res.note, at: t } });
    return res;
  } catch (e) {
    // undo in reverse; a failing undo is logged and never hides the original error
    for (const undo of [...held.reverse(), ...(signerClaim ? [signerClaim] : [])]) {
      try { await undo(); } catch (u) { console.error(JSON.stringify({ event: 'undo_failed', message: String(u?.message || u).slice(0, 200) })); }
    }
    throw e;
  }
}

/** the writes of POST /v1/receipts: replay claim, quota, global cap, append */
async function record(c, { t, acct, keyId, db, signer, sigs, items }) {
  // Replay: each (signer, signature) pair is accepted once, all claimed in one statement before the quota.
  let claimed = [];
  const unclaim = async () => {
    if (claimed.length) await db.prepare('DELETE FROM signed_receipts WHERE signer = ? AND sig IN (SELECT value FROM json_each(?))').bind(signer, JSON.stringify(claimed)).run();
    claimed = [];
  };
  if (signer) {
    claimed = (await db.prepare('INSERT INTO signed_receipts (signer, sig, at) SELECT ?, value, ? FROM json_each(?) WHERE true ON CONFLICT DO NOTHING RETURNING sig')
      .bind(signer, t, JSON.stringify(sigs)).all()).results.map((r) => r.sig);
    if (claimed.length !== sigs.length) {
      await unclaim();
      throw new HttpError(409, 'replay', 'This signed receipt was already recorded. Sign each receipt once, with its own ts.');
    }
  }
  const res = await reserveAndAppend(c, { t, acct, items, signerClaim: signer ? unclaim : null });
  // bookkeeping after the append must never turn a recorded batch into an error
  c.waitUntil(db.prepare('UPDATE api_keys SET last_used = ? WHERE id = ?').bind(t, keyId).run());
  if (signer && t - lastPrune > 5 * 60_000) { lastPrune = t; c.waitUntil(pruneSigned(db, t).run()); }
  return { receipts: res.entries.map((e, i) => bundle(c, e, res.size, res.note, JSON.parse(items[i].entry), opening(acct, items[i].opening))) };
}

/** after a receipts request: if the account was deleted while it was in flight, leave nothing behind for it (a usage
 *  row reserved after the deletion, replay records, or a link in the log; the log also keeps a tombstone for this) */
async function leaveNothingIfDeleted(c, db, acct, signer) {
  if (await db.prepare('SELECT 1 FROM accounts WHERE id = ?').bind(acct).first()) return;
  await db.batch([
    db.prepare('DELETE FROM usage WHERE account_id = ?').bind(acct),
    ...(signer ? [db.prepare('DELETE FROM signed_receipts WHERE signer = ?').bind(signer)] : []),
  ]);
  await c.log.forgetTenant(acct);
}

// ---------------------------------------------------------------- broker receipts
/** which audit actions are broker decisions, and the public decision word for each */
export const DECISION = { proxy: 'allowed', hold: 'held', deny: 'denied', approve: 'approved', proxy_approved: 'executed' };
const RULE = /^[A-Za-z0-9_.:-]{1,80}$/;

/** the public receipt for one broker decision. Only fixed vocabulary goes in: method and provider host, decision, rule
 *  id, map version, a boolean, the time and the audit hash. */
export function brokerReceipt({ action, detail, auditHash, at, mapVersion }) {
  const method = /^[A-Z]{3,7}$/.test(detail.method || '') ? detail.method : null;
  const host = /^[a-z0-9.-]{1,100}$/.test(detail.host || '') ? detail.host : null;
  const meta = { map: mapVersion };
  if (detail.rule && RULE.test(detail.rule)) meta.rule = detail.rule;
  if (detail.agent_key) meta.agent_key = true;
  if (detail.passkey) meta.passkey = true;
  return { agent: 'broker', action: method && host ? `${method} ${host}` : action === 'approve' ? 'approve' : 'decision', decision: DECISION[action], parent: auditHash, ts: at, meta };
}

/** Seal one broker decision in the public log, for an account that has receipts on. Never fails the decision: if the
 *  log is full, over quota or unreachable, the decision stays in the account's audit log, the month's "skipped" count
 *  goes up, and nothing else changes. Runs after the response (ctx.waitUntil): about 3 D1 queries and 1 Durable Object
 *  request. */
export async function sealDecision(env, accountId, receipt) {
  const db = env.DB, t = receipt.ts;
  const skip = async (why) => {
    await db.prepare('INSERT INTO usage (account_id, month, receipts, day, day_receipts, skipped) VALUES (?, ?, 0, ?, 0, 1) ON CONFLICT (account_id, month) DO UPDATE SET skipped = skipped + 1').bind(accountId, month(t), day(t)).run();
    return { sealed: false, why };
  };
  let key;
  try { key = await logKey(env); } catch { return skip('not_configured'); }
  const c = { env, key, log: logOf(env) };
  const salt = randomId(16);
  const entry = canonical({ v: 2, source: 'broker', submitter: await submitterCommitment(accountId, 'broker', salt), received_at: t, receipt });
  const items = [{ tenant: accountId, entry, opening: JSON.stringify({ key: 'broker', salt }) }];
  let res;
  try { res = await reserveAndAppend(c, { t, acct: accountId, items }); }
  catch (e) {
    if (!(e instanceof HttpError)) console.error(JSON.stringify({ event: 'seal_failed', message: String(e?.message || e).slice(0, 200) }));
    return skip(e instanceof HttpError ? e.code : 'append_failed');
  }
  const index = res.entries[0].index;
  await db.prepare('UPDATE audit SET receipt = ? WHERE account_id = ? AND hash = ?').bind(index, accountId, receipt.parent).run();
  return { sealed: true, index };
}

// ---------------------------------------------------------------- routes
/** a well-formed Ed25519 public key (canonical, not of small order) that no other account has bound */
async function signerPub(c, raw) {
  const signer = str(raw, 'signerPublicKey', { max: 60, re: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/ });
  await crypto.subtle.importKey('raw', signerKeyBytes(signer), { name: 'Ed25519' }, false, ['verify']).catch(() => { throw new HttpError(400, 'bad_signerPublicKey'); });
  const other = await c.env.DB.prepare('SELECT 1 FROM api_keys WHERE signer_pub = ? AND account_id != ? UNION ALL SELECT 1 FROM agent_keys WHERE x = ? AND account_id != ? LIMIT 1').bind(signer, c.s.accountId, signer, c.s.accountId).first();
  if (other) throw new HttpError(409, 'signer_taken', 'That public key is bound to another account.');
  return signer;
}

async function myEntryRows(c) {
  const v = c.url.searchParams.get('before');
  const before = v === null ? Number.MAX_SAFE_INTEGER : int(v, 'before');
  return c.log.tenantEntries(c.s.accountId, before, 50);
}

export const LEDGER_ROUTES = [
  // ---- public, verifiable by anyone
  ['GET', /^\/v1\/log\/checkpoint$/, 'pub', async (c) => text((await cachedHead(c))?.note || 'empty log\n')],
  ['GET', /^\/v1\/log\/key$/, 'pub', async (c) => pub({ origin: c.key.name, verifier_key: c.key.vkey, algorithm: 'Ed25519', format: 'c2sp.org/signed-note' })],
  ['GET', /^\/v1\/log\/proof\/inclusion$/, 'pub', async (c) => {
    const h = await cachedHead(c); const size = int(c.url.searchParams.get('size') ?? h?.size, 'size', h?.size || 0);
    const index = int(c.url.searchParams.get('index'), 'index', size - 1);
    return pub({ index, tree_size: size, inclusion_proof: (await c.log.inclusion(index, size)).map(b64std) });
  }],
  ['GET', /^\/v1\/log\/proof\/consistency$/, 'pub', async (c) => {
    const h = await cachedHead(c); const second = int(c.url.searchParams.get('second') ?? h?.size, 'second', h?.size || 0);
    const first = int(c.url.searchParams.get('first'), 'first', second);
    if (first === 0) throw new HttpError(400, 'bad_first');
    return pub({ first, second, consistency_proof: (await c.log.consistency(first, second)).map(b64std) });
  }],
  ['GET', /^\/v1\/log\/entries$/, 'pub', async (c) => {
    const start = int(c.url.searchParams.get('start') ?? 0, 'start'); const count = Math.min(100, int(c.url.searchParams.get('count') ?? 50, 'count'));
    const rows = await c.log.entries(start, count);
    // only the public, hashed entry: never the tenant or the opening
    return pub({ entries: rows.map((r) => ({ index: r.idx, leaf_hash: b64std(new Uint8Array(r.hash)), entry: JSON.parse(r.entry) })) });
  }],
  // the verify page's one call: the head, its signed checkpoint and the verifier key, so the page can verify it in the
  // browser and check pasted bundles against the log's key. Cacheable for a few seconds.
  ['GET', /^\/v1\/stats$/, 'pub', async (c) => {
    const h = await cachedHead(c);
    return json({ tree_size: h?.size || 0, root: h ? b64std(new Uint8Array(h.root)) : null, updated_at: h?.at || null, checkpoint: h?.note || null, origin: c.key.name, verifier_key: c.key.vkey },
      200, { ...CORS, 'cache-control': `public, max-age=${HEAD_TTL / 1000}` });
  }],

  // ---- receipt intake (API key)
  ['POST', /^\/v1\/receipts$/, 'key', async (c) => {
    const list = Array.isArray(c.body.receipts) ? c.body.receipts : c.body.receipt ? [c.body.receipt] : null;
    const maxBatch = c.k.signer_pub ? LIMITS.MAX_SIGNED_BATCH : LIMITS.MAX_BATCH;
    if (!list || !list.length || list.length > maxBatch) throw new HttpError(400, 'bad_batch', `Send receipt, or receipts (1 to ${maxBatch}${c.k.signer_pub ? ' for a key that requires signatures' : ''}).`);
    const t = now(), acct = c.k.account_id, keyId = c.k.id;
    const items = [], sigs = [], db = c.env.DB, signer = c.k.signer_pub;
    const verifyKey = signer ? await importSigner(signer) : null;
    for (const r of list) {
      const v = validate(r);
      await checkSignature(v, verifyKey, t);
      if (signer) {
        if (sigs.includes(v.sig.value)) throw new HttpError(409, 'replay', 'The same signed receipt appears twice in this batch.');
        sigs.push(v.sig.value);
      }
      const salt = randomId(16);
      const entry = canonical({ v: 2, submitter: await submitterCommitment(acct, keyId, salt), received_at: t, receipt: v });
      items.push({ tenant: acct, entry, opening: JSON.stringify({ key: keyId, salt }) });
    }
    try {
      return await record(c, { t, acct, keyId, db, signer, sigs, items });
    } finally {
      // the account may have been deleted while this request was in flight: then leave nothing behind for it
      c.waitUntil(leaveNothingIfDeleted(c, db, acct, signer));
    }
  }],

  // ---- receipts API keys (lsr_). Binding a signer needs proof of possession of the private key.
  ['GET', /^\/v1\/keys$/, 'session', async (c) => ({ keys: (await c.env.DB.prepare('SELECT id, label, signer_pub, revoked, created_at, last_used, expires_at FROM api_keys WHERE account_id = ? ORDER BY created_at DESC LIMIT 200').bind(c.s.accountId).all()).results })],
  ['POST', /^\/v1\/keys\/signer\/begin$/, 'write', async (c) => {
    const signer = await signerPub(c, c.body.signerPublicKey);
    const { id, challenge } = await A.newChallenge(c.env, 'signer', c.s.accountId, signer);
    return { challengeId: id, challenge, origin: c.key.name, account: c.s.accountId, sign: signerProofText(challenge, signer, c.key.name, c.s.accountId) };
  }],
  ['POST', /^\/v1\/keys$/, 'write', async (c) => {
    const label = str(c.body.label ?? 'agent', 'label', { max: 60, re: /^[\p{L}\p{N} ._:/()-]+$/u });
    let signer = null;
    if (c.body.agentKeyId !== undefined) {
      // an agent key already proved possession when it was registered; reuse it as this key's signer
      const k = await c.env.DB.prepare('SELECT x FROM agent_keys WHERE id = ? AND account_id = ? AND revoked_at IS NULL').bind(str(c.body.agentKeyId, 'agentKeyId', { max: 24, re: /^[0-9a-f]{24}$/ }), c.s.accountId).first();
      if (!k) throw new HttpError(404, 'not_found');
      signer = await signerPub(c, k.x);
    } else if (c.body.signerPublicKey !== undefined) {
      // step 2: proof of possession, the private key signed that challenge
      signer = await signerPub(c, c.body.signerPublicKey);
      const ch = await A.takeChallenge(c.env, c.body.signerChallengeId, 'signer');
      if (ch.account_id !== c.s.accountId || ch.name !== signer) throw new HttpError(400, 'challenge_expired', 'Start again.');
      await checkSignerProof(signer, ch.challenge, c.body.signerProof, c.key.name, c.s.accountId);
    }
    const live = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE account_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)').bind(c.s.accountId, now()).first();
    if (live.n >= MAX_RECEIPTS_KEYS) throw new HttpError(409, 'too_many_keys', `Up to ${MAX_RECEIPTS_KEYS} receipts keys. Revoke one first.`);
    const key = 'lsr_' + b64u(rand(32)); const id = randomId();
    // made by a CLI session: it ends when that session ends, and revoking the session revokes it
    const cli = c.s.kind === 'cli' ? await A.sessionId(c.s.hash) : null;
    const expiresAt = cli ? c.s.expiresAt : null;
    await c.env.DB.prepare('INSERT INTO api_keys (id, account_id, hash, label, signer_pub, created_at, session_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(id, c.s.accountId, await sha256hex(key), label, signer, now(), cli, expiresAt).run();
    await audit(c.env, c.s.accountId, c.s.kind, 'receipts_key_created', { id, label, signed: !!signer, ...(cli ? { session: cli, expires_at: expiresAt } : {}) });
    return { id, key, label, ...(expiresAt ? { expiresAt } : {}), note: `Shown once. Only a hash is kept.${expiresAt ? ' It ends with this command line sign-in; make lasting keys in the app.' : ''}` };
  }],
  ['DELETE', /^\/v1\/keys\/([0-9a-f]{24})$/, 'write', async (c) => {
    const r = await c.env.DB.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND account_id = ? AND revoked = 0').bind(c.m[1], c.s.accountId).run();
    if (!r.meta.changes) throw new HttpError(404, 'not_found');
    await audit(c.env, c.s.accountId, c.s.kind, 'receipts_key_revoked', { id: c.m[1] });
    return { ok: true };
  }],
  ['GET', /^\/v1\/my\/receipts$/, 'session', async (c) => {
    const rows = await myEntryRows(c);
    return { receipts: rows.map((r) => ({ index: r.idx, leaf_hash: b64std(new Uint8Array(r.hash)), entry: JSON.parse(r.entry), opening: opening(c.s.accountId, r.opening) })), more: rows.length === 50 };
  }],
  // a fresh, verifiable bundle for one of your receipts, proved against the latest checkpoint
  ['GET', /^\/v1\/my\/receipts\/(\d{1,15})\/bundle$/, 'session', async (c) => {
    const idx = int(c.m[1], 'index');
    const row = await c.log.entry(idx);
    if (!row || row.tenant !== c.s.accountId) throw new HttpError(404, 'not_found');
    const h = await c.log.head();
    const proof = await c.log.inclusion(idx, h.size);
    return bundle(c, { index: idx, leaf: new Uint8Array(row.hash), proof }, h.size, h.note, JSON.parse(row.entry), opening(c.s.accountId, row.opening));
  }],
];

/** account deletion, receipts side: every API key stops working first, then the log is unlinked; the caller's batch
 *  then deletes the rows (deleteStatements) */
export async function forgetAccount(env, accountId) {
  await env.DB.prepare('UPDATE api_keys SET revoked = 1 WHERE account_id = ?').bind(accountId).run();
  await logOf(env).forgetTenant(accountId);
}
export const deleteStatements = (db, id) => [
  db.prepare('DELETE FROM signed_receipts WHERE signer IN (SELECT signer_pub FROM api_keys WHERE account_id = ? AND signer_pub IS NOT NULL)').bind(id),
  db.prepare('DELETE FROM api_keys WHERE account_id = ?').bind(id),
  db.prepare('DELETE FROM usage WHERE account_id = ?').bind(id),
];

/** receipts numbers for the dashboard */
export async function usageOf(env, accountId) {
  const u = await env.DB.prepare('SELECT receipts, skipped, day, day_receipts FROM usage WHERE account_id = ? AND month = ?').bind(accountId, month(now())).first();
  return { usage: u?.receipts || 0, skipped: u?.skipped || 0, today: u && u.day === day(now()) ? u.day_receipts : 0 };
}
