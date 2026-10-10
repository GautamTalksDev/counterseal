// Append-only audit log, hash-chained per account: each entry commits to the one before it, so a deleted or
// edited row breaks the chain (verifyChain). Secrets and tokens are never written here. A hold records the
// SHA-256 of the request preview, so the log proves exactly what was approved without keeping request content forever.
//
// Decisions (an allowed write, a hold, a denial, an approval, an approved call going through) are also sealed in the
// public log when the account has receipts on (src/ledger.js): the public receipt carries this entry's hash as its
// `parent`, so the owner can match every receipt to the private entry it stands for. The receipt index is stored in
// the `receipt` column, outside the hash chain.
import { sha256hex, now } from './util.js';
import { DECISION, brokerReceipt, sealDecision } from './ledger.js';
import { MAP_VERSION } from './providers.js';

/** opts.receipts: whether the account has receipts on, when the caller already knows (saves a query) */
export async function audit(env, accountId, actor, action, detail, opts = {}) {
  const d = JSON.stringify(detail || {});
  const ZERO = '0'.repeat(64);
  // Two requests for one account (an agent making parallel writes) could both read the same head and both append after
  // it, forking the chain so /v1/audit/verify reports it broken. So the insert happens only if the head is still the one
  // this entry commits to, checked in the same statement; if another entry got there first, read the new head and retry.
  // At most 10 tries (20 D1 queries; Workers Free allows 50 per invocation): each try loses only to an entry that landed.
  let at, hash, prevHash;
  for (let attempt = 0; ; attempt++) {
    const prev = await env.DB.prepare('SELECT hash FROM audit WHERE account_id = ? ORDER BY seq DESC LIMIT 1').bind(accountId).first();
    prevHash = prev ? prev.hash : ZERO;
    at = now();
    hash = await sha256hex(`${prevHash}|${accountId}|${at}|${actor}|${action}|${d}`);
    const r = await env.DB.prepare(`INSERT INTO audit (account_id, at, actor, action, detail, prev_hash, hash) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
      WHERE COALESCE((SELECT hash FROM audit WHERE account_id = ?1 ORDER BY seq DESC LIMIT 1), ?8) = ?6`)
      .bind(accountId, at, actor, action, d, prevHash, hash, ZERO).run();
    if (r.meta.changes) break;
    if (attempt >= 9) throw new Error('audit: the chain head kept moving');
  }
  if (DECISION[action]) {
    const p = (async () => {
      const on = opts.receipts ?? (await env.DB.prepare('SELECT receipts FROM accounts WHERE id = ?').bind(accountId).first())?.receipts;
      if (!on) return;
      await sealDecision(env, accountId, brokerReceipt({ action, detail: detail || {}, auditHash: hash, at, mapVersion: MAP_VERSION }));
    })().catch((e) => console.error(JSON.stringify({ event: 'seal_failed', message: String(e?.message || e).slice(0, 200) })));
    // after the response when running on Workers: the decision never waits for the log
    if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p); else await p;
  }
  return hash;
}

export async function list(env, accountId, before, limit = 100) {
  const rows = await env.DB.prepare('SELECT seq, at, actor, action, detail, prev_hash, hash, receipt FROM audit WHERE account_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?')
    .bind(accountId, before || Number.MAX_SAFE_INTEGER, Math.min(200, limit)).all();
  return rows.results.map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
}

/** GET /v1/audit/verify?after=<seq>: the chain checked a page at a time (VERIFY_PAGE entries a request), from the start, or
 *  from the entry after `after` (linked to that entry's stored hash). A whole log in one request would read every row of the
 *  account and hash each one: past a few thousand entries that is over the Workers Free CPU limit, and repeated it would
 *  spend the day's D1 read budget for every tenant. `done: false` and `next_after` say where the next page starts. */
export const VERIFY_PAGE = 100;
export async function verifyChain(env, accountId, after = 0) {
  let prev = '0'.repeat(64);
  if (after) {
    const p = await env.DB.prepare('SELECT hash FROM audit WHERE account_id = ? AND seq = ?').bind(accountId, after).first();
    if (!p) return { ok: false, brokenAt: after, error: 'after_not_found' };
    prev = p.hash;
  }
  const rows = (await env.DB.prepare('SELECT seq, account_id, at, actor, action, detail, prev_hash, hash FROM audit WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?').bind(accountId, after, VERIFY_PAGE + 1).all()).results;
  const done = rows.length <= VERIFY_PAGE, page = rows.slice(0, VERIFY_PAGE);
  for (const r of page) {
    if (r.prev_hash !== prev) return { ok: false, brokenAt: r.seq };
    const h = await sha256hex(`${r.prev_hash}|${r.account_id}|${r.at}|${r.actor}|${r.action}|${r.detail}`);
    if (h !== r.hash) return { ok: false, brokenAt: r.seq };
    prev = r.hash;
  }
  return { ok: true, entries: page.length, head: prev, done, next_after: done ? null : page[page.length - 1].seq };
}
