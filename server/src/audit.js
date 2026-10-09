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
  const prev = await env.DB.prepare('SELECT hash FROM audit WHERE account_id = ? ORDER BY seq DESC LIMIT 1').bind(accountId).first();
  const prevHash = prev ? prev.hash : '0'.repeat(64);
  const at = now();
  const d = JSON.stringify(detail || {});
  const hash = await sha256hex(`${prevHash}|${accountId}|${at}|${actor}|${action}|${d}`);
  await env.DB.prepare('INSERT INTO audit (account_id, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(accountId, at, actor, action, d, prevHash, hash).run();
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

export async function verifyChain(env, accountId) {
  const rows = (await env.DB.prepare('SELECT * FROM audit WHERE account_id = ? ORDER BY seq').bind(accountId).all()).results;
  let prev = '0'.repeat(64);
  for (const r of rows) {
    if (r.prev_hash !== prev) return { ok: false, brokenAt: r.seq };
    const h = await sha256hex(`${r.prev_hash}|${r.account_id}|${r.at}|${r.actor}|${r.action}|${r.detail}`);
    if (h !== r.hash) return { ok: false, brokenAt: r.seq };
    prev = r.hash;
  }
  return { ok: true, entries: rows.length, head: prev };
}
