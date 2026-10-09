// Append-only audit log, hash-chained per account: each entry commits to the one before it, so a deleted or
// edited row breaks the chain (verifyChain). Secrets and tokens are never written here. A hold records the
// SHA-256 of the request preview, so the log proves exactly what was approved without keeping request content forever.
import { sha256hex, now } from './util.js';

export async function audit(env, accountId, actor, action, detail) {
  const prev = await env.DB.prepare('SELECT hash FROM audit WHERE account_id = ? ORDER BY seq DESC LIMIT 1').bind(accountId).first();
  const prevHash = prev ? prev.hash : '0'.repeat(64);
  const at = now();
  const d = JSON.stringify(detail || {});
  const hash = await sha256hex(`${prevHash}|${accountId}|${at}|${actor}|${action}|${d}`);
  await env.DB.prepare('INSERT INTO audit (account_id, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(accountId, at, actor, action, d, prevHash, hash).run();
  const w = witness(env, accountId, actor, action, detail, hash, at).catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(w);
  return hash;
}

export async function list(env, accountId, before, limit = 100) {
  const rows = await env.DB.prepare('SELECT seq, at, actor, action, detail, prev_hash, hash FROM audit WHERE account_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?')
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

// Optional: mirror decisions into WITNESS (https://github.com/GautamTalksDev/witness), a public append-only log, so
// what LEASH decided can be proven later by anyone. Only hashes and labels leave LEASH; never keys or bodies.
const DECISION = { proxy: 'allowed', hold: 'held', deny: 'denied', approve: 'approved', proxy_approved: 'executed' };
// The WITNESS log is public, so paths (repo names, project ids) are never sent in clear: only method, host and a
// SHA-256 of the path, which the account owner can later match against their own audit log.
async function witness(env, accountId, actor, action, detail, auditHash, at) {
  if (!env.WITNESS_URL || !env.WITNESS_KEY || !DECISION[action]) return;
  const receipt = {
    agent: 'leash:' + (await sha256hex(actor)).slice(0, 16), action: `${detail.method || action} ${detail.host || ''}`.trim().slice(0, 200),
    input_sha256: await sha256hex(String(detail.path || '')),
    decision: DECISION[action], ts: at, run: (await sha256hex('run|' + accountId)).slice(0, 32), parent: auditHash,
    meta: { source: 'leash', ...(detail.rule ? { rule: String(detail.rule).slice(0, 200) } : {}) },
  };
  const p = fetch(env.WITNESS_URL.replace(/\/+$/, '') + '/v1/receipts', {
    method: 'POST', redirect: 'error', headers: { authorization: 'Bearer ' + env.WITNESS_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ receipt }),
  });
  await p;
}
