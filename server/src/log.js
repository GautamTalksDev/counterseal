// The public log: one Durable Object, so appends are strictly sequential (a Merkle log must never fork).
// State lives in the object's own SQLite storage (Workers Free requires SQLite-backed Durable Objects). Every append
// returns a signed checkpoint and an inclusion proof, so the caller holds a receipt it can verify offline forever.
import { leafHash, appendNodes, mth, inclusionProof, consistencyProof } from './merkle.js';
import { signCheckpoint, logKey } from './note.js';
import { HttpError } from './util.js';

// leaves.tenant and leaves.opening (key id + salt) are the private side of each entry's public submitter commitment.
// They are never served publicly; only the owner's own views read them.
// meta.vkey pins the log's name and signing key at the first append: a log must never be signed under two names or
// two keys, or every receipt issued before the change stops verifying.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS leaves (idx INTEGER PRIMARY KEY, hash BLOB NOT NULL, entry TEXT NOT NULL, tenant TEXT NOT NULL, opening TEXT, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS leaves_tenant ON leaves(tenant, idx);
CREATE TABLE IF NOT EXISTS nodes (level INTEGER NOT NULL, idx INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY (level, idx));
CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY CHECK (id = 1), size INTEGER NOT NULL, root BLOB NOT NULL, note TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS forgotten (tenant_hash TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
`;

const bytes = (v) => (v instanceof Uint8Array ? v : new Uint8Array(v));
// a deleted account leaves only this one-way tombstone, so an append that was already in flight is unlinked too
const tombstone = async (tenant) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`witness/forgotten/v1\n${tenant}`)))].map((x) => x.toString(16).padStart(2, '0')).join('');

export class LogCore {
  /** sql: Durable Object SQL storage; txn: runs a synchronous function in one storage transaction (ctx.storage.transactionSync) */
  constructor(sql, env, txn = sql.transactionSync) {
    if (typeof txn !== 'function') throw new Error('LogCore needs transactionSync, so an append is all or nothing');
    this.sql = sql;
    this.env = env;
    this.txn = txn;
    for (const s of SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) sql.exec(s);
    this.cache = new Map();
  }
  getNode = async (level, idx) => {
    const k = level + ':' + idx;
    if (this.cache.has(k)) return this.cache.get(k);
    const r = this.sql.exec('SELECT hash FROM nodes WHERE level = ? AND idx = ?', level, idx).toArray()[0];
    if (!r) throw new Error(`missing node ${k}`);
    const h = bytes(r.hash);
    if (this.cache.size > 5000) this.cache.clear();
    this.cache.set(k, h);
    return h;
  };
  size() {
    const r = this.sql.exec('SELECT size FROM head WHERE id = 1').toArray()[0];
    return r ? r.size : 0;
  }
  head() {
    return this.sql.exec('SELECT size, root, note, at FROM head WHERE id = 1').toArray()[0] || null;
  }
  /** append many entries (canonical JSON strings) in order; returns per-entry {index, leaf, proof} and the new checkpoint.
   *  All or nothing: every hash, the signature and the proofs are computed first (async), against an overlay of the new
   *  nodes; then every write happens in one synchronous storage transaction. A failure anywhere leaves the log unchanged. */
  async append(items, now) {
    const start = this.size();
    const { vkey } = await logKey(this.env);
    const pinned = this.sql.exec("SELECT v FROM meta WHERE k = 'vkey'").toArray()[0];
    if (pinned && pinned.v !== vkey) throw new HttpError(503, 'log_key_changed', 'The log name or signing key differs from the one this log was started with. Nothing was recorded.');
    const overlay = new Map();
    const get = async (lv, i) => overlay.get(lv + ':' + i) ?? this.getNode(lv, i);
    const leaves = [], nodes = [];
    for (let j = 0; j < items.length; j++) {
      const idx = start + j, leaf = await leafHash(new TextEncoder().encode(items[j].entry));
      leaves.push({ idx, leaf, item: items[j] });
      for (const [lv, i, h] of await appendNodes(idx, leaf, get)) { overlay.set(lv + ':' + i, h); nodes.push([lv, i, h]); }
    }
    const size = start + items.length;
    const root = await mth(0, size, get);
    const note = await signCheckpoint(this.env, size, root);
    const entries = [];
    for (const { idx, leaf } of leaves) entries.push({ index: idx, leaf, proof: await inclusionProof(idx, size, get) });
    const stones = new Map();
    for (const { item } of leaves) if (!stones.has(item.tenant)) stones.set(item.tenant, await tombstone(item.tenant));
    this.txn(() => {
      if (this.size() !== start) throw new Error('log moved during append'); // never: appends are serialized
      if (!pinned) this.sql.exec("INSERT OR IGNORE INTO meta (k, v) VALUES ('vkey', ?)", vkey);
      const gone = new Set([...stones].filter(([, h]) => this.sql.exec('SELECT 1 FROM forgotten WHERE tenant_hash = ?', h).toArray().length).map(([t]) => t));
      for (const { idx, leaf, item: { tenant, entry, opening = null } } of leaves) {
        const forgotten = gone.has(tenant);
        this.sql.exec('INSERT INTO leaves (idx, hash, entry, tenant, opening, at) VALUES (?, ?, ?, ?, ?, ?)', idx, leaf, entry, forgotten ? 'deleted' : tenant, forgotten ? null : opening, now);
      }
      for (const [lv, i, h] of nodes) this.sql.exec('INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)', lv, i, h);
      this.sql.exec('INSERT INTO head (id, size, root, note, at) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET size = excluded.size, root = excluded.root, note = excluded.note, at = excluded.at', size, root, note, now);
    });
    // the node cache only ever holds committed nodes
    for (const [k, h] of overlay) this.cache.set(k, h);
    return { size, root, note, entries };
  }
  async inclusion(index, size) {
    return inclusionProof(index, size, this.getNode);
  }
  async consistency(m, n) {
    return consistencyProof(m, n, this.getNode);
  }
  entry(index) {
    return this.sql.exec('SELECT idx, hash, entry, tenant, opening, at FROM leaves WHERE idx = ?', index).toArray()[0] || null;
  }
  entries(start, count) {
    return this.sql.exec('SELECT idx, hash, entry, at FROM leaves WHERE idx >= ? ORDER BY idx LIMIT ?', start, count).toArray();
  }
  tenantEntries(tenant, before, count) {
    return this.sql.exec('SELECT idx, hash, entry, opening, at FROM leaves WHERE tenant = ? AND idx < ? ORDER BY idx DESC LIMIT ?', tenant, before, count).toArray();
  }
  /** account deletion: unlink the account from its entries. The public entries stay (that is the point of the log),
   *  but the server can no longer say whose they were, and the openings are gone. A one-way tombstone makes any
   *  append for this account that lands later unlinked as well. */
  async forgetTenant(tenant) {
    const h = await tombstone(tenant);
    this.txn(() => {
      this.sql.exec('INSERT OR IGNORE INTO forgotten (tenant_hash) VALUES (?)', h);
      this.sql.exec("UPDATE leaves SET tenant = 'deleted', opening = NULL WHERE tenant = ?", tenant);
    });
  }
}

/** Cloudflare Durable Object wrapper (RPC methods). Concurrency: blockConcurrencyWhile keeps other calls out while an
 *  append awaits its hashing and signing; transactionSync makes its writes all or nothing. */
export class ReceiptLog {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.core = new LogCore(ctx.storage.sql, env, (fn) => ctx.storage.transactionSync(fn));
  }
  append(items, now) { return this.ctx.blockConcurrencyWhile(() => this.core.append(items, now)); }
  head() { return this.core.head(); }
  inclusion(i, n) { return this.core.inclusion(i, n); }
  consistency(m, n) { return this.core.consistency(m, n); }
  entry(i) { return this.core.entry(i); }
  entries(s, c) { return this.core.entries(s, c); }
  tenantEntries(t, b, c) { return this.core.tenantEntries(t, b, c); }
  forgetTenant(t) { return this.core.forgetTenant(t); }
}
