// Test world: D1 on node:sqlite (counting queries, with the Workers Free cap of 50 per invocation available), the log
// Durable Object on its own node:sqlite, a virtual passkey authenticator (real ECDSA P-256 + CBOR), a fake upstream.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { handle } from '../src/index.js';
import { LogCore } from '../src/log.js';
import { _resetLedgerMemory } from '../src/ledger.js';
import { b64u, sha256 } from '../src/util.js';

// D1 stand-in. Counts every executed statement (a batch counts each of its statements), can simulate the Workers Free
// limit of 50 D1 queries per invocation (cap), and can fail statements whose SQL matches failOn.
class Stmt {
  constructor(w, sql, args = []) { this.w = w; this.sql = sql; this.args = args; }
  bind(...a) { return new Stmt(this.w, this.sql, a); }
  async first() { this.w.tick(this.sql); return this.w.raw.prepare(this.sql).get(...this.args) ?? null; }
  async all() { this.w.tick(this.sql); return { results: this.w.raw.prepare(this.sql).all(...this.args) }; }
  async run() { this.w.tick(this.sql); return this._run(); }
  _run() { const r = this.w.raw.prepare(this.sql).run(...this.args); return { meta: { changes: Number(r.changes) } }; }
}
/** migrations: a filter over file names (default: all), so tests can build an older schema */
export function makeDb({ migrations = () => true } = {}) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  const dir = new URL('../migrations/', import.meta.url);
  for (const f of readdirSync(dir).sort().filter(migrations)) db.exec(readFileSync(new URL(f, dir), 'utf8'));
  const w = {
    raw: db, queries: 0, writes: 0, cap: 0, failOn: null,
    tick(sql) {
      w.queries++;
      if (/^\s*(INSERT|UPDATE|DELETE)/i.test(sql)) w.writes++;
      if (w.cap && w.queries > w.cap) throw new Error('D1: too many queries in this invocation');
      if (w.failOn && w.failOn.test(sql)) throw new Error('D1_ERROR: injected failure');
    },
    prepare: (sql) => new Stmt(w, sql),
    async batch(l) {
      for (const s of l) w.tick(s.sql);
      db.exec('BEGIN');
      try { const out = l.map((s) => s._run()); db.exec('COMMIT'); return out; } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
  return w;
}
/** Durable Object SQL storage stand-in, with transactionSync like ctx.storage */
export function makeDoSql() {
  const db = new DatabaseSync(':memory:');
  const s = {
    raw: db, failOn: null,
    exec: (sql, ...p) => {
      if (s.failOn && s.failOn.test(sql)) { s.failOn = null; throw new Error('SQLITE_ERROR: injected failure'); }
      const st = db.prepare(sql); const rows = /^\s*(select|with)/i.test(sql) ? st.all(...p) : (st.run(...p), []); return { toArray: () => rows };
    },
    transactionSync: (fn) => { db.exec('BEGIN'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } },
  };
  return s;
}
export async function logKeyJwk() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const j = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return JSON.stringify({ d: j.d, x: j.x });
}
const LOG_KEY = await logKeyJwk();

// ---- minimal CBOR encoder (test side only)
function head(mt, n) {
  if (n < 24) return [mt << 5 | n];
  if (n < 256) return [mt << 5 | 24, n];
  if (n < 65536) return [mt << 5 | 25, n >> 8, n & 255];
  return [mt << 5 | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function cbor(v) {
  if (typeof v === 'number') return Uint8Array.from(v >= 0 ? head(0, v) : head(1, -1 - v));
  if (typeof v === 'string') { const b = new TextEncoder().encode(v); return Uint8Array.from([...head(3, b.length), ...b]); }
  if (v instanceof Uint8Array) return Uint8Array.from([...head(2, v.length), ...v]);
  if (v instanceof Map) { const parts = [...v].flatMap(([k, x]) => [...cbor(k), ...cbor(x)]); return Uint8Array.from([...head(5, v.size), ...parts]); }
  throw new Error('cbor type');
}

const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; let v = b.slice(i); if (v[0] & 0x80) v = Uint8Array.of(0, ...v); return Uint8Array.of(2, v.length, ...v); };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

export class Authenticator {
  constructor(origin, rpId) { this.origin = origin; this.rpId = rpId; this.count = 0; }
  async create(options) {
    this.kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', this.kp.publicKey);
    const from = (s) => Uint8Array.from(Buffer.from(s, 'base64url'));
    this.credId = crypto.getRandomValues(new Uint8Array(16));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, from(jwk.x)], [-3, from(jwk.y)]]));
    const authData = cat(await sha256(this.rpId), Uint8Array.of(0x45), Uint8Array.of(0, 0, 0, 0), new Uint8Array(16), Uint8Array.of(0, 16), this.credId, cose);
    const cd = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin }));
    return { id: b64u(this.credId), attestationObject: b64u(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), clientDataJSON: b64u(cd) };
  }
  async get(options, { origin = this.origin, flags = 0x05 } = {}) {
    this.count++;
    const ad = cat(await sha256(this.rpId), Uint8Array.of(flags), Uint8Array.of(0, 0, 0, this.count));
    const cd = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.kp.privateKey, cat(ad, await sha256(cd))));
    return { id: b64u(this.credId), authenticatorData: b64u(ad), clientDataJSON: b64u(cd), signature: b64u(rawToDer(raw)) };
  }
}

export const ORIGIN = 'https://leash.test', RP_ID = 'leash.test', LOG_ORIGIN = 'leash.test/log';

export class World {
  /** opts.db: a prepared D1 stand-in (migration tests) */
  constructor({ db } = {}) {
    _resetLedgerMemory(); // one log key for every world, so the isolate caches keyed by it must start empty
    this.env = { DB: db || makeDb(), LEASH_KEK: b64u(crypto.getRandomValues(new Uint8Array(32))), IP_SALT: 'salt', ORIGIN, RP_ID, LOG_ORIGIN, LOG_KEY_JWK: LOG_KEY };
    this.sql = makeDoSql();
    this.core = new LogCore(this.sql, this.env);
    const core = this.core;
    this.log = {
      append: (i, n) => core.append(i, n), head: () => core.head(), inclusion: (a, b) => core.inclusion(a, b), consistency: (a, b) => core.consistency(a, b),
      entry: (i) => core.entry(i), entries: (s, c) => core.entries(s, c), tenantEntries: (t, b, c) => core.tenantEntries(t, b, c), forgetTenant: (t) => core.forgetTenant(t),
    };
    this.upstream = [];
    this.reply = () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'x=1' } });
    this.fetcher = async (url, init) => {
      this.upstream.push({ url, method: init.method, headers: Object.fromEntries(init.headers), body: init.body ? new TextDecoder().decode(init.body) : null });
      return this.reply(url, init);
    };
  }
  /** a world with its own log key (tests that compare two logs need them to differ) */
  static async create(opts) { const w = new World(opts); w.env.LOG_KEY_JWK = await logKeyJwk(); return w; }
  /** one request. Work passed to ctx.waitUntil (receipts, push) finishes before this returns, and its D1 queries are
   *  counted with the request's (w.env.DB.queries), as Workers counts them per invocation. xw is the receipts tests'
   *  name for the x-leash CSRF header. */
  async req(method, path, { body, cookie, bearer, origin = ORIGIN, xleash, xw, ip = '203.0.113.7', raw, headers = {} } = {}) {
    const h = { 'cf-connecting-ip': ip, ...headers };
    if (body !== undefined && !h['content-type']) h['content-type'] = 'application/json';
    if (cookie) h.cookie = cookie;
    if (bearer) h.authorization = 'Bearer ' + bearer;
    if (origin) h.origin = origin;
    if (xleash ?? xw ?? true) h['x-leash'] = '1';
    const pending = [];
    this.env.DB.queries = 0; this.env.DB.writes = 0;
    const url = path.startsWith('http') ? path : 'https://leash.test' + path;
    const r = await handle(new Request(url, { method, headers: h, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined) }), this.env, { fetcher: this.fetcher, log: this.log, ctx: { waitUntil: (p) => pending.push(p) } });
    const text = await r.text();
    let j; try { j = JSON.parse(text); } catch { j = text; }
    for (let i = 0; i < pending.length; i++) await Promise.allSettled([pending[i]]); // waitUntil may queue more work
    return { status: r.status, body: j, headers: r.headers, queries: this.env.DB.queries, writes: this.env.DB.writes };
  }
  /** passkey sign-up; returns {cookie, auth}, or {status, body} when refused */
  async user(name = 'Gautam', ip) {
    const auth = new Authenticator(ORIGIN, RP_ID);
    const b = await this.req('POST', '/v1/auth/register/begin', { body: { name }, ip });
    const f = await this.req('POST', '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: await auth.create(b.body.options) }, ip });
    if (f.status !== 200) return { status: f.status, body: f.body };
    const cookie = f.headers.get('set-cookie').split(';')[0];
    return { cookie, auth };
  }
  /** the account id behind a cookie */
  async accountId(cookie) { return (await this.req('GET', '/v1/me', { cookie })).body.account.id; }
}

/** an Ed25519 signer bound to a new receipts API key of this user (proof of possession over the server's sign text) */
export async function signedKey(w, cookie, label = 'signed') {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
  const ch = await w.req('POST', '/v1/keys/signer/begin', { cookie, body: { signerPublicKey: pub } });
  const proof = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(ch.body.sign)));
  const k = await w.req('POST', '/v1/keys', { cookie, body: { label, signerPublicKey: pub, signerChallengeId: ch.body.challengeId, signerProof: proof } });
  const { canonical } = await import('../src/receipts.js');
  const sign = async (rc) => ({ ...rc, sig: { alg: 'ed25519', value: b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(canonical(rc)))) } });
  return { key: k.body.key, id: k.body.id, kp, pub, sign };
}
