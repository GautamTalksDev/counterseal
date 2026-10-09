// Drop-in Web Bot Auth verification for sites. Two modes:
//   local (default): verify the signature yourself (directory fetched over https with SSRF checks and a small cache); no third
//          party involved. Replay protection uses a nonce store: by default an in-memory Map, which only protects ONE
//          process or isolate. Pass { nonceStore } (memoryNonceStore, d1NonceStore, kvNonceStore or your own) to share
//          it across instances. Signatures without a nonce are accepted only if valid for 5 minutes or less.
//   api: POST the signature headers to a verify API you name with { api } (there is no default: Counterseal does not
//        run a public verify API or an operator registry). Fails closed.
import { verifyRequest, directoryUrl, DIRECTORY_TYPE } from './websig.mjs';
import { isPublicHttpsUrl, isPrivateIp, vettedLookup, readCapped, parseDirectory, MAX_DIRECTORY_BYTES } from './net.mjs';

export const DEFAULT_API = null;

// ---------------------------------------------------------------- nonce stores
// Interface: { seen(nonce, expiresAtSeconds, keyid) -> Promise<boolean> }  true means "already used" (a replay).
// seen() must record the nonce atomically with the check, and keep it at least until expiresAtSeconds.

/** per-process store. Fine for one Node server; NOT shared between Workers isolates, serverless instances or replicas. */
export function memoryNonceStore({ max = 100000 } = {}) {
  const m = new Map();
  return {
    async seen(nonce, exp, keyid = '') {
      const t = Math.floor(Date.now() / 1000);
      if (m.size >= max) for (const [k, e] of m) if (e < t) m.delete(k);
      if (m.size >= max) m.delete(m.keys().next().value);
      const k = keyid + ' ' + nonce;
      if (m.has(k)) return true;
      m.set(k, exp);
      return false;
    },
  };
}

/** Cloudflare D1 (or any SQLite-like binding). Needs: CREATE TABLE sigil_nonces (k TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
 *  Atomic: the INSERT either adds the row or does nothing. Delete rows with expires_at < now on a schedule. */
export function d1NonceStore(db, table = 'sigil_nonces') {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new Error('bad table name');
  return {
    async seen(nonce, exp, keyid = '') {
      const r = await db.prepare(`INSERT INTO ${table} (k, expires_at) VALUES (?, ?) ON CONFLICT(k) DO NOTHING`).bind(keyid + ' ' + nonce, exp).run();
      return !(r.meta && r.meta.changes > 0);
    },
  };
}

/** Workers KV. KV is eventually consistent, so two requests racing in different locations can both pass: use it only
 *  when that is acceptable, and prefer d1NonceStore or a Durable Object for strict single use. */
export function kvNonceStore(kv, prefix = 'sigil-nonce:') {
  return {
    async seen(nonce, exp, keyid = '') {
      const k = prefix + keyid + ':' + nonce;
      if (await kv.get(k)) return true;
      const ttl = Math.max(60, exp - Math.floor(Date.now() / 1000) + 60);
      await kv.put(k, '1', { expirationTtl: ttl });
      return false;
    },
  };
}

// ---------------------------------------------------------------- safe directory fetch
const isNode = typeof process !== 'undefined' && !!(process.versions && process.versions.node);
const DIRECTORY_TIMEOUT_MS = 5000;
const systemResolver = async () => { const dns = await import('node:dns/promises'); return (h) => dns.lookup(h, { all: true, verbatim: true }); };

/** custom fetch only: resolve and refuse private answers first. Best effort: that fetch resolves again by itself. */
async function assertPublicDns(hostname, lookup) {
  const fn = lookup || (isNode ? await systemResolver() : null);
  if (!fn) return;
  const addrs = await fn(hostname);
  const list = (Array.isArray(addrs) ? addrs : [addrs]).map((a) => (typeof a === 'string' ? a : a.address));
  if (!list.length || list.some((a) => isPrivateIp(a))) throw new Error('directory host not allowed');
}

/**
 * Node: one GET over node:https whose socket uses vettedLookup as its DNS lookup. The host is resolved once, at
 * connect time, every address in the answer is checked, and the socket connects only to an address that passed, so a
 * second DNS answer can never redirect it (no DNS rebinding window). Host and SNI stay the hostname, so TLS still
 * checks the certificate for it. Backstop: the connected peer address is checked again and the socket is destroyed
 * before the HTTP request is sent if it is not public. No redirects, no connection reuse (agent: false).
 * opts.request (the node:https request signature) is injectable for tests.
 */
async function pinnedGet(url, { headers, resolve, request }) {
  const send = request || (await import('node:https')).request;
  const { Readable } = await import('node:stream');
  const signal = AbortSignal.timeout(DIRECTORY_TIMEOUT_MS);
  return new Promise((ok, fail) => {
    const req = send(url, { method: 'GET', headers, lookup: vettedLookup(resolve), agent: false, signal }, (res) => {
      const status = res.statusCode || 0;
      if (status < 200 || status > 299) { res.resume(); return fail(new Error('directory HTTP ' + status)); }
      const h = new Headers();
      for (const [k, v] of Object.entries(res.headers || {})) if (typeof v === 'string') h.set(k, v);
      ok(new Response(status === 204 || status === 205 ? null : Readable.toWeb(res), { status, headers: h }));
    });
    req.on('socket', (s) => s.once('connect', () => { if (isPrivateIp(s.remoteAddress)) s.destroy(new Error('directory host not allowed')); }));
    req.on('error', fail);
    req.end();
  });
}

/**
 * Build a fetchDirectory(agentOrigin) for verifyRequest: https public hosts only, origin only (the well-known path),
 * no redirects, 5 s timeout, 64 KB cap, 1 hour cache. On Node (the default, no opts.fetch) the connection is pinned to
 * an address checked against private, loopback, link-local, metadata and other reserved IPv4 and IPv6 ranges at
 * connect time (see pinnedGet). opts.lookup(hostname) -> [{ address }] replaces system DNS (tests, custom resolvers).
 * opts.fetch replaces the transport: it then gets a DNS pre-check only, which cannot stop rebinding by itself, so such
 * a fetch must pin addresses on its own. Workers and browsers use their fetch (they cannot reach private ranges).
 */
export function safeDirectoryFetcher({ fetch: f, lookup, request, cacheMs = 3600_000, maxBytes = MAX_DIRECTORY_BYTES } = {}) {
  const cache = new Map();
  return async function fetchDirectory(agent) {
    const u = new URL(agent);
    if (!isPublicHttpsUrl(u)) throw new Error('directory host not allowed');
    const url = directoryUrl(u.origin);
    const hit = cache.get(url);
    if (hit && hit.t > Date.now() - cacheMs) return hit.j;
    const headers = { accept: DIRECTORY_TYPE + ', application/json' };
    let r;
    if (!f && isNode) r = await pinnedGet(url, { headers, resolve: lookup || (await systemResolver()), request });
    else {
      await assertPublicDns(u.hostname, lookup);
      r = await (f || ((...a) => fetch(...a)))(url, { redirect: 'error', headers, signal: AbortSignal.timeout(DIRECTORY_TIMEOUT_MS) });
    }
    if (!r.ok) throw new Error('directory HTTP ' + r.status);
    const j = parseDirectory(await readCapped(r, maxBytes));
    if (cache.size > 500) cache.clear();
    cache.set(url, { j, t: Date.now() });
    return j;
  };
}

const defaultFetcher = safeDirectoryFetcher();
const defaultNonces = memoryNonceStore();

// ---------------------------------------------------------------- verify
/** verify a Fetch API Request (Workers, Deno, Bun, Node 22+). Never throws for a bad request; fails closed. */
export async function verify(request, { mode = 'local', api = DEFAULT_API, nonceStore = defaultNonces, fetchDirectory = defaultFetcher, fetch: f = (...a) => fetch(...a) } = {}) {
  if (!request.headers.get('signature-input')) return { verified: false, reason: 'unsigned' };
  if (mode === 'local') {
    const v = await verifyRequest(request, { fetchDirectory, seenNonce: (n, e, k) => nonceStore.seen(n, e, k) });
    return { verified: v.ok === true, reason: v.ok ? null : v.reason, agent: v.agent || null, keyid: v.keyid || null, operator: null };
  }
  if (typeof api !== 'string' || !/^https:\/\//.test(api)) return { verified: false, reason: 'no verify API configured (pass { api })', operator: null };
  const headers = {};
  for (const [k, v] of request.headers) if (/^(signature|signature-input|signature-agent|content-digest|content-type|date)$/i.test(k)) headers[k] = v;
  let r;
  try {
    r = await f(api, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: request.method, url: request.url, headers }), signal: AbortSignal.timeout(5000) });
  } catch { return { verified: false, reason: 'verifier unavailable', operator: null }; }
  if (!r.ok) return { verified: false, reason: 'verifier error HTTP ' + r.status, operator: null };
  const j = await r.json().catch(() => null);
  if (!j || typeof j !== 'object') return { verified: false, reason: 'verifier sent a bad response', operator: null };
  return { ...j, verified: j.verified === true, operator: j.verified === true && j.operator && typeof j.operator === 'object' ? j.operator : null };
}

const clean = (s) => String(s ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, 100);

/** Cloudflare Worker / generic handler wrapper: adds x-signed-agent-* headers for your app, optionally blocks unsigned bots */
export function withSigil(handler, opts = {}) {
  return async (request, ...rest) => {
    const v = await verify(request, opts).catch(() => ({ verified: false, reason: 'verifier unavailable' }));
    if (opts.require && !v.verified) return new Response('Signed agent identity required (Web Bot Auth).', { status: 401, headers: { 'www-authenticate': 'Signature' } });
    const h = new Headers(request.headers);
    for (const k of [...h.keys()]) if (k.toLowerCase().startsWith('x-signed-agent-')) h.delete(k);
    if (v.verified) {
      h.set('x-signed-agent-verified', '1');
      if (v.agent) h.set('x-signed-agent-agent', clean(v.agent));
      if (v.operator) { h.set('x-signed-agent-operator', clean(v.operator.slug)); h.set('x-signed-agent-purpose', clean(v.operator.purpose)); }
    }
    return handler(new Request(request, { headers: h }), ...rest);
  };
}

/**
 * Express / Connect middleware: req.sigil = { verified, operator, ... }.
 * The signature covers @authority, so the URL must be the one the agent signed. Behind a proxy or load balancer either
 * set app.set('trust proxy', ...) correctly (so req.protocol and req.hostname are right) or, better, pass
 * { origin: 'https://shop.example' } so the Host header is never trusted at all.
 */
export function expressSigil(opts = {}) {
  const fixed = opts.origin ? new URL(opts.origin).origin : null;
  return async (req, res, next) => {
    try {
      const url = (fixed || `${req.protocol}://${req.get('host')}`) + req.originalUrl;
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
      req.sigil = await verify(new Request(url, { method: req.method, headers }), opts).catch(() => ({ verified: false, reason: 'verifier unavailable', operator: null }));
      if (opts.require && !req.sigil.verified) return res.status(401).set('www-authenticate', 'Signature').send('Signed agent identity required.');
      next();
    } catch (e) { next(e); }
  };
}
