// Asking for a passkey approval from the MCP wrapper (counterseal mcp wrap): the client of the Approvals API (POST /v1/approvals,
// GET /v1/approvals/:id, POST /v1/approvals/:id/use) with a guard key (lsg_). Zero dependencies.
//
// A guard key can only ask and read its own approvals. It can never approve: every approval needs a web session and a fresh
// passkey ceremony in the app. The key is read from $LEASH_GUARD_KEY or from guard.json ({"key": "lsg_...", "server": "..."})
// next to the CLI's other configuration, the same file `counterseal guard install` writes for the coding-agent guard.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { cfgDir } from './mcp-store.mjs';

export const KEY_RE = /^lsg_[A-Za-z0-9_-]{43}$/;
export const DEFAULT_SERVER = 'https://counterseal.gautamkhosla.com';
const safeServer = (url) => /^https:\/\/[^/?#\s]+$/i.test(url) || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/i.test(url);

/**
 * The guard key and the server to ask. { key, server } or { problem } (a sentence for the agent and the human).
 * @param {object} env
 * @param {(path: string) => string|null} [readText]
 */
export function loadGuard(env = process.env, readText = (p) => (existsSync(p) ? readFileSync(p, 'utf8') : null)) {
  const file = env.LEASH_GUARD_CONFIG || join(cfgDir(env), 'guard.json');
  let cfg = {};
  try { const t = readText(file); if (t) cfg = JSON.parse(t); } catch { return { problem: `The guard configuration (${file}) cannot be read.` }; }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) cfg = {};
  const key = env.LEASH_GUARD_KEY || cfg.key;
  if (typeof key !== 'string' || !KEY_RE.test(key)) return { problem: 'No guard key is set up, so nothing can be approved. Make one in the app (Account, Guard keys) and put it in LEASH_GUARD_KEY, or in ' + file + ' as {"key": "lsg_..."}.' };
  const server = String(env.LEASH_URL || cfg.server || DEFAULT_SERVER).replace(/\/+$/, '');
  if (!safeServer(server)) return { problem: `The server address (${server.slice(0, 80)}) must be https, or http on this machine.` };
  return { key, server };
}

/** a Counterseal client for one guard key. fetch is injectable for tests. */
export function makeAsk({ fetch = globalThis.fetch, server, key, timeoutMs = 10000, version = '0' }) {
  const call = async (method, path, body, extraMs = 0) => {
    try {
      const headers = { accept: 'application/json', authorization: `Bearer ${key}`, 'user-agent': `leash-mcp-wrap/${version}` };
      if (body !== undefined) headers['content-type'] = 'application/json';
      const r = await fetch(server + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(timeoutMs + extraMs) });
      let j = {};
      try { j = await r.json(); } catch { /* not JSON */ }
      return { status: r.status, body: j && typeof j === 'object' && !Array.isArray(j) ? j : {} };
    } catch (e) {
      return { status: 0, body: {}, error: e && e.name ? e.name : 'network' };
    }
  };
  return {
    create: (body) => call('POST', '/v1/approvals', body),
    get: (id, wait = 0) => call('GET', `/v1/approvals/${encodeURIComponent(id)}?wait=${Math.max(0, Math.min(20, wait | 0))}`, undefined, wait * 1000),
    use: (id, hash) => call('POST', `/v1/approvals/${encodeURIComponent(id)}/use`, { hash }),
  };
}

const ID = /^[A-Za-z0-9_-]{8,64}$/, HASH = /^[0-9a-f]{64}$/;
/** the parts of an approval answer that are safe to use, or null when the server sent something this client does not understand */
export function readApproval(body) {
  if (!body || typeof body.id !== 'string' || !ID.test(body.id) || typeof body.hash !== 'string' || !HASH.test(body.hash)) return null;
  const url = typeof body.approve_url === 'string' && /^https?:\/\/[^\s]{1,300}$/.test(body.approve_url) ? body.approve_url : null;
  return { id: body.id, hash: body.hash, status: typeof body.status === 'string' ? body.status : null, url, expiresAt: Number.isFinite(body.expires_at) ? body.expires_at : null };
}

/** why a request to Counterseal failed, as one plain sentence (never the server's own long text beyond its message) */
export function failureText(r) {
  const msg = typeof r.body.message === 'string' ? r.body.message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 300) : '';
  if (r.status === 423) return 'Counterseal is frozen: ' + (msg || 'its owner stopped every agent and every approval.') + ' Do not retry until your human unfreezes it.';
  if (r.status === 401) return 'The guard key was revoked or has ended. Your human can make a new one in the app (Account, Guard keys).';
  if (r.status === 429) return msg || 'Too many requests are waiting for approval. Stop and ask your human to review them.';
  if (r.status === 0 || r.status >= 500) return 'Counterseal could not be reached' + (r.error ? ` (${String(r.error).slice(0, 40)})` : '') + ', so nothing can be approved right now.';
  return msg || `Counterseal refused the request (${r.status}).`;
}
