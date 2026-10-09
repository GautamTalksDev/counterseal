// The free Web Bot Auth checker (/tools/web-bot-auth/). The signature is checked in the visitor's browser with the
// same code as the SDK (sdk/websig.mjs); the only server call is this one: fetch an agent's public key directory, which
// a browser cannot read cross-origin. Nothing is stored: no database row, no nonce, no log line with the URL.
//
// SSRF rules (from the SIGIL registry, which this replaces): https only, port 443, public DNS names only (no IP
// literals, localhost or internal TLDs), the fixed well-known path at the origin, no redirects, 5 s timeout, 64 KB cap
// counted while streaming. Workers cannot open connections to private address space. Limits: 10 lookups a minute per
// caller network (in memory, no D1 write), a 10 minute cache and a 10 minute negative cache per directory, and at most
// 60 uncached fetches a minute per isolate.
import { HttpError, json } from './util.js';
import { isPublicHttpsUrl, readCapped, parseDirectory } from '../../sdk/net.mjs';
import { directoryUrl, DIRECTORY_TYPE } from '../../sdk/websig.mjs';

const CACHE_MS = 10 * 60_000, FAIL_MS = 10 * 60_000, UNCACHED_PER_MIN = 60;
const cache = new Map();
let win = { at: 0, n: 0 };
export const _resetToolCache = () => { cache.clear(); win = { at: 0, n: 0 }; };

export async function directoryTool(c, fetcher = c.env.__toolFetch || fetch) {
  const raw = c.url.searchParams.get('agent');
  if (typeof raw !== 'string' || !raw.length || raw.length > 300) throw new HttpError(400, 'bad_agent', 'Pass ?agent=https://<agent origin>.');
  let u;
  try { u = new URL(raw); } catch { throw new HttpError(400, 'bad_agent', 'Not a URL.'); }
  if (!isPublicHttpsUrl(u)) throw new HttpError(400, 'agent_not_allowed', 'Only https origins on public host names (port 443, no IP addresses or internal names) can be fetched.');
  const url = directoryUrl(u.origin), t = Date.now();
  const hit = cache.get(url);
  if (hit && t - hit.at < (hit.error ? FAIL_MS : CACHE_MS)) {
    if (hit.error) throw new HttpError(502, 'directory_unreadable', hit.error);
    return json({ agent: u.origin, url, keys: hit.keys, fetchedAt: hit.at, cached: true });
  }
  if (t - win.at > 60_000) win = { at: t, n: 0 };
  if (++win.n > UNCACHED_PER_MIN) throw new HttpError(429, 'slow_down', 'Too many directory lookups right now. Try again in a minute.');
  let keys;
  try {
    const r = await fetcher(url, { redirect: 'manual', headers: { accept: DIRECTORY_TYPE + ', application/json' }, signal: AbortSignal.timeout(5000) });
    if (r.status !== 200) throw new Error('the directory answered HTTP ' + r.status + (r.status >= 300 && r.status < 400 ? ' (redirects are not followed)' : ''));
    keys = parseDirectory(await readCapped(r)).keys;
  } catch (e) {
    const error = `Could not read ${url}: ${String(e && e.message).slice(0, 120)}`;
    if (cache.size > 500) cache.clear();
    cache.set(url, { at: t, error });
    throw new HttpError(502, 'directory_unreadable', error);
  }
  if (cache.size > 500) cache.clear();
  cache.set(url, { at: t, keys });
  return json({ agent: u.origin, url, keys, fetchedAt: t, cached: false });
}
