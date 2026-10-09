// Network safety helpers shared by the SDK verifier and the SIGIL Worker. Zero dependencies.
// Fetching a URL that a stranger put in a request header is an SSRF risk; everything here exists to make that safe.

export const MAX_DIRECTORY_BYTES = 65536;

/** true when the URL is https, port 443, no credentials, and its host is a public DNS name (no IP literals, no internal TLDs) */
export function isPublicHttpsUrl(input) {
  let u;
  try { u = input instanceof URL ? input : new URL(input); } catch { return false; }
  if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) return false;
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!h.includes('.') || /^[\d.]+$/.test(h) || h.includes(':') || h.startsWith('[')) return false;
  if (h === 'localhost' || /\.(localhost|local|internal|intranet|lan|home|corp|private|arpa|test|invalid|example)$/.test(h)) return false;
  if (!/^[a-z0-9.-]+$/.test(h)) return false;
  return true;
}

/** expand any IPv6 text form (including "::" and an embedded IPv4 tail) to 8 four-digit lowercase hextets, or null */
export function expandIPv6(ip) {
  let s = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const pct = s.indexOf('%'); if (pct >= 0) s = s.slice(0, pct);
  const slash = s.indexOf('/'); if (slash >= 0) s = s.slice(0, slash);
  if (!s.includes(':')) return null;
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (v4) {
    const b = v4.slice(1).map(Number); if (b.some((n) => n > 255)) return null;
    s = s.slice(0, v4.index) + ((b[0] << 8) | b[1]).toString(16) + ':' + ((b[2] << 8) | b[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : fill < 1) return null;
  const parts = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (parts.some((p) => !/^[0-9a-f]{1,4}$/.test(p))) return null;
  return parts.map((p) => p.padStart(4, '0'));
}

function v4Private(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return true;
  const [a, b, c] = m.slice(1).map(Number);
  if ([a, b, c, Number(m[4])].some((n) => n > 255)) return true;
  return a === 0 || a === 10 || a === 127 || a >= 224 // this net, private, loopback, multicast + reserved
    || (a === 100 && b >= 64 && b <= 127) // CGNAT
    || (a === 169 && b === 254) // link local, cloud metadata
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) || (a === 192 && b === 88 && c === 99)
    || ip === '168.63.129.16'; // Azure platform endpoint (WireServer), reachable from inside Azure VMs
}

/** true for loopback, private, link-local, CGNAT, documentation, multicast and other non-public addresses (IPv4 or IPv6) */
export function isPrivateIp(ip) {
  const s = String(ip || '').trim();
  if (!s.includes(':')) return v4Private(s);
  const x = expandIPv6(s);
  if (!x) return true;
  const w = x.map((p) => parseInt(p, 16));
  if (w.slice(0, 7).every((n) => n === 0)) return true; // :: and ::1
  if (w.slice(0, 5).every((n) => n === 0) && w[5] === 0xffff) return v4Private(`${w[6] >> 8}.${w[6] & 255}.${w[7] >> 8}.${w[7] & 255}`); // ::ffff:a.b.c.d
  if (w[0] === 0x64 && w[1] === 0xff9b) return true; // NAT64
  if ((w[0] & 0xfe00) === 0xfc00 || (w[0] & 0xffc0) === 0xfe80 || (w[0] & 0xff00) === 0xff00) return true; // ULA, link local, multicast
  if (w[0] === 0x2001 && (w[1] === 0x0db8 || w[1] < 0x0200)) return true; // documentation, Teredo and IETF special use
  if (w[0] === 0x2002) return true; // 6to4 can tunnel to private v4
  if (w[0] === 0x3fff && w[1] < 0x1000) return true; // 3fff::/20 documentation (RFC 9637)
  return (w[0] & 0xe000) !== 0x2000; // only 2000::/3 is global unicast
}

/**
 * Wraps a resolver (hostname) -> [{ address, family }] (or strings) into the lookup(hostname, options, callback) shape
 * that node:net and node:https call when they open a socket. Every answer is checked at that moment: if any address
 * is private or reserved the whole answer is refused, and the socket only ever receives addresses that passed. Because
 * the check runs inside the connect itself, there is no second resolution an attacker could answer differently
 * (DNS rebinding). Runtime neutral: no Node imports here.
 */
export function vettedLookup(resolve) {
  return function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (typeof options === 'number') options = { family: options };
    options = options || {};
    const done = (err, list) => queueMicrotask(() => {
      if (err) return callback(err);
      if (options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
    Promise.resolve().then(() => resolve(hostname)).then((answer) => {
      const list = (Array.isArray(answer) ? answer : [answer]).map((a) => {
        const address = String(typeof a === 'string' ? a : a && a.address);
        return { address, family: address.includes(':') ? 6 : 4 };
      });
      if (!list.length || list.some((a) => isPrivateIp(a.address))) throw Object.assign(new Error('directory host not allowed'), { code: 'ESIGILBLOCKED' });
      const fam = options.family === 4 || options.family === 6 ? list.filter((a) => a.family === options.family) : list;
      if (!fam.length) throw Object.assign(new Error('directory host not allowed'), { code: 'ENOTFOUND' });
      done(null, fam);
    }).catch((e) => done(e));
  };
}

/** the /64 network of an IPv6 address ("2001:0db8:0000:0001::/64"), or the IPv4 address unchanged */
export function ipNetwork(ip) {
  const x = expandIPv6(ip);
  return x ? x.slice(0, 4).join(':') + '::/64' : String(ip || 'unknown');
}

/** read a response body as text, refusing more than max bytes (checks Content-Length first, then counts while streaming) */
export async function readCapped(res, max = MAX_DIRECTORY_BYTES) {
  const len = Number(res.headers.get('content-length') || 0);
  if (len > max) throw new Error('directory too large');
  if (!res.body || !res.body.getReader) { const t = await res.text(); if (t.length > max) throw new Error('directory too large'); return t; }
  const reader = res.body.getReader();
  const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) { await reader.cancel().catch(() => {}); throw new Error('directory too large'); }
    chunks.push(value);
  }
  const all = new Uint8Array(total); let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(all);
}

/** parse and sanity check a key directory body */
export function parseDirectory(text) {
  const j = JSON.parse(text);
  if (!j || typeof j !== 'object' || !Array.isArray(j.keys) || j.keys.length > 50) throw new Error('directory malformed');
  return j;
}
