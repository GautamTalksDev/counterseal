// Shared helpers. No dependencies.
export class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const API_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cross-origin-resource-policy': 'same-origin',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
};

export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...API_HEADERS, ...extra } });
}

export function errorResponse(e) {
  if (e instanceof HttpError) return json({ error: e.code, message: e.message, ...(e.extra || {}) }, e.status);
  // never leak internals
  return json({ error: 'internal', message: 'Something went wrong.' }, 500);
}

const enc = new TextEncoder();

export function b64u(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64u(str) {
  if (typeof str !== 'string' || str.length > 200000 || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(str)) throw new HttpError(400, 'bad_encoding');
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256(data) {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export const sha256hex = async (d) => hex(await sha256(d));

export function rand(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export const randomId = (n = 12) => hex(rand(n));

export function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** strict JSON body: content-type, size cap, object only */
export async function readJson(request, max = 16384) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.toLowerCase().startsWith('application/json')) throw new HttpError(415, 'json_only');
  const buf = new Uint8Array(await request.arrayBuffer());
  if (buf.length > max) throw new HttpError(413, 'too_large');
  let v;
  try {
    v = JSON.parse(new TextDecoder().decode(buf));
  } catch {
    throw new HttpError(400, 'bad_json');
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'bad_json');
  return v;
}

export function str(v, name, { min = 1, max = 200, re } = {}) {
  if (typeof v !== 'string' || v.length < min || v.length > max || (re && !re.test(v))) throw new HttpError(400, 'bad_' + name);
  return v;
}

export function now() {
  return Date.now();
}
