// Checkpoints as C2SP signed notes (https://c2sp.org/signed-note, https://c2sp.org/tlog-checkpoint), Ed25519.
// Body: "<origin>\n<tree size>\n<base64 root hash>\n". Signature line: U+2014 (protocol-mandated), space, key name,
// space, base64(4-byte key hash || 64-byte signature). Key hash = SHA-256(name || "\n" || 0x01 || 32-byte public key)[:4].
import { HttpError, b64u, fromB64u } from './util.js';
import { LOG_ORIGIN_DEFAULT } from './brand.js';

const te = new TextEncoder();
const std = (b) => btoa(String.fromCharCode(...b));
const unstd = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const DASH = '—';

let cache = null;
export async function logKey(env) {
  const name = env.LOG_ORIGIN || LOG_ORIGIN_DEFAULT;
  if (cache && cache.src === env.LOG_KEY_JWK && cache.name === name) return cache;
  if (!env.LOG_KEY_JWK) throw new HttpError(503, 'not_configured', 'The log signing key is not configured.');
  if (!/^[\x21-\x7e]{1,200}$/.test(name) || name.includes('+')) throw new HttpError(503, 'log_key_invalid', 'LOG_ORIGIN must be printable ASCII without spaces or "+".');
  let priv, pub;
  try {
    const jwk = JSON.parse(env.LOG_KEY_JWK);
    if (!jwk || typeof jwk.d !== 'string' || typeof jwk.x !== 'string') throw new Error('shape');
    priv = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', d: jwk.d, x: jwk.x }, { name: 'Ed25519' }, false, ['sign']);
    pub = fromB64u(jwk.x);
    if (pub.length !== 32) throw new Error('length');
    // a private part that does not match the public part would sign checkpoints nobody can verify
    const probe = te.encode('log key self test');
    const vk = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    if (!(await crypto.subtle.verify({ name: 'Ed25519' }, vk, await crypto.subtle.sign({ name: 'Ed25519' }, priv, probe), probe))) throw new Error('mismatch');
  } catch {
    throw new HttpError(503, 'log_key_invalid', 'The log signing key (LOG_KEY_JWK) is malformed. Regenerate it with server/dev/log-keygen.mjs.');
  }
  const id = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...te.encode(name + '\n'), 1, ...pub]))).slice(0, 4);
  cache = { src: env.LOG_KEY_JWK, priv, pub, name, id, vkey: `${name}+${[...id].map((x) => x.toString(16).padStart(2, '0')).join('')}+${std(Uint8Array.of(1, ...pub))}` };
  return cache;
}

export async function signCheckpoint(env, size, root) {
  const k = await logKey(env);
  const body = `${k.name}\n${size}\n${std(root)}\n`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, k.priv, te.encode(body)));
  return `${body}\n${DASH} ${k.name} ${std(new Uint8Array([...k.id, ...sig]))}\n`;
}

/** verify a checkpoint note with a verifier key "name+hash+base64(0x01||pub)"; returns {origin, size, root} */
export async function verifyCheckpoint(note, vkey) {
  const i1 = vkey.indexOf('+'), i2 = vkey.indexOf('+', i1 + 1);
  if (i1 < 1 || i2 !== i1 + 9) throw new Error('bad verifier key');
  const name = vkey.slice(0, i1), keyb64 = vkey.slice(i2 + 1);
  const keyBytes = unstd(keyb64);
  if (keyBytes[0] !== 1 || keyBytes.length !== 33) throw new Error('bad verifier key');
  const pub = await crypto.subtle.importKey('raw', keyBytes.slice(1), { name: 'Ed25519' }, false, ['verify']);
  const i = note.indexOf('\n\n');
  if (i < 0) throw new Error('malformed note');
  const body = note.slice(0, i + 1);
  const id = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...te.encode(name + '\n'), 1, ...keyBytes.slice(1)]))).slice(0, 4);
  let ok = false;
  for (const line of note.slice(i + 2).split('\n')) {
    if (!line.startsWith(DASH + ' ' + name + ' ')) continue;
    const raw = unstd(line.slice(name.length + 3));
    if (raw.length !== 68 || !raw.slice(0, 4).every((x, j) => x === id[j])) continue;
    if (await crypto.subtle.verify({ name: 'Ed25519' }, pub, raw.slice(4), te.encode(body))) ok = true;
  }
  if (!ok) throw new Error('signature does not verify');
  const [origin, size, root] = body.split('\n');
  if (origin !== name) throw new Error('origin mismatch');
  if (!/^(0|[1-9][0-9]{0,15})$/.test(size) || !Number.isSafeInteger(Number(size))) throw new Error('bad checkpoint size');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(root)) throw new Error('bad checkpoint root');
  return { origin, size: Number(size), root: unstd(root) };
}

export { std as b64std, unstd as fromB64std };
export const _b64u = b64u;
