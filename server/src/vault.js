// The vault. Envelope encryption: every secret gets its own random AES-256-GCM data key; the data key is wrapped by
// the master key (LEASH_KEK, a Workers secret). AAD binds ciphertexts to their row, so rows cannot be swapped.
// There is no API that returns a secret: plaintext exists only inside the proxy for the length of one upstream call.
import { HttpError, b64u, fromB64u, rand } from './util.js';

// Rotation (docs/KEY_ROTATION.md). The wrapping key is LEASH_KEK_NEXT when it is set, else LEASH_KEK; a wrapped data
// key that does not open with it is tried with the other one (LEASH_KEK, or LEASH_KEK_OLD), and rewrap() (the operator's
// POST /v1/admin/vault/rewrap) moves rows to the wrapping key. So a rotation never needs a copy of the current key:
// set LEASH_KEK_NEXT, rewrap, then make it LEASH_KEK. Only the 32-byte data key is unwrapped and wrapped again: the
// secret itself is never decrypted for a rewrap and its ciphertext never changes.
const kekCache = new Map();
async function importKek(src) {
  const hit = kekCache.get(src);
  if (hit) return hit;
  const raw = fromB64u(src);
  if (raw.length !== 32) throw new HttpError(503, 'not_configured');
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  if (kekCache.size >= 4) kekCache.clear();
  kekCache.set(src, key);
  return key;
}
/** the key new data keys are wrapped with */
async function kek(env) {
  if (!env.LEASH_KEK) throw new HttpError(503, 'not_configured');
  return importKek(env.LEASH_KEK_NEXT || env.LEASH_KEK);
}
/** the one other key a row may still be wrapped with during a rotation, or null */
function otherKek(env) {
  const src = env.LEASH_KEK_NEXT ? env.LEASH_KEK : env.LEASH_KEK_OLD;
  return src && src !== (env.LEASH_KEK_NEXT || env.LEASH_KEK) ? importKek(src) : null;
}

const dekAad = (id) => new TextEncoder().encode(`leash/dek|${id}`);
/** the raw data key of a row, and whether it was wrapped with the other (outgoing) key */
async function unwrap(env, row) {
  const p = { name: 'AES-GCM', iv: fromB64u(row.dek_iv), additionalData: dekAad(row.id) }, w = fromB64u(row.wrapped_dek);
  const cur = await kek(env);
  try { return { dekRaw: new Uint8Array(await crypto.subtle.decrypt(p, cur, w)), old: false }; } catch (e) {
    const k = await otherKek(env);
    if (!k) throw e;
    return { dekRaw: new Uint8Array(await crypto.subtle.decrypt(p, k, w)), old: true };
  }
}

/** null when the row is already on the wrapping key; otherwise its data key wrapped with it, as {wrapped_dek, dek_iv}.
 * Throws HttpError(500, vault_error) when the row opens with neither key. */
export async function rewrap(env, row) {
  let u;
  try { u = await unwrap(env, row); } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(500, 'vault_error'); }
  try {
    if (!u.old) return null;
    const dekIv = rand(12);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dekIv, additionalData: dekAad(row.id) }, await kek(env), u.dekRaw);
    return { wrapped_dek: b64u(wrapped), dek_iv: b64u(dekIv) };
  } finally { u.dekRaw.fill(0); }
}

const te = new TextEncoder(), td = new TextDecoder();

// A key that is sent to a per-store address (Shopify) is sealed together with that address, so a row whose host was changed
// outside the API no longer decrypts. Credentials without a host keep the AAD they always had.
const aadOf = (accountId, id, provider, host) => te.encode(`leash/v1|${accountId}|${id}|${provider}${host ? '|' + host : ''}`);

export async function seal(env, { id, accountId, provider, host }, secret) {
  const dekRaw = rand(32);
  const dek = await crypto.subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['encrypt']);
  const iv = rand(12), dekIv = rand(12);
  const aad = aadOf(accountId, id, provider, host);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, dek, te.encode(secret));
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dekIv, additionalData: te.encode(`leash/dek|${id}`) }, await kek(env), dekRaw);
  dekRaw.fill(0);
  return { ct: b64u(ct), iv: b64u(iv), wrapped_dek: b64u(wrapped), dek_iv: b64u(dekIv) };
}

export async function open(env, row) {
  try {
    const { dekRaw } = await unwrap(env, row);
    const dek = await crypto.subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['decrypt']);
    dekRaw.fill(0);
    const aad = aadOf(row.account_id, row.id, row.provider, row.host);
    return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(row.iv), additionalData: aad }, dek, fromB64u(row.ct)));
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(500, 'vault_error');
  }
}
