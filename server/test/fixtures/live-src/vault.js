// The vault. Envelope encryption: every secret gets its own random AES-256-GCM data key; the data key is wrapped by
// the master key (LEASH_KEK, a Workers secret). AAD binds ciphertexts to their row, so rows cannot be swapped.
// There is no API that returns a secret: plaintext exists only inside the proxy for the length of one upstream call.
import { HttpError, b64u, fromB64u, rand } from './util.js';

let kekCache = null;
async function kek(env) {
  if (kekCache && kekCache.src === env.LEASH_KEK) return kekCache.key;
  if (!env.LEASH_KEK) throw new HttpError(503, 'not_configured');
  const raw = fromB64u(env.LEASH_KEK);
  if (raw.length !== 32) throw new HttpError(503, 'not_configured');
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  kekCache = { src: env.LEASH_KEK, key };
  return key;
}

const te = new TextEncoder(), td = new TextDecoder();

export async function seal(env, { id, accountId, provider }, secret) {
  const dekRaw = rand(32);
  const dek = await crypto.subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['encrypt']);
  const iv = rand(12), dekIv = rand(12);
  const aad = te.encode(`leash/v1|${accountId}|${id}|${provider}`);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, dek, te.encode(secret));
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dekIv, additionalData: te.encode(`leash/dek|${id}`) }, await kek(env), dekRaw);
  dekRaw.fill(0);
  return { ct: b64u(ct), iv: b64u(iv), wrapped_dek: b64u(wrapped), dek_iv: b64u(dekIv) };
}

export async function open(env, row) {
  try {
    const dekRaw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(row.dek_iv), additionalData: te.encode(`leash/dek|${row.id}`) }, await kek(env), fromB64u(row.wrapped_dek)));
    const dek = await crypto.subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['decrypt']);
    dekRaw.fill(0);
    const aad = te.encode(`leash/v1|${row.account_id}|${row.id}|${row.provider}`);
    return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(row.iv), additionalData: aad }, dek, fromB64u(row.ct)));
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(500, 'vault_error');
  }
}
