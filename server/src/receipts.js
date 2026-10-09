// Receipt validation and canonical encoding. Everything in a receipt is public and permanent: send hashes, not content.
// Free-text fields are short labels on purpose, so there is little room to paste content by mistake.
import { HttpError, fromB64u, hex } from './util.js';

const HEX64 = /^[0-9a-f]{64}$/;
const SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;

// Ed25519 encodings: one key and one signature must have exactly one spelling, and no key may be of small order.
const P25519 = 2n ** 255n - 19n, L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;
const le = (b) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
// libsodium's blocklist: the y encodings of the 8 small-order points (sign bit ignored). With such a key, a forged
// signature verifies over any message (R = identity, s = 0 for the identity point), so proof of possession means nothing.
const SMALL_ORDER = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000', '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);
/** a 32-byte Ed25519 public key in canonical encoding (y < p) that is not a small-order point; else 400 */
export function signerKeyBytes(b64) {
  const k = fromB64u(b64);
  const y = k.slice(); if (y.length === 32) y[31] &= 0x7f;
  if (k.length !== 32 || le(y) >= P25519 || SMALL_ORDER.has(hex(y))) throw new HttpError(400, 'bad_signerPublicKey', 'Not a usable Ed25519 public key.');
  return k;
}
/** 64-byte signature with a reduced scalar (s < L): no second spelling of the same signature */
const canonicalSig = (b64) => { const b = fromB64u(b64); return b.length === 64 && le(b.slice(32)) < L25519; };
const DECISIONS = ['allowed', 'denied', 'held', 'approved', 'executed', 'failed'];
// Batch caps keep a request's Worker CPU under the Workers Free limit (10 ms). Measured in Node with the test harness:
// a median of about 4 ms for 50 unsigned and 6 ms for 25 signed receipts (100 signed: about 22 ms). Not load tested on Workers.
// FREE: receipts per account per month; DAY: per account per UTC day (so one account cannot fill the log's 10,000 a day).
const FREE = 10_000, DAY = 2_000, MAX_BATCH = 50, MAX_SIGNED_BATCH = 25;
export const FIELD = { label: 80, subject: 120, metaKeys: 8, metaValue: 120 };

/** deterministic JSON: object keys sorted recursively (RFC 8785 subset: strings, finite numbers, booleans, null) */
export function canonical(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new HttpError(400, 'bad_number'); return JSON.stringify(v); }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  throw new HttpError(400, 'bad_type');
}

// Labels are read by people in a public log: no control characters (C0, DEL, C1), no format characters (bidi overrides
// and isolates, zero-width, BOM), no line or paragraph separators, no lone surrogates.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
const s = (v, max, name) => { if (typeof v !== 'string' || !v.length || v.length > max || UNSAFE.test(v)) throw new HttpError(400, 'bad_' + name); return v; };

export function validate(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new HttpError(400, 'bad_receipt');
  const allowed = ['agent', 'action', 'subject', 'input_sha256', 'output_sha256', 'decision', 'ts', 'run', 'parent', 'meta', 'sig'];
  for (const k of Object.keys(r)) if (!allowed.includes(k)) throw new HttpError(400, 'unknown_field', `Unknown field ${k}`);
  const out = { agent: s(r.agent, FIELD.label, 'agent'), action: s(r.action, FIELD.label, 'action') };
  if (r.subject !== undefined) out.subject = s(r.subject, FIELD.subject, 'subject');
  for (const h of ['input_sha256', 'output_sha256', 'parent']) if (r[h] !== undefined) { if (!HEX64.test(r[h])) throw new HttpError(400, 'bad_' + h); out[h] = r[h]; }
  if (r.decision !== undefined) { if (!DECISIONS.includes(r.decision)) throw new HttpError(400, 'bad_decision'); out.decision = r.decision; }
  if (r.run !== undefined) out.run = s(r.run, FIELD.label, 'run');
  if (r.ts !== undefined) { if (!Number.isInteger(r.ts) || r.ts < 1e12 || r.ts > 1e13) throw new HttpError(400, 'bad_ts', 'ts is Unix milliseconds'); out.ts = r.ts; }
  if (r.meta !== undefined) {
    if (!r.meta || typeof r.meta !== 'object' || Array.isArray(r.meta) || Object.keys(r.meta).length > FIELD.metaKeys) throw new HttpError(400, 'bad_meta', `meta takes up to ${FIELD.metaKeys} keys`);
    out.meta = {};
    for (const [k, v] of Object.entries(r.meta)) {
      if (!/^[a-z0-9_.-]{1,40}$/i.test(k)) throw new HttpError(400, 'bad_meta');
      if (!['string', 'number', 'boolean'].includes(typeof v) || (typeof v === 'string' && (v.length > FIELD.metaValue || UNSAFE.test(v))) || (typeof v === 'number' && !Number.isFinite(v))) throw new HttpError(400, 'bad_meta');
      out.meta[k] = v;
    }
  }
  if (r.sig !== undefined) {
    // exactly 64 bytes in canonical unpadded base64url, so one signature has one spelling (replay check)
    if (!r.sig || r.sig.alg !== 'ed25519' || typeof r.sig.value !== 'string' || !SIG.test(r.sig.value) || !canonicalSig(r.sig.value)) throw new HttpError(400, 'bad_sig');
    out.sig = { alg: 'ed25519', value: r.sig.value };
  }
  return out;
}

/** Freshness: a signed receipt's ts must be within FRESH_MS of the server clock. Replay records (signed_receipts) are
 *  kept for SIGNED_KEEP_MS: a receipt accepted at time t has ts <= t + FRESH_MS, so it is stale after t + 2 * FRESH_MS,
 *  and its record can go after that (plus a margin for clock differences). */
export const FRESH_MS = 10 * 60_000, SIGNED_KEEP_MS = 30 * 60_000;

/** the API key's signer as a verify key; imported once per request, not once per receipt */
export const importSigner = (signerPub) => crypto.subtle.importKey('raw', fromB64u(signerPub), { name: 'Ed25519' }, false, ['verify']);

/** if the API key has a signer (key: its imported verify key), the receipt (without sig) must be signed by it over its
 *  canonical JSON and carry a fresh ts. A sig is accepted only on a key bound to a signer: an unsigned key cannot carry
 *  (or replay) a signature. */
export async function checkSignature(receipt, key, now = Date.now()) {
  if (!key) {
    if (receipt.sig) throw new HttpError(400, 'sig_requires_signer_key', 'This API key has no signer, so it cannot record signed receipts. Bind an Ed25519 signer to a key, or drop sig.');
    return;
  }
  if (!receipt.sig) throw new HttpError(400, 'signature_required', 'This API key requires signed receipts.');
  if (receipt.ts === undefined) throw new HttpError(400, 'ts_required', 'Signed receipts must include ts (Unix milliseconds).');
  if (Math.abs(receipt.ts - now) > FRESH_MS) throw new HttpError(400, 'stale_ts', `Signed receipts must have a ts within 10 minutes of the server clock (now ${now}). Sign each receipt when you send it.`);
  const { sig, ...rest } = receipt;
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, fromB64u(sig.value), new TextEncoder().encode(canonical(rest)));
  if (!ok) throw new HttpError(400, 'bad_signature');
}

/** proof of possession for binding a signer to an API key: a signature over a fresh server challenge. The text names
 *  the log origin and the account, so the key holder can see which log and which account they are binding the key to. */
export const signerProofText = (challenge, signerPub, origin, account) => `witness/signer-proof/v2\n${origin}\n${account}\n${challenge}\n${signerPub}`;
export async function checkSignerProof(signerPub, challenge, proof, origin, account) {
  if (typeof proof !== 'string' || !SIG.test(proof) || !canonicalSig(proof)) throw new HttpError(400, 'bad_signerProof');
  const key = await crypto.subtle.importKey('raw', signerKeyBytes(signerPub), { name: 'Ed25519' }, false, ['verify']).catch(() => { throw new HttpError(400, 'bad_signerPublicKey'); });
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, fromB64u(proof), new TextEncoder().encode(signerProofText(challenge, signerPub, origin, account))))) throw new HttpError(400, 'bad_signerProof', 'The proof does not verify under that public key.');
}

export const LIMITS = { FREE, DAY, MAX_BATCH, MAX_SIGNED_BATCH };
