// Minimal, strict WebAuthn (passkeys) for Workers: "none" attestation, ES256 and RS256, user verification required.
// Spec: https://www.w3.org/TR/webauthn-3/ . Everything an attacker controls is parsed defensively.
import { HttpError, fromB64u, b64u, sha256, eqBytes } from './util.js';

// ---- CBOR (RFC 8949) decoder for the subset WebAuthn uses
export function cborDecode(buf) {
  let p = 0;
  const need = (n) => { if (p + n > buf.length) throw new HttpError(400, 'bad_cbor'); };
  const u = (n) => { need(n); let v = 0; for (let i = 0; i < n; i++) v = v * 256 + buf[p++]; return v; };
  const item = (depth) => {
    if (depth > 8) throw new HttpError(400, 'bad_cbor');
    need(1);
    const b = buf[p++], mt = b >> 5, ai = b & 31;
    let len;
    if (ai < 24) len = ai; else if (ai === 24) len = u(1); else if (ai === 25) len = u(2); else if (ai === 26) len = u(4); else if (ai === 27) len = u(8);
    else throw new HttpError(400, 'bad_cbor');
    switch (mt) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: { need(len); const v = buf.slice(p, p + len); p += len; return v; }
      case 3: { need(len); const v = new TextDecoder().decode(buf.slice(p, p + len)); p += len; return v; }
      case 4: { if (len > 64) throw new HttpError(400, 'bad_cbor'); const a = []; for (let i = 0; i < len; i++) a.push(item(depth + 1)); return a; }
      case 5: { if (len > 64) throw new HttpError(400, 'bad_cbor'); const m = new Map(); for (let i = 0; i < len; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); } return m; }
      case 7: if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; throw new HttpError(400, 'bad_cbor');
      default: throw new HttpError(400, 'bad_cbor');
    }
  };
  const v = item(0);
  return { value: v, end: p };
}

function coseToJwk(m) {
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2 && alg === -7 && m.get(-1) === 1) {
    return { alg: -7, jwk: { kty: 'EC', crv: 'P-256', x: b64u(m.get(-2)), y: b64u(m.get(-3)), ext: true } };
  }
  if (kty === 3 && alg === -257) {
    return { alg: -257, jwk: { kty: 'RSA', n: b64u(m.get(-1)), e: b64u(m.get(-2)), alg: 'RS256', ext: true } };
  }
  throw new HttpError(400, 'unsupported_key');
}

function parseAuthData(ad) {
  if (ad.length < 37) throw new HttpError(400, 'bad_authdata');
  const rpIdHash = ad.slice(0, 32), flags = ad[32];
  const signCount = ((ad[33] << 24) >>> 0) + (ad[34] << 16) + (ad[35] << 8) + ad[36];
  const out = { rpIdHash, flags, signCount, up: !!(flags & 1), uv: !!(flags & 4), at: !!(flags & 64) };
  if (out.at) {
    if (ad.length < 55) throw new HttpError(400, 'bad_authdata');
    const idLen = (ad[53] << 8) + ad[54];
    if (idLen > 1023 || ad.length < 55 + idLen) throw new HttpError(400, 'bad_authdata');
    out.credId = ad.slice(55, 55 + idLen);
    out.cose = cborDecode(ad.slice(55 + idLen)).value;
  }
  return out;
}

function checkClientData(cdBytes, type, challenge, origin) {
  let cd;
  try { cd = JSON.parse(new TextDecoder().decode(cdBytes)); } catch { throw new HttpError(400, 'bad_clientdata'); }
  if (cd.type !== type) throw new HttpError(400, 'bad_clientdata_type');
  if (cd.challenge !== challenge) throw new HttpError(400, 'bad_challenge');
  if (cd.origin !== origin) throw new HttpError(400, 'bad_origin');
  if (cd.crossOrigin === true) throw new HttpError(400, 'bad_origin');
}

/** registration: returns {credId, alg, jwk, signCount} */
export async function verifyRegistration({ attestationObject, clientDataJSON }, { challenge, origin, rpId }) {
  const cd = fromB64u(clientDataJSON);
  checkClientData(cd, 'webauthn.create', challenge, origin);
  const att = cborDecode(fromB64u(attestationObject)).value;
  if (!(att instanceof Map) || !(att.get('authData') instanceof Uint8Array)) throw new HttpError(400, 'bad_attestation');
  if (att.get('fmt') !== 'none' && att.get('fmt') !== 'packed' && att.get('fmt') !== 'apple' && att.get('fmt') !== 'android-key' && att.get('fmt') !== 'tpm' && att.get('fmt') !== 'android-safetynet') throw new HttpError(400, 'bad_attestation');
  // We request attestation "none"; any format is accepted but its statement is not trusted for anything.
  const ad = parseAuthData(att.get('authData'));
  if (!eqBytes(ad.rpIdHash, await sha256(rpId))) throw new HttpError(400, 'bad_rp');
  if (!ad.up || !ad.uv) throw new HttpError(400, 'user_verification_required');
  if (!ad.at || !ad.credId || !(ad.cose instanceof Map)) throw new HttpError(400, 'bad_attestation');
  const { alg, jwk } = coseToJwk(ad.cose);
  return { credId: b64u(ad.credId), alg, jwk, signCount: ad.signCount };
}

function derToRaw(der) {
  // ECDSA DER SEQUENCE{INTEGER r, INTEGER s} -> r||s (32 bytes each)
  if (der[0] !== 0x30) throw new HttpError(400, 'bad_signature');
  let p = 2;
  const int = () => {
    if (der[p] !== 0x02) throw new HttpError(400, 'bad_signature');
    const len = der[p + 1]; let v = der.slice(p + 2, p + 2 + len); p += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new HttpError(400, 'bad_signature');
    const o = new Uint8Array(32); o.set(v, 32 - v.length); return o;
  };
  const r = int(), s = int();
  const out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
}

/** assertion: returns new signCount; throws on any mismatch */
export async function verifyAssertion({ authenticatorData, clientDataJSON, signature }, { challenge, origin, rpId, alg, jwk, signCount }) {
  const cd = fromB64u(clientDataJSON);
  checkClientData(cd, 'webauthn.get', challenge, origin);
  const adBytes = fromB64u(authenticatorData);
  const ad = parseAuthData(adBytes);
  if (!eqBytes(ad.rpIdHash, await sha256(rpId))) throw new HttpError(400, 'bad_rp');
  if (!ad.up || !ad.uv) throw new HttpError(400, 'user_verification_required');
  const data = new Uint8Array(adBytes.length + 32);
  data.set(adBytes); data.set(await sha256(cd), adBytes.length);
  const sig = fromB64u(signature);
  let ok;
  if (alg === -7) {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(sig), data);
  } else if (alg === -257) {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  } else throw new HttpError(400, 'unsupported_key');
  if (!ok) throw new HttpError(401, 'bad_signature');
  // cloned-authenticator check: counters must grow when the authenticator uses them (synced passkeys report 0)
  if (ad.signCount !== 0 || signCount !== 0) {
    if (ad.signCount <= signCount) throw new HttpError(401, 'counter_replay');
  }
  return ad.signCount;
}
