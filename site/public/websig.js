// Signed identity for AI agents: Web Bot Auth (draft-ietf-webbotauth-httpsig-protocol) on RFC 9421 HTTP Message
// Signatures. Also provides the structured-field parser and signature base the broker uses for
// agent keys (server/src/agentkeys.js).
// Zero dependencies. Runs in Node 22+, Deno, Bun, browsers and Cloudflare Workers.
//
// Agent side:
//   const id = await generateIdentity();                 // Ed25519 key + JWK + keyid (RFC 8037 thumbprint)
//   const res = await signedFetch('https://shop.example/api', {}, { key: id.privateKey, keyid: id.keyid, agent: 'https://bots.acme.example' });
//   // and host directory([id.publicJwk]) at https://bots.acme.example/.well-known/http-message-signatures-directory
// Site side:
//   const v = await verifyRequest(request, { fetchDirectory, seenNonce });   // { ok, keyid, agent, ... } or { ok:false, reason }
//
// Spec notes: covered components must include @authority (or @target-uri); @signature-params must carry created, expires,
// keyid (JWK SHA-256 thumbprint) and tag="web-bot-auth"; each signature covers its Signature-Agent member.
// Windows: signatures may be valid for at most 1 hour; a signature without a nonce is accepted only if its window is
// 5 minutes or less (opts.requireNonce refuses it outright). Signature-Agent members must be bare https origins.

const te = new TextEncoder();
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export const TAG = 'web-bot-auth';
export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_TYPE = 'application/http-message-signatures-directory+json';
export const MAX_WINDOW = 3600; // seconds; longest created..expires window accepted or produced
export const MAX_WINDOW_NO_NONCE = 300; // seconds; without a nonce, replay is bounded only by the window
export const DEFAULT_EXPIRES_IN = 60;
const AGENT_TYPES = new Set(['directory']); // Signature-Agent ;type values we understand (absent means directory)

// ---------------------------------------------------------------- RFC 8941 structured fields (the subset HTTP signatures use)
export function parseDictionary(input) {
  const s = String(input || '');
  let i = 0;
  const out = new Map();
  const ws = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const fail = (m) => { throw new Error('structured field: ' + m); };
  const key = () => { const m = /^[a-z*][a-z0-9_\-.*]*/.exec(s.slice(i)); if (!m) fail('key'); i += m[0].length; return m[0]; };
  const bare = () => {
    if (s[i] === '"') { let v = ''; i++; while (i < s.length) { const c = s[i++]; if (c === '\\') { v += s[i++]; continue; } if (c === '"') return v; v += c; } fail('string'); }
    if (s[i] === ':') { const j = s.indexOf(':', i + 1); if (j < 0) fail('bytes'); const v = s.slice(i + 1, j); i = j + 1; return { bytes: v }; }
    if (s[i] === '?') { i += 2; return s[i - 1] === '1'; }
    const m = /^-?[0-9]+(\.[0-9]+)?/.exec(s.slice(i)); if (m) { i += m[0].length; return Number(m[0]); }
    const t = /^[A-Za-z*][A-Za-z0-9:/!#$%&'*+\-.^_`|~]*/.exec(s.slice(i)); if (t) { i += t[0].length; return { token: t[0] }; }
    fail('item');
  };
  const params = () => { const p = {}; while (s[i] === ';') { i++; ws(); const k = key(); let v = true; if (s[i] === '=') { i++; v = bare(); } p[k] = v; } return p; };
  while (i < s.length) {
    ws();
    const k = key();
    const start = i;
    let value, list = null;
    if (s[i] === '=') {
      i++;
      const vstart = i;
      if (s[i] === '(') {
        i++; list = [];
        while (s[i] !== ')') { ws(); if (s[i] === ')') break; const v = bare(); list.push({ value: v, params: params() }); if (i >= s.length) fail('list'); }
        i++;
      } else value = bare();
      const p = params();
      out.set(k, { value: list ? null : value, list, params: p, raw: s.slice(vstart, i) });
    } else out.set(k, { value: true, list: null, params: params(), raw: '' });
    ws();
    if (i < s.length) { if (s[i] !== ',') fail('separator at ' + i + ' after ' + s.slice(start, i)); i++; }
  }
  return out;
}

const sfString = (v) => '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
function sfParams(p) {
  return Object.entries(p).map(([k, v]) => (v === true ? `;${k}` : typeof v === 'number' ? `;${k}=${v}` : `;${k}=${sfString(v)}`)).join('');
}

// ---------------------------------------------------------------- keys
export async function jwkThumbprint(jwk) {
  // RFC 7638 / RFC 8037 A.3: required members only, lexicographic order, no whitespace
  const req = jwk.kty === 'OKP' ? { crv: jwk.crv, kty: 'OKP', x: jwk.x } : jwk.kty === 'EC' ? { crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y } : jwk.kty === 'RSA' ? { e: jwk.e, kty: 'RSA', n: jwk.n } : null;
  if (!req) throw new Error('unsupported key type');
  return b64u(await crypto.subtle.digest('SHA-256', te.encode(JSON.stringify(req))));
}

export async function generateIdentity() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: pub.x };
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { privateKey: kp.privateKey, publicJwk: jwk, privateJwk: { ...jwk, d: priv.d }, keyid: await jwkThumbprint(jwk) };
}

export async function importPrivateJwk(j) {
  return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: j.x, d: j.d }, { name: 'Ed25519' }, false, ['sign']);
}

export function directory(jwks) {
  return { keys: jwks.map((k) => ({ kty: k.kty, crv: k.crv, x: k.x, ...(k.y ? { y: k.y } : {}), ...(k.nbf ? { nbf: k.nbf } : {}), ...(k.exp ? { exp: k.exp } : {}) })) };
}

// ---------------------------------------------------------------- RFC 9421 signature base
function componentValue(name, cparams, req, sigAgentDict) {
  const u = new URL(req.url);
  switch (name) {
    case '@method': return req.method.toUpperCase();
    case '@authority': return u.host.toLowerCase();
    case '@target-uri': return u.href;
    case '@scheme': return u.protocol.replace(':', '');
    case '@path': return u.pathname;
    case '@query': return u.search || '?';
    case '@request-target': return u.pathname + u.search;
  }
  if (name.startsWith('@')) throw new Error('unsupported component ' + name);
  const raw = req.headers.get(name);
  if (raw == null) throw new Error('missing covered header ' + name);
  if (cparams.key !== undefined) {
    const d = name === 'signature-agent' && sigAgentDict ? sigAgentDict : parseDictionary(raw);
    const m = d.get(cparams.key);
    if (!m) throw new Error('missing dictionary member ' + name + ';key=' + cparams.key);
    return m.raw;
  }
  return raw.trim();
}

export function signatureBase(req, components, paramsRaw, sigAgentDict) {
  const lines = components.map((c) => `${sfString(c.value)}${sfParams(c.params)}: ${componentValue(c.value, c.params, req, sigAgentDict)}`);
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------- sign
/** returns headers to add: Signature, Signature-Input, Signature-Agent */
export async function signRequest({ method = 'GET', url, headers = {} }, { key, keyid, agent, label = 'sig1', expiresIn = DEFAULT_EXPIRES_IN, now = Math.floor(Date.now() / 1000), components } = {}) {
  if (!key || !keyid || !agent) throw new Error('key, keyid and agent are required');
  if (!(expiresIn > 0) || expiresIn > MAX_WINDOW) throw new Error('expiry must be between 1 second and 1 hour');
  const au = new URL(agent);
  if (au.origin !== agent.replace(/\/$/, '')) throw new Error('agent must be a bare origin like https://bots.example.com (the directory lives at its well-known path)');
  const h = new Headers(headers);
  h.set('signature-agent', `${label}=${sfString(agent)}`);
  const comps = components || [{ value: '@authority', params: {} }, { value: 'signature-agent', params: { key: label } }];
  const nonce = b64(crypto.getRandomValues(new Uint8Array(32)));
  const paramsRaw = '(' + comps.map((c) => sfString(c.value) + sfParams(c.params)).join(' ') + ')' + sfParams({ created: now, expires: now + expiresIn, keyid, alg: 'ed25519', nonce, tag: TAG });
  const base = signatureBase({ method, url, headers: h }, comps, paramsRaw, parseDictionary(h.get('signature-agent')));
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, te.encode(base));
  return { 'signature-agent': h.get('signature-agent'), 'signature-input': `${label}=${paramsRaw}`, signature: `${label}=:${b64(sig)}:` };
}

export async function signedFetch(url, init = {}, opts) {
  const method = init.method || 'GET';
  const add = await signRequest({ method, url, headers: init.headers || {} }, opts);
  const headers = new Headers(init.headers || {});
  for (const [k, v] of Object.entries(add)) headers.set(k, v);
  return (opts.fetch || fetch)(url, { ...init, headers });
}

// ---------------------------------------------------------------- verify
/**
 * Verify a Web Bot Auth request.
 *   opts.fetchDirectory(agentOrigin) -> JWKS object (you control caching and SSRF rules; see verifier.mjs for a safe one)
 *   opts.seenNonce(nonce, expires, keyid) -> true if already used (replay). Must be shared by every instance that verifies
 *     for you (a Map only protects one process); see the nonce store adapters in verifier.mjs.
 *   opts.requireNonce: refuse signatures without a nonce (a shared verify service should set this).
 *   opts.maxWindow (default 3600 s, never more) and opts.maxWindowNoNonce (default 300 s) cap created..expires.
 *   opts.now (seconds).
 * Signature-Agent members with an unsupported ;type, or whose URL has a path, query or fragment, are ignored (the draft
 * says MUST ignore); a signature whose member is ignored is skipped like a non web-bot-auth signature.
 */
export async function verifyRequest(req, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const maxWindow = Math.min(opts.maxWindow ?? MAX_WINDOW, MAX_WINDOW);
  const maxNoNonce = Math.min(opts.maxWindowNoNonce ?? MAX_WINDOW_NO_NONCE, maxWindow);
  try {
    const si = req.headers.get('signature-input'), sg = req.headers.get('signature'), sa = req.headers.get('signature-agent');
    if (!si || !sg) return { ok: false, reason: 'unsigned' };
    if (!sa) return { ok: false, reason: 'missing Signature-Agent' };
    const inputs = parseDictionary(si), sigs = parseDictionary(sg);
    const agents = /^\s*"/.test(sa) ? new Map([['', { value: parseDictionary('x=' + sa).get('x').value, params: {}, raw: sa.trim() }]]) : parseDictionary(sa);
    let skipped = null;
    for (const [label, input] of inputs) {
      const p = input.params;
      if (p.tag !== TAG) continue;
      const comps = input.list || [];
      const names = comps.map((c) => c.value);
      if (!names.includes('@authority') && !names.includes('@target-uri')) return { ok: false, reason: 'must cover @authority or @target-uri' };
      if (!Number.isInteger(p.created) || !Number.isInteger(p.expires)) return { ok: false, reason: 'created and expires are required' };
      if (p.expires <= p.created) return { ok: false, reason: 'expires must be after created' };
      if (p.expires - p.created > maxWindow) return { ok: false, reason: `validity window over ${maxWindow / 60} minutes` };
      const hasNonce = typeof p.nonce === 'string' && p.nonce.length > 0;
      if (!hasNonce && opts.requireNonce) return { ok: false, reason: 'nonce required' };
      if (!hasNonce && p.expires - p.created > maxNoNonce) return { ok: false, reason: `without a nonce the validity window must be ${maxNoNonce / 60} minutes or less` };
      if (hasNonce && p.nonce.length > 256) return { ok: false, reason: 'nonce too long' };
      if (p.created > now + 60) return { ok: false, reason: 'created in the future' };
      if (p.expires < now) return { ok: false, reason: 'expired' };
      if (typeof p.keyid !== 'string') return { ok: false, reason: 'keyid is required' };
      const member = agents.get(label) || agents.get('');
      if (!member || typeof member.value !== 'string') return { ok: false, reason: 'no Signature-Agent for ' + label };
      const coversAgent = comps.some((c) => c.value === 'signature-agent' && (c.params.key === undefined || c.params.key === label));
      if (!coversAgent) return { ok: false, reason: 'signature must cover its Signature-Agent' };
      const type = member.params && member.params.type;
      if (type !== undefined && !(typeof type === 'string' && AGENT_TYPES.has(type)) && !(type && type.token && AGENT_TYPES.has(type.token))) { skipped = 'unsupported Signature-Agent type'; continue; }
      const agent = member.value;
      let agentUrl;
      try { agentUrl = new URL(agent); } catch { return { ok: false, reason: 'Signature-Agent is not a URL' }; }
      if ((agentUrl.pathname && agentUrl.pathname !== '/') || agentUrl.search || agentUrl.hash || agentUrl.username || agentUrl.password) { skipped = 'Signature-Agent must be a bare origin (path ignored)'; continue; }
      if (agentUrl.protocol !== 'https:' && !opts.allowHttp) return { ok: false, reason: 'Signature-Agent must be https' };
      const jwks = await opts.fetchDirectory(agentUrl.origin);
      let jwk = null;
      for (const k of (jwks && jwks.keys) || []) { if ((await jwkThumbprint(k).catch(() => '')) === p.keyid) { jwk = k; break; } }
      if (!jwk) return { ok: false, reason: 'keyid not in the agent directory', agent };
      if ((jwk.nbf && now < jwk.nbf) || (jwk.exp && now > jwk.exp)) return { ok: false, reason: 'key not valid now', agent };
      const s = sigs.get(label);
      if (!s || !s.value || !s.value.bytes) return { ok: false, reason: 'missing signature for ' + label };
      const paramsRaw = input.raw;
      const base = signatureBase(req, comps.map((c) => ({ value: c.value, params: c.params })), paramsRaw, agents.size && !agents.has('') ? agents : null);
      if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return { ok: false, reason: 'only Ed25519 keys are supported', agent };
      const pub = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']);
      const good = await crypto.subtle.verify({ name: 'Ed25519' }, pub, fromB64(s.value.bytes), te.encode(base));
      if (!good) return { ok: false, reason: 'bad signature', agent };
      if (hasNonce && opts.seenNonce && (await opts.seenNonce(p.nonce, p.expires, p.keyid))) return { ok: false, reason: 'replayed', agent };
      return { ok: true, label, keyid: p.keyid, agent: agentUrl.origin, agentOrigin: agentUrl.origin, created: p.created, expires: p.expires, nonce: hasNonce ? p.nonce : null };
    }
    return { ok: false, reason: skipped || 'no web-bot-auth signature' };
  } catch (e) {
    return { ok: false, reason: 'malformed: ' + String(e.message).slice(0, 120) };
  }
}

/** directory URL for a Signature-Agent value: always the well-known path at its origin (the draft requires a bare origin) */
export function directoryUrl(agent) {
  return new URL(agent).origin + DIRECTORY_PATH;
}

/** what an operator must publish on their own origin so sites can find their keys */
export function directoryInstructions(origin, jwks) {
  const o = new URL(origin).origin;
  return {
    url: o + DIRECTORY_PATH,
    path: DIRECTORY_PATH,
    headers: { 'content-type': DIRECTORY_TYPE, 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' },
    body: directory(jwks),
    signatureAgent: `sig1="${o}"`,
  };
}
