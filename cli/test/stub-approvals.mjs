// A stand-in for the Counterseal Approvals API, written from the contract of agent A (A_CONTRACT.md, feature 1a).
// It is strict on purpose: a request the real server would refuse is refused here, so the tests fail when the hook
// sends something the contract does not allow. Waits are scaled down so a 20 second long poll takes about 0.4 s.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const b64url = (n) => randomBytes(n).toString('base64url');
const CTRL = /[\u0000-\u001f\u007f-\u009f\u200B-\u200F\u2028-\u202E\u2060-\u2064\uFEFF]/g;
const AGENTS = ['claude-code', 'codex', 'cursor', 'copilot', 'gemini', 'antigravity', 'mcp'];
const FIELDS = new Set(['kind', 'agent', 'rule', 'why', 'summary', 'detail', 'context', 'map']);

export async function startStub(opts = {}) {
  const state = {
    sessionToken: 'lsc_' + b64url(24), // a CLI session
    keys: new Map(), // lsg_ key -> { id, label, revoked, expiresAt }
    holds: new Map(),
    log: [], // every request: { method, path, who, body }
    timeScale: opts.timeScale ?? 0.02,
    meta: opts.meta ?? { app: 'http://stub', mapVersion: '2026-10-09.1', common: [], providers: [{ id: 'github', name: 'GitHub', host: 'api.github.com', irreversible: [{ id: 'gh.delete', method: 'DELETE', path: '/**', why: 'x' }] }] },
    fail: {}, // { create: 503, poll: [503, 503], use: 500 } or a function
    hang: false, // never answer
    creates: 0,
  };
  const send = (res, status, body) => { const t = JSON.stringify(body); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(t) }); res.end(t); };
  const err = (res, status, code, message, extra = {}) => send(res, status, { error: code, message: message ?? code, ...extra });
  const take = (k) => { const f = state.fail[k]; if (Array.isArray(f) && f.length) return f.shift(); if (typeof f === 'number') { delete state.fail[k]; return f; } return null; };

  const srv = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks).toString('utf8');
    const u = new URL(req.url, 'http://x');
    const auth = String(req.headers.authorization || '');
    const who = auth.startsWith('Bearer lsg_') ? 'lsg' : auth.startsWith('Bearer lsc_') ? 'lsc' : auth ? 'other' : 'none';
    let body; try { body = raw ? JSON.parse(raw) : undefined; } catch { body = '<<not json>>'; }
    state.log.push({ method: req.method, path: u.pathname + u.search, who, body, tooBig: raw.length > 16 * 1024 });
    if (state.hang) return;
    try { await route(req, res, u, auth, body, raw); } catch (e) { err(res, 500, 'stub_bug', String(e?.stack || e)); }
  });

  async function route(req, res, u, auth, body, raw) {
    const m = req.method, p = u.pathname;
    if (m === 'GET' && p === '/v1/meta') return send(res, 200, state.meta);
    if (p.startsWith('/v1/guard/keys')) { // CLI session
      if (auth !== `Bearer ${state.sessionToken}`) return err(res, 401, 'signed_out', 'Sign in first.');
      if (m === 'POST' && p === '/v1/guard/keys') {
        const label = body?.label ?? 'guard';
        if (typeof label !== 'string' || !/^[A-Za-z0-9 ._:/()-]{1,60}$/.test(label)) return err(res, 400, 'bad_label', 'bad label');
        const key = 'lsg_' + b64url(32), id = randomBytes(12).toString('hex');
        const expiresAt = Date.now() + 7 * 86400000;
        state.keys.set(key, { id, label, revoked: false, expiresAt });
        return send(res, 200, { id, key, label, expiresAt, note: 'Shown once.' });
      }
      if (m === 'GET') return send(res, 200, { keys: [...state.keys.values()].map((k) => ({ id: k.id, label: k.label, revoked: k.revoked ? 1 : 0, expires_at: k.expiresAt })) });
      if (m === 'DELETE') {
        const id = p.split('/').pop();
        const e = [...state.keys.entries()].find(([, v]) => v.id === id && !v.revoked);
        if (!e) return err(res, 404, 'not_found');
        e[1].revoked = true;
        return send(res, 200, { ok: true, closed: 0 });
      }
    }
    if (!p.startsWith('/v1/approvals')) return err(res, 404, 'not_found');
    // ---- guard key auth
    if (!auth.startsWith('Bearer lsg_')) return err(res, 401, 'guard_key_required', 'A guard key is required.');
    const key = auth.slice(7), k = state.keys.get(key);
    if (!k || k.revoked || (k.expiresAt && k.expiresAt < Date.now())) return err(res, 401, 'guard_key_invalid', 'That guard key is not valid.');
    const f = take('any'); if (f) return err(res, f, 'stub_failure', 'injected failure');

    if (m === 'POST' && p === '/v1/approvals') {
      const ct = String(req.headers['content-type'] || '');
      if (!ct.startsWith('application/json')) return err(res, 415, 'json_only');
      if (raw.length > 16 * 1024) return err(res, 413, 'too_large');
      const fc = take('create'); if (fc) return err(res, fc, fc === 429 ? 'slow_down' : 'stub_failure', fc === 429 ? 'Too many holds this hour.' : 'injected failure');
      if (!body || typeof body !== 'object' || Array.isArray(body)) return err(res, 400, 'bad_field');
      for (const f2 of Object.keys(body)) if (!FIELDS.has(f2)) return err(res, 400, 'bad_field', `unknown field ${f2}`);
      if (!['shell', 'tool'].includes(body.kind)) return err(res, 400, 'bad_kind');
      if (!AGENTS.includes(body.agent)) return err(res, 400, 'bad_agent');
      if (typeof body.rule !== 'string' || !/^[a-z0-9._:-]{1,64}$/.test(body.rule)) return err(res, 400, 'bad_rule');
      const why = typeof body.why === 'string' ? body.why.replace(CTRL, ' ').trim() : '';
      if (!why || why.length > 300 || (typeof body.why === 'string' && body.why.length > 300)) return err(res, 400, 'bad_why');
      const summary = typeof body.summary === 'string' ? body.summary.replace(CTRL, ' ').trim() : '';
      if (!summary || body.summary.length > 200) return err(res, 400, 'bad_summary');
      if (typeof body.detail !== 'string' || !body.detail.length || body.detail.length > 4096) return err(res, 400, 'bad_detail');
      let cwd = '';
      if (body.context !== undefined) {
        const c = body.context;
        if (!c || typeof c !== 'object' || Array.isArray(c)) return err(res, 400, 'bad_context');
        for (const f2 of Object.keys(c)) if (!['cwd', 'session'].includes(f2)) return err(res, 400, 'bad_context', `unknown context field ${f2}`);
        if (c.cwd !== undefined) { if (typeof c.cwd !== 'string' || !c.cwd.length || c.cwd.length > 80 || /[\\/\u0000-\u001f\u007f]/.test(c.cwd)) return err(res, 400, 'bad_context', 'cwd'); cwd = c.cwd; }
        if (c.session !== undefined && (typeof c.session !== 'string' || !/^[A-Za-z0-9._:-]{1,64}$/.test(c.session))) return err(res, 400, 'bad_context', 'session');
      }
      if (body.map !== undefined && (typeof body.map !== 'string' || !/^\d{4}-\d{2}-\d{2}\.\d{1,3}$/.test(body.map))) return err(res, 400, 'bad_map');
      const hash = sha256hex(JSON.stringify(['v1', body.kind, body.agent, body.detail, cwd]));
      state.creates++;
      const now = Date.now();
      const same = [...state.holds.values()].find((h) => h.key === key && h.hash === hash && ((h.status === 'pending' && h.expires_at > now) || (h.status === 'approved' && h.expires_at > now)));
      if (same) {
        const approve_url = `${state.origin}/app#hold=${same.id}`;
        return same.status === 'approved' ? send(res, 200, { id: same.id, status: 'approved', hash, approve_url, expires_at: same.expires_at }) : send(res, 202, { id: same.id, status: 'pending', hash, approve_url, expires_at: same.expires_at, created: false });
      }
      const id = randomBytes(12).toString('hex');
      const hold = { id, key, hash, status: 'pending', deny_reason: null, body, expires_at: now + 30 * 60000, createdAt: now };
      state.holds.set(id, hold);
      return send(res, 202, { id, status: 'pending', hash, approve_url: `${state.origin}/app#hold=${id}`, expires_at: hold.expires_at, created: true });
    }
    const mm = /^\/v1\/approvals\/([A-Za-z0-9_-]+)(\/use)?$/.exec(p);
    if (!mm) return err(res, 404, 'not_found');
    const h = state.holds.get(mm[1]);
    if (!h || h.key !== key) return err(res, 404, 'not_found');
    if (m === 'GET' && !mm[2]) {
      const fp = take('poll'); if (fp) return err(res, fp, 'stub_failure', 'injected failure');
      const w = u.searchParams.get('wait') ?? '0';
      if (!/^\d+$/.test(w) || Number(w) > 20) return err(res, 400, 'bad_wait');
      const until = Date.now() + Number(w) * 1000 * state.timeScale;
      while (h.status === 'pending' && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
      if (h.status === 'approved' && h.expires_at < Date.now()) h.status = 'expired';
      return send(res, 200, { id: h.id, status: h.status, deny_reason: h.deny_reason, expires_at: h.expires_at, hash: h.hash });
    }
    if (m === 'POST' && mm[2]) {
      const fu = take('use'); if (fu) return err(res, fu, 'stub_failure', 'injected failure');
      if (!body || typeof body.hash !== 'string' || !/^[0-9a-f]{64}$/.test(body.hash)) return err(res, 400, 'bad_hash');
      if (h.status === 'denied') return err(res, 403, 'denied', 'denied', { deny_reason: h.deny_reason });
      if (h.status === 'used') return err(res, 409, 'already_used');
      if (h.status === 'pending') return err(res, 409, 'not_approved');
      if (h.expires_at < Date.now() || h.status === 'expired') return err(res, 410, 'expired');
      if (body.hash !== h.hash) return err(res, 409, 'hash_mismatch');
      h.status = 'used'; h.usedAt = Date.now();
      return send(res, 200, { ok: true, id: h.id, status: 'used' });
    }
    return err(res, 404, 'not_found');
  }

  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  state.origin = `http://127.0.0.1:${srv.address().port}`;
  const api = {
    url: state.origin,
    state,
    /** a guard key as the CLI would have minted it */
    mintKey(label = 'test') { const key = 'lsg_' + b64url(32); state.keys.set(key, { id: randomBytes(12).toString('hex'), label, revoked: false, expiresAt: null }); return key; },
    holds: () => [...state.holds.values()],
    latest: () => [...state.holds.values()].pop(),
    approve(id) { const h = id ? state.holds.get(id) : api.latest(); h.status = 'approved'; h.expires_at = Date.now() + 10 * 60000; return h; },
    deny(reason = null, id) { const h = id ? state.holds.get(id) : api.latest(); h.status = 'denied'; h.deny_reason = reason; return h; },
    async approveWhenAsked(ms = 60, reason) { // approve the first hold that appears
      for (let i = 0; i < 200; i++) { await new Promise((r) => setTimeout(r, 15)); const h = api.latest(); if (h && h.status === 'pending') { await new Promise((r) => setTimeout(r, ms)); if (reason === undefined) api.approve(h.id); else api.deny(reason, h.id); return h; } }
      throw new Error('no hold appeared');
    },
    close: () => new Promise((ok) => { srv.closeAllConnections?.(); srv.close(ok); }),
  };
  return api;
}
