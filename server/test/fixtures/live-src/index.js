// LEASH Worker: /v1/* control API, /p/<provider>/* agent proxy, everything else is the static site (ASSETS).
import { HttpError, json, errorResponse, readJson, now, str } from './util.js';
import * as A from './auth.js';
import * as B from './broker.js';
import { list as auditList, verifyChain } from './audit.js';
import { limit, ipBucket } from './ratelimit.js';
import { PROVIDERS, MAP_VERSION, COMMON } from './providers.js';
import * as Push from './push.js';

const ID = '([0-9a-f]{24})';
// [method, regex, guard, handler]; guard: 'public' | 'session' (read) | 'write' (session + CSRF for web)
const ROUTES = [
  ['GET', /^\/v1\/meta$/, 'public', () => ({ mapVersion: MAP_VERSION, common: COMMON.map((r) => ({ id: r.id, method: r.m, path: r.p, why: r.why })), providers: Object.entries(PROVIDERS).map(([id, p]) => ({ id, name: p.name, host: p.host, irreversible: p.irreversible.map((r) => ({ id: r.id, method: r.m, path: r.p, why: r.why })) })) })],
  ['POST', /^\/v1\/auth\/register\/begin$/, 'publicw', (c) => A.registerBegin(c.env, c.body)],
  ['POST', /^\/v1\/auth\/register\/finish$/, 'publicw', (c) => A.registerFinish(c.env, c.body, c.request)],
  ['POST', /^\/v1\/auth\/login\/begin$/, 'publicw', (c) => A.loginBegin(c.env)],
  ['POST', /^\/v1\/auth\/login\/finish$/, 'publicw', (c) => A.loginFinish(c.env, c.body)],
  ['POST', /^\/v1\/auth\/logout$/, 'write', (c) => A.logout(c.env, c.s)],
  ['POST', /^\/v1\/device\/start$/, 'public', (c) => A.deviceStart(c.env)],
  ['POST', /^\/v1\/device\/poll$/, 'public', (c) => A.devicePoll(c.env, c.body)],
  ['POST', /^\/v1\/device\/approve\/begin$/, 'webw', (c) => A.deviceApproveBegin(c.env, c.s, c.body)],
  ['POST', /^\/v1\/device\/approve\/finish$/, 'webw', (c) => A.deviceApproveFinish(c.env, c.s, c.body)],
  ['GET', /^\/v1\/me$/, 'session', async (c) => ({ account: await c.env.DB.prepare('SELECT id, name, created_at FROM accounts WHERE id = ?').bind(c.s.accountId).first(), kind: c.s.kind })],
  ['POST', /^\/v1\/me\/delete\/begin$/, 'webw', (c) => deleteBegin(c.env, c.s)],
  ['POST', /^\/v1\/me\/delete\/finish$/, 'webw', (c) => deleteAccount(c.env, c.s, c.body)],
  ['GET', /^\/v1\/push\/key$/, 'session', (c) => Push.publicKey(c.env)],
  ['POST', /^\/v1\/push\/subscribe$/, 'write', (c) => Push.subscribe(c.env, c.s, c.body)],
  ['POST', /^\/v1\/push\/unsubscribe$/, 'write', (c) => Push.unsubscribe(c.env, c.s, c.body)],
  ['POST', /^\/v1\/push\/test$/, 'write', (c) => Push.notify(c.env, c.s.accountId, c.env.__pushFetch || fetch)],
  ['GET', /^\/v1\/credentials$/, 'session', (c) => B.listCredentials(c.env, c.s)],
  ['POST', /^\/v1\/credentials$/, 'write', (c) => B.addCredential(c.env, c.s, c.body)],
  // deleting a vaulted key breaks every token on it; an agent holding a CLI session must not be able to do that
  ['DELETE', new RegExp(`^/v1/credentials/${ID}$`), 'webw', (c) => B.deleteCredential(c.env, c.s, c.m[1])],
  ['GET', /^\/v1\/tokens$/, 'session', (c) => B.listTokens(c.env, c.s)],
  ['POST', /^\/v1\/tokens$/, 'write', (c) => B.mintToken(c.env, c.s, c.body, false)],
  ['POST', /^\/v1\/tokens\/passkey\/begin$/, 'webw', (c) => B.mintBegin(c.env, c.s)],
  ['POST', /^\/v1\/tokens\/passkey\/finish$/, 'webw', (c) => B.mintFinish(c.env, c.s, c.body)],
  ['DELETE', new RegExp(`^/v1/tokens/${ID}$`), 'write', (c) => B.revokeToken(c.env, c.s, c.m[1])],
  ['GET', /^\/v1\/holds$/, 'session', (c) => B.listHolds(c.env, c.s, c.url.searchParams.get('status'))],
  ['POST', new RegExp(`^/v1/holds/${ID}/approve/begin$`), 'webw', (c) => B.approveBegin(c.env, c.s, c.m[1])],
  ['POST', new RegExp(`^/v1/holds/${ID}/approve/finish$`), 'webw', (c) => B.approveFinish(c.env, c.s, c.m[1], c.body)],
  ['POST', new RegExp(`^/v1/holds/${ID}/deny$`), 'write', (c) => B.denyHold(c.env, c.s, c.m[1])],
  ['GET', /^\/v1\/audit$/, 'session', async (c) => ({ entries: await auditList(c.env, c.s.accountId, Number(c.url.searchParams.get('before')) || 0) })],
  ['GET', /^\/v1\/audit\/verify$/, 'session', (c) => verifyChain(c.env, c.s.accountId)],
];

// Erase an account and everything tied to it. Web session only (an agent holding a CLI session can't do it), a fresh
// passkey ceremony (a stolen cookie alone can't), and the body must say {"confirm":"delete"} so a stray request can't.
async function deleteBegin(env, s) {
  const { id, challenge } = await A.newChallenge(env, 'delete', s.accountId);
  return { challengeId: id, options: { challenge, rpId: A.rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
async function deleteAccount(env, s, body) {
  if (body?.confirm !== 'delete') throw new HttpError(400, 'confirm_required', 'Send {"confirm":"delete"}.');
  const ch = await A.takeChallenge(env, body.challengeId, 'delete');
  if (ch.account_id !== s.accountId) throw new HttpError(403, 'forbidden');
  await A.checkAssertion(env, body.credential, ch.challenge, s.accountId);
  const id = s.accountId;
  await env.DB.batch(['push_subs', 'holds', 'tokens', 'credentials', 'audit', 'sessions', 'passkeys', 'challenges', 'device_codes'].map((t) => env.DB.prepare(`DELETE FROM ${t} WHERE account_id = ?`).bind(id))
    .concat([env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(id)]));
  return { deleted: true };
}

export async function handle(request, env, opts = {}) {
  const url = new URL(request.url);
  try {
    // agent proxy
    const pm = url.pathname.match(/^\/p\/([a-z]+)\/(.*)$/);
    if (pm) {
      await limit(env.DB, await ipBucket(env, request, 'pip'), 1200, 60_000, now());
      return await B.proxy(env, request, pm[1], pm[2], opts.fetcher || fetch);
    }
    if (!url.pathname.startsWith('/v1/')) return env.ASSETS ? env.ASSETS.fetch(request) : json({ error: 'not_found' }, 404);
    if (request.method === 'OPTIONS') return json({ error: 'no_cors' }, 403);
    for (const [method, re, guard, fn] of ROUTES) {
      if (method !== request.method) continue;
      const m = url.pathname.match(re);
      if (!m) continue;
      const c = { env, request, url, m, body: {} };
      if (guard.startsWith('public')) await limit(env.DB, await ipBucket(env, request, 'pub'), 60, 60_000, now());
      if (guard === 'publicw' && request.headers.get('origin') !== A.rp(env).origin) throw new HttpError(403, 'csrf');
      if (guard === 'session' || guard === 'write' || guard === 'webw') {
        c.s = await A.session(env, request, guard !== 'session');
        if (guard === 'webw' && c.s.kind !== 'web') throw new HttpError(403, 'passkey_required', 'This needs your passkey in the LEASH app.');
        await limit(env.DB, 'acct:' + c.s.accountId, 300, 60_000, now());
      }
      if (request.method === 'POST') c.body = await readJson(request);
      const out = await fn(c);
      if (out && out.cookie) return json(out.body, 200, { 'set-cookie': out.cookie });
      return json(out);
    }
    return json({ error: 'not_found' }, 404);
  } catch (e) {
    return errorResponse(e);
  }
}

// Expired rows are always rejected at read time; this only tidies them away. It runs from the cron when the plan has
// one, and otherwise on about 1 in 50 requests, after the response, so no request waits for it.
async function sweep(env) {
  const t = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM challenges WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM device_codes WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM ratelimits WHERE reset_at < ?').bind(t),
    env.DB.prepare("UPDATE holds SET status = 'expired' WHERE status IN ('pending','approved') AND expires_at < ?").bind(t),
    // request previews are only needed while a human is deciding; drop them a day after the hold is closed
    env.DB.prepare("UPDATE holds SET preview = NULL WHERE preview IS NOT NULL AND status NOT IN ('pending','approved') AND expires_at < ?").bind(t - 86400_000),
  ]);
}

export default {
  async fetch(request, env, ctx) {
    if (Math.random() < 0.02) ctx.waitUntil(sweep(env).catch(() => {}));
    return handle(request, { ...env, __ctx: ctx });
  },
  async scheduled(event, env) {
    await sweep(env);
  },
};
