// Phone and desktop notifications for held requests (Web Push, RFC 8030 + VAPID RFC 8292).
// Privacy: the push carries NO payload. The push service (Google, Apple, Mozilla, Microsoft) only learns "wake this
// browser"; the service worker then fetches the held request from LEASH over the user's own session and shows it.
// Secret VAPID_PRIVATE_JWK (an ES256 private JWK) is set with `wrangler secret put`; without it push is simply off.
import { HttpError, b64u, now, randomId } from './util.js';

const MAX_SUBS = 10;
// only real push services: an endpoint is a URL we will POST to, so it must never point anywhere else (SSRF)
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^web\.push\.apple\.com$/, /^[a-z0-9-]+\.push\.apple\.com$/, /^[a-z0-9-]+\.notify\.windows\.com$/];

export function checkEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.length > 1024) throw new HttpError(400, 'bad_endpoint');
  let u;
  try { u = new URL(endpoint); } catch { throw new HttpError(400, 'bad_endpoint'); }
  if (u.protocol !== 'https:' || u.port || u.username || u.password || !PUSH_HOSTS.some((r) => r.test(u.hostname))) throw new HttpError(400, 'bad_endpoint', 'Not a known push service.');
  return u.href;
}

async function keys(env) {
  if (!env.VAPID_PRIVATE_JWK) return null;
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const priv = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const x = Uint8Array.from(atob(jwk.x.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const y = Uint8Array.from(atob(jwk.y.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const pub = new Uint8Array(65); pub[0] = 4; pub.set(x, 1); pub.set(y, 33);
  return { priv, pub: b64u(pub) };
}

export async function publicKey(env) {
  const k = await keys(env);
  return { enabled: !!k, key: k ? k.pub : null };
}

async function vapidHeader(env, k, endpoint) {
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  const aud = new URL(endpoint).origin;
  const body = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'mailto:security@gautamkhosla.com' })}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.priv, new TextEncoder().encode(body));
  return `vapid t=${body}.${b64u(sig)}, k=${k.pub}`;
}

export async function subscribe(env, sess, body) {
  const endpoint = checkEndpoint(body.endpoint);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs WHERE account_id = ?').bind(sess.accountId).first();
  const dup = await env.DB.prepare('SELECT id FROM push_subs WHERE endpoint = ?').bind(endpoint).first();
  if (dup) await env.DB.prepare('UPDATE push_subs SET account_id = ?, created_at = ? WHERE id = ?').bind(sess.accountId, now(), dup.id).run();
  else {
    if (n.n >= MAX_SUBS) throw new HttpError(409, 'too_many_devices', `Up to ${MAX_SUBS} devices. Turn alerts off on one first.`);
    await env.DB.prepare('INSERT INTO push_subs (id, account_id, endpoint, created_at) VALUES (?, ?, ?, ?)').bind(randomId(), sess.accountId, endpoint, now()).run();
  }
  return { ok: true };
}

export async function unsubscribe(env, sess, body) {
  const endpoint = checkEndpoint(body.endpoint);
  await env.DB.prepare('DELETE FROM push_subs WHERE account_id = ? AND endpoint = ?').bind(sess.accountId, endpoint).run();
  return { ok: true };
}

/** wake every device of the account; dead subscriptions (404/410) are removed */
export async function notify(env, accountId, fetcher = fetch) {
  const k = await keys(env);
  if (!k) return { sent: 0 };
  const subs = (await env.DB.prepare('SELECT id, endpoint FROM push_subs WHERE account_id = ?').bind(accountId).all()).results;
  let sent = 0;
  const results = [];
  for (const s of subs) {
    try {
      const r = await fetcher(s.endpoint, { method: 'POST', redirect: 'manual', headers: { authorization: await vapidHeader(env, k, s.endpoint), ttl: '600', urgency: 'high' }, body: '' });
      results.push({ service: new URL(s.endpoint).hostname, status: r.status, reason: r.status >= 300 ? (await r.text()).slice(0, 200) : undefined });
      if (r.status === 404 || r.status === 410) await env.DB.prepare('DELETE FROM push_subs WHERE id = ?').bind(s.id).run();
      else if (r.status < 300) { sent++; await env.DB.prepare('UPDATE push_subs SET last_ok_at = ? WHERE id = ?').bind(now(), s.id).run(); }
    } catch (e) { results.push({ service: new URL(s.endpoint).hostname, error: String(e && e.message || e).slice(0, 200) }); }
  }
  return { sent, devices: subs.length, results };
}
