import { HttpError, sha256hex } from './util.js';
import { ipNetwork } from '../../sdk/net.mjs';

// Fixed-window counter in D1, for limits that have to hold across isolates (sign-in, sign-up, the API, the proxy).
// Each check writes a D1 row (Workers Free: 100k rows written a day), so once D1 says a bucket is over its limit, this
// isolate refuses it from memory until the window resets: a flood past the limit costs no more D1 writes.
const blocked = new Map();
export async function limit(db, bucket, max, windowMs, now) {
  const until = blocked.get(bucket);
  if (until > now) throw new HttpError(429, 'slow_down', `Too many requests. Try again in ${Math.ceil((until - now) / 1000)} s.`);
  const row = await db.prepare(
    `INSERT INTO ratelimits (bucket, count, reset_at) VALUES (?1, 1, ?2)
     ON CONFLICT(bucket) DO UPDATE SET
       count    = CASE WHEN ratelimits.reset_at <= ?3 THEN 1 ELSE ratelimits.count + 1 END,
       reset_at = CASE WHEN ratelimits.reset_at <= ?3 THEN ?2 ELSE ratelimits.reset_at END
     RETURNING count, reset_at`
  ).bind(bucket, now + windowMs, now).first();
  if (row && row.count > max) {
    if (blocked.size > 10_000) blocked.clear(); // bounded memory; a reset only means one more D1 check
    blocked.set(bucket, row.reset_at);
    throw new HttpError(429, 'slow_down', `Too many requests. Try again in ${Math.ceil((row.reset_at - now) / 1000)} s.`);
  }
}

/** the same fixed window, as a yes or no instead of a 429 (for work that is skipped, not refused: a phone alert) */
export async function allow(db, bucket, max, windowMs, now) {
  try { await limit(db, bucket, max, windowMs, now); return true; } catch (e) { if (e instanceof HttpError && e.status === 429) return false; throw e; }
}

// Reads of the public log, the receipts API and the free signature tool never cost a D1 write for their limit. In
// order of preference:
// 1. a Workers Rate Limiting binding (env.READ_LIMITER) if configured, shared across isolates in a location;
// 2. an in-memory token bucket per isolate (best effort, zero storage cost).
const buckets = new Map();
export function _resetMemoryBuckets() { buckets.clear(); blocked.clear(); }

export function memoryLimit(bucket, perMinute, now) {
  let b = buckets.get(bucket);
  if (!b) {
    if (buckets.size > 10_000) buckets.clear(); // bounded memory; a reset only loosens the limit briefly
    b = { tokens: perMinute, at: now };
    buckets.set(bucket, b);
  }
  b.tokens = Math.min(perMinute, b.tokens + (Math.max(0, now - b.at) * perMinute) / 60_000); // a clock step back refills nothing and takes nothing
  b.at = now;
  if (b.tokens < 1) throw new HttpError(429, 'slow_down', `Too many requests. Try again in ${Math.ceil(((1 - b.tokens) * 60) / perMinute)} s.`);
  b.tokens -= 1;
}

export async function readLimit(env, bucket, perMinute, now) {
  if (env.READ_LIMITER && typeof env.READ_LIMITER.limit === 'function') {
    const { success } = await env.READ_LIMITER.limit({ key: bucket });
    if (!success) throw new HttpError(429, 'slow_down', 'Too many requests. Try again in a minute.');
    return;
  }
  memoryLimit(bucket, perMinute, now);
}

/** a caller's network as a salted hash: IPv4 address, or the IPv6 /64 after full expansion (so "2001:db8::1" and
 *  "2001:db8:0:0:ffff::2" are one network and one host cannot rotate addresses). Raw IPs are never stored. */
export async function callerKey(env, request) {
  if (!env.IP_SALT) throw new HttpError(503, 'not_configured');
  const ip = ipNetwork(request.headers.get('cf-connecting-ip') || 'unknown');
  return (await sha256hex(`${env.IP_SALT}|${ip}`)).slice(0, 24);
}

export async function ipBucket(env, request, prefix) {
  return prefix + ':' + (await callerKey(env, request));
}
