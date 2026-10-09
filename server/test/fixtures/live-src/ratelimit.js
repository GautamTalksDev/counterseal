import { HttpError, sha256hex } from './util.js';

// Fixed-window counter in D1.
export async function limit(db, bucket, max, windowMs, now) {
  const row = await db.prepare(
    `INSERT INTO ratelimits (bucket, count, reset_at) VALUES (?1, 1, ?2)
     ON CONFLICT(bucket) DO UPDATE SET
       count    = CASE WHEN ratelimits.reset_at <= ?3 THEN 1 ELSE ratelimits.count + 1 END,
       reset_at = CASE WHEN ratelimits.reset_at <= ?3 THEN ?2 ELSE ratelimits.reset_at END
     RETURNING count, reset_at`
  ).bind(bucket, now + windowMs, now).first();
  if (row && row.count > max) throw new HttpError(429, 'slow_down', `Too many requests. Try again in ${Math.ceil((row.reset_at - now) / 1000)} s.`);
}

/** IP buckets: IPv6 grouped by /64 so one host cannot rotate addresses; hashed with a secret salt, never stored raw */
export async function ipBucket(env, request, prefix) {
  if (!env.IP_SALT) throw new HttpError(503, 'not_configured');
  let ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (ip.includes(':')) ip = ip.split(':').slice(0, 4).join(':') + '::/64';
  return prefix + ':' + (await sha256hex(`${env.IP_SALT}|${ip}`)).slice(0, 24);
}
