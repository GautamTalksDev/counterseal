// Team alert channels (two-person seal, part 2b): Slack, Discord and Google Chat get the alert. They only ever get told:
// approving always needs a passkey in the app, so a channel can neither approve nor be used to.
//
// A webhook URL is a secret (anyone holding it can post to the channel), so it is sealed with the vault's key, bound to the
// account, the row and the kind, and never shown again: the app lists the label and the host only. Adding a channel needs an
// owner's passkey (it sends team information out), and what the passkey approves is exactly that URL (its hash rides in the
// challenge). Removing one only tightens.
//
// SSRF: the server will POST to a URL a person typed, so the URL is held to a closed list: https, the exact host of the service
// (hooks.slack.com, discord.com or discordapp.com, chat.googleapis.com), the exact path shape of that service's webhooks, no
// credentials, no port, no fragment, no query except Google Chat's own two, and the URL must be byte for byte what the URL parser
// makes of it (so tabs, upper case hosts, a trailing dot, an IP address, punycode, %2e, backslashes and the like are all refused).
// A request never follows a redirect, waits 3 seconds, and a channel that fails 10 times in a row stops sending until a test succeeds.
//
// What is sent: who asked (a token, a guard key's agent or a gate: only characters of a label), the rule's id, how many seals,
// and the link to approve in the app. Never the path, the command, the body, an amount, a name or a reason. Discord's message
// switches mentions off (allowed_mentions), so nothing typed anywhere can ping a channel.
import { HttpError, randomId, sha256hex, now, str, cleanText } from './util.js';
import { audit } from './audit.js';
import { seal, open } from './vault.js';
import { limit } from './ratelimit.js';
import { appOrigin } from './auth.js';
import { newChallenge, takeChallenge, checkAssertion, rp } from './auth.js';

export const MAX_CHANNELS = 3, MAX_FAILURES = 10, TIMEOUT_MS = 3000, TESTS_PER_MINUTE = 1, MAX_TEXT = 400;
const LABEL = /^[\p{L}\p{N} ._:/()-]+$/u;

/** the closed list: for each kind, the hosts, the path shape and the query allowed */
export const KINDS = {
  slack: { hosts: ['hooks.slack.com'], path: /^\/services\/T[A-Za-z0-9]{2,30}\/B[A-Za-z0-9]{2,30}\/[A-Za-z0-9]{8,64}$/, query: null, name: 'Slack' },
  discord: { hosts: ['discord.com', 'discordapp.com'], path: /^\/api\/webhooks\/[0-9]{5,25}\/[A-Za-z0-9_-]{20,120}$/, query: null, name: 'Discord' },
  gchat: { hosts: ['chat.googleapis.com'], path: /^\/v1\/spaces\/[A-Za-z0-9_-]{4,60}\/messages$/, query: /^\?key=[A-Za-z0-9_-]{16,80}&token=(?:[A-Za-z0-9_-]|%3[Dd]){8,120}$/, name: 'Google Chat' },
};

/** the URL as the parser makes it, if it is exactly a webhook of this kind; else a 400 that says what was wrong */
export function checkUrl(kind, raw) {
  const k = KINDS[kind];
  if (!k) throw new HttpError(400, 'bad_kind', 'A channel is Slack, Discord or Google Chat (slack, discord or gchat).');
  const bad = (why) => new HttpError(400, 'bad_url', `That is not a ${k.name} webhook address: ${why}`);
  if (typeof raw !== 'string' || raw.length > 600 || raw.length < 20) throw bad('it should be the address you copied from the service.');
  let u;
  try { u = new URL(raw); } catch { throw bad('it is not a web address.'); }
  if (u.protocol !== 'https:') throw bad('it must start with https://.');
  if (u.username || u.password) throw bad('it must not contain a user name or password.');
  if (u.port) throw bad('it must not name a port.');
  if (u.hash) throw bad('it must not end with a #.');
  if (!k.hosts.includes(u.hostname)) throw bad(`the host must be ${k.hosts.join(' or ')}.`);
  if (!k.path.test(u.pathname)) throw bad('the path is not the shape of one of its webhooks.');
  if (k.query ? !k.query.test(u.search) : u.search) throw bad(k.query ? 'it needs the key and token it was given, and nothing else.' : 'it must have no query.');
  if (u.href !== raw) throw bad('it has characters that a web address does not normally contain; copy it again from the service.');
  return { href: u.href, host: u.hostname };
}

const bodyOf = (kind, text) => JSON.stringify(kind === 'discord' ? { content: text, allowed_mentions: { parse: [] } } : { text });
const fetcherOf = (env) => env.__channelFetch || fetch;
/** only characters a label is made of, so nothing typed anywhere can become a mention, a link or markup in a channel */
export const safeLabel = (s, n = 40) => cleanText(s ?? '').replace(/[^\p{L}\p{N} ._:/()-]/gu, '').slice(0, n).trim();

/** one POST; never throws: { ok, status } */
async function post(env, kind, url, text) {
  try {
    const { href } = checkUrl(kind, url); // checked again at use: what is stored is never trusted
    const res = await fetcherOf(env)(href, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/json; charset=utf-8' },
      body: bodyOf(kind, text.slice(0, MAX_TEXT)), signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    try { await res.body?.cancel(); } catch { /* nothing to read */ }
    return { ok: res.status >= 200 && res.status < 300, status: res.status };
  } catch {
    return { ok: false, status: 0 };
  }
}

const rowFor = (c) => ({ id: c.id, account_id: c.account_id, provider: 'channel:' + c.kind, ct: c.ct, iv: c.iv, wrapped_dek: c.wrapped_dek, dek_iv: c.dek_iv });
async function send(env, c, text) {
  let r;
  try { r = await post(env, c.kind, await open(env, rowFor(c)), text); } catch { r = { ok: false, status: 0 }; }
  const t = now();
  // writes only when something changed: a healthy channel is touched at most once an hour
  try {
    if (r.ok) await env.DB.prepare('UPDATE channels SET failures = 0, last_ok_at = ?1 WHERE id = ?2 AND (failures > 0 OR last_ok_at IS NULL OR last_ok_at < ?3)').bind(t, c.id, t - 3600_000).run();
    else await env.DB.prepare('UPDATE channels SET failures = failures + 1 WHERE id = ?').bind(c.id).run();
  } catch { /* the alert matters more than its bookkeeping */ }
  return r;
}

/** tell every working channel of the account; never throws, never waits for more than the timeout */
export async function announce(env, accountId, text) {
  try {
    const rows = (await env.DB.prepare('SELECT id, account_id, kind, ct, iv, wrapped_dek, dek_iv FROM channels WHERE account_id = ? AND failures < ? ORDER BY created_at LIMIT ?').bind(accountId, MAX_FAILURES, MAX_CHANNELS).all()).results;
    await Promise.all(rows.map((c) => send(env, c, text)));
  } catch { /* alerts are best effort */ }
}

/** "Counterseal: <who> needs approval for <rule> (needs 2 seals). Approve with your passkey: <link>" */
export function holdText({ who, rule, needs = 1, seals = 0, url }) {
  const rest = needs > 1 ? ` (${seals} of ${needs} seals so far)` : '';
  // a label is typed by whoever made the token (a command line session or an agent may): one that could read as a web
  // address ("https://counterseal-login.example") is put in code formatting, which Slack, Discord and Google Chat never
  // turn into a link next to the real approve link
  const label = safeLabel(who);
  const shown = /[.:/]/.test(label) ? '`' + label + '`' : label;
  return `Counterseal: ${shown || 'An agent'} needs approval for ${String(rule).replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 80) || 'an action'}${rest}. Approve with your passkey: ${url}`;
}
export const sealText = ({ seals, needs, url }) => `Counterseal: a held action has ${seals} of ${needs} seals and needs another approver. Approve with your passkey: ${url}`;

/** the one call the three places that hold something make, after their phone alert (and under the same one-a-minute limit) */
export async function holdAlert(env, accountId, { who, rule, needs, holdId }) {
  const url = `${appOrigin(env)}/app#hold=${holdId}`;
  return announce(env, accountId, holdText({ who, rule, needs, seals: 0, url }));
}

// ---------------------------------------------------------------- the owner's side
export async function listChannels(env, accountId) {
  const r = await env.DB.prepare('SELECT id, kind, label, host, created_by, created_at, last_ok_at, failures FROM channels WHERE account_id = ? ORDER BY created_at LIMIT ?').bind(accountId, MAX_CHANNELS).all();
  return r.results.map((c) => ({ ...c, name: KINDS[c.kind]?.name || c.kind, disabled: c.failures >= MAX_FAILURES }));
}

function addParams(body) {
  for (const k of Object.keys(body)) if (!['kind', 'url', 'label', 'challengeId', 'credential'].includes(k)) throw new HttpError(400, 'bad_field', 'Unknown field. Send only: kind, url, label.');
  const label = str(body.label, 'label', { max: 60, re: LABEL });
  const { href, host } = checkUrl(body.kind, body.url);
  return { kind: body.kind, label, href, host };
}

export async function addBegin(env, sess, body) {
  const p = addParams(body);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM channels WHERE account_id = ?').bind(sess.accountId).first();
  if (n.n >= MAX_CHANNELS) throw new HttpError(409, 'too_many_channels', `Up to ${MAX_CHANNELS} channels. Remove one first.`);
  // what the passkey approves is exactly this address (its hash), kind and label
  const { id, challenge } = await newChallenge(env, 'team_channel', sess.accountId, JSON.stringify({ kind: p.kind, label: p.label, url: await sha256hex(p.href) }));
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function addFinish(env, sess, body) {
  const p = addParams(body);
  const ch = await takeChallenge(env, body.challengeId, 'team_channel');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const want = JSON.parse(ch.name);
  if (want.kind !== p.kind || want.label !== p.label || want.url !== await sha256hex(p.href)) throw new HttpError(409, 'channel_changed', 'This is not the channel you began adding. Start again.');
  const id = randomId(), t = now();
  const sealed = await seal(env, { id, accountId: sess.accountId, provider: 'channel:' + p.kind }, p.href);
  // at most 3, decided in the statement itself
  const ins = await env.DB.prepare(`INSERT INTO channels (id, account_id, kind, label, host, ct, iv, wrapped_dek, dek_iv, created_by, created_at)
    SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11 WHERE (SELECT COUNT(*) FROM channels WHERE account_id = ?2) < ?12`)
    .bind(id, sess.accountId, p.kind, p.label, p.host, sealed.ct, sealed.iv, sealed.wrapped_dek, sealed.dek_iv, sess.memberId || null, t, MAX_CHANNELS).run();
  if (!ins.meta.changes) throw new HttpError(409, 'too_many_channels', `Up to ${MAX_CHANNELS} channels. Remove one first.`);
  await audit(env, sess.accountId, 'web', 'channel_added', { id, kind: p.kind, label: p.label, host: p.host, by: sess.memberId });
  return { id, kind: p.kind, name: KINDS[p.kind].name, label: p.label, host: p.host, created_at: t, last_ok_at: null, failures: 0, disabled: false };
}

/** removing only tightens */
export async function remove(env, sess, id) {
  const r = await env.DB.prepare('DELETE FROM channels WHERE id = ? AND account_id = ?').bind(id, sess.accountId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'channel_removed', { id, by: sess.memberId });
  return { ok: true };
}

/** a test message, once a minute per account; also the way to turn a channel that stopped back on */
export async function test(env, sess, id) {
  await limit(env.DB, 'chtest:' + sess.accountId, TESTS_PER_MINUTE, 60_000, now());
  const c = await env.DB.prepare('SELECT id, account_id, kind, ct, iv, wrapped_dek, dek_iv FROM channels WHERE id = ? AND account_id = ?').bind(id, sess.accountId).first();
  if (!c) throw new HttpError(404, 'not_found');
  const r = await send(env, c, `Counterseal: a test message. Alerts about held actions will arrive here; approving always needs your passkey in the app.`);
  return { ok: r.ok, status: r.status };
}
