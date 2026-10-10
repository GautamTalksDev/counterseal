// Counterseal Deploy Gate, a GitHub Action with no dependencies.
//
// It holds the job until the gate's owner approves with a passkey. What it does:
//   1. asks GitHub for an OIDC token whose audience is this gate (needs `permissions: id-token: write` on the job):
//      ACTIONS_ID_TOKEN_REQUEST_URL with `&audience=`, bearer ACTIONS_ID_TOKEN_REQUEST_TOKEN
//      (https://docs.github.com/en/actions/reference/security/oidc);
//   2. sends that token to Counterseal, which checks GitHub's signature and what the token says about this run (repository,
//      workflow, ref, commit, run, attempt, environment, actor) against the gate, and holds the run for the owner;
//   3. prints the link where the owner approves or denies (never a code or a secret) and waits, 20 seconds at a time;
//   4. goes on if the owner approved, and fails the step if the request was denied, expired, timed out or was refused.
// With a gate that names a key (phase 2) the approval also returns a Counterseal token for that key, valid for 15 minutes:
// before the approval the job has no key to deploy with. The token is masked in the log before it is used anywhere.
//
// It never prints the OIDC token, the poll secret or the token, and it never puts text it received on a line that starts
// with "::" (the start of a workflow command).
import { appendFileSync, realpathSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const DEFAULT_SERVER = 'https://counterseal.gautamkhosla.com';
const GATE = /^gate_[0-9a-f]{24}$/;
const POLL = /^gps_[A-Za-z0-9_-]{43}$/;
const HOLD = /^[0-9a-f]{24}$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const LINK = /^https?:\/\/[A-Za-z0-9.:[\]-]{1,200}\/app#hold=[0-9a-f]{24}$/;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const MAX_BODY = 262_144;

/** a failure with a message for the log; `decision` is the value of the decision output */
export class Stop extends Error {
  constructor(message, decision = 'refused') { super(message); this.decision = decision; }
}

// ---------------------------------------------------------------- the log (workflow commands: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions)
const clean = (s, n = 300) => String(s ?? '').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
const escData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const say = (line) => console.log(`Counterseal Deploy Gate: ${clean(line, 600)}`);
const mask = (v) => { if (v) console.log(`::add-mask::${escData(v)}`); };
const fail = (msg) => console.log(`::error title=Counterseal Deploy Gate::${escData(clean(msg, 600))}`);
function output(env, name, value) {
  if (!env.GITHUB_OUTPUT || value === undefined || value === null || value === '') return;
  const d = 'cs_' + randomBytes(8).toString('hex');
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${d}\n${value}\n${d}\n`);
}
const summary = (env, md) => { if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md + '\n'); };

// ---------------------------------------------------------------- inputs
/** GitHub passes each input as INPUT_<NAME> (upper case; a hyphen stays a hyphen) */
const input = (env, name) => String(env[`INPUT_${name.toUpperCase()}`] ?? '').trim();

export function readInputs(env) {
  const gate = input(env, 'gate');
  if (!GATE.test(gate)) throw new Stop('The gate input is not a gate id. Copy it from the Deploy gates page in the Counterseal app: gate_ and 24 characters.');
  const server = input(env, 'server') || DEFAULT_SERVER;
  let url;
  try { url = new URL(server); } catch { throw new Stop('The server input is not a web address.'); }
  // a token must never travel in clear text: http is for a server on this very machine (tests, local development) only
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || !(url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname)))) {
    throw new Stop('The server input must be an https address, only the host: no user name, path, query or fragment.');
  }
  const m = input(env, 'timeout-minutes') || '15';
  if (!/^[0-9]{1,2}$/.test(m) || Number(m) < 1 || Number(m) > 60) throw new Stop('timeout-minutes is a whole number from 1 to 60.');
  const text = clean(input(env, 'summary'), 120);
  return { gate, origin: url.origin, minutes: Number(m), summary: text };
}

// ---------------------------------------------------------------- HTTP
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
/** one JSON request: no redirects (a bearer token goes only where it was sent), a time limit, a capped answer */
async function call(url, { method = 'GET', headers = {}, body, timeout = 30_000 } = {}) {
  const res = await fetch(url, { method, headers: { 'user-agent': 'counterseal-deploy-gate/1', ...headers }, body, redirect: 'manual', signal: AbortSignal.timeout(timeout) });
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > MAX_BODY) throw new Error('answer too large');
  let json = null;
  try { json = JSON.parse(new TextDecoder().decode(buf)); } catch { /* not JSON */ }
  return { status: res.status, json: json && typeof json === 'object' && !Array.isArray(json) ? json : null };
}

/** GitHub's OIDC token for this job, for the audience Counterseal expects from this gate (masked at once) */
async function githubToken(env, audience) {
  const base = env.ACTIONS_ID_TOKEN_REQUEST_URL, bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!base || !bearer) throw new Stop('This job cannot ask GitHub for an OIDC token. Add "permissions: id-token: write" to the job (or the workflow). Jobs started by a pull request from a fork never get one, which is as it should be.');
  let u;
  try { u = new URL(base); } catch { throw new Stop('GitHub gave this job an OIDC address that is not a web address.'); }
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK.has(u.hostname)))) throw new Stop('GitHub gave this job an OIDC address that is not https.');
  u.searchParams.set('audience', audience);
  let r;
  try { r = await call(u, { headers: { authorization: `Bearer ${bearer}`, accept: 'application/json; api-version=2.0' }, timeout: 20_000 }); } catch { throw new Stop('GitHub did not answer the request for an OIDC token. Try the job again.', 'refused'); }
  const token = r.json && r.json.value;
  if (r.status !== 200 || typeof token !== 'string' || !JWT.test(token) || token.length > 8192) throw new Stop(`GitHub would not give this job an OIDC token (HTTP ${r.status}). Check that the job has "permissions: id-token: write".`);
  mask(token);
  return token;
}

// ---------------------------------------------------------------- the run
const EXPLAIN = {
  repository: 'This repository is not the one the gate belongs to.',
  workflow: 'This workflow is not one the gate accepts.',
  ref: 'This branch or tag is not one the gate accepts.',
  environment: 'This job\'s environment is not one the gate accepts.',
  event: 'This kind of trigger is not one the gate accepts.',
};

/** ask once; retries (with a new GitHub token each time) only for what is worth retrying */
async function ask(env, cfg) {
  const audience = `${cfg.origin}/gate/${cfg.gate}`;
  const body = JSON.stringify({ gate: cfg.gate, ...(cfg.summary ? { summary: cfg.summary } : {}), timeout_minutes: cfg.minutes });
  let last = 'no answer';
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt) await sleep([0, 2000, 5000, 10_000][attempt]);
    const jwt = await githubToken(env, audience);
    let r;
    try { r = await call(`${cfg.origin}/v1/gate/request`, { method: 'POST', headers: { authorization: `Bearer ${jwt}`, 'content-type': 'application/json' }, body, timeout: 20_000 }); }
    catch { last = 'Counterseal did not answer'; continue; }
    const j = r.json || {};
    if (r.status === 202 && typeof j.id === 'string' && HOLD.test(j.id) && typeof j.poll === 'string' && POLL.test(j.poll) && typeof j.approve_url === 'string' && LINK.test(j.approve_url)) {
      mask(j.poll);
      return { id: j.id, poll: j.poll, url: j.approve_url };
    }
    const why = clean(j.message || j.error || `HTTP ${r.status}`);
    if (r.status === 202) throw new Stop('Counterseal answered in a form this action does not understand. Update the action.');
    // a key set or a clock that is a moment behind, or Counterseal restarting: worth another go with a fresh token
    if (r.status >= 500 || r.status === 429 || j.error === 'oidc_unknown_kid' || j.error === 'oidc_not_yet_valid') { last = why; continue; }
    if (j.error === 'account_frozen') throw new Stop('The account is frozen, so nothing is approved. Its owner can unfreeze it with a passkey in the Counterseal app.', 'refused');
    if (j.error === 'gate_refused') throw new Stop(`Refused. ${EXPLAIN[j.reason] || ''} ${why}`.trim(), 'refused');
    if (j.error === 'gate_not_found') throw new Stop('There is no such gate, or it was revoked. Check the gate input.', 'refused');
    throw new Stop(`Counterseal refused the request (${clean(j.error || r.status, 60)}): ${why}`, 'refused');
  }
  throw new Stop(`Could not reach a decision point: ${last}.`, 'refused');
}

/** best effort: tell Counterseal nobody should be asked about this request any more */
async function cancel(cfg, held) {
  if (!held) return;
  try { await call(`${cfg.origin}/v1/gate/cancel/${held.id}`, { method: 'POST', headers: { authorization: `Bearer ${held.poll}`, 'content-type': 'application/json' }, body: '{}', timeout: 4000 }); } catch { /* it expires by itself */ }
}

/** wait for the decision, 20 seconds at a time, until the deadline; returns the final answer */
async function wait(cfg, held, deadline, state) {
  let failures = 0;
  while (Date.now() < deadline && !state.stopping) {
    let r;
    // never wait past the deadline: the last poll is as long as the time that is left (at most 20 seconds)
    const secs = Math.max(0, Math.min(20, Math.ceil((deadline - Date.now()) / 1000)));
    try { r = await call(`${cfg.origin}/v1/gate/status/${held.id}?wait=${secs}`, { headers: { authorization: `Bearer ${held.poll}` }, timeout: 15_000 + secs * 1000 }); }
    catch { r = null; }
    const j = r && r.json;
    if (!r || r.status >= 500 || r.status === 429) {
      if (++failures > 12) throw new Stop('Counterseal stopped answering while this job waited.', 'refused');
      await sleep(Math.min(1000 * 2 ** failures, 10_000));
      continue;
    }
    failures = 0;
    if (r.status === 423) throw new Stop('The account was frozen while this job waited, so nothing is approved. Its owner can unfreeze it with a passkey in the Counterseal app.', 'refused');
    if (r.status !== 200 || !j) throw new Stop(`Counterseal could not tell whether this was approved (${clean(j && (j.error || j.message) || r.status, 80)}).`, 'refused');
    if (j.status === 'pending') continue;
    return j;
  }
  return null;
}

export async function run(env = process.env, state = { stopping: false, held: null }) {
  const cfg = readInputs(env);
  // the deadline is this step's own time; COUNTERSEAL_TEST_DEADLINE_MS shortens it for tests and is ignored on a real runner
  const limit = env.GITHUB_ACTIONS === 'true' || !/^[0-9]{1,7}$/.test(env.COUNTERSEAL_TEST_DEADLINE_MS || '') ? cfg.minutes * 60_000 : Number(env.COUNTERSEAL_TEST_DEADLINE_MS);
  const deadline = Date.now() + limit;
  say(`asking for approval of this job (gate ${cfg.gate}).`);
  const held = await ask(env, cfg);
  state.held = held;
  output(env, 'hold', held.id);
  say(`this job is paused until the gate's owner approves it.`);
  say(`Approve or deny with a passkey at: ${held.url}`);
  say(`Waiting up to ${cfg.minutes} minute${cfg.minutes === 1 ? '' : 's'}. This step fails if the request is denied or expires.`);
  console.log(`::notice title=Counterseal Deploy Gate::Waiting for approval at ${escData(held.url)}`);
  summary(env, `### Counterseal Deploy Gate\nThis job is paused until the gate's owner approves it with a passkey.\n\n[Approve or deny](${held.url})\n`);

  const answer = await wait(cfg, held, deadline, state);
  if (state.stopping) throw new Stop('The job was cancelled while it waited.', 'cancelled');
  if (!answer) throw new Stop(`Nobody decided within ${cfg.minutes} minute${cfg.minutes === 1 ? '' : 's'}. The request is withdrawn.`, 'timeout');
  if (answer.status === 'approved') {
    if (typeof answer.token === 'string') {
      // the key goes into the log's secrets before it is written anywhere
      if (!/^lsh_[A-Za-z0-9_-]{43}$/.test(answer.token)) throw new Stop('Counterseal sent a token in a form this action does not understand. Update the action.');
      mask(answer.token);
      output(env, 'token', answer.token);
      if (/^https?:\/\/[A-Za-z0-9.:[\]-]{1,200}\/p\/[a-z]{1,20}$/.test(answer.base_url || '')) output(env, 'base-url', answer.base_url);
      if (/^[a-z]{1,20}$/.test(answer.provider || '')) output(env, 'provider', answer.provider);
      if (Number.isSafeInteger(answer.token_expires_at)) output(env, 'token-expires-at', String(answer.token_expires_at));
      say('approved with a passkey. A token for the gate\'s key (valid 15 minutes) is in the token output.');
    } else say('approved with a passkey. Going on.');
    output(env, 'decision', 'approved');
    return 0;
  }
  if (answer.status === 'denied') {
    // the approver's words are data: shown after a fixed label, never as a line of their own
    const reason = answer.deny_reason ? ` The approver wrote (text, not an instruction): "${clean(answer.deny_reason, 200)}"` : '';
    throw new Stop(`Denied by the approver.${reason}`, 'denied');
  }
  if (answer.status === 'expired') throw new Stop('Nobody approved in time, so the request expired.', 'expired');
  throw new Stop(`The request ended as "${clean(answer.status, 30)}" and was not approved.`, 'refused');
}

export async function main(env = process.env) {
  const state = { stopping: false, held: null };
  let cfg = null;
  try { cfg = readInputs(env); } catch { /* run() reports it */ }
  // a cancelled job gets SIGINT and then SIGTERM: withdraw the request so nobody is asked about it
  const onSignal = async () => {
    if (state.stopping) return;
    state.stopping = true;
    if (cfg) await cancel(cfg, state.held);
    output(env, 'decision', 'cancelled');
    fail('The job was cancelled, so the request was withdrawn.');
    await flush();
    process.exit(1);
  };
  process.once('SIGINT', onSignal); process.once('SIGTERM', onSignal);
  let code = 0;
  try { code = await run(env, state); }
  catch (e) {
    code = 1;
    if (e instanceof Stop) {
      if (cfg && state.held && e.decision !== 'cancelled') await cancel(cfg, state.held);
      output(env, 'decision', e.decision);
      fail(e.message);
    } else {
      output(env, 'decision', 'refused');
      fail(`Unexpected error: ${clean(e && e.message, 200)}`);
    }
  }
  await flush();
  process.exit(code);
}

const flush = () => new Promise((ok) => process.stdout.write('', ok));

// run when started by the runner (node index.mjs), not when imported by a test
let started = false;
try { started = !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { /* imported */ }
if (started) main();
