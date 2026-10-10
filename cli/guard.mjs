#!/usr/bin/env node
// leashcli guard: hold the irreversible commands of a coding agent until a human approves them with a passkey.
//   leashcli guard install [--agents claude-code,codex,cursor|none] [--scope user|project] [--paste-key] [--label x] [--dry-run]
//                          (--agents none makes the key only: the Claude Code plugin brings its own hook)
//   leashcli guard uninstall [--agents ...] [--scope ...] [--keep-key] [--revoke-key]
//   leashcli guard status            what is installed, whether the key works, how long it lasts
//   leashcli guard check [--cwd dir] [--json] -- <command>     what the map says about a command (no network)
//   leashcli guard map [--json]      the rules on the shell map
//   leashcli guard update-map        fetch the current API map from the server
//   leashcli guard hook --agent <claude-code|codex|cursor> [--mode wait|retry]   what the agent calls (reads JSON on stdin)
//
// This is a seatbelt, not a sandbox. It runs on the machine of the agent it guards, as the same user, and it only
// sees what the agent's hook shows it. An agent that can edit its own hook settings, run a script it wrote, or use a
// tool the hook does not cover is not stopped. For a hard stop give the agent a Counterseal token, not the real key.
//
// Zero dependencies, Node 20+. The hook never prints the guard key, and never prints "allow" (silence leaves the
// agent's own permissions in charge), except for Cursor, whose hook contract requires an answer.
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, renameSync, unlinkSync, copyFileSync, readdirSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { classify, classifyTool, redact, canonicalJson, apiMapFromMeta, SHELL_MAP_VERSION, SHELL_RULES, TOOL_RULES } from './shellmap.mjs';

export const GUARD_VERSION = '0.2.1';
const HERE = dirname(fileURLToPath(import.meta.url));
const AGENTS = ['claude-code', 'codex', 'cursor'];
const NOT_YET = ['copilot', 'gemini', 'antigravity'];
const KEY_RE = /^lsg_[A-Za-z0-9_-]{43}$/;
const HOOK_MARK = 'guard.mjs';

// ---------------------------------------------------------------- places
const cfgDir = (env = process.env) => join(env.XDG_CONFIG_HOME || join(env.HOME || homedir(), '.config'), 'leash');
const paths = (env = process.env) => {
  const d = cfgDir(env);
  return { dir: d, guard: env.LEASH_GUARD_CONFIG || join(d, 'guard.json'), session: join(d, 'config.json'), map: join(d, 'guard-map.json'), scripts: join(d, 'guard'), mcp: join(d, 'mcp') };
};
const homeDir = (env = process.env) => env.HOME || env.USERPROFILE || homedir();

function writeAtomic(path, data, mode = 0o644) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, data, { mode });
  try { chmodSync(tmp, mode); } catch { /* not on every file system */ }
  renameSync(tmp, path);
}
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// ---------------------------------------------------------------- configuration
export const DEFAULTS = Object.freeze({
  onUnavailable: 'deny', // the server cannot be reached: deny (default) or allow
  unreadable: 'allow', // a command the parser could not read and the plain scan found nothing in: allow (default) or hold
  waitSeconds: 540, // how long the hook waits for the passkey before it denies (the agent's own timeout is longer)
  mode: { 'claude-code': 'wait', codex: 'wait', cursor: 'wait' }, // wait: hold the command at the hook; retry: deny now, run again after approval
  cursorPassThrough: 'allow', // Cursor's hook contract needs an answer for every command: allow or ask
  disableRules: [],
});
export function loadConfig(env = process.env, io = null) {
  const p = paths(env);
  const raw = (io ? io.readJson(p.guard) : readJson(p.guard)) || {};
  const c = { ...DEFAULTS, ...raw, mode: { ...DEFAULTS.mode, ...(raw.mode || {}) } };
  const e = (k) => env[k];
  if (e('LEASH_GUARD_ON_UNAVAILABLE') === 'allow' || e('LEASH_GUARD_ON_UNAVAILABLE') === 'deny') c.onUnavailable = e('LEASH_GUARD_ON_UNAVAILABLE');
  if (e('LEASH_GUARD_WAIT') && /^\d{1,3}$/.test(e('LEASH_GUARD_WAIT'))) c.waitSeconds = Number(e('LEASH_GUARD_WAIT'));
  if (e('LEASH_URL')) c.server = e('LEASH_URL');
  c.server = String(c.server || 'https://counterseal.gautamkhosla.com').replace(/\/+$/, '');
  c.waitSeconds = Math.max(0, Math.min(590, Number(c.waitSeconds) || 0));
  c.requestTimeoutMs = Math.max(200, Math.min(30000, Number(e('LEASH_GUARD_TIMEOUT_MS')) || Number(c.requestTimeoutMs) || 10000)); // one request; the long poll adds its own wait
  if (!['deny', 'allow'].includes(c.onUnavailable)) c.onUnavailable = 'deny';
  if (!['allow', 'hold'].includes(c.unreadable)) c.unreadable = 'allow';
  if (!['allow', 'ask'].includes(c.cursorPassThrough)) c.cursorPassThrough = 'allow';
  if (!Array.isArray(c.disableRules)) c.disableRules = [];
  c.disableRules = c.disableRules.filter((x) => typeof x === 'string').slice(0, 100);
  return c;
}
const safeServer = (url) => /^https:\/\//i.test(url) || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(url);

// ---------------------------------------------------------------- the input an agent sends
const clean = (s, n = 300) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
const scrub = (s) => String(s).replace(/\bls[cgh]_[A-Za-z0-9_-]{16,}/g, '[redacted]');

/** what the agent is about to do: { kind: 'shell'|'tool'|null, command, cwd, session, tool: {server, name, input} } */
export function readCall(agent, input) {
  let j;
  try { j = JSON.parse(input); } catch { return { kind: null, why: 'the hook input is not JSON' }; }
  if (!j || typeof j !== 'object') return { kind: null, why: 'the hook input is not an object' };
  const cwd = typeof j.cwd === 'string' ? j.cwd : (Array.isArray(j.workspace_roots) && typeof j.workspace_roots[0] === 'string' ? j.workspace_roots[0] : null);
  const session = typeof j.session_id === 'string' ? j.session_id : (typeof j.conversation_id === 'string' ? j.conversation_id : null);
  if (agent === 'cursor') {
    if (typeof j.command === 'string' && j.tool_name === undefined) return { kind: 'shell', command: j.command, cwd, session };
    if (typeof j.tool_name === 'string') {
      let inp = j.tool_input;
      if (typeof inp === 'string') { try { inp = JSON.parse(inp); } catch { /* keep the text */ } }
      return { kind: 'tool', cwd, session, tool: { server: typeof j.mcp_server_name === 'string' ? j.mcp_server_name : '', name: j.tool_name, input: inp } };
    }
    return { kind: null, why: 'not a shell or tool call' };
  }
  const name = j.tool_name;
  if (name === 'Bash' && typeof j.tool_input?.command === 'string') return { kind: 'shell', command: j.tool_input.command, cwd, session };
  if (typeof name === 'string' && name.startsWith('mcp__')) {
    const rest = name.slice(5), i = rest.indexOf('__');
    return { kind: 'tool', cwd, session, tool: { server: i > 0 ? rest.slice(0, i) : '', name: i > 0 ? rest.slice(i + 2) : rest, input: j.tool_input } };
  }
  return { kind: null, why: 'not a shell or tool call' };
}

/** the project root: the nearest folder above the working directory that has a .git entry */
export function projectRoot(cwd, exists = existsSync) {
  if (!cwd || !cwd.startsWith('/')) return cwd || null;
  let d = cwd;
  for (let i = 0; i < 12; i++) {
    if (exists(join(d, '.git'))) return d;
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  return cwd;
}

// ---------------------------------------------------------------- what is sent to the server
const MAX_DETAIL = 4096;
function fit(text, extra = '') {
  if (text.length <= MAX_DETAIL && !extra) return text;
  if (text.length + extra.length + 4 <= MAX_DETAIL) return `${text}\n[${extra}]`;
  const tail = `\n[... ${text.length - 3800} more characters, sha256 ${sha256(text).slice(0, 16)}${extra ? '; ' + extra : ''}]`;
  return text.slice(0, MAX_DETAIL - tail.length) + tail;
}
const SECRET_KEY = /pass(word|wd)?|secret|token|api[-_]?key|authorization|credential|private[-_]?key|cookie/i;
function redactDeep(v, depth = 0) {
  if (depth > 12) return '[too deep]';
  if (typeof v === 'string') return redact(v);
  if (Array.isArray(v)) return v.slice(0, 200).map((x) => redactDeep(x, depth + 1));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).slice(0, 200).map(([k, x]) => [k, SECRET_KEY.test(k) && typeof x === 'string' ? '[redacted]' : redactDeep(x, depth + 1)]));
  return v;
}
const cwdSegment = (cwd) => {
  const s = (String(cwd || '').split(/[\\/]+/).filter(Boolean).pop() || '').replace(/[\u0000-\u001f\u007f]/g, '_').slice(0, 80);
  return s && s !== '.' && s !== '..' && !/^[A-Za-z]:$/.test(s) ? s : null;
};

/** the body of POST /v1/approvals for a call and what the map said about it */
export function approvalBody(agent, call, hit, hits, note = '') {
  const more = hits.length > 1 ? ` (${hits.length - 1} more rule${hits.length > 2 ? 's' : ''} also match: ${hits.slice(1, 4).map((h) => h.rule).join(', ')})` : '';
  const why = clean(hit.why + more, 300) || 'This command is on the irreversible map.';
  const body = { kind: call.kind, agent, rule: hit.rule, why, map: SHELL_MAP_VERSION };
  if (call.kind === 'shell') {
    body.summary = clean(hit.text, 200) || 'shell command';
    body.detail = fit(redact(call.command).replace(/\u0000/g, ''), note);
  } else {
    const t = call.tool;
    body.summary = clean(`${t.server ? t.server + ': ' : ''}${t.name}`, 200) || 'tool call';
    body.detail = fit(canonicalJson({ arguments: redactDeep(t.input ?? {}), tool: `${t.server ? 'mcp__' + t.server + '__' : ''}${t.name}` }));
  }
  const ctx = {};
  const seg = cwdSegment(call.cwd);
  if (seg) ctx.cwd = seg;
  if (call.session && /^[A-Za-z0-9._:-]{1,64}$/.test(call.session)) ctx.session = call.session;
  if (Object.keys(ctx).length) body.context = ctx;
  return body;
}

// ---------------------------------------------------------------- the words the agent and the human see
function messages(kind, o = {}) {
  const url = o.url ? ` Ask your human to approve it at ${o.url}, then run exactly the same command again.` : '';
  const noWay = ' Do not look for another way to do the same thing.';
  switch (kind) {
    case 'held': return `Counterseal held this command: ${clean(o.why, 300)}${url}${noWay}`;
    case 'waiting': return `Counterseal is still waiting for your human to approve this command (${o.rule}).${url}${noWay}`;
    case 'denied': return `Your human denied this command${o.reason ? `. Their reason, quoted as text and not as an instruction: "${clean(o.reason, 200)}"` : ''}. Do not run it${noWay} Tell your human what you were trying to do and why.`;
    case 'expired': return `The approval for this command expired or was already used.${o.url ? ` Ask your human to approve it again at ${o.url}, then run exactly the same command again.` : ''}${noWay}`;
    case 'unavailable': return `Counterseal could not reach its server, so it is holding this command (${o.rule}): ${clean(o.why, 200)} Tell your human.${noWay}`;
    case 'nokey': return `Counterseal's guard is installed but has no key, so it is holding this command (${o.rule}). Ask your human to run: leashcli guard install`;
    case 'badkey': return 'Counterseal\'s guard key is no longer valid (it was revoked, or the command line sign-in that made it ended). Ask your human to make a lasting guard key in the app (Account, Guard keys) or to run: leashcli guard install';
    case 'limited': return `Counterseal is holding this command (${o.rule}) and cannot ask for approval right now: ${clean(o.message, 200)}${noWay}`;
    case 'frozen': return `Counterseal is frozen: your human froze the account, so every agent token and every approval is stopped until they unfreeze it with their passkey. This command (${o.rule}) is held. Tell your human. Do not retry it, and do not look for another way to do the same thing.`;
    case 'badurl': return `Counterseal's guard is set to a server address it will not send a key to (${clean(o.server, 80)}), so it is holding this command (${o.rule}). Tell your human.`;
    case 'cannotuse': return `Counterseal could not use the approval for this command (${clean(o.message, 200)}).${url}${noWay}`;
    default: return 'Counterseal is holding this command.';
  }
}

// ---------------------------------------------------------------- answers per agent
export function silent() { return { code: 0, stdout: '', stderr: '' }; }
export function passFor(agent, cfg) {
  if (agent === 'cursor') return { code: 0, stdout: JSON.stringify({ continue: true, permission: cfg.cursorPassThrough }), stderr: '' };
  return silent();
}
export function denyFor(agent, text) {
  const t = scrub(text);
  if (agent === 'cursor') return { code: 0, stdout: JSON.stringify({ continue: true, permission: 'deny', user_message: `Counterseal: ${t}`, agent_message: t }), stderr: '' };
  return { code: 0, stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: t } }), stderr: '' };
}

// ---------------------------------------------------------------- talking to the server
async function call(io, cfg, key, method, path, body, extraMs = 0) {
  const timeout = cfg.requestTimeoutMs + extraMs;
  try {
    const headers = { accept: 'application/json', authorization: `Bearer ${key}`, 'user-agent': `leash-guard/${GUARD_VERSION}` };
    if (body !== undefined) headers['content-type'] = 'application/json';
    const r = await io.fetch(cfg.server + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(timeout) });
    let j = {};
    try { j = await r.json(); } catch { /* not JSON */ }
    return { status: r.status, body: j && typeof j === 'object' ? j : {} };
  } catch (e) {
    return { status: 0, body: {}, error: e?.name || 'network' };
  }
}

// ---------------------------------------------------------------- the hook
export function makeIO(env = process.env) {
  return {
    fetch: (...a) => fetch(...a),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
    exists: existsSync,
    readJson,
    readText: (p) => { try { const t = readFileSync(p, 'utf8'); return t.length <= 1_000_000 ? t : null; } catch { return null; } },
    readdir: (p) => { try { return readdirSync(p); } catch { return []; } },
  };
}

/** C:\Users\me\proj as the Git Bash path /c/Users/me/proj (the shell the agent's commands run in on Windows) */
export function posixPath(p) {
  const s = typeof p === 'string' ? p : '';
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(s);
  if (m) return `/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`.replace(/\/+$/, '') || '/';
  return s.startsWith('/') ? s : null;
}
function classifyCall(call, cfg, io, env) {
  const p = paths(env);
  if (call.kind === 'shell') {
    const metaCache = io.readJson(p.map);
    const apiMap = metaCache?.meta ? apiMapFromMeta(metaCache.meta) : undefined;
    const cwd = posixPath(call.cwd);
    const r = classify(call.command, {
      cwd, root: projectRoot(cwd, io.exists), home: posixPath(homeDir(env)) ?? undefined, apiMap, disable: cfg.disableRules,
      readFile: (f) => (/\/package\.json$/.test(f) ? io.readText(f) : null),
    });
    return { hits: r.hits, unreadable: r.unreadable };
  }
  const t = call.tool;
  let policy = {};
  if (/^[A-Za-z0-9_.-]{1,64}$/.test(t.server)) policy = io.readJson(join(p.mcp, `${t.server}.json`)) || {};
  const r = classifyTool({ server: t.server, tool: t.name, input: t.input && typeof t.input === 'object' ? t.input : {} }, policy);
  return { hits: r.hold ? [{ rule: r.rule, why: r.why, text: clean(`${t.server ? t.server + ': ' : ''}${t.name}`, 200) }] : [], unreadable: false };
}

/**
 * Decide one call. Returns { code, stdout, stderr } for the agent's hook runner.
 * io: { fetch, sleep, now, exists, readJson, readText }
 */
export async function runHook({ agent, mode, input, over = false, env = process.env, io = makeIO(env), progress = () => {} }) {
  const cfg = loadConfig(env, io);
  const pass = () => passFor(agent, cfg);
  const deny = (text) => denyFor(agent, text);
  const call0 = readCall(agent, input);
  if (!call0.kind) {
    if (over) { // too big to parse: look for the command text in what we have
      const m = /"command"\s*:\s*"((?:[^"\\]|\\.)*)/.exec(input);
      if (m) { try { call0.kind = 'shell'; call0.command = JSON.parse(`"${m[1]}"`); } catch { call0.kind = null; } }
      const c = /"cwd"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(input);
      if (c) { try { call0.cwd = JSON.parse(`"${c[1]}"`); } catch { /* no cwd */ } }
    }
    if (!call0.kind) return pass();
  }
  let verdict;
  try { verdict = classifyCall(call0, cfg, io, env); } catch (e) {
    return pass(); // a bug in the map must not stop every command; `guard status` and the tests are where it shows
  }
  if (!verdict.hits.length && verdict.unreadable && cfg.unreadable === 'hold' && call0.kind === 'shell') {
    verdict.hits = [{ rule: 'sh.unreadable', why: 'The guard could not read this command, and your settings say to hold what it cannot read.', text: clean(call0.command, 200) }];
  }
  if (!verdict.hits.length) return pass();
  const hit = verdict.hits[0];
  const body = approvalBody(agent, call0, hit, verdict.hits, over ? 'the hook input was cut at 256 KB' : '');

  // ---- fail closed unless the settings say otherwise
  const unavailable = (why) => {
    if (cfg.onUnavailable === 'allow') return { ...pass(), stderr: `Counterseal guard: ${clean(why, 160)}; allowing "${hit.rule}" because onUnavailable is "allow".\n` };
    return deny(messages('unavailable', { rule: hit.rule, why }));
  };
  const key = io.readJson(paths(env).guard)?.key;
  if (typeof key !== 'string' || !KEY_RE.test(key)) return deny(messages('nokey', { rule: hit.rule }));
  if (!safeServer(cfg.server)) return deny(messages('badurl', { rule: hit.rule, server: cfg.server }));

  const created = await call(io, cfg, key, 'POST', '/v1/approvals', body);
  if (created.status === 401) return deny(messages('badkey'));
  if (created.status === 423) return deny(messages('frozen', { rule: hit.rule })); // Freeze is a deliberate stop: onUnavailable never lets it through
  if (created.status === 429) return deny(messages('limited', { rule: hit.rule, message: created.body.message || 'too many holds' }));
  if (created.status === 0 || created.status >= 500 || ![200, 202].includes(created.status)) {
    if (created.status >= 400 && created.status < 500) return deny(messages('limited', { rule: hit.rule, message: created.body.message || `the server refused the request (${created.status})` }));
    return unavailable(created.error ? 'the server could not be reached' : `the server answered ${created.status}`);
  }
  const a = created.body;
  if (typeof a.id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(a.id) || typeof a.hash !== 'string' || !/^[0-9a-f]{64}$/.test(a.hash)) return unavailable('the server sent an answer the guard does not understand');
  const url = typeof a.approve_url === 'string' && /^https?:\/\//.test(a.approve_url) ? clean(a.approve_url, 300) : null;

  const use = async () => {
    const u = await call(io, cfg, key, 'POST', `/v1/approvals/${a.id}/use`, { hash: a.hash });
    if (u.status === 200) return pass();
    if (u.status === 403) return deny(messages('denied', { reason: u.body.deny_reason }));
    if (u.status === 410 || (u.status === 409 && u.body.error === 'already_used')) return deny(messages('expired', { url }));
    if (u.status === 0 || u.status >= 500) return unavailable(u.error ? 'the server could not be reached' : `the server answered ${u.status}`);
    if (u.status === 401) return deny(messages('badkey'));
    if (u.status === 423) return deny(messages('frozen', { rule: hit.rule }));
    return deny(messages('cannotuse', { message: u.body.message || u.body.error || `status ${u.status}`, url }));
  };

  if (created.status === 200 && a.status === 'approved') return use();
  if (a.status !== 'pending') {
    if (a.status === 'approved') return use();
    return deny(messages('expired', { url }));
  }
  const how = mode || cfg.mode[agent] || 'wait';
  if (how === 'retry' || cfg.waitSeconds === 0) return deny(messages('held', { why: body.why, url }));

  // ---- wait for the passkey
  progress(`Counterseal: waiting for your passkey at ${url ?? cfg.server + '/app'} (${hit.rule})`);
  const deadline = io.now() + cfg.waitSeconds * 1000;
  let failures = 0;
  while (io.now() < deadline) {
    const left = Math.ceil((deadline - io.now()) / 1000);
    const w = Math.max(0, Math.min(20, left));
    const g = await call(io, cfg, key, 'GET', `/v1/approvals/${a.id}?wait=${w}`, undefined, w * 1000);
    if (g.status === 401) return deny(messages('badkey'));
    if (g.status === 423) return deny(messages('frozen', { rule: hit.rule })); // a freeze ends the wait at once
    if (g.status === 429) { await io.sleep(Math.min(5000, Math.max(0, deadline - io.now()))); continue; }
    if (g.status !== 200) {
      if (++failures >= 3 || (g.status >= 400 && g.status < 500)) return g.status >= 400 && g.status < 500 ? deny(messages('expired', { url })) : unavailable(g.error ? 'the server could not be reached' : `the server answered ${g.status}`);
      await io.sleep(Math.min(2000, Math.max(0, deadline - io.now())));
      continue;
    }
    failures = 0;
    const s = g.body.status;
    if (s === 'approved') return use();
    if (s === 'denied') return deny(messages('denied', { reason: g.body.deny_reason }));
    if (s === 'expired' || s === 'used') return deny(messages('expired', { url }));
    if (w === 0) break;
  }
  return deny(messages('waiting', { rule: hit.rule, url }));
}

async function readStdin(stream, cap = 256 * 1024, ms = 10000) {
  if (stream.isTTY) return { text: '', over: false };
  const chunks = [];
  let n = 0, over = false, timer;
  await Promise.race([
    new Promise((done) => {
      stream.on('data', (c) => { if (over) return; n += c.length; if (n > cap) { chunks.push(c.subarray(0, c.length - (n - cap))); over = true; } else chunks.push(c); });
      stream.on('end', done); stream.on('error', done); stream.on('close', done);
    }),
    new Promise((r) => { timer = setTimeout(r, ms); }),
  ]);
  clearTimeout(timer); // a pending timer would keep the process alive
  return { text: Buffer.concat(chunks).toString('utf8'), over };
}

// ---------------------------------------------------------------- argument helpers
const flag = (a, n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };
const has = (a, n) => a.includes(n);
const out = (s) => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');
const fail = (m, code = 1) => { err(m); process.exit(code); };

// ---------------------------------------------------------------- installing into each agent
const nodeCmd = () => process.execPath;
const quote = (s) => `"${String(s).replace(/(["\\$`])/g, '\\$1')}"`;
export function hookEntries(agent, scriptPath, node) {
  if (agent === 'claude-code') {
    const h = { type: 'command', command: node, args: [scriptPath, 'hook', '--agent', 'claude-code'], timeout: 660, onFailure: 'block', statusMessage: 'Counterseal guard' };
    return { PreToolUse: [{ matcher: 'Bash', hooks: [h] }, { matcher: 'mcp__.*', hooks: [{ ...h }] }] };
  }
  if (agent === 'codex') {
    return { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `${quote(node)} ${quote(scriptPath)} hook --agent codex`, timeout: 600, statusMessage: 'Counterseal guard' }] }] };
  }
  const c = `${quote(node)} ${quote(scriptPath)} hook --agent cursor`;
  return { beforeShellExecution: [{ command: c, timeout: 660, failClosed: true }], beforeMCPExecution: [{ command: c, timeout: 660, failClosed: true }] };
}
const isOurs = (h, agent) => {
  const s = [h?.command, ...(Array.isArray(h?.args) ? h.args : [])].filter((x) => typeof x === 'string').join(' ');
  return s.includes(HOOK_MARK) && /\bhook\b/.test(s) && s.includes(`--agent ${agent}`);
};
function agentFile(agent, scope, env, cwd) {
  const home = homeDir(env);
  const base = scope === 'project' ? cwd : home;
  if (agent === 'claude-code') return join(base, '.claude', 'settings.json');
  if (agent === 'codex') return join(base, '.codex', 'hooks.json');
  return join(base, '.cursor', 'hooks.json');
}
/** add or replace our entries in a hooks file object; returns the new object */
export function mergeHooks(agent, doc, entries) {
  const next = JSON.parse(JSON.stringify(doc || {}));
  if (agent === 'cursor' && next.version === undefined) next.version = 1;
  next.hooks = next.hooks && typeof next.hooks === 'object' ? next.hooks : {};
  for (const [event, groups] of Object.entries(entries)) {
    const list = Array.isArray(next.hooks[event]) ? next.hooks[event] : [];
    const kept = agent === 'cursor'
      ? list.filter((h) => !isOurs(h, agent))
      : list.map((g) => ({ ...g, hooks: (g.hooks || []).filter((h) => !isOurs(h, agent)) })).filter((g) => (g.hooks || []).length);
    next.hooks[event] = [...kept, ...groups];
  }
  return next;
}
export function removeHooks(agent, doc) {
  const next = JSON.parse(JSON.stringify(doc || {}));
  if (!next.hooks || typeof next.hooks !== 'object') return next;
  for (const event of Object.keys(next.hooks)) {
    const list = Array.isArray(next.hooks[event]) ? next.hooks[event] : [];
    const kept = agent === 'cursor' ? list.filter((h) => !isOurs(h, agent)) : list.map((g) => ({ ...g, hooks: (g.hooks || []).filter((h) => !isOurs(h, agent)) })).filter((g) => (g.hooks || []).length);
    if (kept.length) next.hooks[event] = kept; else delete next.hooks[event];
  }
  if (!Object.keys(next.hooks).length) delete next.hooks;
  return next;
}
export function lineDiff(a, b) {
  const A = a.split('\n'), B = b.split('\n');
  const n = A.length, m = B.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const lines = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { lines.push('  ' + A[i]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) lines.push('- ' + A[i++]); else lines.push('+ ' + B[j++]);
  }
  while (i < n) lines.push('- ' + A[i++]);
  while (j < m) lines.push('+ ' + B[j++]);
  const keep = lines.map((l, k) => l[0] !== ' ' || lines.slice(Math.max(0, k - 2), k + 3).some((x) => x[0] !== ' '));
  const res = [];
  let skipped = false;
  lines.forEach((l, k) => { if (keep[k]) { res.push(l); skipped = false; } else if (!skipped) { res.push('  ...'); skipped = true; } });
  return res.join('\n');
}
function planAgent(agent, scope, env, cwd, scriptPath) {
  const file = agentFile(agent, scope, env, cwd);
  const existed = existsSync(file);
  let before = {};
  if (existed) {
    try { before = JSON.parse(readFileSync(file, 'utf8')); } catch { return { agent, file, error: `${file} is not valid JSON, so the guard will not touch it. Fix it or add the hook by hand.` }; }
    if (!before || typeof before !== 'object' || Array.isArray(before)) return { agent, file, error: `${file} is not a JSON object, so the guard will not touch it.` };
  }
  const after = mergeHooks(agent, before, hookEntries(agent, scriptPath, nodeCmd()));
  const a = existed ? JSON.stringify(before, null, 2) : '', b = JSON.stringify(after, null, 2);
  return { agent, file, existed, before, after, same: a === b, diff: existed ? lineDiff(a, b) : b.split('\n').map((l) => '+ ' + l).join('\n') };
}

function detectAgents(env) {
  const h = homeDir(env);
  return AGENTS.filter((a) => existsSync(join(h, a === 'claude-code' ? '.claude' : a === 'codex' ? '.codex' : '.cursor')));
}
/** is the Counterseal plugin switched on in Claude Code? Then its hook is already there and a second one would run twice. */
export function pluginEnabled(env) {
  const s = readJson(join(homeDir(env), '.claude', 'settings.json'));
  const e = s && typeof s === 'object' ? s.enabledPlugins : null;
  return !!e && typeof e === 'object' && Object.entries(e).some(([k, v]) => /^counterseal@/.test(k) && v === true);
}
function parseAgents(a, env) {
  const v = flag(a, '--agents');
  if (!v) return { list: detectAgents(env), detected: true };
  if (v.trim() === 'none') return { list: [], keyOnly: true };
  const list = v.split(',').map((x) => x.trim()).filter(Boolean);
  for (const x of list) {
    if (NOT_YET.includes(x)) fail(`${x} is not supported yet: its hook has not been tested with the guard. Supported: ${AGENTS.join(', ')}.`);
    if (!AGENTS.includes(x)) fail(`Unknown agent "${x}". Supported: ${AGENTS.join(', ')}.`);
  }
  return { list, detected: false };
}

async function sessionApi(env, method, path, body) {
  const p = paths(env);
  const c = readJson(p.session) || {};
  const server = String(env.LEASH_URL || c.server || 'https://counterseal.gautamkhosla.com').replace(/\/+$/, '');
  if (!c.token) return { status: 401, body: { error: 'not_signed_in', message: 'Not signed in. Run: leashcli login' } };
  if (!safeServer(server)) return { status: 0, body: { message: `will not send a sign-in to ${server}` } };
  try {
    const r = await fetch(server + path, { method, redirect: 'error', headers: { accept: 'application/json', authorization: `Bearer ${c.token}`, 'user-agent': `leash-guard/${GUARD_VERSION}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
    const j = await r.json().catch(() => ({}));
    return { status: r.status, body: j, server };
  } catch (e) { return { status: 0, body: { message: e?.message || 'network error' }, server }; }
}
async function hidden(prompt) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) { let s = ''; process.stdin.on('data', (d) => (s += d)); process.stdin.on('end', () => resolve(s.trim())); return; }
    process.stderr.write(prompt);
    process.stdin.setRawMode(true);
    let s = '';
    process.stdin.on('data', function on(ch) {
      const c = ch.toString();
      if (c === '\r' || c === '\n') { process.stdin.setRawMode(false); process.stdin.off('data', on); process.stdin.pause(); process.stderr.write('\n'); resolve(s); }
      else if (c === '\u0003') process.exit(130);
      else if (c === '\u007f') s = s.slice(0, -1);
      else s += c;
    });
  });
}

async function fetchMap(env) {
  const p = paths(env);
  const c = readJson(p.session) || {};
  const server = String(env.LEASH_URL || readJson(p.guard)?.server || c.server || 'https://counterseal.gautamkhosla.com').replace(/\/+$/, '');
  if (!safeServer(server)) return { ok: false, why: `will not fetch from ${server}` };
  try {
    const r = await fetch(server + '/v1/meta', { redirect: 'error', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return { ok: false, why: `the server answered ${r.status}` };
    const meta = await r.json();
    if (!meta || !Array.isArray(meta.providers)) return { ok: false, why: 'the server sent a map the guard does not understand' };
    const small = { mapVersion: meta.mapVersion, providers: meta.providers.map((x) => ({ id: x.id, host: x.host, irreversible: x.irreversible })) };
    writeAtomic(p.map, JSON.stringify({ fetchedAt: Date.now(), server, meta: small }, null, 2), 0o644);
    return { ok: true, version: meta.mapVersion, providers: meta.providers.length };
  } catch (e) { return { ok: false, why: e?.message || 'network error' }; }
}

const SCRIPT_FILES = ['guard.mjs', 'shellmap.mjs'];
function installScripts(env) {
  const p = paths(env);
  mkdirSync(p.scripts, { recursive: true });
  const sums = {};
  for (const f of SCRIPT_FILES) {
    const src = join(HERE, f);
    const text = readFileSync(src, 'utf8');
    writeAtomic(join(p.scripts, f), text, 0o644);
    sums[f] = sha256(text);
  }
  return sums;
}

async function install(a, env, cwd) {
  const dry = has(a, '--dry-run');
  const scope = flag(a, '--scope') || 'user';
  if (!['user', 'project'].includes(scope)) fail('--scope must be user or project');
  const parsed = parseAgents(a, env);
  const { detected, keyOnly } = parsed;
  let list = parsed.list;
  if (list.includes('claude-code') && scope === 'user' && pluginEnabled(env)) {
    list = list.filter((x) => x !== 'claude-code');
    err('The Counterseal plugin is switched on in Claude Code, so no hook was added to ~/.claude/settings.json (it would run twice, and the second run would deny a command you approved).');
  }
  if (!list.length && !keyOnly && !pluginEnabled(env)) fail('No coding agent found (looked for ~/.claude, ~/.codex and ~/.cursor). Name them: leashcli guard install --agents claude-code,codex,cursor   (or --agents none for a key only, with the Claude Code plugin)');
  const p = paths(env);
  const scriptPath = join(p.scripts, 'guard.mjs');
  const plans = list.map((ag) => planAgent(ag, scope, env, cwd, scriptPath));
  for (const pl of plans) if (pl.error) fail(pl.error);
  if (detected && list.length) err(`Agents found: ${list.join(', ')}.`);

  if (dry) {
    for (const pl of plans) out(`\n${pl.agent}: ${pl.file}${pl.same ? ' (already up to date)' : ''}\n${pl.same ? '' : pl.diff}`);
    out(`\nDry run: nothing was written, no guard key was made.${list.length ? ` The hook would run ${scriptPath} (a copy of this CLI's guard).` : ''}`);
    return;
  }
  // the key
  let key, id, label, expiresAt = null;
  if (has(a, '--paste-key')) {
    key = await hidden('Paste your guard key (lsg_..., from the app: Account, Guard keys) (hidden): ');
    if (!KEY_RE.test(key)) fail('That is not a guard key (it starts with lsg_ and is 47 characters). Nothing was changed.');
    label = flag(a, '--label') || 'pasted';
  } else {
    label = flag(a, '--label') || `guard on ${hostname() || 'this machine'}`.slice(0, 60);
    const r = await sessionApi(env, 'POST', '/v1/guard/keys', { label: label.replace(/[^A-Za-z0-9 ._:/()-]/g, '').slice(0, 60) || 'guard' });
    if (r.status === 401) fail('Not signed in. Run: leashcli login   (or make a guard key in the app, Account, Guard keys, and run: leashcli guard install --paste-key)');
    if (r.status !== 200 || !KEY_RE.test(r.body.key || '')) fail(`The server did not make a guard key (${r.status} ${r.body.error || r.body.message || ''}). Nothing was changed.`);
    ({ key, id } = { key: r.body.key, id: r.body.id });
    expiresAt = r.body.expiresAt ?? null;
  }
  const prev = readJson(p.guard);
  const hooked = list.length ? list : (prev?.agents ?? []);
  const sums = list.length ? installScripts(env) : (prev?.files ?? {});
  const server = String(env.LEASH_URL || (readJson(p.session) || {}).server || prev?.server || 'https://counterseal.gautamkhosla.com').replace(/\/+$/, '');
  const cfg = { version: 1, server, key, keyId: id ?? null, label, expiresAt, installed: new Date().toISOString(), node: nodeCmd(), files: sums, agents: hooked, keyOnly: !hooked.length, onUnavailable: prev?.onUnavailable ?? DEFAULTS.onUnavailable, waitSeconds: prev?.waitSeconds ?? DEFAULTS.waitSeconds, disableRules: prev?.disableRules ?? [], mode: prev?.mode ?? DEFAULTS.mode, unreadable: prev?.unreadable ?? DEFAULTS.unreadable, cursorPassThrough: prev?.cursorPassThrough ?? DEFAULTS.cursorPassThrough };
  writeAtomic(p.guard, JSON.stringify(cfg, null, 2) + '\n', 0o600);
  const m = await fetchMap(env);
  let revoked = null;
  if (prev?.keyId && id && prev.keyId !== id) { // the key this one replaces is no longer needed: tighten, never leave it behind
    const r = await sessionApi(env, 'DELETE', `/v1/guard/keys/${encodeURIComponent(prev.keyId)}`);
    revoked = r.status === 200 ? prev.keyId : null;
  }
  const results = [];
  for (const pl of plans) {
    if (!pl.same) {
      if (pl.existed) copyFileSync(pl.file, `${pl.file}.leash-bak-${Date.now()}`);
      writeAtomic(pl.file, JSON.stringify(pl.after, null, 2) + '\n', pl.existed ? 0o600 : 0o644);
    }
    results.push(pl);
  }
  for (const pl of results) out(`\n${pl.agent}: ${pl.file}${pl.same ? ' (already up to date)' : pl.existed ? ' (backup saved next to it)' : ' (new file)'}\n${pl.same ? '' : pl.diff}`);
  out('');
  out(`Guard key ${id ? id + ' ' : ''}("${label}") saved in ${p.guard} (mode 600). It can only ask for approval; it can never approve.`);
  if (revoked) out(`The guard key this replaces (${revoked}) was revoked.`);
  if (expiresAt) out(`This key was made by your command line sign-in and ends with it (${new Date(expiresAt).toISOString().slice(0, 16).replace('T', ' ')} UTC at the latest). For a key that lasts, make one in the app (Account, Guard keys) and run: leashcli guard install --paste-key`);
  out(m.ok ? `API map: ${m.providers} providers, version ${m.version}.` : `API map: using the bundled copy (${m.why}).`);
  out(`Shell map ${SHELL_MAP_VERSION}: ${SHELL_RULES.length} rules (leashcli guard map).`);
  if (list.includes('codex')) out('Codex: open /hooks once and trust the new hook, or Codex will skip it.');
  if (list.includes('cursor')) out('Cursor: restart Cursor if the hook does not load. The Cursor hook is not tested end to end yet.');
  out('Try it: leashcli guard check -- terraform destroy     and     leashcli guard status');
  out('A seatbelt, not a sandbox: an agent that can edit its own settings or run a script it wrote can get around it.');
}

async function uninstall(a, env, cwd) {
  const scope = flag(a, '--scope') || 'user';
  const p = paths(env);
  const list = flag(a, '--agents') ? parseAgents(a, env).list : AGENTS;
  for (const ag of list) {
    const file = agentFile(ag, scope, env, cwd);
    if (!existsSync(file)) continue;
    let doc;
    try { doc = JSON.parse(readFileSync(file, 'utf8')); } catch { err(`${file} is not valid JSON; left alone.`); continue; }
    const next = removeHooks(ag, doc);
    const was = JSON.stringify(doc, null, 2), now = JSON.stringify(next, null, 2);
    if (was === now) continue;
    copyFileSync(file, `${file}.leash-bak-${Date.now()}`);
    writeAtomic(file, now + '\n', 0o600);
    out(`${ag}: removed the guard hook from ${file}\n${lineDiff(was, now)}`);
  }
  const cfg = readJson(p.guard);
  const full = !flag(a, '--agents') || has(a, '--revoke-key'); // removing one agent's hook keeps the key the others use
  if (cfg && !full) out('The guard key was kept for the other agents (add --revoke-key to revoke it too).');
  if (!has(a, '--keep-key') && cfg && full) {
    if (cfg.keyId) {
      const r = await sessionApi(env, 'DELETE', `/v1/guard/keys/${encodeURIComponent(cfg.keyId)}`);
      out(r.status === 200 ? `Guard key ${cfg.keyId} revoked on the server.` : `Could not revoke guard key ${cfg.keyId} (${r.status} ${r.body.error || r.body.message || ''}). Revoke it in the app: Account, Guard keys.`);
    } else out('This key was pasted from the app: revoke it there if you no longer need it (Account, Guard keys).');
    try { unlinkSync(p.guard); out(`Removed ${p.guard}.`); } catch { /* already gone */ }
  }
  for (const f of SCRIPT_FILES) { try { unlinkSync(join(p.scripts, f)); } catch { /* not there */ } }
  out('Done. The hooks this command installed are gone.');
  if (pluginEnabled(env)) out('The Counterseal plugin is still switched on in Claude Code and now has no key, so it will deny commands on the map. Switch it off: claude plugin disable counterseal');
}

async function status(env, cwd) {
  const p = paths(env);
  const cfg = readJson(p.guard);
  let bad = 0;
  const line = (ok, text) => { if (!ok) bad++; out(`${ok ? 'ok     ' : 'PROBLEM'} ${text}`); };
  if (!cfg) { line(false, `no guard config at ${p.guard}. Run: leashcli guard install`); process.exitCode = 1; return; }
  const c = loadConfig(env);
  line(KEY_RE.test(cfg.key || ''), `guard key ${cfg.keyId ?? '(pasted)'} "${cfg.label ?? ''}" in ${p.guard}`);
  if (cfg.expiresAt) {
    const days = (cfg.expiresAt - Date.now()) / 86400000;
    line(days > 0, days > 0 ? `the key ends with the command line sign-in that made it, in ${days.toFixed(1)} days (${new Date(cfg.expiresAt).toISOString().slice(0, 16)} UTC). For a lasting key: make one in the app and run leashcli guard install --paste-key` : 'the key has ended. Run leashcli guard install again, or paste a lasting key from the app');
  } else out('ok      the key has no expiry');
  line(safeServer(c.server), `server ${c.server}`);
  if (pluginEnabled(env)) out('ok      the Counterseal plugin is switched on in Claude Code (its hook uses this key; its scripts are pinned inside the plugin)');
  if (!cfg.keyOnly) {
    for (const f of SCRIPT_FILES) {
      const here = join(p.scripts, f);
      if (!existsSync(here)) { line(false, `${here} is missing (run leashcli guard install)`); continue; }
      const sum = sha256(readFileSync(here, 'utf8'));
      line(sum === cfg.files?.[f], sum === cfg.files?.[f] ? `${f} is the copy that was installed` : `${f} was changed after it was installed (an agent may have edited it). Run leashcli guard install to restore it`);
    }
    if (cfg.node) line(existsSync(cfg.node), `node at ${cfg.node}${existsSync(cfg.node) ? '' : ' no longer exists (re-run leashcli guard install after upgrading Node)'}`);
  } else if (!pluginEnabled(env)) out('info    key only: no hook was installed by the CLI. Install the Claude Code plugin, or run leashcli guard install --agents claude-code');
  for (const ag of AGENTS) for (const scope of ['user', 'project']) {
    const file = agentFile(ag, scope, env, cwd);
    if (!existsSync(file)) continue;
    const doc = readJson(file);
    const found = doc && JSON.stringify(doc.hooks || {}).includes(HOOK_MARK) && JSON.stringify(doc.hooks).includes(ag);
    if (found || scope === 'user') out(`${found ? 'ok     ' : 'info   '} ${ag} (${scope}): ${found ? 'the hook is in ' + file : 'no guard hook in ' + file}`);
  }
  out(`info    fail mode: ${c.onUnavailable === 'deny' ? 'closed (commands on the map are denied when the server cannot be reached)' : 'OPEN (commands on the map run when the server cannot be reached)'}; waits up to ${c.waitSeconds} s for the passkey`);
  out(`info    shell map ${SHELL_MAP_VERSION}, ${SHELL_RULES.length} rules; API map: ${readJson(p.map)?.meta?.mapVersion ?? 'bundled copy'}`);
  try {
    const r = await fetch(c.server + '/v1/approvals/000000000000000000000000?wait=0', { headers: { authorization: `Bearer ${cfg.key}`, accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10000) });
    if (r.status === 423) out('info    the server accepts the key, but the account is FROZEN: nothing is approved until you unfreeze it with your passkey in the app');
    else line(r.status === 404, r.status === 404 ? 'the server accepts the key' : r.status === 401 ? 'the server does not accept the key (revoked, or the sign-in that made it ended). Run leashcli guard install' : `the server answered ${r.status}`);
  } catch (e) { line(false, `the server could not be reached (${e?.message || 'network'})`); }
  out('info    untested end to end: Cursor, Codex, Windows. A seatbelt, not a sandbox.');
  process.exitCode = bad ? 1 : 0;
}

function check(a, env, cwd0) {
  const dd = a.indexOf('--');
  const cmd = dd >= 0 ? a.slice(dd + 1).join(' ') : a.filter((x, i) => !x.startsWith('--') && a[i - 1] !== '--cwd').join(' ');
  if (!cmd) fail('usage: leashcli guard check [--cwd dir] [--json] -- <command>');
  const cwd = flag(a, '--cwd') || cwd0;
  const io = makeIO(env);
  const cfg = loadConfig(env, io);
  const apiMeta = io.readJson(paths(env).map)?.meta;
  const r = classify(cmd, { cwd: posixPath(cwd) ?? undefined, root: projectRoot(posixPath(cwd), io.exists) ?? undefined, home: posixPath(homeDir(env)) ?? undefined, apiMap: apiMeta ? apiMapFromMeta(apiMeta) : undefined, disable: cfg.disableRules, readFile: (f) => (/\/package\.json$/.test(f) ? io.readText(f) : null) });
  if (has(a, '--json')) out(JSON.stringify(r, null, 2));
  else if (r.hold) { for (const h of r.hits) out(`HELD  ${h.rule}\n      ${h.why}\n      ${h.text}`); out(r.unreadable ? '(the command could not be fully read; this is the plain scan)' : ''); } else out(`not on the map${r.unreadable ? ' (the command could not be read; the plain scan found nothing)' : ''}: your agent\'s own permission settings decide.`);
  process.exitCode = r.hold ? 10 : 0;
}
function showMap(a) {
  if (has(a, '--json')) return out(JSON.stringify({ version: SHELL_MAP_VERSION, rules: SHELL_RULES, toolRules: TOOL_RULES }, null, 2));
  out(`Shell map ${SHELL_MAP_VERSION}`);
  for (const r of SHELL_RULES) out(`  ${r.id.padEnd(22)} ${r.what}`);
  out('MCP tool calls');
  for (const r of TOOL_RULES) out(`  ${r.id.padEnd(22)} ${r.what}`);
}

let pipesQuiet = false;
/** `leashcli guard map | head` closes the pipe early: that is not an error, and the hook keeps its own exit code */
function quietPipes() {
  if (pipesQuiet) return;
  pipesQuiet = true;
  process.stdout.on('error', (e) => {
    if (e && e.code === 'EPIPE') process.exit(process.exitCode || 0);
    process.stderr.write(`leashcli guard: ${scrub(e?.message || e)}\n`);
    process.exit(1);
  });
}

/** the entry point: leashcli guard <command> ... */
export async function main(argv, env = process.env, cwd = process.cwd()) {
  quietPipes();
  const [sub, ...a] = argv;
  switch (sub) {
    case 'hook': {
      const agent = flag(a, '--agent');
      if (!AGENTS.includes(agent)) { err(`leashcli guard hook --agent <${AGENTS.join('|')}>`); process.exit(1); }
      const mode = flag(a, '--mode');
      const { text, over } = await readStdin(process.stdin);
      const r = await runHook({ agent, mode: mode === 'retry' || mode === 'wait' ? mode : undefined, input: text, over, env, progress: (m) => err(m) });
      if (r.stderr) process.stderr.write(r.stderr);
      if (r.stdout) process.stdout.write(r.stdout);
      process.exitCode = r.code;
      return;
    }
    case 'install': return install(a, env, cwd);
    case 'uninstall': return uninstall(a, env, cwd);
    case 'status': return status(env, cwd);
    case 'check': return check(a, env, cwd);
    case 'map': return showMap(a);
    case 'update-map': { const m = await fetchMap(env); out(m.ok ? `API map updated: ${m.providers} providers, version ${m.version}.` : `Could not update the API map: ${m.why}`); process.exitCode = m.ok ? 0 : 1; return; }
    default:
      out(`leashcli guard ${GUARD_VERSION}\n\n  install [--agents claude-code,codex,cursor|none] [--scope user|project] [--paste-key] [--label x] [--dry-run]\n           (--agents none: a key only, for the Claude Code plugin)\n  uninstall [--agents ...] [--scope ...] [--keep-key] [--revoke-key]\n  status\n  check [--cwd dir] [--json] -- <command>\n  map [--json]\n  update-map\n  hook --agent <claude-code|codex|cursor> [--mode wait|retry]   (what the agent calls)`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((e) => { process.stderr.write(`leashcli guard: ${scrub(e?.message || e)}\n`); process.exit(1); });
}
