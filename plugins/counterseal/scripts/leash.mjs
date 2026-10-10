#!/usr/bin/env node
// leash: CLI and MCP server for Counterseal. Zero dependencies, Node 20+.
//   leash login                      sign in this machine (approve with your passkey in the browser)
//   leash add <provider> [label] [--host store.myshopify.com]  store a real key in the vault (read from stdin, never echoed,
//                                    never saved here); --host is the store address, for Shopify only
//   leash creds | tokens | holds     list
//   leash token <credentialId> [--label x] [--policy file.json] [--ttl hours] [--agent-key <id>]
//   leash agent-key [file] [--label x]  make an Ed25519 agent key (private key stays in the file) and register it
//   leash agent-keys                 list agent keys
//   leash freeze                     stop every agent token on the account at once (unfreezing needs your passkey, in the app)
//   leash watch                      print new holds with their approve links as they happen
//   leash mcp                        MCP server over stdio; set LEASH_TOKENS="github=lsh_...,railway=lsh_..."
//                                    and, for tokens bound to an agent key, LEASH_AGENT_KEY=<path to the key file>
//   leash guard install | uninstall | status | check | map | hook   hold a coding agent's irreversible shell commands
//                                    until you approve them with a passkey (see guard.mjs)
//   leash mcp wrap --name <id> -- <command> [args...]   put a local MCP server behind Counterseal: destructive tool calls wait
//                                    for your passkey, and a tool definition that changes after you pinned it is held
//   leash mcp pin|unpin|status --name <id>              pin what the server shows now, forget the pin, show it (see mcp-wrap.mjs)
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { signBrokerRequest, generateAgentKey, importAgentKey, keyid, proveAgentKey } from './sign.mjs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const VERSION = '0.4.0';
// the npm package that runs this CLI (published as counterseal; leashcli is the old name, a thin alias that runs this one)
const PKG = 'counterseal';
const CFG_DIR = join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'leash');
const CFG = join(CFG_DIR, 'config.json');
const cfg = () => (existsSync(CFG) ? JSON.parse(readFileSync(CFG, 'utf8')) : {});
const die = (m, code = 1) => { process.stderr.write(m + '\n'); process.exit(code); };
/** a server address the session token may be sent to: https, or http only to this machine (local development) */
const safeUrl = (u) => {
  let x; try { x = new URL(u); } catch { return false; }
  if (x.username || x.password || x.search || x.hash) return false;
  return x.protocol === 'https:' || (x.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname));
};
/** s without its trailing slashes, in linear time (a /\/+$/ regex backtracks quadratically on many slashes) */
const noTrailingSlash = (s) => { let i = s.length; while (i > 0 && s.charCodeAt(i - 1) === 47) i--; return s.slice(0, i); };
const server = () => {
  const s = noTrailingSlash(String(process.env.LEASH_URL || cfg().server || 'https://counterseal.gautamkhosla.com'));
  if (!safeUrl(s)) die(`Refusing to talk to ${s}: the server must be an https address (http only for localhost).`);
  return s;
};

function save(c) {
  mkdirSync(CFG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CFG, JSON.stringify(c, null, 2), { mode: 0o600 });
  try { chmodSync(CFG, 0o600); } catch {}
}

async function api(method, path, body, auth = true) {
  const headers = { accept: 'application/json', 'user-agent': `leash-cli/${VERSION}` };
  if (auth) {
    const c = cfg(), t = c.token;
    if (!t) die('Not signed in. Run: leash login');
    // the session is sent only to the server that made it (a changed --server or LEASH_URL never receives it)
    if (c.tokenServer && c.tokenServer !== server()) die(`This command line is signed in to ${c.tokenServer}, not ${server()}. Run: leash login`);
    headers.authorization = `Bearer ${t}`;
  }
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await fetch(server() + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.message || j.error || `HTTP ${r.status}`); e.code = j.error; e.status = r.status; throw e; }
  return j;
}

function hidden(prompt) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) { let s = ''; process.stdin.on('data', (d) => (s += d)); process.stdin.on('end', () => resolve(s.trim())); return; }
    process.stderr.write(prompt);
    const rl = createInterface({ input: process.stdin, output: null, terminal: true });
    process.stdin.setRawMode(true);
    let s = '';
    process.stdin.on('data', function on(ch) {
      const c = ch.toString();
      if (c === '\r' || c === '\n') { process.stdin.setRawMode(false); process.stdin.off('data', on); rl.close(); process.stderr.write('\n'); resolve(s); }
      else if (c === '\u0003') process.exit(130);
      else if (c === '\u007f') s = s.slice(0, -1);
      else s += c;
    });
  });
}

const flag = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const table = (rows, cols) => { for (const r of rows) console.log(cols.map((c) => String(r[c] ?? '')).join('  ')); };

/** a form body the way Stripe reads it: name=value pairs in the order given, an object one level down as name[key], a list
 * as name[0]. Names are plain words (nothing that could be read as two parameters), values are strings, numbers or booleans. */
const NAME = /^[A-Za-z0-9_.-]{1,64}$/;
function formEncode(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw new Error('form must be an object of fields.');
  const p = new URLSearchParams();
  const put = (k, v) => {
    if (v === null || v === undefined) return;
    if (!['string', 'number', 'boolean'].includes(typeof v) || (typeof v === 'number' && !Number.isFinite(v))) throw new Error(`form field ${k} must be a string, number or boolean.`);
    p.append(k, String(v));
  };
  for (const [k, v] of Object.entries(o)) {
    if (!NAME.test(k)) throw new Error(`form field name ${JSON.stringify(k.slice(0, 40))} is not a plain word.`);
    if (v && typeof v === 'object') {
      for (const [k2, v2] of Object.entries(v)) {
        if (!NAME.test(k2)) throw new Error(`form field name ${JSON.stringify(k2.slice(0, 40))} is not a plain word.`);
        put(`${k}[${k2}]`, v2);
      }
    } else put(k, v);
  }
  return p.toString();
}

// ---------------------------------------------------------------- MCP (JSON-RPC 2.0 over stdio, newline-delimited)
function mcp() {
  const tokens = Object.fromEntries((process.env.LEASH_TOKENS || '').split(',').map((s) => s.trim().split('=')).filter((p) => p.length === 2 && /^lsh_/.test(p[1])));
  // an agent key, if set, signs every request (needed for tokens bound to it; harmless for others)
  let signer = null;
  if (process.env.LEASH_AGENT_KEY) {
    const jwk = JSON.parse(readFileSync(process.env.LEASH_AGENT_KEY, 'utf8'));
    signer = (async () => ({ key: await importAgentKey(jwk), kid: await keyid(jwk.x) }))();
  }
  const providers = Object.keys(tokens);
  const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
  const tools = [{
    name: 'leash_request',
    description: 'Call a cloud API (' + (providers.join(', ') || 'none configured') + ') through the broker. You never hold the real key. Irreversible operations (deleting data, force pushes, moving money, destructive SQL) are HELD for human approval: if the result says held_for_approval, stop, tell the human the approve_url, and after they approve, retry the exact same call once. Do not try another route around a hold. If the result says account_frozen, your human has stopped every agent: stop, tell them, and do not retry. A hold whose rule starts with brake. means a limit was reached: the same, stop and ask your human.',
    inputSchema: {
      type: 'object', additionalProperties: false, required: ['provider', 'method', 'path'],
      properties: {
        provider: { type: 'string', enum: providers.length ? providers : ['none'] },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        path: { type: 'string', description: 'API path, e.g. /repos/acme/app/issues (GitHub), /zones (Cloudflare, without /client/v4)' },
        query: { type: 'object', additionalProperties: { type: 'string' } },
        body: { description: 'JSON body for POST/PUT/PATCH' },
        form: { type: 'object', description: 'Form fields for POST/PUT/PATCH to an API that takes a form, not JSON (Stripe). Use this or body, not both. Values are strings, numbers or booleans; an object one level down is sent as name[key], a list as name[0], name[1].' },
      },
    },
  }];
  const rl = createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    let msg; try { msg = JSON.parse(line); } catch { return; }
    const { id, method, params } = msg;
    if (id === undefined) return; // notification
    try {
      if (method === 'initialize') return send({ jsonrpc: '2.0', id, result: { protocolVersion: params?.protocolVersion || '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'leash', version: VERSION } } });
      if (method === 'ping') return send({ jsonrpc: '2.0', id, result: {} });
      if (method === 'tools/list') return send({ jsonrpc: '2.0', id, result: { tools } });
      if (method === 'tools/call') {
        const a = params?.arguments || {};
        if (params?.name !== 'leash_request') throw Object.assign(new Error('unknown tool'), { rpc: -32602 });
        const tok = tokens[a.provider];
        if (!tok) return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: `No proxy token configured for ${a.provider} (set LEASH_TOKENS).` }] } });
        if (typeof a.path !== 'string' || !a.path.startsWith('/') || a.path.length > 2000) return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'path must start with /' }] } });
        const qs = a.query && typeof a.query === 'object' ? '?' + new URLSearchParams(a.query).toString() : '';
        const url = new URL(`${server()}/p/${a.provider}${a.path}${qs}`).href;
        if (a.body !== undefined && a.form !== undefined) return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'Send body (JSON) or form, not both.' }] } });
        let form;
        if (a.form !== undefined) { try { form = formEncode(a.form); } catch (e) { return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: e.message }] } }); } }
        const body = a.method === 'GET' ? undefined : form !== undefined ? form : a.body !== undefined ? JSON.stringify(a.body) : undefined;
        const ctype = form !== undefined ? 'application/x-www-form-urlencoded' : a.body !== undefined ? 'application/json' : undefined;
        const headers = { authorization: `Bearer ${tok}`, accept: 'application/json', ...(ctype ? { 'content-type': ctype } : {}) };
        if (signer) Object.assign(headers, await signBrokerRequest({ method: a.method, url, body, contentType: headers['content-type'] }, await signer));
        const r = await fetch(url, { method: a.method, redirect: 'error', headers, body });
        let text = await r.text();
        if (text.length > 20000) text = text.slice(0, 20000) + '\n[truncated]';
        return send({ jsonrpc: '2.0', id, result: { isError: r.status >= 400, content: [{ type: 'text', text: `HTTP ${r.status}\n${text}` }] } });
      }
      throw Object.assign(new Error('method not found'), { rpc: -32601 });
    } catch (e) {
      send({ jsonrpc: '2.0', id, error: { code: e.rpc || -32603, message: e.message } });
    }
  });
}

// ---------------------------------------------------------------- commands
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'login': {
      // another server: the old session is dropped, never sent there
      const s = flag(args, '--server');
      if (s) {
        const to = noTrailingSlash(String(s));
        if (!safeUrl(to)) die(`Refusing ${to}: the server must be an https address (http only for localhost).`);
        const c = cfg();
        save(c.server === to ? c : { server: to });
      }
      const d = await api('POST', '/v1/device/start', {}, false);
      // the code is typed in the browser, never sent as a link: nobody else should ever see it or ask you for it
      process.stderr.write(`\nTo sign in this computer:\n  1. Open ${d.verification_uri} in your browser and sign in.\n  2. Type this code: ${d.user_code}\n  3. Check where the sign-in started, then approve with your passkey.\n\nThe code works once, for ${Math.round(d.expires_in / 60)} minutes. Never send it to anyone, and never type a code\nsomeone sent you: whoever approves a code gives that command line their account.\n\n`);
      const until = Date.now() + d.expires_in * 1000;
      let interval = d.interval;
      while (Date.now() < until) {
        await new Promise((r) => setTimeout(r, interval * 1000));
        try {
          const t = await api('POST', '/v1/device/poll', { device_code: d.device_code }, false);
          save({ ...cfg(), token: t.access_token, tokenServer: server() });
          // say whose account this is, so a code approved by someone else (their account, not yours) is noticed at once
          const me = await api('GET', '/v1/me').catch(() => null);
          console.log(`Signed in${me?.account?.name ? ` to the account of ${me.account.name}` : ''}, for ${Math.round(t.expires_in / 86400)} days.${me?.account?.name ? ' If that is not your account, run leash logout now.' : ''}`);
          process.exit(0);
        } catch (e) {
          if (e.code === 'slow_down') { interval += 5; continue; } // RFC 8628 section 3.5
          if (e.code === 'access_denied') die('The sign-in was denied in the browser. Nothing was signed in.');
          if (e.code === 'expired_token') die('The code expired or was used. Run leash login again.');
          if (e.code !== 'authorization_pending') throw e;
        }
      }
      die('The code expired. Run leash login again.');
      break;
    }
    case 'logout': {
      // end the session on the server too, not only on this machine
      if (cfg().token) await api('POST', '/v1/auth/logout', {}).catch(() => {});
      save({ server: cfg().server }); console.log('Signed out on this machine.'); break;
    }
    case 'add': {
      const provider = args[0]; if (!provider) die('usage: leash add <github|cloudflare|railway|stripe|supabase|vercel|neon|fly|resend|shopify> [label] [--host your-store.myshopify.com] (--host is for Shopify only)');
      const host = flag(args, '--host');
      const label = args.slice(1).find((x, i, a) => !x.startsWith('--') && a[i - 1] !== '--host');
      const secret = await hidden(`Paste your ${provider} key (hidden): `);
      const r = await api('POST', '/v1/credentials', { provider, label, secret, ...(host ? { host } : {}) });
      console.log(`Stored ${r.provider} key ...${r.hint}${r.host ? ` for ${r.host}` : ''} as ${r.id}. It is encrypted in the vault; nothing was saved on this machine.`);
      break;
    }
    case 'creds': table((await api('GET', '/v1/credentials')).credentials, ['id', 'provider', 'label', 'hint', 'host']); break;
    case 'tokens': table((await api('GET', '/v1/tokens')).tokens.filter((t) => !t.revoked), ['id', 'provider', 'label', 'minted_by']); break;
    case 'token': {
      const p = flag(args, '--policy');
      const ak = flag(args, '--agent-key');
      let credentialId = args[0] && !args[0].startsWith('--') ? args[0] : null;
      if (!credentialId) {
        const cs = (await api('GET', '/v1/credentials')).credentials;
        if (cs.length !== 1) die(cs.length ? `Which key? You have ${cs.length}: run "leash creds" and then "leash token <id>".` : 'Your vault is empty. Add a key first: leash add github');
        credentialId = cs[0].id;
        process.stderr.write(`Using your only key: ${cs[0].label} (${cs[0].provider}).\n`);
      }
      const r = await api('POST', '/v1/tokens', { credentialId, label: flag(args, '--label'), ttlHours: flag(args, '--ttl') ? Number(flag(args, '--ttl')) : undefined, policy: p ? JSON.parse(readFileSync(p, 'utf8')) : undefined, agentKeyId: ak });
      const env = { LEASH_TOKENS: `${r.provider}=${r.token}`, ...(ak ? { LEASH_AGENT_KEY: '<path to your agent key file>' } : {}) };
      console.log(`${r.token}\n\nBase URL: ${r.baseUrl}\nExpires:  ${new Date(r.expiresAt).toISOString()}${r.agentKey ? `\nBound to agent key ${r.agentKey}: every request must be signed with it.` : ''}\n${r.note}\n\nMCP server config for your agent:
${JSON.stringify({ mcpServers: { leash: { command: 'npx', args: ['-y', PKG, 'mcp'], env } } }, null, 2)}`);
      break;
    }
    case 'revoke': await api('DELETE', `/v1/tokens/${args[0]}`); console.log('Revoked.'); break;
    case 'freeze': {
      // stopping is always safe, so any signed-in session can do it; only a passkey in the app can undo it
      const r = await api('POST', '/v1/me/freeze', {});
      console.log(`${r.already ? 'Already frozen' : 'Frozen'}: every agent token on this account is stopped (HTTP 423) until you unfreeze it with your passkey at ${server()}/app. This command line cannot unfreeze.`);
      break;
    }
    case 'holds': table((await api('GET', '/v1/holds')).holds, ['id', 'method', 'host', 'path', 'rule']); break;
    case 'watch': {
      const seen = new Set();
      process.stderr.write('Watching for held requests. Ctrl+C to stop.\n');
      for (;;) {
        // a coding agent's command or tool call (kind shell or tool) reads "RUN claude-code: <summary>"
        for (const h of (await api('GET', '/v1/holds')).holds) if (!seen.has(h.id)) { seen.add(h.id); console.log(`\nHELD  ${h.method} ${h.host}${h.kind && h.kind !== 'proxy' ? ': ' : ''}${h.path}\n      ${h.why}\n      approve: ${server()}/app#hold=${h.id}`); process.stdout.write('\u0007'); }
        await new Promise((r) => setTimeout(r, 4000));
      }
    }
    case 'agent-key': {
      const file = args.find((x, i) => !x.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--'))) || 'agent-key.json';
      const jwk = await generateAgentKey();
      // 'wx': created only if absent, in one step (no check-then-write race that could overwrite a key)
      try { writeFileSync(file, JSON.stringify(jwk, null, 2), { mode: 0o600, flag: 'wx' }); } catch (e) { die(e?.code === 'EEXIST' ? `${file} exists; refusing to overwrite a key.` : `cannot write ${file}: ${e?.message}`); }
      try { chmodSync(file, 0o600); } catch {}
      const b = await api('POST', '/v1/agent-keys/begin', { publicKey: jwk.x });
      process.stderr.write(`Registering Ed25519 public key ${jwk.x}\nwith account ${b.account} on ${b.origin}.\n`);
      const r = await api('POST', '/v1/agent-keys', { label: flag(args, '--label'), publicKey: jwk.x, challengeId: b.challengeId, proof: await proveAgentKey(await importAgentKey(jwk), b.sign) });
      console.log(`Agent key ${r.id} registered (keyid ${r.keyid}).\nPrivate key: ${file} (mode 600; keep it on the agent's machine, never commit it).\nBind a token to it: leash token <credentialId> --agent-key ${r.id}\nThen run the MCP server with LEASH_AGENT_KEY=${file}`);
      break;
    }
    case 'agent-keys': table((await api('GET', '/v1/agent-keys')).agentKeys.filter((k) => !k.revoked_at), ['id', 'label', 'keyid', 'tokens']); break;
    case 'mcp': if (['wrap', 'pin', 'unpin', 'status'].includes(args[0])) await (await import('./mcp-wrap.mjs')).main(args); else mcp(); break;
    case 'guard': await (await import('./guard.mjs')).main(args); break;
    case '--version': case '-v': console.log(VERSION); break;
    default:
      console.log('leash ' + VERSION + '\n\n  login | logout | add <provider> [label] [--host store] | creds | tokens | token [credentialId] [--label] [--policy file] [--ttl h] [--agent-key id] | revoke <id> | freeze | holds | watch | agent-key [file] [--label] | agent-keys | mcp | mcp wrap|pin|unpin|status --name <id> | guard install|uninstall|status|check|map');
  }
} catch (e) {
  die(`leash: ${e.message}`);
}
