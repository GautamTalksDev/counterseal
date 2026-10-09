#!/usr/bin/env node
// leash: CLI and MCP server for LEASH. Zero dependencies, Node 20+.
//   leash login                      sign in this machine (approve with your passkey in the browser)
//   leash add <provider> [label]     store a real key in the vault (read from stdin, never echoed, never saved here)
//   leash creds | tokens | holds     list
//   leash token <credentialId> [--label x] [--policy file.json] [--ttl hours]
//   leash watch                      print new holds with their approve links as they happen
//   leash mcp                        MCP server over stdio; set LEASH_TOKENS="github=lsh_...,railway=lsh_..."
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const VERSION = '0.1.1';
const CFG_DIR = join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'leash');
const CFG = join(CFG_DIR, 'config.json');
const cfg = () => (existsSync(CFG) ? JSON.parse(readFileSync(CFG, 'utf8')) : {});
const server = () => (process.env.LEASH_URL || cfg().server || 'https://leash.gautamkhosla.com').replace(/\/+$/, '');
const die = (m, code = 1) => { process.stderr.write(m + '\n'); process.exit(code); };

function save(c) {
  mkdirSync(CFG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CFG, JSON.stringify(c, null, 2), { mode: 0o600 });
  try { chmodSync(CFG, 0o600); } catch {}
}

async function api(method, path, body, auth = true) {
  const headers = { accept: 'application/json', 'user-agent': `leash-cli/${VERSION}` };
  if (auth) { const t = cfg().token; if (!t) die('Not signed in. Run: leash login'); headers.authorization = `Bearer ${t}`; }
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

// ---------------------------------------------------------------- MCP (JSON-RPC 2.0 over stdio, newline-delimited)
function mcp() {
  const tokens = Object.fromEntries((process.env.LEASH_TOKENS || '').split(',').map((s) => s.trim().split('=')).filter((p) => p.length === 2 && /^lsh_/.test(p[1])));
  const providers = Object.keys(tokens);
  const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
  const tools = [{
    name: 'leash_request',
    description: 'Call a cloud API (' + (providers.join(', ') || 'none configured') + ') through LEASH. You never hold the real key. Irreversible operations (deleting data, force pushes, moving money, destructive SQL) are HELD for human approval: if the result says held_for_approval, stop, tell the human the approve_url, and after they approve, retry the exact same call once. Do not try another route around a hold.',
    inputSchema: {
      type: 'object', additionalProperties: false, required: ['provider', 'method', 'path'],
      properties: {
        provider: { type: 'string', enum: providers.length ? providers : ['none'] },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        path: { type: 'string', description: 'API path, e.g. /repos/acme/app/issues (GitHub), /zones (Cloudflare, without /client/v4)' },
        query: { type: 'object', additionalProperties: { type: 'string' } },
        body: { description: 'JSON body for POST/PUT/PATCH' },
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
        if (!tok) return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: `No LEASH token configured for ${a.provider}.` }] } });
        if (typeof a.path !== 'string' || !a.path.startsWith('/') || a.path.length > 2000) return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'path must start with /' }] } });
        const qs = a.query && typeof a.query === 'object' ? '?' + new URLSearchParams(a.query).toString() : '';
        const r = await fetch(`${server()}/p/${a.provider}${a.path}${qs}`, {
          method: a.method, redirect: 'error',
          headers: { authorization: `Bearer ${tok}`, accept: 'application/json', ...(a.body !== undefined ? { 'content-type': 'application/json' } : {}) },
          body: a.body !== undefined && a.method !== 'GET' ? JSON.stringify(a.body) : undefined,
        });
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
      const s = flag(args, '--server'); if (s) save({ ...cfg(), server: s.replace(/\/+$/, '') });
      const d = await api('POST', '/v1/device/start', {}, false);
      process.stderr.write(`\nOpen ${d.verification_uri}\nand confirm the code ${d.user_code} with your passkey.\n\n`);
      const until = Date.now() + d.expires_in * 1000;
      while (Date.now() < until) {
        await new Promise((r) => setTimeout(r, d.interval * 1000));
        try { const t = await api('POST', '/v1/device/poll', { device_code: d.device_code }, false); save({ ...cfg(), token: t.access_token }); console.log('Signed in.'); process.exit(0); }
        catch (e) { if (e.code !== 'authorization_pending') throw e; }
      }
      die('The code expired. Run leash login again.');
      break;
    }
    case 'logout': save({ server: cfg().server }); console.log('Signed out on this machine.'); break;
    case 'add': {
      const provider = args[0]; if (!provider) die('usage: leash add <github|cloudflare|railway|stripe|supabase> [label]');
      const secret = await hidden(`Paste your ${provider} key (hidden): `);
      const r = await api('POST', '/v1/credentials', { provider, label: args[1], secret });
      console.log(`Stored ${r.provider} key ...${r.hint} as ${r.id}. It is encrypted in the vault; nothing was saved on this machine.`);
      break;
    }
    case 'creds': table((await api('GET', '/v1/credentials')).credentials, ['id', 'provider', 'label', 'hint']); break;
    case 'tokens': table((await api('GET', '/v1/tokens')).tokens.filter((t) => !t.revoked), ['id', 'provider', 'label', 'minted_by']); break;
    case 'token': {
      const p = flag(args, '--policy');
      const r = await api('POST', '/v1/tokens', { credentialId: args[0], label: flag(args, '--label'), ttlHours: flag(args, '--ttl') ? Number(flag(args, '--ttl')) : undefined, policy: p ? JSON.parse(readFileSync(p, 'utf8')) : undefined });
      console.log(`${r.token}\n\nBase URL: ${r.baseUrl}\nExpires:  ${new Date(r.expiresAt).toISOString()}\n${r.note}\n\nMCP server config for your agent:
${JSON.stringify({ mcpServers: { leash: { command: 'npx', args: ['-y', 'leashcli', 'mcp'], env: { LEASH_TOKENS: `${r.provider}=${r.token}` } } } }, null, 2)}`);
      break;
    }
    case 'revoke': await api('DELETE', `/v1/tokens/${args[0]}`); console.log('Revoked.'); break;
    case 'holds': table((await api('GET', '/v1/holds')).holds, ['id', 'method', 'host', 'path', 'rule']); break;
    case 'watch': {
      const seen = new Set();
      process.stderr.write('Watching for held requests. Ctrl+C to stop.\n');
      for (;;) {
        for (const h of (await api('GET', '/v1/holds')).holds) if (!seen.has(h.id)) { seen.add(h.id); console.log(`\nHELD  ${h.method} ${h.host}${h.path}\n      ${h.why}\n      approve: ${server()}/app#hold=${h.id}`); process.stdout.write('\u0007'); }
        await new Promise((r) => setTimeout(r, 4000));
      }
    }
    case 'mcp': mcp(); break;
    case '--version': case '-v': console.log(VERSION); break;
    default:
      console.log('leash ' + VERSION + '\n\n  login | logout | add <provider> [label] | creds | tokens | token <credentialId> [--label] [--policy file] [--ttl h] | revoke <id> | holds | watch | mcp');
  }
} catch (e) {
  die(`leash: ${e.message}`);
}
