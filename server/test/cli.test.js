// The CLI end to end against a local server: the MCP server signs every proxied call with the agent key, so a token
// bound to that key works through it; the same token without the key does not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { World } from './helpers.js';
import { handle } from '../src/index.js';
import { generateAgentKey, importAgentKey, proveAgentKey } from '../../cli/sign.mjs';

const CLI = fileURLToPath(new URL('../../cli/leash.mjs', import.meta.url));

/** serve a World over real HTTP on 127.0.0.1, as the published CLI would see it */
async function serve(w) {
  const srv = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const h = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') h.set(k, v);
    h.set('cf-connecting-ip', '127.0.0.1');
    const pending = [];
    const r = await handle(new Request(w.base + req.url, { method: req.method, headers: h, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), w.env, { fetcher: w.fetcher, log: w.log, ctx: { waitUntil: (p) => pending.push(p) } });
    await Promise.allSettled(pending);
    res.writeHead(r.status, Object.fromEntries(r.headers)); res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return srv;
}

function mcpCall(env, calls) {
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [CLI, 'mcp'], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; let buf = '';
    p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { out.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); if (out.length === calls.length) p.kill(); } });
    p.on('exit', () => done(out.sort((a, b) => a.id - b.id))); // the MCP server answers calls as they finish p.on('error', fail);
    for (const c of calls) p.stdin.write(JSON.stringify(c) + '\n');
    setTimeout(() => p.kill(), 15000);
  });
}

test('MCP server: requests are signed with LEASH_AGENT_KEY, so a bound token works; without the key it is refused', async () => {
  const w = new World();
  const srv = await serve(w);
  w.base = `http://127.0.0.1:${srv.address().port}`;
  const dir = mkdtempSync(join(tmpdir(), 'cli-'));
  try {
    const u = await w.user();
    const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'C'.repeat(36) } })).body.id;
    const jwk = await generateAgentKey(); const key = await importAgentKey(jwk);
    const b = (await w.req('POST', '/v1/agent-keys/begin', { cookie: u.cookie, body: { publicKey: jwk.x } })).body;
    const ak = (await w.req('POST', '/v1/agent-keys', { cookie: u.cookie, body: { publicKey: jwk.x, challengeId: b.challengeId, proof: await proveAgentKey(key, b.sign) } })).body;
    const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, agentKeyId: ak.id } })).body.token;
    const keyFile = join(dir, 'agent-key.json');
    writeFileSync(keyFile, JSON.stringify(jwk));
    const call = (id, method, path, body) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'leash_request', arguments: { provider: 'github', method, path, ...(body ? { body } : {}) } } });
    const env = { LEASH_URL: w.base, LEASH_TOKENS: `github=${tok}` };
    const signed = await mcpCall({ ...env, LEASH_AGENT_KEY: keyFile }, [call(1, 'GET', '/repos/acme/app'), call(2, 'POST', '/repos/acme/app/issues', { title: 'from mcp' }), call(3, 'DELETE', '/repos/acme/app')]);
    assert.match(signed[0].result.content[0].text, /^HTTP 200/);
    assert.match(signed[1].result.content[0].text, /^HTTP 200/);
    assert.match(signed[2].result.content[0].text, /^HTTP 428[\s\S]*held_for_approval/, 'held, with a signed request');
    assert.equal(w.upstream.length, 2);
    assert.equal(w.upstream.find((x) => x.method === 'POST').body, '{"title":"from mcp"}');
    const unsigned = await mcpCall(env, [call(4, 'GET', '/repos/acme/app')]);
    assert.match(unsigned[0].result.content[0].text, /^HTTP 401[\s\S]*agent_signature_required/);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});
