import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../leash.mjs', import.meta.url));

async function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'token-flags-'));
  const requests = [];
  const srv = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    requests.push({ method: req.method, path: req.url, body: chunks.length ? JSON.parse(Buffer.concat(chunks)) : undefined });
    const body = req.url === '/v1/credentials'
      ? { credentials: [{ id: 'credential-1', label: 'test', provider: 'github' }] }
      : { token: 'lsh_test', provider: 'github', baseUrl: 'http://localhost/p/github', expiresAt: Date.now() + 3600000, note: 'test token' };
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
  });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${srv.address().port}`;
  mkdirSync(join(dir, 'leash'));
  writeFileSync(join(dir, 'leash', 'config.json'), JSON.stringify({ token: 'lsc_test', tokenServer: url }));
  t.after(async () => { await new Promise((resolve) => srv.close(resolve)); rmSync(dir, { recursive: true, force: true }); });
  const run = (args) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'token', ...args], {
      env: { ...process.env, XDG_CONFIG_HOME: dir, LEASH_URL: url }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  return { dir, requests, run };
}

test('token refuses invalid values before requesting credentials or minting a token', async (t) => {
  const { dir, requests, run } = await setup(t);
  const invalidPolicy = join(dir, 'invalid.json');
  const missingPolicy = join(dir, 'missing.json');
  writeFileSync(invalidPolicy, '{not json}');
  const cases = [
    ...['abc', 'NaN', 'Infinity', '0', '-1'].map((value) => ({ args: ['--ttl', value], error: /--ttl.*positive.*hours/ })),
    ...['--label', '--policy', '--ttl', '--agent-key'].flatMap((flag) => [
      { args: [flag], error: new RegExp(`${flag}.*value`) },
      { args: [flag, '--label', 'test'], error: new RegExp(`${flag}.*value`) },
    ]),
    { args: ['--policy', missingPolicy], error: /--policy.*cannot read/, file: missingPolicy },
    { args: ['--policy', invalidPolicy], error: /--policy.*not valid JSON/, file: invalidPolicy },
  ];
  for (const { args, error, file } of cases) {
    for (const prefix of [[], ['credential-1']]) {
      await t.test(JSON.stringify([...prefix, ...args]), async () => {
        const result = await run([...prefix, ...args]);
        assert.notEqual(result.code, 0);
        assert.match(result.stderr, error);
        if (file) assert.ok(result.stderr.includes(JSON.stringify(file)));
        assert.equal(result.stdout, '');
        assert.deepEqual(requests, [], 'invalid input must not make even a credential lookup');
      });
    }
  }
});

test('token preserves valid flag values and default values in the server request', async (t) => {
  const { dir, requests, run } = await setup(t);
  const policyFile = join(dir, 'policy.json');
  const policy = { allow: [{ method: 'GET', path: '/repos/*' }] };
  writeFileSync(policyFile, JSON.stringify(policy));
  const explicit = await run(['credential-1', '--label', 'test token', '--ttl', '0.5', '--policy', policyFile, '--agent-key', 'key-1']);
  assert.equal(explicit.code, 0, explicit.stderr);
  assert.deepEqual(requests, [{ method: 'POST', path: '/v1/tokens', body: { credentialId: 'credential-1', label: 'test token', ttlHours: 0.5, policy, agentKeyId: 'key-1' } }]);
  requests.length = 0;
  const defaults = await run([]);
  assert.equal(defaults.code, 0, defaults.stderr);
  assert.deepEqual(requests, [
    { method: 'GET', path: '/v1/credentials', body: undefined },
    { method: 'POST', path: '/v1/tokens', body: { credentialId: 'credential-1' } },
  ]);
});
