// `<command> --help` (or -h) prints help and exits 0 without reading the network, signing in, freezing, writing a key
// file or touching an agent's settings. Each run is signed in (a session in the config) and points at a local server
// that records every request, so a command that did its real work would be seen. The CLI and the plugin's pinned copy
// are both run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLIS = ['../leash.mjs', '../../plugins/counterseal/scripts/leash.mjs'].map((p) => fileURLToPath(new URL(p, import.meta.url)));
const seen = [];
let srv, base;
before(async () => {
  srv = http.createServer((req, res) => { seen.push(`${req.method} ${req.url}`); res.writeHead(500, { 'content-type': 'application/json' }); res.end('{"error":"the test server answers nothing"}'); });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  base = `http://127.0.0.1:${srv.address().port}`;
});
after(() => srv.close());

/** every file under dir with its bytes, to compare before and after */
function snapshot(dir) {
  const out = {};
  const walk = (d) => { for (const n of readdirSync(d)) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else out[p] = readFileSync(p, 'utf8'); } };
  walk(dir);
  return out;
}

function run(cli, args) {
  const home = mkdtempSync(join(tmpdir(), 'cs-help-'));
  const cfgDir = join(home, 'config'), cwd = join(home, 'work');
  mkdirSync(join(cfgDir, 'leash'), { recursive: true }); mkdirSync(cwd);
  writeFileSync(join(cfgDir, 'leash', 'config.json'), JSON.stringify({ server: base, token: 'lsc_' + 'A'.repeat(43), tokenServer: base }));
  // a guard config with a key, so guard install, status and update-map would reach the server if they ran
  mkdirSync(join(cfgDir, 'counterseal'), { recursive: true });
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: cfgDir, LEASH_URL: base, COUNTERSEAL_URL: base, LEASH_TOKENS: 'github=lsh_' + 'B'.repeat(43) };
  const was = snapshot(home);
  const before = seen.length;
  return new Promise((done) => {
    const p = spawn(process.execPath, [cli, ...args], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => (stdout += d)); p.stderr.on('data', (d) => (stderr += d));
    p.stdin.end();
    const timer = setTimeout(() => p.kill('SIGKILL'), 15_000);
    p.on('exit', (code, signal) => {
      clearTimeout(timer);
      // let a request that was in flight reach the server before counting
      setTimeout(() => {
        const files = snapshot(home);
        rmSync(home, { recursive: true, force: true });
        done({ code, signal, stdout, stderr, requests: seen.slice(before), changed: JSON.stringify(files) !== JSON.stringify(was) });
      }, 200);
    });
  });
}

const CASES = [
  ['login', '--help'], ['login', '-h'], ['login', '--server', 'https://example.com', '--help'],
  ['logout', '--help'], ['add', 'github', '--help'], ['add', '-h'], ['creds', '--help'], ['tokens', '-h'],
  ['token', '--help'], ['token', 'cred_1', '--label', 'x', '-h'], ['revoke', 'tok_1', '--help'],
  ['freeze', '--help'], ['freeze', '-h'], ['holds', '--help'], ['watch', '--help'],
  ['agent-key', '--help'], ['agent-key', 'k.json', '-h'], ['agent-keys', '--help'], ['mcp', '--help'], ['mcp', '-h'],
  ['mcp', 'wrap', '--help'], ['mcp', 'wrap', '--name', 'gh', '-h', '--', 'node', 'server.js'], ['mcp', 'pin', '--name', 'gh', '--help'],
  ['mcp', 'unpin', '--name', 'gh', '--help'], ['mcp', 'status', '--name', 'gh', '--check', '--help'],
  ['guard', 'install', '--help'], ['guard', 'install', '--agents', 'claude-code', '-h'], ['guard', 'uninstall', '--help'],
  ['guard', 'status', '--help'], ['guard', 'check', '--help'], ['guard', 'map', '-h'], ['guard', 'update-map', '--help'],
];

for (const cli of CLIS) {
  const which = cli.includes('plugins') ? 'plugin copy' : 'cli';
  test(`${which}: <command> --help prints help, exits 0, sends nothing and writes nothing`, async () => {
    // the plugin ships the CLI, the guard and the signer, not the MCP wrapper (plugins/counterseal/scripts)
    const wrapper = (args) => args[0] === 'mcp' && ['wrap', 'pin', 'unpin', 'status'].includes(args[1]);
    for (const args of CASES.filter((x) => which === 'cli' || !wrapper(x))) {
      const r = await run(cli, args);
      const name = args.join(' ');
      assert.equal(r.code, 0, `${name}: exit ${r.code} ${r.signal || ''} ${r.stderr}`);
      assert.deepEqual(r.requests, [], `${name}: no request may reach the server`);
      assert.equal(r.changed, false, `${name}: no file may be written or changed`);
      const want = args[0] === 'guard' ? /^counterseal guard \d/ : args[0] === 'mcp' && args.length > 1 && args[1] !== '--help' && args[1] !== '-h' ? /^usage:\n {2}counterseal mcp wrap/ : new RegExp(`^counterseal ${args[0]}\\b`);
      assert.match(r.stdout, want, `${name}: help on stdout`);
      assert.doesNotMatch(r.stdout + r.stderr, /Type this code|Frozen|Registering|Signed out|Stored/, `${name}: the command itself did not run`);
    }
  });

  test(`${which}: a --help after "--" belongs to the other program, not to Counterseal`, async () => {
    const r = await run(cli, ['guard', 'check', '--', 'terraform', 'destroy', '--help']);
    assert.equal(r.code, 10, r.stderr);
    assert.match(r.stdout, /^HELD {2}sh\.terraform-destroy/);
    assert.deepEqual(r.requests, []);
  });

  test(`${which}: an unknown command with --help is still an unknown command`, async () => {
    const r = await run(cli, ['frezee', '--help']);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /^counterseal: unknown command "frezee"/);
    assert.deepEqual(r.requests, []);
  });

  test(`${which}: without --help the same setup does reach the server (the trap works)`, async () => {
    const r = await run(cli, ['freeze']);
    assert.notEqual(r.code, 0);
    assert.deepEqual(r.requests, ['POST /v1/me/freeze']);
    assert.match(r.stderr, /^counterseal: /, 'errors start with counterseal:');
  });
}
