// The Claude Code plugin and marketplace files: shape, consistency with the installer, a self-contained hook, and
// `claude plugin validate --strict` when the Claude Code CLI is available (set CLAUDE_BIN, or have `claude` on PATH).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, existsSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PLUGIN = join(ROOT, 'plugins', 'counterseal');
const rj = (p) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'));

test('plugin.json follows the Claude Code plugin format', () => {
  const m = rj('plugins/counterseal/.claude-plugin/plugin.json');
  assert.equal(m.name, 'counterseal');
  assert.match(m.name, /^[a-z0-9]+(-[a-z0-9]+)*$/, 'kebab case');
  assert.ok(!/^(claude|anthropic|anthropics|cc-plugin)-/.test(m.name) && !/claude|anthropic/.test(m.name), 'not a reserved name');
  assert.match(m.version, /^\d+\.\d+\.\d+$/);
  assert.ok(m.description.length > 40 && m.author?.name && m.homepage && m.repository && m.license === 'Apache-2.0');
  assert.deepEqual(Object.keys(m.userConfig), ['tokens']);
  assert.deepEqual(m.userConfig.tokens, { ...m.userConfig.tokens, type: 'string', sensitive: true, required: false });
  assert.ok(m.userConfig.tokens.title && m.userConfig.tokens.description, 'title and description are required by the format');
  for (const dir of ['hooks', 'skills']) assert.ok(existsSync(join(PLUGIN, dir)));
  assert.ok(!existsSync(join(PLUGIN, '.claude-plugin', 'hooks')), 'only the manifest lives in .claude-plugin');
});

test('hooks.json: PreToolUse on Bash and on MCP tools, exec form, pinned copy (no npx), long timeout, fail closed', () => {
  const h = rj('plugins/counterseal/hooks/hooks.json');
  assert.ok(h.description);
  const groups = h.hooks.PreToolUse;
  assert.deepEqual(groups.map((g) => g.matcher), ['Bash', 'mcp__.*']);
  for (const g of groups) {
    assert.equal(g.hooks.length, 1);
    const x = g.hooks[0];
    assert.equal(x.type, 'command');
    assert.equal(x.command, 'node');
    assert.deepEqual(x.args, ['${CLAUDE_PLUGIN_ROOT}/scripts/guard.mjs', 'hook', '--agent', 'claude-code']);
    assert.equal(x.timeout, 660, 'longer than the 540 second wait for the passkey');
    assert.equal(x.onFailure, 'block');
  }
  assert.ok(!JSON.stringify(h).includes('npx'), 'no npx at hook time');
  assert.deepEqual(Object.keys(h.hooks), ['PreToolUse']);
});

test('the plugin hook and the hook that `guard install` writes are the same hook (only the program and path differ)', async () => {
  const { hookEntries } = await import('../guard.mjs');
  const plugin = rj('plugins/counterseal/hooks/hooks.json').hooks.PreToolUse;
  assert.deepEqual(hookEntries('claude-code', '${CLAUDE_PLUGIN_ROOT}/scripts/guard.mjs', 'node').PreToolUse, plugin);
});

test('the MCP file uses only a declared user option and holds no secret', () => {
  const t = readFileSync(join(PLUGIN, '.mcp.json'), 'utf8');
  const m = JSON.parse(t);
  assert.deepEqual(Object.keys(m.mcpServers), ['counterseal']);
  assert.equal(m.mcpServers.counterseal.command, 'node');
  assert.deepEqual(m.mcpServers.counterseal.args, ['${CLAUDE_PLUGIN_ROOT}/scripts/leash.mjs', 'mcp']);
  assert.deepEqual(m.mcpServers.counterseal.env, { LEASH_TOKENS: '${user_config.tokens}' });
  assert.ok(!/lsh_|lsg_|lsc_/.test(t));
});

test('the skill has a name and a description and no dash characters', () => {
  const t = readFileSync(join(PLUGIN, 'skills', 'counterseal', 'SKILL.md'), 'utf8');
  const fm = /^---\nname: ([a-z0-9-]+)\ndescription: ([^\n]+)\n---\n/.exec(t);
  assert.ok(fm, 'frontmatter');
  assert.equal(fm[1], 'counterseal');
  assert.ok(fm[2].length > 50 && fm[2].length <= 1024);
  assert.ok(!/[\u2013\u2014]/.test(t));
  for (const needle of ['Counterseal held this command', 'exactly the same command', 'seatbelt, not a sandbox']) assert.ok(t.includes(needle), needle);
});

test('marketplace.json: a name Claude Code accepts, an owner, one plugin whose source exists and whose name matches the manifest', () => {
  const m = rj('.claude-plugin/marketplace.json');
  assert.match(m.name, /^[A-Za-z0-9][A-Za-z0-9._-]*$/);
  assert.ok(!['claude-plugins-official', 'anthropic-marketplace', 'claude-code-plugins', 'inline', 'builtin', 'synced', 'skills-dir', 'npm', 'pip', 'uv', 'cargo', 'github', 'gh'].includes(m.name));
  assert.ok(!/^claudeai-/.test(m.name) && !/claude|anthropic/i.test(m.name));
  assert.ok(m.owner?.name);
  assert.equal(m.plugins.length, 1);
  const p = m.plugins[0];
  assert.equal(p.name, rj('plugins/counterseal/.claude-plugin/plugin.json').name);
  assert.match(p.source, /^\.\/[a-z0-9/_-]+$/);
  assert.ok(!p.source.includes('..'));
  assert.ok(existsSync(join(ROOT, p.source, '.claude-plugin', 'plugin.json')));
  assert.equal(p.version, undefined, 'the version lives in plugin.json only');
  assert.ok(p.description.length > 40);
  assert.ok(!/[\u2013\u2014]/.test(JSON.stringify(m)));
});

test('the plugin folder is self-contained: the hook runs from a copy with nothing else around it', async () => {
  const copy = mkdtempSync(join(tmpdir(), 'plugin-'));
  const home = mkdtempSync(join(tmpdir(), 'home-'));
  try {
    const { cpSync } = await import('node:fs');
    cpSync(PLUGIN, copy, { recursive: true });
    const run = (input) => new Promise((done) => {
      const p = spawn('node', [join(copy, 'scripts', 'guard.mjs'), 'hook', '--agent', 'claude-code'], { env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, '.config') } });
      let out = '', err = '';
      p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
      p.on('close', (code) => done({ code, out, err }));
      p.stdin.end(input);
    });
    const call = (command) => JSON.stringify({ session_id: 's', cwd: home, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
    const ok = await run(call('ls'));
    assert.deepEqual([ok.code, ok.out, ok.err], [0, '', '']);
    const held = await run(call('terraform destroy'));
    assert.equal(held.code, 0);
    assert.match(JSON.parse(held.out).hookSpecificOutput.permissionDecisionReason, /has no key.*(?:leashcli|counterseal) guard install/, 'without a key, a command on the map is denied with the fix');
    // the MCP script is the existing one and starts
    const mcp = spawnSync('node', [join(copy, 'scripts', 'leash.mjs'), '--version'], { encoding: 'utf8' });
    assert.match(mcp.stdout, /^\d+\.\d+\.\d+/);
  } finally { rmSync(copy, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); }
});

test('claude plugin validate --strict passes (needs the Claude Code CLI: CLAUDE_BIN or claude on PATH)', (t) => {
  const bin = process.env.CLAUDE_BIN || 'claude';
  const probe = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) return t.skip('the Claude Code CLI is not available here');
  for (const target of [PLUGIN, ROOT]) {
    const r = spawnSync(bin, ['plugin', 'validate', target, '--strict'], { encoding: 'utf8' });
    assert.equal(r.status, 0, `${target}: ${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /Validation passed/);
  }
});
