// The dashboard's side of the Deploy Gate: the page's own code (site/public/app/app.js) run against a small fake DOM and
// the answers the real Worker gives, so a deploy hold card, the gates list and the new-gate form are exercised, not just
// grepped. Everything the page shows is set as text (Trusted Types forbids innerHTML), and a link is only followed if it is
// a plain github.com address.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { world, gateId, ask, approve, makeGate, db } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });

// ---------------------------------------------------------------- a fake DOM, just enough for app.js
class Txt { constructor(t) { this.text = String(t); } get textContent() { return this.text; } }
class El {
  constructor(tag, id) { this.tag = tag; this.id = id; this.children = []; this.options = [{ value: '' }]; this.dataset = {}; this.attrs = {}; this._text = ''; this.hidden = false; this.value = ''; this.checked = false; this.disabled = false; this.title = ''; this.listeners = {}; const on = new Set(); this.classList = { toggle: (c, f) => ((f ?? !on.has(c)) ? on.add(c) : on.delete(c)), add: (c) => on.add(c), contains: (c) => on.has(c) }; }
  append(...kids) { for (const k of kids) this.children.push(typeof k === 'string' ? new Txt(k) : k); }
  replaceChildren(...kids) { this.children = []; this.append(...kids); }
  get childElementCount() { return this.children.filter((c) => c instanceof El).length; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  setAttribute(n, v) { this.attrs[n] = String(v); }
  focus() {} scrollIntoView() {} setSelectionRange() {} remove() {} click() { return this.onclick && this.onclick({ preventDefault() {} }); }
  all(test, out = []) { for (const c of this.children) if (c instanceof El) { if (test(c)) out.push(c); c.all(test, out); } return out; }
  querySelectorAll(sel) { return sel === 'input' ? this.all((c) => c.tag === 'input') : []; }
  querySelector() { return null; }
}

/** run app.js: routes maps "METHOD /path" to a function (body, init) returning [status, json] */
async function page(routes, { hash = '' } = {}) {
  const els = new Map(), created = [], calls = [], toasts = [];
  const NAV = ['holds', 'vault', 'tokens', 'gates', 'agentkeys', 'receipts', 'audit', 'account'].map((v) => { const a = new El('a'); a.dataset.view = v; return a; });
  const VIEWS = NAV.map((a) => { const s = new El('section'); s.dataset.view = a.dataset.view; return s; });
  const byId = (id) => { if (!els.has(id)) els.set(id, new El(id === 'toast' ? 'div' : 'div', id)); return els.get(id); };
  const document = {
    hidden: false, addEventListener() {},
    getElementById: byId, createElement: (t) => { created.push(t); return new El(t); }, createTextNode: (t) => new Txt(t), activeElement: null, body: new El('body'),
    querySelectorAll: (sel) => (sel === '#snav a' ? NAV : sel === '.view' ? VIEWS : []),
  };
  const fetch = async (path, init = {}) => {
    const method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body });
    const r = routes[`${method} ${path}`] || routes[`${method} *`];
    if (!r) return { ok: false, status: 404, json: async () => ({ error: 'not_found' }) };
    const [status, json] = await r(body, init);
    return { ok: status < 400, status, json: async () => json };
  };
  const ctx = vm.createContext({
    document, fetch, window: { addEventListener() {}, scrollTo() {}, trustedTypes: undefined }, location: { hash, origin: 'https://leash.test', assign() {}, replace() {}, reload() {} }, history: { replaceState() {} },
    navigator: { credentials: { get: async () => ({ id: 'cred', response: { authenticatorData: new ArrayBuffer(4), clientDataJSON: new ArrayBuffer(4), signature: new ArrayBuffer(4) } }) }, clipboard: { writeText: async (t) => { ctx.copied = t; } } },
    confirm: () => true, setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {}, Intl, URL, Blob, btoa, atob, Uint8Array, ArrayBuffer, Promise, JSON, Object, Array, String, Number, Date, Math, Set, Map, console, Error, SyntaxError, encodeURIComponent,
  });
  const src = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8').replace(/^import .*$/m, 'const BRAND = { name: "Counterseal" };');
  vm.runInContext(src, ctx, { filename: 'app.js' });
  const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
  await settle();
  const toast = () => byId('toast').textContent;
  return { byId, calls, created, NAV, VIEWS, settle, toast, ctx, go: async (view) => { NAV.find((a) => a.dataset.view === view).click(); await settle(); } };
}

/** what the Worker answers the dashboard with (so the page is fed real output, not a guess at it) */
async function fixtures({ summary = 'deploy a1b2c3d to production', claims = {} } = {}) {
  const { w, gh } = await world();
  const u = await w.user('Ada');
  const g = await gateId(w, u, { environments: ['production'] });
  const r = await ask(w, gh, g, claims, { summary });
  const get = async (p) => (await w.req('GET', p, { cookie: u.cookie })).body;
  return { w, gh, u, g, r, holds: await get('/v1/holds'), gates: await get('/v1/gates'), me: await get('/v1/me') };
}
const baseRoutes = (f, over = {}) => ({
  'GET /v1/me': async () => [200, f.me], 'GET /v1/meta': async () => [200, { providers: [], app: 'https://leash.test', legacyApp: null }], 'GET /v1/credentials': async () => [200, { credentials: [{ id: 'c'.repeat(24), provider: 'github', label: 'deploy key', hint: 'DDDD', created_at: 1 }] }],
  'GET /v1/tokens': async () => [200, { tokens: [] }], 'GET /v1/holds': async () => [200, f.holds], 'GET /v1/audit': async () => [200, { entries: [] }], 'GET /v1/agent-keys': async () => [200, { agentKeys: [] }],
  'GET /v1/push/key': async () => [200, { enabled: false }], 'GET /v1/gates': async () => [200, f.gates], ...over,
});

test('a deploy hold card shows what GitHub signed, the links, and the workflow\'s own text apart under "Not verified"', async () => {
  const f = await fixtures();
  const p = await page(baseRoutes(f));
  const card = p.byId('holds').children[0];
  assert.ok(card, 'one card');
  const text = card.textContent;
  for (const s of ['Held', 'Deploy', 'prod deploy', 'github-actions', 'wants to deploy', 'Signed by GitHub', 'First run of this gate. Approving also binds it to acme/app (GitHub id 1001)', 'acme/app', '(private)', 'a1b2c3d', 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', 'refs/heads/main',
    'acme/app/.github/workflows/deploy.yml@refs/heads/main', 'production', 'octocat', '(push)', '#812, attempt 1', 'github-hosted', 'Not verified', 'Text from the workflow: deploy a1b2c3d to production', 'Approve with passkey', 'Deny', 'Deny with a reason', 'Rule gate.bind']) assert.ok(text.includes(s), `the card has "${s}"`);
  // no raw block of text for a deploy; the two links are plain github.com addresses opened safely
  assert.equal(card.all((c) => c.tag === 'pre').length, 0);
  const links = card.all((c) => c.tag === 'a');
  assert.deepEqual(links.map((a) => a.href), ['https://github.com/acme/app/commit/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', 'https://github.com/acme/app/actions/runs/812/attempts/1']);
  for (const a of links) { assert.equal(a.rel, 'noopener noreferrer'); assert.equal(a.target, '_blank'); }
  // the signed table comes before the unverified line, and the unverified text is not in the table
  assert.ok(text.indexOf('Signed by GitHub') < text.indexOf('Repository') && text.indexOf('Repository') < text.indexOf('Not verified'));
  const dl = card.all((c) => c.tag === 'dl')[0];
  assert.ok(!dl.textContent.includes('deploy a1b2c3d to production'));
  // the placeholder for a reason says where it goes
  const input = card.all((c) => c.tag === 'input')[0];
  assert.match(input.placeholder, /shown in the job log/);
});

test('nothing the workflow sent can become markup or a link: text only, and a link that is not github.com is not followed', async () => {
  const f = await fixtures({ summary: '<img src=x onerror=alert(1)> <a href="https://evil.example">click</a>' });
  // the answer carries a link that is not github.com (a hostile or buggy server): the page shows it as plain text
  const holds = JSON.parse(JSON.stringify(f.holds));
  holds.holds[0].context.gate.commit_url = 'javascript:alert(1)';
  holds.holds[0].context.gate.run_url = 'https://evil.example/actions/runs/1';
  holds.holds[0].context.gate.actor = '<script>alert(1)</script>';
  const p = await page(baseRoutes(f, { 'GET /v1/holds': async () => [200, holds] }));
  const card = p.byId('holds').children[0];
  assert.deepEqual(card.all((c) => c.tag === 'a'), [], 'no link survives');
  assert.ok(card.textContent.includes('<script>alert(1)</script>'), 'the actor is shown as text');
  assert.ok(card.textContent.includes('<img src=x onerror=alert(1)>'), 'so is the workflow\'s own text');
  for (const tag of ['img', 'script', 'iframe']) assert.ok(!p.created.includes(tag), tag + ' was never created');
  const src = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8');
  assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(/.test(src));
});

test('while the account is frozen the Approve button of a deploy card is off; a card without facts (dropped a day after it closed) falls back to the text', async () => {
  const f = await fixtures();
  const frozen = JSON.parse(JSON.stringify(f.me)); frozen.account.frozen_at = Date.now();
  const p = await page(baseRoutes(f, { 'GET /v1/me': async () => [200, frozen] }));
  const buttons = p.byId('holds').children[0].all((c) => c.tag === 'button');
  assert.equal(buttons.find((b) => b.textContent === 'Approve with passkey').disabled, true);
  assert.equal(buttons.find((b) => b.textContent === 'Deny').disabled, false);
  const gone = JSON.parse(JSON.stringify(f.holds)); gone.holds[0].context = null;
  const q = await page(baseRoutes(f, { 'GET /v1/holds': async () => [200, gone] }));
  const card = q.byId('holds').children[0];
  assert.equal(card.all((c) => c.tag === 'pre').length, 1, 'the preview text is shown instead');
  assert.match(card.textContent, /Commit: a1b2c3d4e5f60718293a4b5c6d7e8f9012345678/);
});

test('approving a deploy card runs the passkey ceremony on the hold and says the job can go on, once', async () => {
  const f = await fixtures();
  const id = f.r.body.id;
  const p = await page(baseRoutes(f, {
    [`POST /v1/holds/${id}/approve/begin`]: async () => [200, { challengeId: 'aa', options: { challenge: 'AAAA', rpId: 'leash.test' } }],
    [`POST /v1/holds/${id}/approve/finish`]: async () => [200, { ok: true, approved: true, seals: 1, needs: 1 }],
  }));
  const ok = p.byId('holds').children[0].all((c) => c.tag === 'button').find((b) => b.textContent === 'Approve with passkey');
  ok.click(); await p.settle();
  assert.deepEqual(p.calls.filter((c) => c.path.includes('/approve/')).map((c) => `${c.method} ${c.path}`), [`POST /v1/holds/${id}/approve/begin`, `POST /v1/holds/${id}/approve/finish`]);
  assert.equal(p.toast(), 'Approved. The job can go on, once, within 10 minutes.');
  // deny with a reason goes to the same route as every other hold
  const p2 = await page(baseRoutes(f, { [`POST /v1/holds/${id}/deny`]: async () => [200, { ok: true }] }));
  const card = p2.byId('holds').children[0];
  card.all((c) => c.tag === 'input')[0].value = 'Not on a Friday';
  card.all((c) => c.tag === 'button').find((b) => b.textContent === 'Deny with this reason').click(); await p2.settle();
  assert.deepEqual(p2.calls.find((c) => c.path.endsWith('/deny')).body, { reason: 'Not on a Friday' });
  assert.equal(p2.toast(), 'Denied. The job log shows your reason.');
});

test('the Deploy gates view lists what each gate accepts, its binding, and offers the step to paste and revoke', async () => {
  const f = await fixtures();
  // bind it, so both states are on screen
  await approve(f.w, f.u, f.r.body.id);
  await (await import('./gate-helpers.js')).poll(f.w, f.r.body.poll, f.r.body.id);
  const gates = (await f.w.req('GET', '/v1/gates', { cookie: f.u.cookie })).body;
  const second = await makeGate(f.w, f.u, { label: 'staging', repository: 'acme/web', workflows: ['.github/workflows/stage.yml'], refs: ['refs/heads/release/*'], publishRepo: true });
  assert.equal(second.status, 200);
  const both = (await f.w.req('GET', '/v1/gates', { cookie: f.u.cookie })).body;
  const p = await page(baseRoutes(f, { 'GET /v1/gates': async () => [200, both], [`DELETE /v1/gates/${f.g}`]: async () => [200, { ok: true, closed: 0, tokens: 0 }] }));
  await p.go('gates');
  assert.ok(p.VIEWS.find((s) => s.dataset.view === 'gates').hidden === false && p.VIEWS.find((s) => s.dataset.view === 'holds').hidden === true);
  const rows = p.byId('gates').children;
  assert.equal(rows.length, 2);
  const t0 = rows.map((r) => r.textContent).find((t) => t.includes('prod deploy'));
  const t1 = rows.map((r) => r.textContent).find((t) => t.includes('staging'));
  for (const s of ['Bound to the repository', 'Repository acme/app (GitHub id 1001', 'Workflows: .github/workflows/deploy.yml', 'Branches and tags: refs/heads/main', 'Environments: production', 'Triggers: push, workflow_dispatch, release, deployment, merge_group', 'Public receipts: DEPLOY, the decision and the rule; never the repository', f.g, 'Revoke', 'Copy step']) assert.ok(t0.includes(s), `the first gate shows "${s}"`);
  for (const s of ['Binds on its first approved run', 'Repository acme/web', 'Environments: any, or none', 'Public receipts name this repository', 'never passed']) assert.ok(t1.includes(s), `the second gate shows "${s}"`);
  // copy the step
  const prod = rows.find((r) => r.textContent.includes('prod deploy'));
  prod.all((c) => c.tag === 'button').find((b) => b.textContent === 'Copy step').click(); await p.settle();
  const step = p.ctx.copied;
  assert.match(step, /permissions:\n  id-token: write/); assert.ok(step.includes(`      gate: ${f.g}\n`)); assert.match(step, /uses: \.\/\.github\/actions\/counterseal-gate/);
  assert.match(step, /environment: production/);
  assert.ok(step.includes('${{ github.sha }}'), 'a literal expression for the workflow, not interpolated by the page');
  // a gate without environments does not tell the job to use one
  rows.find((r) => r.textContent.includes('staging')).all((c) => c.tag === 'button').find((b) => b.textContent === 'Copy step').click(); await p.settle();
  assert.ok(!/environment:/.test(p.ctx.copied));
  // revoke
  rows.find((r) => r.textContent.includes('prod deploy')).all((c) => c.tag === 'button').find((b) => b.textContent === 'Revoke').click(); await p.settle();
  assert.ok(p.calls.some((c) => c.method === 'DELETE' && c.path === `/v1/gates/${f.g}`));
  assert.match(p.toast(), /^Revoked\./);
  void gates;
});

test('the new-gate form sends what was typed through the passkey ceremony, leaves out what was not asked for, and shows the step to paste', async () => {
  const f = await fixtures();
  let made = null;
  const p = await page(baseRoutes(f, {
    'POST /v1/gates/passkey/begin': async () => [200, { challengeId: 'aa', options: { challenge: 'AAAA', rpId: 'leash.test' } }],
    'POST /v1/gates/passkey/finish': async (body) => { made = body; return [200, { id: 'gate_' + 'a'.repeat(24), label: body.label, repository: body.repository, workflows: body.workflows, refs: body.refs, environments: body.environments || null, events: body.events, credential: null }]; },
  }));
  await p.go('gates');
  const set = (id, v) => { p.byId(id).value = v; };
  set('gtLabel', ' web deploy '); set('gtRepo', 'acme/web'); set('gtWorkflows', '.github/workflows/deploy.yml\n\n  .github/workflows/release.yml  \n'); set('gtRefs', 'refs/heads/main\nrefs/tags/v*');
  p.byId('gtNew').click(); await p.settle();
  assert.equal(made.label, 'web deploy'); assert.equal(made.repository, 'acme/web');
  assert.deepEqual(made.workflows, ['.github/workflows/deploy.yml', '.github/workflows/release.yml']); assert.deepEqual(made.refs, ['refs/heads/main', 'refs/tags/v*']);
  assert.deepEqual(made.events, ['push', 'workflow_dispatch', 'release', 'deployment', 'merge_group'], 'the defaults, and pull requests are not a choice');
  for (const k of ['environments', 'publishRepo', 'credentialId', 'policy']) assert.ok(!(k in made), k + ' was not asked for');
  assert.ok(made.challengeId && made.credential, 'the passkey ceremony went with it');
  assert.equal(p.byId('newGate').hidden, false);
  assert.match(p.byId('newGateSnippet').textContent, /gate: gate_a{24}/);
  p.byId('newGateCopy').click(); await p.settle();
  assert.match(p.ctx.copied, /gate: gate_a{24}/);
  // environments, the public-name box, a key and a policy
  made = null;
  set('gtEnvs', 'production\nstaging'); p.byId('gtPublish').checked = true; set('gtCred', 'c'.repeat(24)); set('gtPolicy', '{"allow":[{"method":"GET","path":"/repos/acme/**"}]}');
  p.byId('gtEvents').all((c) => c.tag === 'input' && c.value === 'schedule')[0].checked = true;
  p.byId('gtNew').click(); await p.settle();
  assert.deepEqual(made.environments, ['production', 'staging']); assert.equal(made.publishRepo, true); assert.equal(made.credentialId, 'c'.repeat(24)); assert.deepEqual(made.policy, { allow: [{ method: 'GET', path: '/repos/acme/**' }] });
  assert.ok(made.events.includes('schedule'));
  // a policy with no key is refused by the page; a policy that is not JSON too; nothing is sent
  const before = p.calls.length;
  set('gtCred', ''); p.byId('gtNew').click(); await p.settle();
  assert.match(p.toast(), /A policy is for the key a gate hands out/);
  set('gtCred', 'c'.repeat(24)); set('gtPolicy', '{not json'); p.byId('gtNew').click(); await p.settle();
  assert.equal(p.toast(), 'The policy is not valid JSON.');
  assert.equal(p.calls.length, before, 'nothing was sent');
  // the server's refusal is shown as it is
  const q = await page(baseRoutes(f, {
    'POST /v1/gates/passkey/begin': async () => [200, { challengeId: 'aa', options: { challenge: 'AAAA', rpId: 'leash.test' } }],
    'POST /v1/gates/passkey/finish': async () => [400, { error: 'bad_workflows', message: 'workflows needs at least 1.' }],
  }));
  await q.go('gates');
  q.byId('gtNew').click(); await q.settle();
  assert.equal(q.toast(), 'workflows needs at least 1.');
  void db;
});

test('the page and its styles name the gate\'s parts: the nav entry, the form fields, the badge, no dash in the words', () => {
  const html = readFileSync(new URL('../../site/public/app/index.html', import.meta.url), 'utf8');
  for (const id of ['gates', 'noGates', 'gtLabel', 'gtRepo', 'gtWorkflows', 'gtRefs', 'gtEnvs', 'gtEvents', 'gtPublish', 'gtCred', 'gtPolicy', 'gtNew', 'newGate', 'newGateSnippet', 'newGateCopy']) assert.ok(html.includes(`id="${id}"`), id);
  assert.match(html, /<a href="#" data-view="gates">[^<]*<span[^>]*><\/span>Deploy gates<\/a>/);
  assert.match(html, /<section class="view" data-view="gates" hidden>/);
  assert.ok(!new RegExp('[' + String.fromCharCode(0x2013, 0x2014) + ']').test(html), 'no en or em dash in the page');
  assert.match(readFileSync(new URL('../../site/public/styles.css', import.meta.url), 'utf8'), /\.badge\.ok\{/);
  const sw = readFileSync(new URL('../../site/public/sw.js', import.meta.url), 'utf8');
  assert.match(sw, /h\.kind === 'deploy' \? `\$\{who\} wants to deploy`/);
});
