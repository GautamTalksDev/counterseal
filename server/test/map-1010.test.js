// Map 2026-10-10.1: Vercel, Neon, Fly.io, Resend and Shopify (and the per-store host Shopify needs, migration 0010).
// Every rule has a positive case, a negative case (reads and ordinary writes pass), and the parser-differential patterns the
// first five providers were hardened with on 9 Oct: case, trailing slash, format suffix, encoded letters, method override,
// repeated and escaped keys, query-string and form copies, non-UTF-8 bodies. Rule sources: see the comments in src/providers.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { World } from './helpers.js';
import * as M from '../src/providers.js';
import { canonPath } from '../src/broker.js';

const rule = (prov, m, p, b = '', q = '') => M.irreversibleRule(prov, m, p, b, q)?.id;
const J = JSON.stringify;
const P = { origin: null, xleash: false };
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const ROOT = new URL('../../', import.meta.url);
const read = (f) => readFileSync(new URL(f, ROOT), 'utf8');

/** the same call written the ways a server may read as one call: as is, upper case, a trailing slash, an unreserved letter
 *  percent-encoded (all through the broker's own canonPath), and with a format suffix (the map tries that itself) */
function variants(path) {
  const v = [path, path.toUpperCase(), path + '/'];
  const i = path.search(/[a-z]/);
  if (i >= 0) v.push(path.slice(0, i) + '%' + path.charCodeAt(i).toString(16) + path.slice(i + 1));
  return [...v.map(canonPath), path + '.json'];
}
/** every row [method, path, expected rule id, body, query] is held with that id, in every variant of its path */
function held(prov, rows) {
  for (const [m, path, id, b = '', q = ''] of rows) for (const p of variants(path)) assert.equal(rule(prov, m, p, b, q), id, `${prov} ${m} ${p} ${q}`);
}
/** every row [method, path, body, query] passes */
function passes(prov, rows) {
  for (const [m, path, b = '', q = ''] of rows) for (const p of variants(path)) assert.equal(rule(prov, m, p, b, q), undefined, `${prov} ${m} ${p} ${q}`);
}

const PROVIDER_NAMES = 'GitHub, Cloudflare, Railway, Stripe, Supabase, Vercel, Neon, Fly.io, Resend and Shopify';
const CLAIM = `The irreversible map covers 10 APIs: ${PROVIDER_NAMES}.`;
const CAVEAT = 'management APIs only; SQL sent straight over a database connection string never passes through Counterseal.';

// ---------------------------------------------------------------- the map as a whole
test('the map covers exactly these ten APIs, every one holds every DELETE, every glob compiles, and every why is plain text', () => {
  assert.equal(M.MAP_VERSION, '2026-10-10.1');
  const ids = Object.keys(M.PROVIDERS);
  assert.deepEqual(ids, ['github', 'cloudflare', 'railway', 'stripe', 'supabase', 'vercel', 'neon', 'fly', 'resend', 'shopify']);
  const names = Object.values(M.PROVIDERS).map((p) => p.name);
  assert.equal(names.length, 10);
  assert.equal(names.slice(0, -1).join(', ') + ' and ' + names.at(-1), PROVIDER_NAMES, 'the claim is built from the code, not typed twice');
  const seen = new Set();
  for (const [id, p] of Object.entries(M.PROVIDERS)) {
    assert.ok(p.irreversible.length >= 3, id);
    for (const r of p.irreversible) {
      assert.ok(!seen.has(r.id), 'rule id is unique: ' + r.id); seen.add(r.id);
      assert.doesNotThrow(() => M.globToRe(r.p), `${id} ${r.id} glob`);
      assert.ok(r.m.split(',').every((x) => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(x)), r.id);
      assert.ok(r.why && r.why.length < 420 && (!['vercel', 'neon', 'fly', 'resend', 'shopify'].includes(id) || r.why.length > 40), r.id + ' has a reason');
      assert.ok(!/[\u2013\u2014]|--/.test(r.why), r.id + ': no em or en dashes, no double hyphen');
    }
    // "every DELETE is held on every provider" (Shopify's path allow list refuses other paths before the map is asked)
    assert.ok(rule(id, 'DELETE', '/anything/at/all'), id + ' holds every DELETE');
    assert.ok(rule(id, 'DELETE', '/Anything.json'), id);
  }
  for (const id of ['vercel', 'neon', 'fly', 'resend', 'shopify']) assert.ok(M.PROVIDERS[id].irreversible.every((r) => r.id.length < 40), id);
});

test('/v1/meta lists all ten providers with the new map version, and site/public/data/meta.json is exactly that', async () => {
  const w = new World();
  const meta = (await w.req('GET', '/v1/meta', { ...P })).body;
  assert.equal(meta.mapVersion, '2026-10-10.1');
  assert.equal(meta.providers.length, 10);
  assert.deepEqual(meta.providers.map((p) => p.id), Object.keys(M.PROVIDERS));
  const shop = meta.providers.find((p) => p.id === 'shopify');
  assert.deepEqual(shop.perCredentialHost, { suffix: '.myshopify.com', label: 'Store address', example: 'your-store.myshopify.com' });
  assert.match(shop.note, /Admin GraphQL API only/);
  assert.equal(meta.providers.find((p) => p.id === 'vercel').perCredentialHost, undefined);
  const { app, ...rest } = meta;
  assert.deepEqual(JSON.parse(read('site/public/data/meta.json')), rest, 'regenerate: node scripts/gen-meta.mjs');
  assert.equal(read('site/public/data/meta.json'), J(M.metaOf()), 'byte for byte what scripts/gen-meta.mjs writes');
});

test('the public copy makes the claim exactly, with the caveat next to it, and says 10 only because the code has 10', () => {
  for (const f of ['README.md', 'site/public/index.html']) {
    const t = read(f).replace(/\s+/g, ' ');
    const at = t.indexOf(CLAIM);
    assert.ok(at >= 0, f + ' has the claim');
    assert.ok(t.slice(at, at + CLAIM.length + 260).toLowerCase().includes(CAVEAT.toLowerCase()), f + ' has the caveat next to the claim');
  }
});

// ---------------------------------------------------------------- Vercel
test('Vercel: every irreversible endpoint is held, in every spelling; reads and ordinary writes pass', () => {
  held('vercel', [
    ['DELETE', '/v9/projects/prj_1', 'vc.delete'], ['DELETE', '/v13/deployments/dpl_1', 'vc.delete'], ['DELETE', '/v6/domains/example.com', 'vc.delete'],
    ['DELETE', '/v2/aliases/als_1', 'vc.delete'], ['DELETE', '/v9/projects/prj_1/env/env_1', 'vc.delete'], ['DELETE', '/v1/teams/team_1', 'vc.delete'],
    ['DELETE', '/v1/user', 'vc.delete'], ['DELETE', '/v8/artifacts', 'vc.delete'], ['DELETE', '/storage/stores/blob/store_1', 'vc.delete'],
    ['POST', '/v13/deployments', 'vc.deploy', J({ name: 'app', target: 'production' })], ['POST', '/v13/deployments', 'vc.deploy', J({ name: 'app' })],
    ['POST', '/deployments', 'vc.deploy', J({ name: 'app' })], // no version segment
    ['POST', '/v10/projects/prj_1/promote/dpl_1', 'vc.production'], ['POST', '/v1/projects/prj_1/rollback/dpl_0', 'vc.production'],
    ['POST', '/projects/prj_1/promote/dpl_1', 'vc.production'],
    ['POST', '/v2/deployments/dpl_1/aliases', 'vc.production', J({ alias: 'example.com' })],
    ['POST', '/v1/projects/prj_1/rolling-release/start', 'vc.production', J({ canaryDeploymentId: 'd' })],
    ['POST', '/v1/projects/prj_1/rolling-release/approve-stage', 'vc.production'], ['POST', '/v1/projects/prj_1/rolling-release/complete', 'vc.production'],
    ['POST', '/v1/projects/prj_1/routes/versions', 'vc.production', J({ id: 'v', action: 'promote' })], ['POST', '/v1/bulk-redirects/versions', 'vc.production', J({ id: 'v', action: 'promote' })],
    ['POST', '/v1/projects/prj_1/pause', 'vc.pause'],
    ['PATCH', '/v9/projects/prj_1', 'vc.project-settings', J({ buildCommand: 'x' })],
    ['POST', '/v1/security/attack-mode', 'vc.security'], ['PUT', '/v1/security/firewall/config', 'vc.security'], ['PATCH', '/v1/security/firewall/config', 'vc.security'],
    ['POST', '/v1/security/firewall/config/12/activate', 'vc.security'], ['POST', '/v1/security/firewall/bypass', 'vc.security'],
    ['PATCH', '/v3/domains/example.com', 'vc.domain'], ['PATCH', '/v9/projects/prj_1/domains/example.com', 'vc.domain'], ['POST', '/v1/projects/prj_1/domains/example.com/move', 'vc.domain'],
    ['PATCH', '/v1/registrar/domains/example.com/nameservers', 'vc.domain'], ['PATCH', '/v1/registrar/domains/example.com/auto-renew', 'vc.domain'],
    ['PATCH', '/v1/domains/records/rec_1', 'vc.dns'], ['PUT', '/domains/example.com/records', 'vc.dns'], ['PUT', '/v2/domains/example.com/records', 'vc.dns'],
    ['POST', '/v1/registrar/domains/buy', 'vc.money'], ['POST', '/v1/registrar/domains/example.com/buy', 'vc.money'], ['POST', '/v1/registrar/domains/example.com/transfer', 'vc.money'],
    ['POST', '/v1/registrar/domains/example.com/renew', 'vc.money'], ['POST', '/v1/billing/buy', 'vc.money'],
    ['PATCH', '/v9/projects/prj_1/env/env_1', 'vc.env'], ['PATCH', '/v1/env', 'vc.env'],
    ['POST', '/v10/projects/prj_1/env', 'vc.env-upsert', J({ key: 'A', value: 'b', type: 'plain', target: ['production'] }), '?upsert=true'],
    ['POST', '/v1/edge-cache/dangerously-delete-by-tags', 'vc.cache'], ['POST', '/v1/edge-cache/dangerously-delete-by-src-images', 'vc.cache'],
    ['POST', '/v1/global-config/ecfg_1/backups/ver_1/restore', 'vc.restore'],
    ['POST', '/v2/teams/team_1/members', 'vc.access', J({ email: 'a@b.co', role: 'OWNER' })], ['PATCH', '/v1/teams/team_1/members/usr_1', 'vc.access'],
    ['POST', '/v1/projects/prj_1/members', 'vc.access'], ['POST', '/v1/access-groups/ag_1/projects', 'vc.access'], ['PATCH', '/v1/access-groups/ag_1/projects/prj_1', 'vc.access'],
    ['POST', '/projects/prj_1/transfer-request', 'vc.access'], ['PUT', '/projects/transfer-request/code123', 'vc.access'],
    ['POST', '/v3/user/tokens', 'vc.token', J({ name: 'x' })], ['POST', '/api-keys', 'vc.token', J({ purpose: 'ai-gateway' })],
  ]);
  passes('vercel', [
    ['GET', '/v9/projects'], ['GET', '/v9/projects/prj_1/env', '', '?decrypt=true'], ['GET', '/v13/deployments/dpl_1'], ['GET', '/v6/domains'], ['GET', '/v2/teams'],
    ['POST', '/v2/files', 'binary'], ['POST', '/v1/projects/prj_1/unpause'], ['POST', '/v11/projects', J({ name: 'new' })], ['POST', '/v10/projects/prj_1/domains', J({ name: 'a.example.com' })],
    ['POST', '/v10/projects/prj_1/env', J({ key: 'A', value: 'b', type: 'plain', target: ['preview'] })], ['POST', '/v10/projects/prj_1/env', J([{ key: 'A', value: 'b' }]), '?upsert=false'],
    ['POST', '/v10/projects/prj_1/env', J({ key: 'A', value: 'b' }), '?upsert=0'], ['POST', '/v10/projects/prj_1/env', J({ key: 'A', value: 'b' }), '?upsert='],
    ['POST', '/v2/domains/example.com/records', J({ name: 'www', type: 'A', value: '1.2.3.4' })], ['POST', '/v1/edge-cache/invalidate-by-tags', J({ tags: ['a'] })],
    ['PATCH', '/v1/global-config/ecfg_1/items', J({ items: [] })], ['POST', '/v1/env', J({ key: 'A' })], ['POST', '/v1/webhooks', J({ url: 'https://x.example' })],
  ]);
});

test('Vercel: upsert is read from every copy (query string, repeated, odd forms, a body that cannot be read one way)', () => {
  const up = (b, q) => rule('vercel', 'POST', '/v10/projects/p/env', b, q);
  const ok = J({ key: 'A', value: 'b', type: 'plain' });
  for (const q of ['?upsert=true', '?upsert=TRUE', '?upsert=1', '?upsert=yes', '?upsert=false&upsert=true', '?upsert=true&upsert=false', '?Upsert=true', '?upsert[]=true',
    '?%75psert=true', '?x=1;upsert=true', '?upsert=false;upsert=true', '? upsert=true'])
    assert.equal(up(ok, q), 'vc.env-upsert', q);
  assert.equal(up('upsert=true', ''), 'vc.env-upsert', 'a form reading of the body');
  assert.equal(up(J({ key: 'A', upsert: 'true' })), 'vc.env-upsert', 'a JSON field of that name');
  assert.equal(up('{"key":"A","key":"B"', ''), 'vc.env-upsert', 'looks like JSON, is not');
  assert.equal(up('--x\r\nContent-Disposition: form-data; name="upsert"\r\n\r\ntrue\r\n--x--', ''), 'vc.env-upsert', 'multipart');
  assert.equal(up(ok, '?upsert=false'), undefined);
  assert.equal(up(ok, '?upsert'), undefined, 'a bare flag is an empty value, like upsert=');
  assert.equal(up(J([{ key: 'A', value: 'b' }, { key: 'C', value: 'd' }]), ''), undefined, 'an array body carries no copy of a query parameter');
});

// ---------------------------------------------------------------- Neon
test('Neon: every irreversible endpoint is held, in every spelling; reads and ordinary writes pass', () => {
  held('neon', [
    ['DELETE', '/projects/p1', 'neon.delete'], ['DELETE', '/projects/p1/branches/br1', 'neon.delete'], ['DELETE', '/projects/p1/branches/br1/databases/db', 'neon.delete'],
    ['DELETE', '/projects/p1/branches/br1/roles/r', 'neon.delete'], ['DELETE', '/projects/p1/snapshots/s1', 'neon.delete'], ['DELETE', '/api_keys/k1', 'neon.delete'],
    ['DELETE', '/projects/p1/branches/br1/buckets/b/objects-by-prefix', 'neon.delete'],
    ['POST', '/projects/p1/branches/br1/restore', 'neon.restore', J({ source_branch_id: 'br0' })], ['POST', '/projects/p1/snapshots/s1/restore', 'neon.restore', J({ finalize_restore: true })],
    ['POST', '/projects/p1/branches/br1/finalize_restore', 'neon.restore'],
    ['POST', '/projects/p1/branches/br1/roles/neondb_owner/reset_password', 'neon.password'],
    ['PATCH', '/projects/p1', 'neon.settings', J({ project: { settings: { allowed_ips: { ips: [] } } } })], ['PATCH', '/projects/p1/endpoints/ep-1', 'neon.settings'],
    ['PATCH', '/projects/p1/branches/br1/databases/db', 'neon.settings'],
    ['PATCH', '/projects/p1/branches/br1', 'neon.retention', J({ branch: { protected: false } })], ['PATCH', '/projects/p1/snapshots/s1', 'neon.retention'], ['PUT', '/projects/p1/branches/br1/backup_schedule', 'neon.retention'],
    ['POST', '/projects/p1/vpc_endpoints/vpce-1', 'neon.network'], ['POST', '/organizations/o1/vpc/region/aws-us-east-1/vpc_endpoints/vpce-1', 'neon.network'],
    ['POST', '/projects/p1/transfer_requests', 'neon.transfer'], ['PUT', '/projects/p1/transfer_requests/tr1', 'neon.transfer'], ['POST', '/organizations/o1/projects/transfer', 'neon.transfer'],
    ['POST', '/api_keys', 'neon.secrets', J({ key_name: 'x' })], ['POST', '/organizations/o1/api_keys', 'neon.secrets'], ['POST', '/projects/p1/branches/br1/credentials', 'neon.secrets'],
    ['POST', '/projects/p1/branches/br1/credentials/nak_live_1/reveal', 'neon.secrets'], ['POST', '/projects/p1/branches/br1/credentials/nak_live_1/rotate', 'neon.secrets'],
    ['POST', '/projects/p1/branches/br1/realtime/rotate_secret', 'neon.secrets'],
    ['POST', '/projects/p1/permissions', 'neon.access', J({ email: 'a@b.co' })], ['PUT', '/projects/p1/members/m1/role', 'neon.access'], ['PATCH', '/organizations/o1/members/m1', 'neon.access'],
    ['POST', '/organizations/o1/invitations', 'neon.access'],
    ['POST', '/projects/p1/auth/domains', 'neon.auth'], ['PATCH', '/projects/p1/auth/oauth_providers/o', 'neon.auth'], ['PUT', '/projects/p1/branches/br1/auth/users/u/role', 'neon.auth'],
    ['POST', '/projects/p1/branches/br1/auth', 'neon.auth'], ['PATCH', '/projects/p1/branches/br1/auth/config', 'neon.auth'], ['POST', '/projects/auth/create', 'neon.auth'], ['POST', '/projects/auth/keys', 'neon.auth'],
    ['POST', '/projects/p1/branches/br1/functions/f/deployments', 'neon.function'], ['PATCH', '/projects/p1/branches/br1/functions/f', 'neon.function'],
  ]);
  passes('neon', [
    ['GET', '/projects'], ['GET', '/projects/p1/branches'], ['GET', '/projects', '', '?recoverable=true'], ['POST', '/projects', J({ project: { name: 'x' } })],
    ['POST', '/projects/p1/branches', J({ branch: { name: 'preview' } })], ['POST', '/projects/p1/branches/br1/databases', J({ database: { name: 'd', owner_name: 'o' } })],
    ['POST', '/projects/p1/branches/br1/roles', J({ role: { name: 'r' } })], ['POST', '/projects/p1/endpoints/ep-1/start'], ['POST', '/projects/p1/endpoints/ep-1/suspend'],
    ['POST', '/projects/p1/endpoints/ep-1/restart'], ['POST', '/projects/p1/branches/br1/snapshot'], ['POST', '/projects/p1/recover'], ['POST', '/projects/p1/branches/br1/set_as_default'],
    ['PUT', '/organizations/o1/billing/spending_limit', J({ spending_limit_cents: 1000 })], ['POST', '/projects/p1/branches/br1/logs/query'],
  ]);
});

// ---------------------------------------------------------------- Fly.io
test('Fly.io: every irreversible endpoint is held, in every spelling; reads and ordinary writes pass', () => {
  held('fly', [
    ['DELETE', '/apps/myapp', 'fly.delete'], ['DELETE', '/apps/myapp', 'fly.delete', '', '?force=true'], ['DELETE', '/apps/myapp/volumes/vol_1', 'fly.delete'],
    ['DELETE', '/apps/myapp/machines/m1', 'fly.delete', '', '?force=true'], ['DELETE', '/apps/myapp/certificates/example.com', 'fly.delete'], ['DELETE', '/apps/myapp/ip_assignments/1.2.3.4', 'fly.delete'],
    ['DELETE', '/postgres/pg_1', 'fly.delete'], ['DELETE', '/apps/myapp/secrets/KEY', 'fly.delete'],
    ['POST', '/apps/myapp/machines/m1/exec', 'fly.exec', J({ command: ['rm', '-rf', '/data'] })],
    ['POST', '/apps/myapp/machines/m1', 'fly.machine-update', J({ config: { image: 'x' } })],
    ['POST', '/apps/myapp/machines/m1/stop', 'fly.machine-stop'], ['POST', '/apps/myapp/machines/m1/suspend', 'fly.machine-stop'],
    ['POST', '/apps/myapp/machines/m1/signal', 'fly.machine-stop', J({ signal: 'SIGKILL' })], ['POST', '/apps/myapp/machines/m1/cordon', 'fly.machine-stop'],
    ['PUT', '/apps/myapp/volumes/vol_1/extend', 'fly.volume', J({ size_gb: 100 })], ['PUT', '/apps/myapp/volumes/vol_1', 'fly.volume', J({ snapshot_retention: 1 })],
    ['POST', '/apps/myapp/secrets', 'fly.secrets', J({ values: { A: 'b' } })], ['POST', '/apps/myapp/secrets/KEY', 'fly.secrets'], ['POST', '/apps/myapp/secretkeys/k', 'fly.secrets'],
    ['POST', '/apps/myapp/secretkeys/k/generate', 'fly.secrets'],
    ['POST', '/apps/myapp/deploy_token', 'fly.token'],
    ['POST', '/postgres/pg_1/users/admin/rotate_password', 'fly.postgres', J({ kill_sessions: true })], ['PATCH', '/postgres/pg_1/users/admin', 'fly.postgres'],
  ]);
  passes('fly', [
    ['GET', '/apps', '', '?org_slug=personal'], ['GET', '/apps/myapp/machines'], ['GET', '/apps/myapp/machines/m1'], ['POST', '/apps', J({ app_name: 'x', org_slug: 'o' })],
    ['POST', '/apps/myapp/machines', J({ config: { image: 'x' } })], ['POST', '/apps/myapp/machines/m1/start'], ['POST', '/apps/myapp/machines/m1/restart'],
    ['POST', '/apps/myapp/machines/m1/lease'], ['PATCH', '/apps/myapp/machines/m1/metadata', J({})], ['POST', '/apps/myapp/volumes', J({ name: 'data', size_gb: 1 })],
    ['POST', '/apps/myapp/volumes/vol_1/snapshots'], ['POST', '/apps/myapp/certificates/acme', J({ hostname: 'a.example.com' })], ['POST', '/apps/myapp/ip_assignments', J({})],
    ['POST', '/apps/myapp/secretkeys/k/decrypt', J({})], ['POST', '/postgres', J({})], ['POST', '/postgres/pg_1/restore', J({})], ['POST', '/tokens/oidc', J({ aud: 'x' })],
  ]);
});

// ---------------------------------------------------------------- Resend
test('Resend: batch, broadcasts, many recipients, automations, suppressions, secrets and keys are held; a single email passes', () => {
  held('resend', [
    ['DELETE', '/domains/d1', 'rs.delete'], ['DELETE', '/audiences/a1', 'rs.delete'], ['DELETE', '/contacts/c1', 'rs.delete'], ['DELETE', '/segments/s1', 'rs.delete'], ['DELETE', '/api-keys/k1', 'rs.delete'],
    ['DELETE', '/webhooks/w1', 'rs.delete'], ['DELETE', '/templates/t1', 'rs.delete'], ['DELETE', '/suppressions/x@y.co', 'rs.delete'], ['DELETE', '/inboxes/i1', 'rs.delete'],
    ['POST', '/emails/batch', 'rs.batch', J([{ from: 'a@x.co', to: 'b@y.co', subject: 's' }])],
    ['POST', '/broadcasts/b1/send', 'rs.broadcast', J({ scheduled_at: 'in 1 hour' })], ['POST', '/broadcasts', 'rs.broadcast-now', J({ segment_id: 's', from: 'a@x.co', subject: 's', send: true })],
    ['POST', '/emails', 'rs.recipients', J({ from: 'a@x.co', to: ['b@y.co', 'c@y.co'], subject: 's' })],
    ['POST', '/inboxes/i1/drafts/d1/send', 'rs.inbox-send'], ['POST', '/inboxes/i1/threads/t1/emails/e1/reply', 'rs.inbox-send', J({ reply_all: true })],
    ['POST', '/inboxes/i1/threads/t1/emails/e1/forward', 'rs.inbox-send', J({ to: ['a@x.co'] })],
    ['POST', '/automations', 'rs.automation', J({ name: 'n', status: 'enabled', steps: [], connections: [] })], ['PATCH', '/automations/a1', 'rs.automation-edit', J({ status: 'enabled' })],
    ['PATCH', '/automations/a1', 'rs.automation-edit', J({ steps: [], connections: [] })],
    ['POST', '/suppressions/batch/remove', 'rs.suppression', J({ emails: ['a@b.co'] })], ['POST', '/webhooks/w1/signing-secret/rotate', 'rs.webhook-secret'],
    ['POST', '/api-keys', 'rs.api-key', J({ name: 'x', permission: 'full_access' })],
  ]);
  passes('resend', [
    ['GET', '/emails'], ['GET', '/domains'], ['POST', '/emails', J({ from: 'a@x.co', to: 'b@y.co', subject: 's', html: '<p>hi</p>' })], ['POST', '/emails', J({ from: 'a@x.co', to: ['b@y.co'], subject: 's' })],
    ['POST', '/emails', J({ from: 'a@x.co', to: 'Jane Doe <jane@y.co>', subject: 's', scheduled_at: '2026-10-11T10:00:00Z' })],
    ['POST', '/emails', J({ from: 'a@x.co', to: 'b@y.co', cc: [], bcc: '', subject: 's' })],
    ['POST', '/broadcasts', J({ segment_id: 's', from: 'a@x.co', subject: 's' })], ['POST', '/broadcasts', J({ segment_id: 's', from: 'a@x.co', subject: 's', send: false })],
    ['POST', '/automations', J({ name: 'n', steps: [], connections: [] })], ['POST', '/automations', J({ name: 'n', status: 'disabled', steps: [] })],
    ['PATCH', '/automations/a1', J({ name: 'renamed' })], ['PATCH', '/automations/a1', J({ status: 'disabled' })], ['POST', '/automations/a1/stop'],
    ['POST', '/contacts', J({ email: 'a@b.co' })], ['PATCH', '/contacts/c1', J({ first_name: 'A' })], ['POST', '/domains', J({ name: 'example.com' })], ['POST', '/domains/d1/verify'],
    ['POST', '/webhooks', J({ endpoint: 'https://x.example', events: [] })], ['POST', '/events/send', J({ event: 'e', email: 'a@b.co' })], ['POST', '/emails/e1/cancel'],
    ['POST', '/suppressions', J({ email: 'a@b.co' })], ['POST', '/templates', J({ name: 't' })],
  ]);
});

test('Resend recipients: one address passes; a list, a list hidden in one string, cc, bcc, a repeated or escaped key, or a body it cannot read is held', () => {
  const em = (b, q) => rule('resend', 'POST', '/emails', b, q);
  const base = { from: 'a@x.co', subject: 's' };
  for (const to of ['b@y.co', ['b@y.co'], 'Jane <j@y.co>', 'Doe Jane <j@y.co>']) assert.equal(em(J({ ...base, to })), undefined, J(to));
  for (const to of [['b@y.co', 'c@y.co'], 'b@y.co,c@y.co', 'b@y.co, c@y.co', 'b@y.co;c@y.co', 'b@y.co c@y.co', 'b@y.co\nc@y.co', 'b@y.co\uff0cc@y.co', '"a@b" <c@d.co>', [], [''], [['b@y.co']], '', 5, null, { a: 'b@y.co' }, ['b@y.co', 7]])
    assert.equal(em(J({ ...base, to })), 'rs.recipients', J(to));
  assert.equal(em(J({ ...base })), 'rs.recipients', 'no recipient at all');
  assert.equal(em(J({ ...base, to: 'b@y.co', cc: ['c@y.co'] })), 'rs.recipients');
  assert.equal(em(J({ ...base, to: 'b@y.co', bcc: 'c@y.co' })), 'rs.recipients');
  assert.equal(em(J({ ...base, to: 'b@y.co', bcc: [''] })), 'rs.recipients', 'a list with an empty string is not an empty list');
  for (const b of ['{"to":"b@y.co","to":"c@y.co"}', '{"to":"b@y.co","\\u0074o":"c@y.co"}', '{"to":"b@y.co","TO":"c@y.co"}', '{"to":"b@y.co","Cc":["c@y.co"],"cc":[]}', '{"to":"b@y.co"', 'to=b%40y.co', '[{"to":"b@y.co"}]',
    '--x\r\nContent-Disposition: form-data; name="to"\r\n\r\nb@y.co\r\n--x--', J(base), '', 'not json'])
    assert.equal(em(b), 'rs.recipients', b);
  assert.equal(em(J({ ...base, to: 'b@y.co' }), '?to=c%40y.co'), 'rs.recipients', 'a recipient in the query string');
  assert.equal(em(J({ ...base, to: 'b@y.co' }), '?bcc=c%40y.co'), 'rs.recipients');
  assert.equal(em(J({ ...base, to: 'b@y.co' }), '?x=1;cc=c%40y.co'), 'rs.recipients');
  // broadcasts: only an explicit false (or no field) is a draft
  const bc = (b, q) => rule('resend', 'POST', '/broadcasts', b, q);
  for (const b of [J({ send: true }), J({ send: 'true' }), J({ send: 'false' }), J({ send: null }), J({ send: 1 }), '{"send":false,"send":true}', '{"\\u0073end":true}', '{"SEND":true}', '[{"send":true}]', 'not json'])
    assert.equal(bc(b), 'rs.broadcast-now', b);
  assert.equal(bc(J({ send: false })), undefined); assert.equal(bc(J({ name: 'n' })), undefined);
  assert.equal(bc(J({ name: 'n' }), '?send=true'), 'rs.broadcast-now', 'the query string');
  // automations: status must be exactly "disabled" when given; a PATCH may not touch steps or connections
  const au = (m, b) => rule('resend', m, m === 'POST' ? '/automations' : '/automations/a1', b);
  for (const b of [J({ status: 'enabled' }), J({ status: 'ENABLED' }), J({ status: 'Disabled' }), J({ status: null }), '{"status":"disabled","status":"enabled"}', '{"\\u0073tatus":"enabled"}'])
    for (const m of ['POST', 'PATCH']) assert.equal(au(m, b), m === 'POST' ? 'rs.automation' : 'rs.automation-edit', m + ' ' + b);
  assert.equal(au('POST', J({ name: 'n', steps: [{}], connections: [] })), undefined, 'a new automation is created disabled');
  assert.equal(au('PATCH', J({ name: 'n', steps: [] })), 'rs.automation-edit');
});

// ---------------------------------------------------------------- Shopify GraphQL
const DOC = '/admin/api/2026-07/graphql.json';
const gql = (query, extra = {}) => J({ query, ...extra });
const sh = (b, q = '') => rule('shopify', 'POST', DOC, b, q);

test('Shopify: every mutation family is held under its own rule id; plain queries and ordinary writes pass', () => {
  const m = (field) => gql(`mutation { ${field} }`);
  const cases = [
    ['productDelete(input: {id: "gid://shopify/Product/1"}) { deletedProductId }', 'sh.delete'], ['orderDelete(orderId: "x") { deletedId }', 'sh.delete'],
    ['collectionDelete(input: {id: "x"}) { deletedCollectionId }', 'sh.delete'], ['customerDelete(input: {id: "x"}) { deletedCustomerId }', 'sh.delete'],
    ['webhookSubscriptionDelete(id: "x") { deletedWebhookSubscriptionId }', 'sh.delete'], ['urlRedirectBulkDeleteAll { job { id } }', 'sh.delete'],
    ['delegateAccessTokenDestroy(accessToken: "x") { status }', 'sh.delete'], ['deliveryProfileRemove(id: "x") { job { id } }', 'sh.delete'],
    ['shopLocaleDisable(locale: "fr") { locale }', 'sh.delete'], ['inventoryDeactivate(inventoryLevelId: "x") { userErrors { message } }', 'sh.delete'],
    ['locationDeactivate(locationId: "x") { location { id } }', 'sh.delete'], ['appUninstall { app { id } }', 'sh.delete'],
    ['inventoryBulkToggleActivation(inventoryItemId: "x", inventoryItemUpdates: []) { inventoryItem { id } }', 'sh.delete'],
    ['refundCreate(input: {orderId: "x"}) { refund { id } }', 'sh.money'], ['orderCapture(input: {}) { transaction { id } }', 'sh.money'], ['orderMarkAsPaid(input: {id: "x"}) { order { id } }', 'sh.money'],
    ['returnProcess(input: {}) { return { id } }', 'sh.money'], ['subscriptionBillingAttemptCreate(subscriptionContractId: "x", subscriptionBillingAttemptInput: {}) { subscriptionBillingAttempt { id } }', 'sh.money'],
    ['shippingLabelPurchase(input: {}) { userErrors { message } }', 'sh.money'], ['appUsageRecordCreate(subscriptionLineItemId: "x", price: {}, description: "x") { appUsageRecord { id } }', 'sh.money'],
    ['giftCardCreate(input: {initialValue: "100"}) { giftCard { id } }', 'sh.giftcard'], ['giftCardCredit(id: "x", creditInput: {}) { giftCardCreditTransaction { id } }', 'sh.giftcard'],
    ['storeCreditAccountCredit(id: "x", creditInput: {}) { storeCreditAccountTransaction { id } }', 'sh.giftcard'], ['storeCreditAccountDebit(id: "x", debitInput: {}) { userErrors { message } }', 'sh.giftcard'],
    ['orderCancel(orderId: "x", reason: OTHER, refund: true, restock: true) { job { id } }', 'sh.cancel'], ['subscriptionContractCancel(subscriptionContractId: "x") { contract { id } }', 'sh.cancel'],
    ['customerRequestDataErasure(customerId: "x") { customerId }', 'sh.customer-data'], ['customerMerge(customerOneId: "a", customerTwoId: "b") { job { id } }', 'sh.customer-data'],
    ['delegateAccessTokenCreate(input: {delegateAccessScope: []}) { delegateAccessToken { accessToken } }', 'sh.access'], ['appRevokeAccessScopes(scopes: []) { revoked { handle } }', 'sh.access'],
    ['themePublish(id: "x") { theme { id } }', 'sh.theme'], ['themeFilesUpsert(themeId: "x", files: []) { job { id } }', 'sh.theme'], ['themeFilesCopy(themeId: "x", files: []) { job { id } }', 'sh.theme'],
    ['webhookSubscriptionCreate(topic: ORDERS_CREATE, webhookSubscription: {}) { webhookSubscription { id } }', 'sh.webhook'],
    ['bulkOperationRunMutation(mutation: "mutation { x }", stagedUploadPath: "p") { bulkOperation { id } }', 'sh.bulk'],
  ];
  for (const [f, id] of cases) for (const p of variants(DOC)) assert.equal(rule('shopify', 'POST', p, m(f)), id, `${f.slice(0, 40)} ${p}`);
  for (const q of [
    '{ shop { name } }', 'query Shop { shop { name myshopifyDomain } }', 'query { products(first: 5) { edges { node { id title } } } }',
    'mutation { productUpdate(input: {id: "x", title: "t"}) { product { id } } }', 'mutation { productCreate(input: {title: "t"}) { product { id } } }',
    'mutation { inventorySetQuantities(input: {}) { inventoryAdjustmentGroup { id } } }', 'mutation { collectionCreate(input: {title: "t"}) { collection { id } } }',
    'mutation { customerUpdate(input: {id: "x", note: "n"}) { customer { id } } }', 'mutation { draftOrderCreate(input: {}) { draftOrder { id } } }', 'mutation { __typename }',
    'query { products(query: "mutation { productDelete }") { edges { node { id } } } }', // text inside a string is not a mutation
    'query { deleteMe: shop { name } }', // a query field with delete in its alias
    'subscription { x }',
  ]) for (const p of variants(DOC)) assert.equal(rule('shopify', 'POST', p, gql(q)), undefined, q + ' ' + p);
  assert.equal(sh(gql('query($q: String) { products(query: $q) { edges { node { id } } } }', { variables: { q: 'productDelete' }, operationName: null })), undefined, 'a variable value named like a mutation');
  assert.equal(sh(gql('{ shop { name } }', { operationName: 'X', extensions: {} })), undefined);
  // the priority when a document does several things: unreadable beats nothing, bulk beats the rest
  assert.equal(sh(m('productUpdate(input: {}) { product { id } } refundCreate(input: {}) { refund { id } }')), 'sh.money');
  assert.equal(sh(m('bulkOperationRunMutation(mutation: "x") { bulkOperation { id } } productDelete(input: {}) { deletedProductId }')), 'sh.bulk');
  // transports that are not a normal client path
  for (const p of variants(DOC)) {
    assert.equal(rule('shopify', 'GET', p, null, '?query=%7Bshop%7Bname%7D%7D'), 'sh.get');
    assert.equal(rule('shopify', 'HEAD', p), 'sh.get', 'HEAD trips the GET rule');
    for (const meth of ['PUT', 'PATCH', 'DELETE']) assert.equal(rule('shopify', meth, p, gql('{ shop { name } }')), 'sh.method');
  }
});

test('Shopify: documents the broker cannot read with certainty are held (aliases, fragments, operations, escapes, batches, persisted queries)', () => {
  const D = 'productDelete(input: {id: "x"}) { deletedProductId }';
  // an alias cannot rename a mutation: the real field name is read
  assert.equal(sh(gql(`mutation { safe: ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation { shop: ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation { a: productUpdate(input: {}) { product { id } } b: ${D} }`)), 'sh.delete');
  // several operations, operationName picks the harmless one: every mutation in the document still counts
  assert.equal(sh(gql(`query A { shop { name } } mutation B { ${D} }`, { operationName: 'A' })), 'sh.delete');
  assert.equal(sh(gql(`mutation A { productUpdate(input: {}) { product { id } } } mutation B { ${D} }`, { operationName: 'A' })), 'sh.delete');
  // a fragment can hide any field at the mutation root: refused as unreadable
  assert.equal(sh(gql(`mutation { ...F } fragment F on Mutation { ${D} }`)), 'sh.unreadable');
  assert.equal(sh(gql(`mutation { ... on Mutation { ${D} } }`)), 'sh.unreadable');
  assert.equal(sh(gql(`fragment F on Mutation { ${D} } mutation { ...F }`)), 'sh.unreadable');
  // comments, commas, directives, variables, block strings and escapes cannot move a field out of sight
  assert.equal(sh(gql(`# mutation { safe }\nmutation { ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation { # productUpdate\n ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation { ,,, ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation($id: ID!) { productDelete(input: {id: $id}) @include(if: true) { deletedProductId } }`, { variables: { id: 'x' } })), 'sh.delete');
  assert.equal(sh(gql(`mutation { productUpdate(input: {description: """mutation { x }"""}) { product { id } } ${D} }`)), 'sh.delete');
  assert.equal(sh(gql(`mutation { productUpdate(input: {title: "a \\" mutation { b"}) { product { id } } ${D} }`)), 'sh.delete');
  assert.equal(sh(gql('mutation { \\u0070roductDelete(input: {}) { deletedProductId } }')), 'sh.unreadable', 'a backslash is not part of a GraphQL name');
  assert.equal(sh(gql('mutation { PRODUCTDELETE(input: {}) { x } }')), 'sh.delete', 'held in any case, though Shopify would refuse the field');
  assert.equal(sh(gql(`mutation { ${D}`)), 'sh.unreadable', 'unterminated');
  assert.equal(sh(gql('mutation { productUpdate(input: {title: "unterminated}) { x } }')), 'sh.unreadable');
  // not one clean JSON object with a query: batches, persisted queries, document ids, repeated or escaped keys, other keys
  const one = '{"query":"mutation { productDelete(input: {}) { deletedProductId } }"}';
  assert.equal(sh(one), 'sh.delete');
  for (const b of [`[${one}]`, `[${one},${one}]`, '{"query":"{ shop { name } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"x"}}}', '{"documentId":"abc"}', '{"doc_id":"abc","query":"{ shop { name } }"}',
    '{"query":"{ shop { name } }","query":"mutation { productDelete(input: {}) { x } }"}', '{"\\u0071uery":"mutation { productDelete(input: {}) { x } }","query":"{ shop { name } }"}',
    '{"QUERY":"{ shop { name } }","query":"mutation { productDelete(input: {}) { x } }"}', '{"query":"{ shop { name } }","other":1}', '{"query":5}', '{"query":"{ shop { name } }"} trailing',
    'query=%7Bshop%7Bname%7D%7D', 'mutation { productDelete(input: {}) { x } }', '{ shop { name } }', '', 'null', '"query"', '{"query":"{ shop { name } }"', String.fromCharCode(0xfeff) + '{"query":"{ shop { name } }"}'])
    assert.equal(sh(b), 'sh.unreadable', b);
  // parameters outside the JSON body that a server may read in place of it
  const view = gql('{ shop { name } }');
  assert.equal(sh(view, '?query=' + encodeURIComponent('mutation { productDelete(input: {}) { x } }')), 'sh.unreadable', 'the query string');
  assert.equal(sh(view, '?operationName=x'), 'sh.unreadable');
  assert.equal(sh(view, '?documentId=x'), 'sh.unreadable');
  assert.equal(sh(gql('{ shop { name } }', { variables: { a: '&query=mutation{productDelete}&' } })), 'sh.unreadable', 'a form reading of the body');
  assert.equal(sh(view, '?x=1'), undefined, 'an unrelated parameter');
  assert.equal(sh(view), undefined);
});

test('Shopify: every one of the 484 mutations in the published schema is classified, and the held set is frozen', () => {
  // names from Shopify's Admin GraphQL schema as served for its docs, versions 2026-01, 2026-07 and 2026-10 (read 9 Oct 2026)
  const HELD = {
  'sh.delete': `analyticsAnnotationDelete analyticsTargetsDelete appUninstall articleDelete blogDelete carrierServiceDelete cartTransformDelete cashManagementReasonCodeDelete catalogDelete channelDelete collectionConditionsSourceDelete collectionDelete commentDelete companiesDelete companyAddressDelete companyContactDelete companyContactsDelete companyDelete companyLocationDelete companyLocationsDelete customerAddressDelete customerDelete delegateAccessTokenDestroy deliveryCustomizationDelete deliveryProfileRemove discountAutomaticBulkDelete discountAutomaticDelete discountCodeBulkDelete discountCodeDelete discountCodeRedeemCodeBulkDelete draftOrderBulkDelete draftOrderDelete fileDelete fulfillmentConstraintRuleDelete fulfillmentServiceDelete inventoryBulkToggleActivation inventoryDeactivate inventoryShipmentDelete inventoryTransferDelete locationDeactivate locationDelete marketDelete marketingActivitiesDeleteAllExternal marketingActivityDeleteExternal marketingEngagementsDelete menuDelete metafieldDefinitionDelete metafieldsDelete metaobjectBulkDelete metaobjectDefinitionDelete metaobjectDelete mobilePlatformApplicationDelete orderAttributionDefinitionDelete orderDelete pageDelete paymentCustomizationDelete paymentTermsDelete priceListDelete priceListFixedPricesDelete productDelete productFeedDelete productOptionsDelete productVariantsBulkDelete publicationDelete quantityRulesDelete savedSearchDelete scriptTagDelete segmentDelete sellingPlanGroupDelete serverPixelDelete shippingPackageDelete shopLocaleDisable storefrontAccessTokenDelete subscriptionBillingCycleEditDelete subscriptionBillingCycleEditsDelete themeDelete themeFilesDelete urlRedirectBulkDeleteAll urlRedirectBulkDeleteByIds urlRedirectBulkDeleteBySavedSearch urlRedirectBulkDeleteBySearch urlRedirectDelete validationDelete webPixelDelete webPresenceDelete webhookSubscriptionDelete`,
  'sh.money': `appPurchaseOneTimeCreate appSubscriptionCreate appSubscriptionLineItemUpdate appUsageRecordCreate orderCapture orderCreateMandatePayment orderCreateManualPayment orderMarkAsPaid paymentScheduleCapture refundCreate returnProcess shippingLabelPurchase shopifyPaymentsPayoutAlternateCurrencyCreate subscriptionBillingAttemptCreate subscriptionBillingCycleBulkCharge subscriptionBillingCycleCharge transactionVoid`,
  'sh.access': `appRevokeAccessScopes delegateAccessTokenCreate`,
  'sh.bulk': `bulkOperationRunMutation`,
  'sh.customer-data': `customerMerge customerPaymentMethodRevoke customerRequestDataErasure privacyFeaturesDisable`,
  'sh.giftcard': `giftCardCreate giftCardCredit giftCardDeactivate giftCardDebit giftCardProductSet giftCardSendNotificationToCustomer giftCardSendNotificationToRecipient giftCardUpdate storeCreditAccountCredit storeCreditAccountDebit`,
  'sh.cancel': `orderCancel subscriptionContractCancel subscriptionContractExpire`,
  'sh.theme': `themeFilesCopy themeFilesUpsert themePublish`,
  'sh.webhook': `webhookSubscriptionCreate webhookSubscriptionUpdate`,
  };
  const PASS = `
    abandonmentUpdateActivitiesDeliveryStatuses analyticsAnnotationCreate analyticsAnnotationUpdate
    analyticsTargetCreate analyticsTargetUpdate appSubscriptionCancel appSubscriptionTrialExtend articleCreate
    articleUpdate backupRegionUpdate blogCreate blogUpdate bulkOperationCancel bulkOperationRunQuery
    bulkProductResourceFeedbackCreate carrierServiceCreate carrierServiceUpdate cartTransformCreate cashDrawerCreate
    cashDrawerFindOrCreate cashDrawerUpdate cashManagementReasonCodeCreate catalogContextUpdate catalogCreate
    catalogUpdate channelCreate channelFullSync channelUpdate checkoutAndAccountsConfigurationUpdate
    collectionConditionsSourceCreate collectionConditionsSourceUpdate collectionCreate collectionDuplicate
    collectionReorderProducts collectionUpdate combinedListingUpdate commentApprove commentNotSpam commentSpam
    companyAssignCustomerAsContact companyAssignMainContact companyContactAssignRole companyContactAssignRoles
    companyContactCreate companyContactRemoveFromCompany companyContactRevokeRole companyContactRevokeRoles
    companyContactSendWelcomeEmail companyContactUpdate companyCreate companyLocationAssignAddress
    companyLocationAssignRoles companyLocationAssignStaffMembers companyLocationCreate companyLocationRemoveStaffMembers
    companyLocationRevokeRoles companyLocationTaxSettingsUpdate companyLocationUpdate companyRevokeMainContact
    companyUpdate consentPolicyUpdate customerAddTaxExemptions customerAddressCreate customerAddressUpdate
    customerCancelDataErasure customerCreate customerEmailMarketingConsentUpdate customerGenerateAccountActivationUrl
    customerPaymentMethodCreateFromDuplicationData customerPaymentMethodCreditCardCreate
    customerPaymentMethodCreditCardUpdate customerPaymentMethodGetDuplicationData customerPaymentMethodGetUpdateUrl
    customerPaymentMethodPaypalBillingAgreementCreate customerPaymentMethodPaypalBillingAgreementUpdate
    customerPaymentMethodRemoteCreate customerPaymentMethodSendUpdateEmail customerRemoveTaxExemptions
    customerReplaceTaxExemptions customerSegmentMembersQueryCreate customerSendAccountInviteEmail customerSet
    customerSmsMarketingConsentUpdate customerUpdate customerUpdateDefaultAddress customerWhatsAppMarketingConsentUpdate
    dataSaleOptOut deliveryCustomizationActivation deliveryCustomizationCreate deliveryCustomizationUpdate
    deliveryProfileCreate deliveryProfileUpdate deliveryPromiseParticipantsUpdate deliveryPromiseProviderUpsert
    deliverySettingUpdate discountAutomaticActivate discountAutomaticAppCreate discountAutomaticAppUpdate
    discountAutomaticBasicCreate discountAutomaticBasicUpdate discountAutomaticBxgyCreate discountAutomaticBxgyUpdate
    discountAutomaticDeactivate discountAutomaticFreeShippingCreate discountAutomaticFreeShippingUpdate
    discountBulkTagsAdd discountBulkTagsRemove discountCodeActivate discountCodeAppCreate discountCodeAppUpdate
    discountCodeBasicCreate discountCodeBasicUpdate discountCodeBulkActivate discountCodeBulkDeactivate
    discountCodeBxgyCreate discountCodeBxgyUpdate discountCodeDeactivate discountCodeFreeShippingCreate
    discountCodeFreeShippingUpdate discountRedeemCodeBulkAdd disputeEvidenceUpdate draftOrderBulkAddTags
    draftOrderBulkRemoveTags draftOrderCalculate draftOrderComplete draftOrderCreate draftOrderCreateFromOrder
    draftOrderDuplicate draftOrderInvoicePreview draftOrderInvoiceSend draftOrderUpdate eventBridgeServerPixelUpdate
    fileAcknowledgeUpdateFailed fileCreate fileUpdate flowGenerateSignature flowTriggerReceive fulfillmentCancel
    fulfillmentConstraintRuleCreate fulfillmentConstraintRuleUpdate fulfillmentCreate fulfillmentEventCreate
    fulfillmentOrderAcceptCancellationRequest fulfillmentOrderAcceptFulfillmentRequest fulfillmentOrderCancel
    fulfillmentOrderClose fulfillmentOrderHold fulfillmentOrderLineItemsPreparedForPickup fulfillmentOrderMerge
    fulfillmentOrderMove fulfillmentOrderOpen fulfillmentOrderRejectCancellationRequest
    fulfillmentOrderRejectFulfillmentRequest fulfillmentOrderReleaseHold fulfillmentOrderReportProgress
    fulfillmentOrderReschedule fulfillmentOrderSplit fulfillmentOrderSubmitCancellationRequest
    fulfillmentOrderSubmitFulfillmentRequest fulfillmentOrdersReroute fulfillmentOrdersSetFulfillmentDeadline
    fulfillmentServiceCreate fulfillmentServiceUpdate fulfillmentTrackingInfoUpdate inventoryActivate
    inventoryAdjustQuantities inventoryItemUpdate inventoryMoveQuantities inventorySetQuantities
    inventoryShipmentAddItems inventoryShipmentCreate inventoryShipmentCreateInTransit inventoryShipmentMarkInTransit
    inventoryShipmentReceive inventoryShipmentRemoveItems inventoryShipmentSetBarcode inventoryShipmentSetTracking
    inventoryShipmentUpdateItemQuantities inventoryTransferCancel inventoryTransferCreate
    inventoryTransferCreateAsReadyToShip inventoryTransferDuplicate inventoryTransferEdit
    inventoryTransferMarkAsReadyToShip inventoryTransferRemoveItems inventoryTransferSetItems locationActivate
    locationAdd locationEdit locationLocalPickupDisable locationLocalPickupEnable marketCreate
    marketLocalizationsRegister marketLocalizationsRemove marketUpdate marketingActivityCreate marketingActivityUpdate
    marketingActivityUpdateExternal marketingActivityUpsertExternal marketingEngagementCreate menuCreate menuUpdate
    metafieldDefinitionCreate metafieldDefinitionPin metafieldDefinitionUnpin metafieldDefinitionUpdate metafieldsSet
    metaobjectCreate metaobjectDefinitionCreate metaobjectDefinitionUpdate metaobjectUpdate metaobjectUpsert
    mobilePlatformApplicationCreate mobilePlatformApplicationUpdate orderAttributionDefinitionUpsert orderClose
    orderCreate orderCustomerRemove orderCustomerSet orderEditAddCustomItem orderEditAddLineItemDiscount
    orderEditAddShippingLine orderEditAddVariant orderEditBegin orderEditCommit orderEditRemoveDiscount
    orderEditRemoveShippingLine orderEditSetQuantity orderEditUpdateDiscount orderEditUpdateShippingLine
    orderInvoiceSend orderOpen orderRiskAssessmentCreate orderUpdate pageCreate pageUpdate
    paymentCustomizationActivation paymentCustomizationCreate paymentCustomizationUpdate paymentInstrumentSendAddEmail
    paymentReminderSend paymentTermsCreate paymentTermsUpdate pointOfSaleDeviceAssignToCashDrawer
    pointOfSaleDevicePaymentSessionAdjust pointOfSaleDevicePaymentSessionClose pointOfSaleDevicePaymentSessionCount
    pointOfSaleDevicePaymentSessionOpen previewInstall priceListCreate priceListFixedPricesAdd
    priceListFixedPricesByProductUpdate priceListFixedPricesUpdate priceListUpdate productBundleCreate
    productBundleUpdate productCreate productDuplicate productFeedCreate productFullSync productJoinSellingPlanGroups
    productLeaveSellingPlanGroups productOptionUpdate productOptionsCreate productOptionsReorder productReorderMedia
    productSet productUpdate productVariantAppendMedia productVariantDetachMedia productVariantJoinSellingPlanGroups
    productVariantLeaveSellingPlanGroups productVariantRelationshipBulkUpdate productVariantsBulkCreate
    productVariantsBulkReorder productVariantsBulkUpdate pubSubServerPixelUpdate publicationCreate publicationUpdate
    publishablePublish publishableUnpublish quantityPricingByVariantUpdate quantityRulesAdd removeFromReturn
    requestedOrderEditCreate requestedOrderEditDecline requestedOrderEditResolve returnApproveRequest returnCancel
    returnClose returnCreate returnDeclineRequest returnReopen returnRequest reverseDeliveryCreateWithShipping
    reverseDeliveryShippingUpdate reverseFulfillmentOrderDispose savedSearchCreate savedSearchUpdate scriptTagCreate
    scriptTagUpdate segmentCreate segmentUpdate sellingPlanGroupAddProductVariants sellingPlanGroupAddProducts
    sellingPlanGroupCreate sellingPlanGroupRemoveProductVariants sellingPlanGroupRemoveProducts sellingPlanGroupUpdate
    serverPixelCreate shippingPackageMakeDefault shippingPackageUpdate shopLocaleEnable shopLocaleUpdate
    shopPolicyUpdate shopResourceFeedbackCreate stagedUploadsCreate standardMetafieldDefinitionEnable
    standardMetaobjectDefinitionEnable storefrontAccessTokenCreate subscriptionBillingCycleBulkSearch
    subscriptionBillingCycleContractDraftCommit subscriptionBillingCycleContractDraftConcatenate
    subscriptionBillingCycleContractEdit subscriptionBillingCycleContractEditCalculate
    subscriptionBillingCycleScheduleEdit subscriptionBillingCycleSkip subscriptionBillingCycleUnskip
    subscriptionContractActivate subscriptionContractAtomicCreate subscriptionContractCalculationCommit
    subscriptionContractCreateCalculate subscriptionContractFail subscriptionContractPause
    subscriptionContractProductChange subscriptionContractSetNextBillingDate subscriptionContractUpdateCalculate tagsAdd
    tagsRemove taxAppConfigure taxSummaryCreate themeCreate themeDuplicate themeUpdate translationsRegister
    translationsRemove urlRedirectCreate urlRedirectImportCreate urlRedirectImportSubmit urlRedirectUpdate
    validationCreate validationUpdate webPixelCreate webPixelUpdate webPresenceCreate webPresenceUpdate
  `.trim().split(/\s+/);
  const heldAll = Object.values(HELD).flatMap((s) => s.trim().split(/\s+/));
  assert.equal(heldAll.length + PASS.length, 484);
  assert.equal(new Set([...heldAll, ...PASS]).size, 484, 'no name twice');
  for (const [id, names] of Object.entries(HELD)) for (const n of names.trim().split(/\s+/)) assert.equal(sh(gql(`mutation { ${n} }`)), id, n);
  for (const n of PASS) assert.equal(sh(gql(`mutation { ${n} }`)), undefined, n);
  // independent of the frozen lists: nothing with delete or destroy in its name, and no gift card or store credit, can pass
  for (const n of PASS) assert.ok(!/delete|destroy|^giftcard|^storecredit/i.test(n), n);
  // the routine writes an operations agent needs stay unattended
  for (const n of ['productCreate', 'productUpdate', 'productSet', 'collectionCreate', 'collectionUpdate', 'customerCreate', 'customerUpdate', 'inventorySetQuantities', 'inventoryAdjustQuantities',
    'orderUpdate', 'orderClose', 'orderOpen', 'fulfillmentCreate', 'draftOrderCreate', 'draftOrderComplete', 'orderCreate', 'metafieldsSet', 'discountCodeBasicCreate', 'fileCreate', 'stagedUploadsCreate'])
    assert.ok(PASS.includes(n), n + ' passes');
});

// ---------------------------------------------------------------- the per-store host
test('Shopify store host: exactly <store>.myshopify.com (SSRF): no port, userinfo, path, IP literal, trailing dot, extra subdomain, punycode or non-ASCII', () => {
  const S = M.PROVIDERS.shopify;
  const ok = (h) => M.storeHost(S, h);
  for (const [i, o] of [['my-store.myshopify.com', 'my-store.myshopify.com'], ['a.myshopify.com', 'a.myshopify.com'], ['0.myshopify.com', '0.myshopify.com'], ['Shop-1.MyShopify.COM', 'shop-1.myshopify.com'],
    ['a'.repeat(63) + '.myshopify.com', 'a'.repeat(63) + '.myshopify.com'], ['x--y.myshopify.com', 'x--y.myshopify.com'], ['a-b-c.myshopify.com', 'a-b-c.myshopify.com']])
    assert.equal(ok(i), o, i);
  const bad = [
    'myshopify.com', '.myshopify.com', 'shop.myshopify.com.', 'shop.myshopify.com:443', 'shop.myshopify.com:80', 'shop.myshopify.com:', 'user@shop.myshopify.com', 'user:pw@shop.myshopify.com', '@shop.myshopify.com',
    'https://shop.myshopify.com', 'http://shop.myshopify.com', '//shop.myshopify.com', 'shop.myshopify.com/', 'shop.myshopify.com/admin', 'shop.myshopify.com?x=1', 'shop.myshopify.com#x', 'shop.myshopify.com\\x',
    'shop.myshopify.com@evil.com', 'shop.myshopify.com%00', 'shop%2emyshopify.com', 'shop.myshopify%2ecom', 'shop.myshopify.com.evil.com', 'evil.com#.myshopify.com', 'evil.com?.myshopify.com', 'evil.com/.myshopify.com',
    'a.b.myshopify.com', 'a.b.c.myshopify.com', 'shop.myshopify.com.evil.com', 'evil.com', 'shopmyshopify.com', 'shop.myshopify.co', 'shop.myshopify.net', 'shop.shopify.com', 'shop.myshopify.com.myshopify.com',
    '-shop.myshopify.com', 'shop-.myshopify.com', '-.myshopify.com', 'sh_op.myshopify.com', 'sh op.myshopify.com', 'sh*op.myshopify.com', 'sh!op.myshopify.com',
    'xn--shop-abc.myshopify.com', 'XN--shop.myshopify.com', 'ab--cd.myshopify.com', 'in--valid.myshopify.com', 'a'.repeat(64) + '.myshopify.com', 'a'.repeat(200) + '.myshopify.com',
    '127.0.0.1', '127.0.0.1:443', '0x7f.0.0.1', '2130706433', '017700000001', '[::1]', '[::1]:443', '[::1].myshopify.com', '::1', '169.254.169.254', '127.0.0.1.myshopify.com', '1.2.3.4.myshopify.com', 'localhost', 'localhost.myshopify.com.',
    ' shop.myshopify.com', 'shop.myshopify.com ', 'shop.myshopify.com\n', 'shop.myshopify.com\r\n', '\tshop.myshopify.com', 'sh\nop.myshopify.com', 'shop.myshopify.com\u0000', 'shop\u0000.myshopify.com',
    'shop\u212a.myshopify.com', 'sh\u017fop.myshopify.com', 'shop\uff0emyshopify.com', 'shop.myshopify.com\u3002', 'sh\u00f6p.myshopify.com', 'shop.myshopify\u2024com', 'shop.myshopify.com\u200b', '\u202eshop.myshopify.com',
    '', ' ', null, undefined, 7, true, {}, [], ['shop.myshopify.com'], { toString: () => 'shop.myshopify.com' }, 'x'.repeat(100000),
  ];
  for (const b of bad) assert.equal(ok(b), null, JSON.stringify(b)?.slice(0, 60));
  assert.equal(M.storeHost(M.PROVIDERS.github, 'shop.myshopify.com'), null, 'only a provider that declares a per-credential host has one');
  assert.equal(M.storeHost(undefined, 'shop.myshopify.com'), null);
  // public receipts never carry the store
  assert.equal(M.publicHost('secret-brand.myshopify.com'), 'myshopify.com');
  assert.equal(M.publicHost('api.github.com'), 'api.github.com');
  assert.equal(M.publicHost('a.b.myshopify.com'), 'myshopify.com');
});

// ---------------------------------------------------------------- end to end through the broker
async function setup(w, provider, secret, { host, policy } = {}) {
  const u = await w.user();
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: 'prod', ...(host !== undefined ? { host } : {}) } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id, policy } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return { u, cred: c.body, token: t.body.token };
}
async function approve(w, u, holdId) {
  const b = await w.req('POST', `/v1/holds/${holdId}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  return w.req('POST', `/v1/holds/${holdId}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
const call = (w, prov, token, method, path, opts = {}) => w.req(method, `/p/${prov}${path}`, { bearer: token, ...P, ...opts });

test('Vercel, Neon, Fly.io and Resend end to end: reads pass to the fixed host with the key injected; irreversible calls are held, approved once, never twice', async () => {
  const secrets = { vercel: 'vcl_' + 'x'.repeat(24), neon: 'napi_' + 'n'.repeat(24), fly: 'FlyV1 fm2_' + 'f'.repeat(40), resend: 're_' + 'r'.repeat(24) };
  const plan = [
    // provider, a read, its upstream URL, auth header, an irreversible call, its rule, how to send it
    ['vercel', ['GET', '/v9/projects?limit=3'], 'https://api.vercel.com/v9/projects?limit=3', 'Bearer ' + secrets.vercel, ['POST', '/v10/projects/prj_1/promote/dpl_1'], 'vc.production'],
    ['neon', ['GET', '/projects'], 'https://console.neon.tech/api/v2/projects', 'Bearer ' + secrets.neon, ['POST', '/projects/p1/branches/br1/restore', J({ source_branch_id: 'br0' })], 'neon.restore'],
    ['fly', ['GET', '/apps?org_slug=personal'], 'https://api.machines.dev/v1/apps?org_slug=personal', 'Bearer ' + secrets.fly, ['DELETE', '/apps/myapp/volumes/vol_1'], 'fly.delete'],
    ['resend', ['GET', '/emails'], 'https://api.resend.com/emails', 'Bearer ' + secrets.resend, ['POST', '/emails/batch', J([{ from: 'a@x.co', to: 'b@y.co', subject: 's' }])], 'rs.batch'],
  ];
  for (const [prov, [rm, rp], url, auth, [bm, bp, bb], id] of plan) {
    const w = new World();
    const { u, token } = await setup(w, prov, secrets[prov]);
    const r = await call(w, prov, token, rm, rp);
    assert.equal(r.status, 200, prov);
    assert.equal(w.upstream.at(-1).url, url, prov);
    assert.equal(w.upstream.at(-1).headers.authorization, auth, prov + ': the real key reaches upstream, exactly as stored');
    const n = w.upstream.length;
    const opts = bb !== undefined ? { raw: bb, headers: { 'content-type': 'application/json' } } : {};
    const h = await call(w, prov, token, bm, bp, opts);
    assert.equal(h.status, 428, prov + ' ' + J(h.body));
    assert.equal(h.body.error, 'held_for_approval');
    assert.equal(h.body.rule, id);
    assert.equal(h.body.map_version, '2026-10-10.1');
    assert.equal(w.upstream.length, n, prov + ': nothing was sent upstream');
    assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
    assert.equal((await call(w, prov, token, bm, bp, opts)).status, 200, prov + ': the approved call goes through once');
    assert.equal(w.upstream.length, n + 1);
    assert.equal((await call(w, prov, token, bm, bp, opts)).status, 428, prov + ': a second attempt waits again');
    const dump = J(w.env.DB.raw.prepare('SELECT * FROM credentials').all()) + J(w.env.DB.raw.prepare('SELECT * FROM audit').all());
    assert.ok(!dump.includes(secrets[prov]), prov + ': the key is stored only encrypted');
  }
});

test('Body rules end to end: Vercel upsert in the query string, and non-UTF-8 or other-charset bodies on Resend and Vercel are refused before anything is sent', async () => {
  const w = new World();
  const v = await setup(w, 'vercel', 'vcl_' + 'v'.repeat(24));
  const env = (q, ct = 'application/json') => call(w, 'vercel', v.token, 'POST', '/v10/projects/prj_1/env' + q, { raw: J({ key: 'A', value: 'b', type: 'plain', target: ['production'] }), headers: { 'content-type': ct } });
  assert.equal((await env('')).status, 200);
  assert.equal((await env('?upsert=false')).status, 200);
  const n = w.upstream.length;
  for (const q of ['?upsert=true', '?upsert=true&upsert=false', '?Upsert=1', '?up%73ert=true']) assert.equal((await env(q)).body.rule, 'vc.env-upsert', q);
  assert.equal(w.upstream.length, n, 'an overwrite never reached Vercel');
  assert.equal((await env('', 'application/json; charset=utf-16')).body.error, 'bad_body');
  const r = await setup(w, 'resend', 're_' + 'r'.repeat(24));
  const bad = (raw, ct = 'application/json') => call(w, 'resend', r.token, 'POST', '/emails', { raw, headers: { 'content-type': ct } });
  assert.equal((await bad(new Uint8Array([0x7b, 0x22, 0x74, 0x6f, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]))).body.error, 'bad_body', 'a byte that is not UTF-8');
  assert.equal((await bad(J({ to: 'a@b.co' }), 'application/json; charset=iso-8859-1')).body.error, 'bad_body', 'another charset');
  assert.equal(w.upstream.length, n);
});

test('Fly.io tokens: the whole line `fly tokens create` prints (with its FlyV1 prefix) is accepted and sent as given; the others are as before', async () => {
  const w = new World();
  const u = await w.user();
  const add = (provider, secret) => w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret } });
  assert.equal((await add('fly', 'FlyV1 fm2_abcdefgh')).status, 200);
  assert.equal((await add('fly', 'fm2_abcdefgh')).status, 200);
  assert.equal((await add('fly', 'FlyV1  fm2_abcdefgh')).body.error, 'bad_secret', 'two spaces');
  assert.equal((await add('fly', ' FlyV1 fm2_abcdefgh')).body.error, 'bad_secret');
  assert.equal((await add('fly', 'FlyV1 fm2_abc defgh')).body.error, 'bad_secret', 'a space inside the token');
  assert.equal((await add('fly', 'FlyV1 fm2_abc\ndefgh')).body.error, 'bad_secret');
  assert.equal((await add('github', 'ghp_ ' + 'a'.repeat(30))).body.error, 'bad_secret', 'no other provider takes a space');
  assert.equal((await add('resend', 'sk_' + 'x'.repeat(20))).body.error, 'bad_secret', 'Resend keys start with re_');
  assert.equal((await add('resend', 're_' + 'x'.repeat(20))).status, 200);
});

test('Resend end to end: one recipient is sent; more than one waits for a passkey and is sent once approved', async () => {
  const w = new World();
  const { u, token } = await setup(w, 'resend', 're_' + 'r'.repeat(24));
  const send = (to) => call(w, 'resend', token, 'POST', '/emails', { raw: J({ from: 'a@x.co', to, subject: 's', text: 't' }), headers: { 'content-type': 'application/json', 'idempotency-key': 'k1' } });
  assert.equal((await send('b@y.co')).status, 200);
  assert.equal(w.upstream.at(-1).headers['idempotency-key'], 'k1');
  const n = w.upstream.length;
  const h = await send(['b@y.co', 'c@y.co']);
  assert.equal(h.status, 428); assert.equal(h.body.rule, 'rs.recipients'); assert.equal(w.upstream.length, n);
  const holds = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds;
  assert.match(holds[0].preview, /c@y\.co/, 'the approver sees every recipient');
  assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
  assert.equal((await send(['b@y.co', 'c@y.co'])).status, 200);
  assert.equal((await send(['b@y.co', 'c@y.co', 'd@y.co'])).status, 428, 'a different list is a different request');
});

test('Shopify end to end: the store address is required and checked, the key goes only to that store, and only the Admin GraphQL endpoint is brokered', async () => {
  const w = new World();
  const KEY = 'shpat_' + 'a'.repeat(32);
  const u = await w.user();
  const add = (body) => w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'shopify', secret: KEY, ...body } });
  assert.equal((await add({})).body.error, 'bad_host', 'a Shopify key needs its store');
  for (const host of ['evil.example.com', 'shop.myshopify.com:443', 'https://shop.myshopify.com', 'a.b.myshopify.com', '127.0.0.1', 'xn--a.myshopify.com', 7, null, ''])
    assert.equal((await add({ host })).body.error, 'bad_host', String(host));
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'shopify', secret: 'sk_live_' + 'a'.repeat(30), host: 'a.myshopify.com' } })).body.error, 'bad_secret', 'the key hint');
  const c = await add({ host: 'Secret-Brand.MyShopify.com', label: 'brand' });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  assert.equal(c.body.host, 'secret-brand.myshopify.com', 'stored in lower case');
  const c2 = await add({ host: 'other-shop.myshopify.com', label: 'other' });
  assert.equal((await w.req('GET', '/v1/credentials', { cookie: u.cookie })).body.credentials.map((x) => x.host).sort().join(), 'other-shop.myshopify.com,secret-brand.myshopify.com');
  // a provider with one fixed address takes no host (each with a key that is otherwise fine)
  const fine = { github: 'ghp_' + 'a'.repeat(36), vercel: 'vcl_' + 'a'.repeat(24), neon: 'napi_' + 'a'.repeat(24), fly: 'FlyV1 fm2_' + 'a'.repeat(24), resend: 're_' + 'a'.repeat(24), stripe: 'sk_test_' + 'a'.repeat(24) };
  for (const [provider, secret] of Object.entries(fine)) {
    const r = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, host: 'secret-brand.myshopify.com' } });
    assert.equal(r.body.error, 'bad_host', provider);
    assert.equal((await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, host: null } })).status, 200, provider + ' accepts a null host');
  }
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id } })).body.token;
  const tok2 = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c2.body.id } })).body.token;
  const q = (token, query, path = DOC) => call(w, 'shopify', token, 'POST', path, { raw: gql(query), headers: { 'content-type': 'application/json' } });
  assert.equal((await q(tok, '{ shop { name } }')).status, 200);
  assert.equal(w.upstream.at(-1).url, 'https://secret-brand.myshopify.com/admin/api/2026-07/graphql.json');
  assert.equal(w.upstream.at(-1).headers['x-shopify-access-token'], KEY);
  assert.equal(w.upstream.at(-1).headers.authorization, undefined);
  assert.equal((await q(tok2, '{ shop { name } }')).status, 200);
  assert.equal(w.upstream.at(-1).url, 'https://other-shop.myshopify.com/admin/api/2026-07/graphql.json', 'each token goes to its own store');
  assert.equal((await q(tok, '{ shop { name } }', '/admin/api/unstable/graphql.json')).status, 200);
  // everything else on the store is refused before anything is sent: REST, storefront pages, app proxies, odd spellings
  const n = w.upstream.length;
  for (const path of ['/admin/api/2026-07/products.json', '/admin/products.json', '/apps/some-proxy/anything', '/cart.js', '/admin/api/2026-07/graphql', '/admin/api/2026-07/graphql.json.json',
    '/Admin/api/2026-07/graphql.json', '/admin/api/2026-07/GraphQL.json', '/admin/api/9999-99/graphql.json', '/admin/api/2026-02/graphql.json', '/admin/api/latest/graphql.json', '/admin/api/2026-07/x/graphql.json',
    '/admin/api//graphql.json', '/api/2026-07/graphql.json', '/admin/oauth/access_token', '/admin/api/2026-07/graphql.json/x'])
    assert.ok([400, 404].includes((await q(tok, '{ shop { name } }', path)).status), path);
  assert.equal((await q(tok, '{ shop { name } }', '/admin/api/2026-07/graphql.json/')).status, 200, 'one trailing slash is the same path');
  assert.equal(w.upstream.length, n + 1, 'nothing else reached the store');
  assert.equal((await q(tok, '{ shop { name } }', '/admin/api/2026-07/products.json')).body.error, 'unsupported_path');
  // a held mutation is shown to its owner with the store, approved once
  const h = await q(tok, 'mutation { orderCancel(orderId: "gid://shopify/Order/1", reason: OTHER, refund: true, restock: true) { job { id } } }');
  assert.equal(h.status, 428); assert.equal(h.body.rule, 'sh.cancel');
  const holds = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds;
  assert.equal(holds[0].host, 'secret-brand.myshopify.com'); assert.match(holds[0].preview, /GraphQL mutations: orderCancel/);
  assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
  const m = w.upstream.length;
  assert.equal((await q(tok, 'mutation { orderCancel(orderId: "gid://shopify/Order/1", reason: OTHER, refund: true, restock: true) { job { id } } }')).status, 200);
  assert.equal(w.upstream.length, m + 1);
  // an approval is for one store: the same document on another store's token is held again
  assert.equal((await q(tok2, 'mutation { orderCancel(orderId: "gid://shopify/Order/1", reason: OTHER, refund: true, restock: true) { job { id } } }')).status, 428);
  // a non-UTF-8 body is refused as for every provider
  const bad = await call(w, 'shopify', tok, 'POST', DOC, { raw: new Uint8Array([0x7b, 0x22, 0x71, 0x22, 0x3a, 0xff, 0x7d]), headers: { 'content-type': 'application/json' } });
  assert.equal(bad.body.error, 'bad_body');
  // and the method override is held here too
  assert.equal((await call(w, 'shopify', tok, 'POST', DOC, { raw: '_method=DELETE', headers: FORM })).body.rule, 'any.method-override');
  assert.equal((await call(w, 'shopify', tok, 'POST', DOC + '?_method=DELETE', { raw: gql('{ shop { name } }'), headers: { 'content-type': 'application/json' } })).body.rule, 'any.method-override');
});

test('Shopify store host cannot be changed behind the broker: the database refuses a bad one, the key no longer decrypts for another, and a bad row stops the call', async () => {
  const w = new World();
  const { cred, token } = await setup(w, 'shopify', 'shpat_' + 'b'.repeat(32), { host: 'mine.myshopify.com' });
  const db = w.env.DB.raw;
  const q = () => call(w, 'shopify', token, 'POST', DOC, { raw: gql('{ shop { name } }'), headers: { 'content-type': 'application/json' } });
  assert.equal((await q()).status, 200);
  for (const bad of ['evil.example.com', 'a.b.myshopify.com', 'MINE.myshopify.com', 'mine.myshopify.com:443', 'x y.myshopify.com', '.myshopify.com', 'mine.myshopify.com.', 'https://x.myshopify.com'])
    assert.throws(() => db.prepare('UPDATE credentials SET host = ? WHERE id = ?').run(bad, cred.id), /CHECK constraint/, bad);
  assert.throws(() => db.prepare("INSERT INTO credentials (id, account_id, provider, label, hint, ct, iv, wrapped_dek, dek_iv, created_at, host) SELECT 'zz', account_id, 'shopify', 'x', 'abcd', ct, iv, wrapped_dek, dek_iv, 1, 'evil.com' FROM credentials LIMIT 1").run(), /CHECK constraint/);
  // someone with write access to the database moves the key to another store: it no longer decrypts (the host is part of its AAD)
  const n = w.upstream.length;
  db.prepare('UPDATE credentials SET host = ? WHERE id = ?').run('attacker.myshopify.com', cred.id);
  const moved = await q();
  assert.equal(moved.status, 500); assert.equal(moved.body.error, 'vault_error');
  assert.equal(w.upstream.length, n, 'nothing was sent to the other store');
  // even with the database check switched off, a host that is not a store stops the call before the key is touched
  db.exec('PRAGMA ignore_check_constraints = ON');
  db.prepare('UPDATE credentials SET host = ? WHERE id = ?').run('evil.example.com', cred.id);
  assert.equal((await q()).body.error, 'bad_host');
  db.prepare('UPDATE credentials SET host = NULL WHERE id = ?').run(cred.id);
  assert.equal((await q()).body.error, 'bad_host', 'a Shopify credential with no store never falls back to anything');
  db.exec('PRAGMA ignore_check_constraints = OFF');
  assert.equal(w.upstream.length, n);
  // the rest of the database is untouched by all this: other providers still work
  const gh = await setup(w, 'github', 'ghp_' + 'g'.repeat(36));
  assert.equal((await call(w, 'github', gh.token, 'GET', '/repos/acme/app')).status, 200);
});

test('Shopify privacy: the store is in the owner\'s private audit log and holds, and never in the public log; the public receipt says only myshopify.com', async () => {
  const w = new World();
  const { u, token, cred } = await setup(w, 'shopify', 'shpat_' + 'c'.repeat(32), { host: 'very-private-brand.myshopify.com' });
  const q = (query) => call(w, 'shopify', token, 'POST', DOC, { raw: gql(query), headers: { 'content-type': 'application/json' } });
  assert.equal((await q('mutation { productUpdate(input: {id: "x"}) { product { id } } }')).status, 200, 'an allowed write is sealed');
  const del = 'mutation { productDelete(input: {id: "gid://shopify/Product/9"}) { deletedProductId } }';
  const h = await q(del);
  assert.equal(h.status, 428);
  assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
  assert.equal((await q(del)).status, 200);
  assert.equal((await q('{ shop { name } }')).status, 200, 'a GraphQL read is a POST, so it is recorded like any POST (the same on GitHub and Railway)');
  const log = (await w.req('GET', '/v1/log/entries?count=100', { ...P })).body.entries;
  assert.deepEqual(log.map((e) => e.entry.receipt.decision), ['allowed', 'held', 'approved', 'executed', 'allowed']);
  for (const { entry } of log) {
    assert.equal(entry.receipt.action.endsWith(' myshopify.com'), true, entry.receipt.action);
    assert.match(entry.receipt.action, /^(POST) myshopify\.com$/);
  }
  assert.equal(log[1].entry.receipt.meta.rule, 'sh.delete'); assert.equal(log[1].entry.receipt.meta.map, '2026-10-10.1');
  // everything the public log holds: its API and every table of its storage
  const storage = w.sql.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => [t.name, w.sql.raw.prepare(`SELECT * FROM ${t.name}`).all()]);
  const text = (v) => J(v, (_, x) => (typeof x === 'bigint' ? String(x) : x instanceof Uint8Array ? Buffer.from(x).toString('latin1') : x));
  for (const dump of [text(log), text(storage), J((await w.req('GET', '/v1/log/checkpoint', { ...P })).body), J((await w.req('GET', '/v1/stats', { ...P })).body)])
    assert.ok(!/private-brand|gid:\/\/shopify|productDelete/i.test(dump), 'nothing about the store or the call in the public log');
  assert.ok(storage.some(([, rows]) => rows.length), 'the dump did look at real rows');
  // the owner's own audit log and holds do name the store
  const audit = (await w.req('GET', '/v1/audit', { cookie: u.cookie })).body.entries;
  assert.ok(audit.some((e) => e.action === 'add_credential' && e.detail.host === 'very-private-brand.myshopify.com'));
  assert.ok(audit.filter((e) => ['hold', 'approve', 'proxy_approved'].includes(e.action)).every((e) => e.detail.host === 'very-private-brand.myshopify.com'));
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
  // the owner can still open any receipt: the parent is the private entry
  const mine = (await w.req('GET', '/v1/my/receipts', { cookie: u.cookie })).body.receipts;
  assert.equal(mine.length, 5);
  assert.equal(cred.host, 'very-private-brand.myshopify.com');
});

test('Method override, duplicate keys and the other parser tricks are held on all ten providers', async () => {
  const paths = { github: '/repos/a/b/issues', cloudflare: '/zones/z/dns_records', railway: '/', stripe: '/v1/customers', supabase: '/v1/projects/p/x', vercel: '/v10/projects/p/domains', neon: '/projects/p/branches',
    fly: '/apps/a/machines', resend: '/contacts', shopify: DOC };
  assert.deepEqual(Object.keys(paths), Object.keys(M.PROVIDERS));
  for (const [prov, path] of Object.entries(paths))
    for (const [b, q] of [['_method=DELETE'], ['%5Fmethod=DELETE'], ['title=x', '?_method=DELETE'], ['{"_method":"DELETE"}'], ['{"_METHOD":"DELETE"}'],
      ['--x\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--x--'], ['a=1;_method=DELETE'], ['_method[]=DELETE']])
      assert.equal(rule(prov, 'POST', path, b, q), 'any.method-override', `${prov} ${b} ${q || ''}`);
  // a value that merely mentions it is not a name
  assert.equal(rule('resend', 'POST', '/contacts', J({ email: 'a@b.co', first_name: '_method' })), undefined);
});

test('Path spellings that could dodge a rule are refused or held: doubled slashes, parameters, dot segments, encoded slashes and dots', () => {
  for (const p of ['/v9/projects//prj_1', '/v9/projects/prj_1;x=1', '/v9/projects/prj_1/../x', '/v9/projects/%2e%2e/x', '/v9/projects/a%2Fb', '/v9/projects/a%5Cb', '/v9/projects/x%00', '/apps/a/machines/m/exec//', '/apps/a/machines/m\\exec'])
    assert.throws(() => canonPath(p), /bad_path/, p);
  assert.equal(canonPath('/apps/a/machines/m/%65xec'), '/apps/a/machines/m/exec', 'an encoded letter is the letter');
  assert.equal(rule('fly', 'POST', canonPath('/apps/a/machines/m/%65%78%65%63')), 'fly.exec');
  assert.equal(rule('fly', 'POST', canonPath('/apps/a/machines/m/EXEC/')), 'fly.exec');
  assert.equal(rule('fly', 'POST', '/apps/a/machines/m/exec.json'), 'fly.exec');
  assert.equal(rule('vercel', 'POST', canonPath('/V10/PROJECTS/P/PROMOTE/D')), 'vc.production');
  assert.equal(rule('neon', 'POST', canonPath('/Projects/p/Branches/b/Restore')), 'neon.restore');
});

test('Shopify and the others are listed in the privacy-safe receipt vocabulary only: method word and host word', () => {
  // brokerReceipt keeps its fixed vocabulary for every new provider
  for (const [host, want] of [['api.vercel.com', 'api.vercel.com'], ['console.neon.tech', 'console.neon.tech'], ['api.machines.dev', 'api.machines.dev'], ['api.resend.com', 'api.resend.com'], ['x.myshopify.com', 'myshopify.com']])
    assert.equal(M.publicHost(host), want);
});
