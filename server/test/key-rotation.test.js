// Rotating the vault's master key (LEASH_KEK) without losing a stored secret: docs/KEY_ROTATION.md, tested end to end.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { seal, open, rewrap } from '../src/vault.js';
import { b64u } from '../src/util.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const anon = { origin: null, xleash: false };
const TOKEN = 'st_' + 'r'.repeat(40);
const newKey = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
const SECRET = 'ghp_' + 'R'.repeat(36);

test('vault: a row sealed with the old key opens with LEASH_KEK_OLD, rewraps to the new key, then opens without it', async () => {
  const k1 = newKey(), k2 = newKey();
  const meta = { id: 'cred_1', accountId: 'acct_1', provider: 'github' };
  const s = await seal({ LEASH_KEK: k1 }, meta, SECRET);
  const row = { id: 'cred_1', account_id: 'acct_1', provider: 'github', host: null, ...s };
  assert.equal(await open({ LEASH_KEK: k1 }, row), SECRET);
  assert.equal(await rewrap({ LEASH_KEK: k1 }, row), null, 'already on the current key');
  await assert.rejects(open({ LEASH_KEK: k2 }, row), { status: 500, code: 'vault_error' }, 'a new key alone cannot open old rows');
  const env = { LEASH_KEK: k2, LEASH_KEK_OLD: k1 };
  assert.equal(await open(env, row), SECRET, 'read during the rotation');
  const w = await rewrap(env, row);
  assert.ok(w && w.wrapped_dek !== row.wrapped_dek);
  const moved = { ...row, ...w };
  assert.equal(moved.ct, row.ct, 'the secret\'s ciphertext is untouched');
  assert.equal(await open({ LEASH_KEK: k2 }, moved), SECRET, 'after the rotation the old key is not needed');
  await assert.rejects(open({ LEASH_KEK: k1 }, moved), { code: 'vault_error' });
  assert.equal(await rewrap(env, moved), null);
  // a row from a third key opens with neither
  await assert.rejects(rewrap({ LEASH_KEK: k2, LEASH_KEK_OLD: newKey() }, row), { code: 'vault_error' });
  // the AAD still binds the wrapped key to its row: a rewrapped key moved to another row id does not open
  await assert.rejects(open({ LEASH_KEK: k2 }, { ...moved, id: 'cred_2' }), { code: 'vault_error' });
});

test('POST /v1/admin/vault/rewrap: hidden without the token; moves every sealed row; proxy works before, during, after', async () => {
  const w = new World();
  const rw = (body, bearer = TOKEN) => w.req('POST', '/v1/admin/vault/rewrap', { ...anon, bearer, body });
  assert.equal((await rw({})).status, 404, 'no ADMIN_TOKEN: the route does not exist');
  w.env.STATS_TOKEN = TOKEN;
  assert.equal((await rw({})).status, 404, 'the read-only stats token cannot rewrap (gate L1)');
  w.env.ADMIN_TOKEN = TOKEN;
  assert.equal((await rw({}, 'wrong')).status, 404);
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: SECRET } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  const call = async () => {
    const before = w.upstream.length;
    const r = await w.req('GET', '/p/github/user', { ...anon, bearer: tok });
    return { status: r.status, sent: JSON.stringify(w.upstream.slice(before)).includes(SECRET) };
  };
  assert.deepEqual(await call(), { status: 200, sent: true });
  const raw = w.env.DB.raw;
  raw.prepare("INSERT INTO channels (id, account_id, kind, label, host, ct, iv, wrapped_dek, dek_iv, created_at) SELECT 'ch_x', account_id, 'slack', 'l', 'hooks.slack.com', ct, iv, wrapped_dek, dek_iv, 1 FROM credentials").run();
  const before = raw.prepare('SELECT id, ct, wrapped_dek FROM credentials').get();
  // nothing to do while there is one key
  let r = await rw({});
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual([r.body.credentials.rewrapped, r.body.credentials.checked, r.body.done, r.body.rotating], [0, 1, true, false]);
  // rotate: new key in, old key kept as LEASH_KEK_OLD
  const k1 = w.env.LEASH_KEK;
  w.env.LEASH_KEK = newKey(); w.env.LEASH_KEK_OLD = k1;
  assert.deepEqual(await call(), { status: 200, sent: true }, 'during the rotation');
  r = await rw({});
  assert.deepEqual(r.body.credentials, { checked: 1, rewrapped: 1, failed: 0, next: null });
  assert.equal(r.body.channels.failed, 1, 'the copied row has the wrong AAD for its id, so it is counted, not changed');
  assert.ok(!JSON.stringify(r.body).includes(SECRET) && !JSON.stringify(r.body).includes(before.wrapped_dek));
  const after = raw.prepare('SELECT id, ct, wrapped_dek FROM credentials').get();
  assert.equal(after.ct, before.ct); assert.notEqual(after.wrapped_dek, before.wrapped_dek);
  assert.equal((await rw({})).body.credentials.rewrapped, 0, 'a second pass finds nothing left');
  delete w.env.LEASH_KEK_OLD;
  assert.deepEqual(await call(), { status: 200, sent: true }, 'after the rotation, without the old key');
  // a pass with a cursor past the end and a table marked done
  r = await rw({ after: { credentials: 'zzzz', channels: null } });
  assert.deepEqual([r.body.credentials.checked, r.body.channels.next, r.body.done], [0, null, true]);
});

test('rotation without a copy of the current key: LEASH_KEK_NEXT wraps, LEASH_KEK still opens, then NEXT becomes LEASH_KEK', async () => {
  const w = new World();
  w.env.ADMIN_TOKEN = TOKEN;
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: SECRET } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  const ok = async () => (await w.req('GET', '/p/github/user', { ...anon, bearer: tok })).status === 200 && JSON.stringify(w.upstream.at(-1)).includes(SECRET);
  const next = newKey();
  w.env.LEASH_KEK_NEXT = next;
  assert.ok(await ok(), 'old rows open with LEASH_KEK while NEXT is set');
  // a key added during the rotation is wrapped with NEXT straight away
  const SECRET2 = 'ghp_' + 'N'.repeat(36);
  const cred2 = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: SECRET2 } })).body.id;
  const r = await w.req('POST', '/v1/admin/vault/rewrap', { ...anon, bearer: TOKEN, body: {} });
  assert.deepEqual([r.body.credentials.checked, r.body.credentials.rewrapped, r.body.rotating, r.body.done], [2, 1, true, true]);
  // finish: NEXT becomes LEASH_KEK, NEXT is removed; the outgoing key is gone for good
  w.env.LEASH_KEK = next; delete w.env.LEASH_KEK_NEXT;
  assert.ok(await ok(), 'after the rotation');
  const tok2 = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred2 } })).body.token;
  assert.equal((await w.req('GET', '/p/github/user', { ...anon, bearer: tok2 })).status, 200);
  assert.ok(JSON.stringify(w.upstream.at(-1)).includes(SECRET2));
});
