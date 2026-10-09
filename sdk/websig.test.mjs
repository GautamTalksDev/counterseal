import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, signRequest, signatureBase, verifyRequest, jwkThumbprint, parseDictionary, directory, directoryUrl, directoryInstructions } from './websig.mjs';
import { verify, safeDirectoryFetcher, memoryNonceStore, d1NonceStore, kvNonceStore, withSigil, expressSigil } from './verifier.mjs';
import { isPublicHttpsUrl, isPrivateIp, expandIPv6, ipNetwork, readCapped, vettedLookup } from './net.mjs';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

const AGENT = 'https://bots.acme.example';
const API = 'https://verifier.example/v1/verify';
const T0 = 1_800_000_000;
async function setup() {
  const id = await generateIdentity();
  const dir = directory([id.publicJwk]);
  const seen = new Set();
  const opts = { fetchDirectory: async (u) => { assert.equal(u, AGENT); return dir; }, seenNonce: async (n) => { if (seen.has(n)) return true; seen.add(n); return false; } };
  return { id, opts };
}
const reqWith = (url, headers, method = 'GET') => ({ method, url, headers: new Headers(headers) });

/** sign with full control over the signature params (to test what verifiers accept) */
async function rawSign(id, url, { agentHeader = `sig1="${AGENT}"`, created = T0, expires = T0 + 60, nonce = 'n-' + Math.random(), keyAgent = 'sig1' } = {}) {
  const headers = new Headers({ 'signature-agent': agentHeader });
  const comps = [{ value: '@authority', params: {} }, { value: 'signature-agent', params: { key: keyAgent } }];
  const paramsRaw = `("@authority" "signature-agent";key="${keyAgent}");created=${created};expires=${expires};keyid="${id.keyid}";alg="ed25519"${nonce ? `;nonce="${nonce}"` : ''};tag="web-bot-auth"`;
  const base = signatureBase({ method: 'GET', url, headers }, comps, paramsRaw, parseDictionary(agentHeader));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, id.privateKey, new TextEncoder().encode(base)));
  return { 'signature-agent': agentHeader, 'signature-input': `${keyAgent}=${paramsRaw}`, signature: `${keyAgent}=:${btoa(String.fromCharCode(...sig))}:` };
}

test('RFC 8037 A.3 thumbprint test vector', async () => {
  // https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3
  assert.equal(await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('structured fields: dictionaries with inner lists, params, strings, bytes', () => {
  const d = parseDictionary('sig1=("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="k";tag="web-bot-auth", sig2=:YWJj:');
  assert.deepEqual(d.get('sig1').list.map((x) => x.value), ['@authority', 'signature-agent']);
  assert.equal(d.get('sig1').list[1].params.key, 'sig1');
  assert.equal(d.get('sig1').params.tag, 'web-bot-auth');
  assert.equal(d.get('sig1').raw, '("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="k";tag="web-bot-auth"');
  assert.equal(d.get('sig2').value.bytes, 'YWJj');
  assert.equal(parseDictionary('a="x, y", b=1').get('a').value, 'x, y', 'commas inside strings');
  assert.equal(parseDictionary('sig1="https://a.example";type="directory"').get('sig1').params.type, 'directory');
});

test('sign then verify; tampering, wrong host, replay, expiry, unknown key all fail', async () => {
  const { id, opts } = await setup();
  const url = 'https://shop.example/api/cart?x=1';
  const h = await signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT, now: T0, expiresIn: 60 });
  const ok = await verifyRequest(reqWith(url, h), { ...opts, now: T0 + 10 });
  assert.equal(ok.ok, true, ok.reason); assert.equal(ok.agent, AGENT); assert.equal(ok.keyid, id.keyid);
  assert.equal((await verifyRequest(reqWith(url, h), { ...opts, now: T0 + 11 })).reason, 'replayed');
  const h2 = await signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT, now: T0 });
  assert.equal((await verifyRequest(reqWith('https://other.example/api/cart', h2), { ...opts, now: T0 + 10 })).reason, 'bad signature', 'signature is bound to the host');
  assert.equal((await verifyRequest(reqWith(url, h2), { ...opts, now: T0 + 100 })).reason, 'expired');
  const forged = { ...h2, 'signature-agent': 'sig1="https://evil.example"' };
  assert.notEqual((await verifyRequest(reqWith(url, forged), { ...opts, fetchDirectory: async () => directory([id.publicJwk]), now: T0 + 10 })).ok, true, 'swapping the agent breaks the signature');
  const other = await generateIdentity();
  const h3 = await signRequest({ url }, { key: other.privateKey, keyid: other.keyid, agent: AGENT, now: T0 });
  assert.equal((await verifyRequest(reqWith(url, h3), { ...opts, now: T0 + 10 })).reason, 'keyid not in the agent directory');
  assert.equal((await verifyRequest(reqWith(url, {}), opts)).reason, 'unsigned');
});

test('windows: max 1 hour; without a nonce max 5 minutes; requireNonce refuses nonce-less signatures', async () => {
  const { id, opts } = await setup();
  const url = 'https://shop.example/';
  await assert.rejects(signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT, expiresIn: 3601 }), /1 hour/);
  await assert.rejects(signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT, expiresIn: 86400 }), /1 hour/);
  const hour = await signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT, expiresIn: 3600, now: T0 });
  assert.equal((await verifyRequest(reqWith(url, hour), { ...opts, now: T0 + 5 })).ok, true);
  const day = await rawSign(id, url, { expires: T0 + 86400 });
  assert.match((await verifyRequest(reqWith(url, day), { ...opts, now: T0 + 5 })).reason, /over 60 minutes/);
  const longNoNonce = await rawSign(id, url, { expires: T0 + 600, nonce: null });
  assert.match((await verifyRequest(reqWith(url, longNoNonce), { ...opts, now: T0 + 5 })).reason, /without a nonce.*5 minutes/);
  const shortNoNonce = await rawSign(id, url, { expires: T0 + 300, nonce: null });
  assert.equal((await verifyRequest(reqWith(url, shortNoNonce), { ...opts, now: T0 + 5 })).ok, true, '5 minutes without a nonce is allowed locally');
  assert.equal((await verifyRequest(reqWith(url, shortNoNonce), { ...opts, now: T0 + 5, requireNonce: true })).reason, 'nonce required');
  const inverted = await rawSign(id, url, { created: T0 + 60, expires: T0 });
  assert.match((await verifyRequest(reqWith(url, inverted), { ...opts, now: T0 + 5 })).reason, /after created/);
});

test('draft compliance: Signature-Agent type parameter and path-bearing members', async () => {
  const { id, opts } = await setup();
  const url = 'https://shop.example/';
  const typed = await rawSign(id, url, { agentHeader: `sig1="${AGENT}";type="directory"` });
  assert.equal((await verifyRequest(reqWith(url, typed), { ...opts, now: T0 + 5 })).ok, true, 'type="directory" is understood');
  let fetched = false;
  const unknown = await rawSign(id, url, { agentHeader: `sig1="${AGENT}";type="jwks-over-carrier-pigeon"` });
  const r1 = await verifyRequest(reqWith(url, unknown), { ...opts, fetchDirectory: async () => { fetched = true; return directory([id.publicJwk]); }, now: T0 + 5 });
  assert.equal(r1.ok, false); assert.equal(r1.reason, 'unsupported Signature-Agent type'); assert.equal(fetched, false, 'ignored members are never fetched');
  const pathy = await rawSign(id, url, { agentHeader: `sig1="${AGENT}/keys/dir.json"` });
  const r2 = await verifyRequest(reqWith(url, pathy), { ...opts, fetchDirectory: async () => { fetched = true; return directory([id.publicJwk]); }, now: T0 + 5 });
  assert.equal(r2.ok, false); assert.match(r2.reason, /bare origin/); assert.equal(fetched, false);
  // an ignored signature does not stop a good one on the same request
  const good = await rawSign(id, url, { agentHeader: `sig2="${AGENT}"`, keyAgent: 'sig2' });
  const both = { 'signature-agent': `${unknown['signature-agent']}, ${good['signature-agent']}`, 'signature-input': `${unknown['signature-input']}, ${good['signature-input']}`, signature: `${unknown.signature}, ${good.signature}` };
  const r3 = await verifyRequest(reqWith(url, both), { ...opts, now: T0 + 5 });
  assert.equal(r3.ok, true, r3.reason); assert.equal(r3.label, 'sig2');
  await assert.rejects(signRequest({ url }, { key: id.privateKey, keyid: id.keyid, agent: AGENT + '/keys' }), /bare origin/);
  assert.equal(directoryUrl('https://a.example/x/y?z'), 'https://a.example/.well-known/http-message-signatures-directory');
  const ins = directoryInstructions('https://bots.acme.example/', [id.publicJwk]);
  assert.equal(ins.headers['content-type'], 'application/http-message-signatures-directory+json');
  assert.equal(ins.signatureAgent, 'sig1="https://bots.acme.example"');
});

test('signature base matches RFC 9421 layout', () => {
  const req = reqWith('https://example.com/foo', { 'signature-agent': 'sig1="https://a.example"' });
  const base = signatureBase(req, [{ value: '@authority', params: {} }, { value: 'signature-agent', params: { key: 'sig1' } }], '("@authority" "signature-agent";key="sig1");created=1;keyid="k"');
  assert.equal(base, '"@authority": example.com\n"signature-agent";key="sig1": "https://a.example"\n"@signature-params": ("@authority" "signature-agent";key="sig1");created=1;keyid="k"');
});

test('net: public host rules, private ranges (v4, v6, mapped), IPv6 expansion and /64 networks', () => {
  for (const ok of ['https://bots.acme.com', 'https://a.b.co.uk/', 'https://x.io:443']) assert.equal(isPublicHttpsUrl(ok), true, ok);
  for (const bad of ['http://bots.acme.com', 'https://127.0.0.1', 'https://[::1]', 'https://localhost', 'https://a.internal', 'https://a.local', 'https://x.com:8443', 'https://u:p@x.com', 'https://intranet', 'https://0x7f000001', 'https://2130706433']) assert.equal(isPublicHttpsUrl(bad), false, bad);
  for (const p of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::a00:1', '2001:db8::1', 'ff02::1', '2002:a00:1::']) assert.equal(isPrivateIp(p), true, p);
  for (const p of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8', '2001:4860:4860::8888']) assert.equal(isPrivateIp(p), false, p);
  // cloud metadata and platform endpoints, IPv4 and IPv6: AWS/GCP/Azure 169.254.169.254, Alibaba 100.100.100.200,
  // Azure WireServer 168.63.129.16, AWS IMDS over IPv6 fd00:ec2::254, the same through IPv4-mapped and NAT64 forms
  for (const p of ['169.254.169.254', '100.100.100.200', '168.63.129.16', 'fd00:ec2::254', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '64:ff9b::a9fe:a9fe', '3fff::1', '192.0.0.192', 'not-an-ip', '']) assert.equal(isPrivateIp(p), true, p);
  assert.deepEqual(expandIPv6('2001:db8::1'), ['2001', '0db8', '0000', '0000', '0000', '0000', '0000', '0001']);
  assert.deepEqual(expandIPv6('::'), Array(8).fill('0000'));
  assert.equal(expandIPv6('1::2::3'), null);
  assert.equal(ipNetwork('2001:db8::1'), '2001:0db8:0000:0000::/64');
  assert.equal(ipNetwork('2001:db8::1'), ipNetwork('2001:db8:0:0:ffff::2'));
  assert.notEqual(ipNetwork('2001:db8::1'), ipNetwork('2001:db8:0:1::1'));
  assert.equal(ipNetwork('203.0.113.9'), '203.0.113.9');
});

test('local verifier: SSRF checks, DNS to private ranges refused, origin only, response size capped, no redirects', async () => {
  const calls = [];
  const fetchOk = async (u, init) => { calls.push([u, init.redirect]); return new Response('{"keys":[]}'); };
  const pub = async () => [{ address: '93.184.216.34' }];
  const f = safeDirectoryFetcher({ fetch: fetchOk, lookup: pub });
  assert.deepEqual(await f('https://bots.acme.com'), { keys: [] });
  assert.deepEqual(calls[0], ['https://bots.acme.com/.well-known/http-message-signatures-directory', 'error']);
  for (const bad of ['https://127.0.0.1', 'https://localhost', 'http://bots.acme.com', 'https://bots.acme.com:8443', 'https://x.internal']) await assert.rejects(f(bad), /not allowed/, bad);
  const rebind = safeDirectoryFetcher({ fetch: fetchOk, lookup: async () => [{ address: '93.184.216.34' }, { address: '10.0.0.5' }] });
  await assert.rejects(rebind('https://evil-rebind.com'), /not allowed/, 'any private answer is refused');
  const v6 = safeDirectoryFetcher({ fetch: fetchOk, lookup: async () => [{ address: '::ffff:169.254.169.254' }] });
  await assert.rejects(v6('https://evil-v6.com'), /not allowed/);
  const huge = safeDirectoryFetcher({ fetch: async () => new Response('x'.repeat(70000)), lookup: pub });
  await assert.rejects(huge('https://big.acme.com'), /too large/);
  const lying = safeDirectoryFetcher({ fetch: async () => new Response(new ReadableStream({ start(c) { for (let i = 0; i < 20; i++) c.enqueue(new Uint8Array(8192)); c.close(); } })), lookup: pub });
  await assert.rejects(lying('https://stream.acme.com'), /too large/, 'streamed bodies are counted, not trusted');
  await assert.rejects(readCapped(new Response('abc', { headers: { 'content-length': '999999' } })), /too large/);
  const malformed = safeDirectoryFetcher({ fetch: async () => new Response('{"nokeys":1}'), lookup: pub });
  await assert.rejects(malformed('https://bad.acme.com'), /malformed/);
});

test('net: vettedLookup checks every answer when the socket asks (v4, v6, mapped, metadata), in both callback shapes', async () => {
  const ask = (lk, opts) => new Promise((done) => lk('dir.acme.com', opts, (err, a, f) => done({ err, a, f })));
  const pub = vettedLookup(async () => [{ address: '93.184.216.34', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }]);
  assert.deepEqual((await ask(pub, { all: true })).a, [{ address: '93.184.216.34', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }]);
  assert.deepEqual(await ask(pub, {}), { err: null, a: '93.184.216.34', f: 4 });
  assert.equal((await ask(pub, { family: 6 })).a, '2606:4700:4700::1111');
  assert.equal((await ask(pub, 4)).a, '93.184.216.34', 'numeric family form');
  assert.equal((await ask(vettedLookup(async () => ['8.8.8.8']), { all: true })).a[0].address, '8.8.8.8', 'plain string answers');
  // one bad address anywhere in the answer refuses the whole answer, so the socket can never pick it
  for (const bad of ['127.0.0.1', '10.0.0.5', '172.16.9.9', '192.168.0.1', '169.254.169.254', '100.100.100.200', '168.63.129.16', '0.0.0.0',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd00:ec2::254', '::ffff:127.0.0.1', '::ffff:169.254.169.254', '64:ff9b::a00:1', '2002:a00:1::', 'garbage']) {
    const r = await ask(vettedLookup(async () => [{ address: '93.184.216.34' }, { address: bad }]), { all: true });
    assert.match(String(r.err && r.err.message), /not allowed/, bad);
  }
  assert.match((await ask(vettedLookup(async () => []), {})).err.message, /not allowed/, 'empty answer');
  assert.equal((await ask(vettedLookup(async () => { throw Object.assign(new Error('nope'), { code: 'ENOTFOUND' }); }), {})).err.code, 'ENOTFOUND');
  assert.match((await ask(pub, { family: 7 })).a, /^93\./, 'unknown family values mean any');
});

/** stands in for node:https.request and does what node:net does with options.lookup: ask it, then connect to its answer */
function fakeHttps({ status = 200, body = '{"keys":[]}', connectTo } = {}) {
  const log = { connects: [], responses: 0, opts: null };
  const request = (url, opts, onResponse) => {
    const req = new EventEmitter();
    req.end = () => {
      log.opts = opts;
      const sock = new EventEmitter();
      sock.destroy = (e) => { sock.destroyed = true; req.emit('error', e); };
      req.emit('socket', sock);
      opts.lookup(new URL(url).hostname, { all: true }, (err, addrs) => {
        if (err) return req.emit('error', err);
        sock.remoteAddress = connectTo || addrs[0].address; // connectTo: a runtime that ignores the lookup option
        log.connects.push(sock.remoteAddress);
        sock.emit('connect');
        if (sock.destroyed) return;
        log.responses++;
        onResponse(Object.assign(Readable.from([Buffer.from(body)]), { statusCode: status, headers: { 'content-type': 'application/json' } }));
      });
    };
    return req;
  };
  return { request, log };
}

test('local verifier on Node: DNS is resolved once, at connect time, and the socket goes to the checked address (no DNS rebinding)', async () => {
  let answers = 0;
  const rebinding = async () => (++answers === 1 ? [{ address: '93.184.216.34' }] : [{ address: '127.0.0.1' }]);
  const t = fakeHttps();
  const f = safeDirectoryFetcher({ lookup: rebinding, request: t.request });
  assert.deepEqual(await f('https://rebind.attacker-example.com'), { keys: [] });
  assert.equal(answers, 1, 'one resolution per fetch: there is no separate pre-check to rebind against');
  assert.deepEqual(t.log.connects, ['93.184.216.34'], 'connected to the address that was checked');
  assert.equal(t.log.opts.agent, false, 'no pooled connection reuse');
  assert.equal(t.log.opts.method, 'GET');
  assert.match(t.log.opts.headers.accept, /http-message-signatures-directory/);
  // the next answer is private: refused inside the lookup, nothing connects
  await assert.rejects(safeDirectoryFetcher({ lookup: rebinding, request: t.request })('https://rebind2.attacker-example.com'), /not allowed/);
  assert.deepEqual(t.log.connects, ['93.184.216.34']);
  // backstop: if a runtime ignored the lookup option and connected elsewhere, the peer address is checked before any request
  const sneaky = fakeHttps({ connectTo: '169.254.169.254' });
  await assert.rejects(safeDirectoryFetcher({ lookup: async () => [{ address: '93.184.216.34' }], request: sneaky.request })('https://x.acme.com'), /not allowed/);
  assert.equal(sneaky.log.responses, 0);
  const v6 = fakeHttps({ connectTo: 'fd00:ec2::254' });
  await assert.rejects(safeDirectoryFetcher({ lookup: async () => [{ address: '2606:4700:4700::1111' }], request: v6.request })('https://y.acme.com'), /not allowed/);
  // redirects are not followed, bodies stay capped, URL rules still apply before any DNS
  const redirect = fakeHttps({ status: 302 });
  await assert.rejects(safeDirectoryFetcher({ lookup: async () => ['93.184.216.34'], request: redirect.request })('https://r.acme.com'), /HTTP 302/);
  const big = fakeHttps({ body: 'x'.repeat(70000) });
  await assert.rejects(safeDirectoryFetcher({ lookup: async () => ['93.184.216.34'], request: big.request })('https://big.acme.com'), /too large/);
  let asked = 0;
  const g = safeDirectoryFetcher({ lookup: async () => { asked++; return ['93.184.216.34']; }, request: fakeHttps().request });
  for (const bad of ['https://127.0.0.1', 'https://localhost', 'http://bots.acme.com', 'https://bots.acme.com:8443', 'https://x.internal']) await assert.rejects(g(bad), /not allowed/, bad);
  assert.equal(asked, 0);
});

test('local verifier on Node, real node:https: the socket uses the vetted lookup (refused before connecting, no network needed)', async () => {
  for (const address of ['127.0.0.1', '169.254.169.254', 'fd00:ec2::254', '::1']) {
    let asked = 0;
    const f = safeDirectoryFetcher({ lookup: async (h) => { asked++; assert.equal(h, 'directory.websig-rebind-check.com'); return [{ address }]; } });
    await assert.rejects(f('https://directory.websig-rebind-check.com'), (e) => /not allowed/.test(e.message) && e.code === 'ESIGILBLOCKED', address);
    assert.equal(asked, 1, address);
  }
});

test('local mode end to end, with a shared nonce store adapter', async () => {
  const id = await generateIdentity();
  const agent = 'https://bots.acme.com';
  const fetchDirectory = safeDirectoryFetcher({ fetch: async () => Response.json(directory([id.publicJwk])), lookup: async () => [{ address: '93.184.216.34' }] });
  const store = memoryNonceStore();
  const h = await signRequest({ url: 'https://shop.example/' }, { key: id.privateKey, keyid: id.keyid, agent });
  const req = () => new Request('https://shop.example/', { headers: h });
  const a = await verify(req(), { mode: 'local', fetchDirectory, nonceStore: store });
  assert.equal(a.verified, true, a.reason);
  assert.equal((await verify(req(), { mode: 'local', fetchDirectory, nonceStore: store })).reason, 'replayed', 'a second instance sharing the store sees the replay');
});

test('nonce store adapters: D1 and KV shapes', async () => {
  const rows = new Set();
  const db = { prepare: (sql) => ({ bind: (k) => ({ run: async () => { assert.match(sql, /ON CONFLICT\(k\) DO NOTHING/); if (rows.has(k)) return { meta: { changes: 0 } }; rows.add(k); return { meta: { changes: 1 } }; } }) }) };
  const d1 = d1NonceStore(db);
  assert.equal(await d1.seen('n1', T0, 'k'), false);
  assert.equal(await d1.seen('n1', T0, 'k'), true);
  assert.equal(await d1.seen('n1', T0, 'other-key'), false, 'nonces are scoped per key');
  assert.throws(() => d1NonceStore(db, 'x; DROP TABLE y'), /bad table/);
  const kvm = new Map();
  const kv = kvNonceStore({ get: async (k) => kvm.get(k) ?? null, put: async (k, v, o) => { assert.ok(o.expirationTtl >= 60); kvm.set(k, v); } });
  assert.equal(await kv.seen('n', Math.floor(Date.now() / 1000) + 60, 'k'), false);
  assert.equal(await kv.seen('n', Math.floor(Date.now() / 1000) + 60, 'k'), true);
});

test('API mode fails closed: network error, non-2xx, junk body, or a spoofed operator without verified', async () => {
  const id = await generateIdentity();
  const h0 = await signRequest({ url: 'https://shop.example/' }, { key: id.privateKey, keyid: id.keyid, agent: AGENT });
  assert.equal((await verify(new Request('https://shop.example/', { headers: h0 }), { mode: 'api' })).verified, false, 'no verify API named: never verified');
  const h = await signRequest({ url: 'https://shop.example/' }, { key: id.privateKey, keyid: id.keyid, agent: AGENT });
  const req = () => new Request('https://shop.example/', { headers: h });
  assert.equal((await verify(req(), { mode: 'api', api: API, fetch: async () => { throw new Error('down'); } })).verified, false);
  const e500 = await verify(req(), { mode: 'api', api: API, fetch: async () => Response.json({ verified: true }, { status: 500 }) });
  assert.equal(e500.verified, false); assert.match(e500.reason, /HTTP 500/);
  assert.equal((await verify(req(), { mode: 'api', api: API, fetch: async () => new Response('<html>') })).verified, false);
  const weird = await verify(req(), { mode: 'api', api: API, fetch: async () => Response.json({ verified: 'yes', operator: { slug: 'x' } }) });
  assert.equal(weird.verified, false); assert.equal(weird.operator, null);
  const good = await verify(req(), { mode: 'api', api: API, fetch: async (u, init) => { assert.equal(init.redirect, 'error'); return Response.json({ verified: true, operator: { slug: 'acme', purpose: 'shopping' } }); } });
  assert.equal(good.verified, true); assert.equal(good.operator.slug, 'acme');
  // withSigil: headers from the client are stripped, ours are set only when verified
  const app = withSigil(async (r) => new Response(JSON.stringify([r.headers.get('x-signed-agent-verified'), r.headers.get('x-signed-agent-operator')])), { mode: 'api', api: API, fetch: async () => Response.json({ verified: false }, { status: 502 }) });
  const spoof = new Request('https://shop.example/', { headers: { ...h, 'x-signed-agent-verified': '1', 'x-signed-agent-operator': 'admin' } });
  assert.deepEqual(await (await app(spoof)).json(), [null, null]);
  const anyPrefix = withSigil(async (r) => new Response(String([...r.headers.keys()].filter((k) => k.startsWith('x-signed-agent')).length)), { mode: 'api', api: API, fetch: async () => Response.json({ verified: false }, { status: 502 }) });
  assert.equal(await (await anyPrefix(new Request('https://shop.example/', { headers: { 'X-Signed-Agent-Trust': 'high', 'x-signed-agent-whatever': '1' } }))).text(), '0', 'every x-signed-agent-* header from the client is removed');
  const strict = withSigil(async () => new Response('in'), { require: true, mode: 'api', api: API, fetch: async () => new Response('', { status: 503 }) });
  assert.equal((await strict(req())).status, 401);
});

test('Express middleware: fixed origin ignores the Host header; require blocks when the verifier is down', async () => {
  const id = await generateIdentity();
  const h = await signRequest({ url: 'https://shop.example/x' }, { key: id.privateKey, keyid: id.keyid, agent: AGENT });
  let sentUrl;
  const mw = expressSigil({ origin: 'https://shop.example', mode: 'api', api: API, fetch: async (u, init) => { sentUrl = JSON.parse(init.body).url; return Response.json({ verified: true }); } });
  const req = { protocol: 'http', get: () => 'evil.example', originalUrl: '/x', method: 'GET', headers: { ...h, host: 'evil.example' } };
  await new Promise((done) => mw(req, {}, done));
  assert.equal(sentUrl, 'https://shop.example/x');
  assert.equal(req.sigil.verified, true);
  const res = { code: 0, status(c) { this.code = c; return this; }, set() { return this; }, send() { return this; } };
  const blocked = expressSigil({ require: true, mode: 'api', api: API, fetch: async () => new Response('', { status: 500 }) });
  let nextCalled = false;
  await blocked({ ...req }, res, () => { nextCalled = true; });
  assert.equal(res.code, 401); assert.equal(nextCalled, false);
});
