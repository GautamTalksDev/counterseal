// Generates the log's Ed25519 signing key as {"d","x"} for `wrangler secret put LOG_KEY_JWK`, and prints the public
// verifier key to publish. The private part goes to stdout only once; pipe it straight into wrangler.
const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const j = await crypto.subtle.exportKey('jwk', kp.privateKey);
process.stderr.write(`public key (x): ${j.x}\n`);
process.stdout.write(JSON.stringify({ d: j.d, x: j.x }));
