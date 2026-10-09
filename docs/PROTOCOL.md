# Protocol

Two wire formats are new in the merged service: receipts in the public log, and agent signatures on proxied requests.
The broker itself is described in the [README](../README.md) and [POLICY.md](POLICY.md).

## Receipts

### Entry

Each receipt is wrapped and canonically encoded (JSON with object keys sorted recursively, RFC 8785 subset), then
appended to the log. Everything in an entry is public and permanent.

Reported by an agent (`POST /v1/receipts` with an `lsr_` key):

```json
{"receipt":{"action":"stripe.refund","agent":"billing-bot","decision":"approved","input_sha256":"..."},"received_at":1791300000000,"submitter":"<hex>","v":2}
```

Written by the broker for its own decision (no API can set `source`):

```json
{"receipt":{"action":"DELETE api.github.com","agent":"broker","decision":"held","meta":{"agent_key":true,"map":"2026-10-09.1","rule":"gh.delete"},"parent":"<SHA-256 of the audit entry>","ts":1791300000000},"received_at":1791300000000,"source":"broker","submitter":"<hex>","v":2}
```

Broker decisions: `allowed` (a write the policy let through), `held`, `approved` (a passkey approved a hold; `meta.passkey`
is true), `executed` (the approved call went through), `denied` (a policy denial or a human denying a hold). Reads (GET,
HEAD) are not recorded. `parent` is the account's own audit entry hash (`/v1/audit` returns it as `hash`, with the entry's
`receipt` index); the audit detail names the path, the token, the agent key and the approving passkey's fingerprint.

`submitter` is a per-entry salted commitment, so entries cannot be grouped by account:

```
submitter = hex(SHA-256("witness/submitter/v2\n" || account_id || "\n" || key_id || "\n" || salt))
```

`key_id` is the receipts API key id, or `broker`. `salt` is 16 random bytes (hex), fresh per entry. The opening
`{account_id, key_id, salt}` is returned only to the owner (`/v1/my/receipts`, `/v1/my/receipts/<index>/bundle`, and
`POST /v1/receipts` responses). Deleting an account erases openings and the server-side link; the entries stay.

Reported receipt fields: `agent` (required, up to 80 characters), `action` (required, up to 80), `subject` (up to 120),
`decision` (`allowed`, `denied`, `held`, `approved`, `executed`, `failed`), `input_sha256`, `output_sha256`, `parent` (hex
SHA-256), `run` (up to 80), `ts` (Unix ms), `meta` (up to 8 keys; strings up to 120 characters, finite numbers or
booleans). No Unicode control, format, surrogate or separator characters. Unknown fields are refused. Batches: up to 25,
or 12 for a key bound to a signer.

`sig` (`{"alg":"ed25519","value":"<base64url>"}` over the canonical receipt without `sig`) is accepted only on a receipts
key bound to a signer, and such a key accepts only signed receipts, with `ts` within 10 minutes of the server clock; each
`(signer, sig)` is accepted once (replay records kept 30 minutes). Binding a signer: `POST /v1/keys/signer/begin
{signerPublicKey}` returns `sign`, the text
`"witness/signer-proof/v2\n" || log name || "\n" || account id || "\n" || challenge || "\n" || signerPublicKey`; sign it and
send `POST /v1/keys {label, signerPublicKey, signerChallengeId, signerProof}`. Or pass `agentKeyId` to reuse a registered
agent key, which already proved possession. <!-- brand:history -->

### Tree, checkpoint, bundle

RFC 6962: `leaf = SHA-256(0x00 || entry)`, `node = SHA-256(0x01 || left || right)`. Proofs per RFC 6962 section 2.1,
verified per RFC 9162 sections 2.1.3.2 and 2.1.4.2.

Checkpoint, a C2SP signed note (`c2sp.org/signed-note`, `c2sp.org/tlog-checkpoint`):

```
counterseal.gautamkhosla.com/log
51907
<base64 root hash>

<U+2014> counterseal.gautamkhosla.com/log <base64(4-byte key hash || 64-byte Ed25519 signature)>
```

The key hash is the first 4 bytes of `SHA-256(name || "\n" || 0x01 || public key)`; the verifier key string is
`name+<key hash hex>+<base64(0x01 || public key)>` (`GET /v1/log/key`). The log's name is fixed for life.

Bundle: `{index, leaf_hash, tree_size, inclusion_proof, checkpoint, entry, log, opening?}`. Verification: the checkpoint
verifies under the pinned key and its size equals `tree_size`; the canonical entry hashes to `leaf_hash`; the proof walks
to the root; an opening, if present, matches `submitter`.

## Agent signatures (profile `leash-pop`)

A token bound to an agent key (`POST /v1/tokens {agentKeyId}`) needs an RFC 9421 signature on every proxied request:

```
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type");created=1791300000;expires=1791300060;keyid="<thumbprint>";alg="ed25519";nonce="<8 to 128 base64 characters>";tag="leash-pop"
Signature: sig1=:<base64 Ed25519 signature over the RFC 9421 signature base>:
Content-Digest: sha-256=:<base64 SHA-256 of the body>:
```

- Required components: `@method`, `@target-uri`; with a body, `content-digest` (and the header must match the body) and,
  when a `Content-Type` is sent, `content-type`. Allowed besides: `@authority`, `@path`, `@query`. No component
  parameters.
- `created` and `expires` are integers; `expires - created` is 300 seconds at most; `created` at most 60 seconds ahead;
  not expired. `alg`, if present, is `ed25519`.
- `keyid` is the RFC 7638 thumbprint (RFC 8037 for OKP) of the bound key: `base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))`.
- Exactly one signature with `tag="leash-pop"`; others are ignored. Each `(keyid, nonce)` is accepted once.
- The signature base is rebuilt from the exact `Signature-Input` member text (RFC 9421 section 2.5).

Registering a key: `POST /v1/agent-keys/begin {publicKey}` (or `{jwk}` without `d`) returns `sign`:
`"leash/agent-key-proof/v1\n" || origin || "\n" || account id || "\n" || challenge || "\n" || x`. Sign it with the private
key and send `POST /v1/agent-keys {label, publicKey, challengeId, proof}`. Small-order and non-canonical keys are refused;
a key belongs to one account; up to 20 active per account. A reference signer is `cli/sign.mjs`.

## Web Bot Auth

The checker and `sdk/websig.mjs` implement draft -00 of `draft-ietf-webbotauth-httpsig-protocol` (September 2026):
`tag="web-bot-auth"`, `@authority` (or `@target-uri`) and the request's own `Signature-Agent` member covered, a window of
an hour at most (5 minutes without a nonce), keys from `<agent origin>/.well-known/http-message-signatures-directory`
matched by thumbprint, Ed25519 only. `Signature-Agent` may be a dictionary (draft -00) or a bare string (earlier drafts);
members with a type other than `directory`, or with a path, are ignored. A directory `kid` is not compared with the
thumbprint.
