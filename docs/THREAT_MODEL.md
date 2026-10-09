# Threat model

Counterseal sits between an AI agent and production APIs, records what it decided in a public log, and can require each
agent to sign its own requests. It assumes the agent is **capable, fast, and sometimes wrong**, and that anything the agent
can read on the machine it runs on, an attacker who prompt-injects that agent can read too. Read this with
[PROTOCOL.md](PROTOCOL.md) and [SECURITY.md](../SECURITY.md).

## Assets

1. Real API keys in the vault.
2. The decision of whether an irreversible call happens.
3. The integrity of the audit log and of the public log.
4. The privacy of what accounts and agents do: paths, bodies, names, and who sent which receipt.
5. The meaning of an agent key: "this request was signed by that agent".

## Actors

| Actor | Can | Cannot |
|---|---|---|
| The agent (honest but wrong, or prompt-injected) | Use its `lsh_` token; sign with its agent key; read the CLI config on its machine | See a real key; approve a hold; mint a token with pre-approved irreversible calls; turn receipts off |
| Someone holding a leaked `lsh_` token, unbound | Make the calls that token's policy allows, until it expires or is revoked | Exceed the policy; get past a hold; read the key |
| Someone holding a leaked `lsh_` token bound to an agent key | Nothing: every request is refused before the policy, the rate limit or the upstream | Use it without the agent's private key |
| Someone holding a stolen CLI session | List holds; mint ordinary tokens; register agent keys and bind tokens to them | Approve holds; mint pre-approved tokens; read keys; delete vaulted keys; revoke agent keys; turn receipts on or off; delete the account |
| Someone holding a receipts API key (`lsr_`) | Record receipts within the account's quotas (public, reported, never `source: "broker"`) | Make a broker receipt; record signed receipts without the signer; replay a signed receipt |
| A phishing site | Ask for a passkey | Get an assertion the service accepts (origin and RP ID are bound into it) |
| A malicious web page in the user's browser | Send requests | Write to the API (SameSite=Strict, Origin check, custom header, no CORS on private routes) |
| Anyone on the internet | Read every public log entry, checkpoint and proof; use the signature checker | Learn a path, body, name, email, IP or account id from the log; link entries to each other or to an account |
| An attacker with a database dump | Read ciphertext, hashes, agent public keys, receipt openings | Decrypt keys without the master key; use token or session hashes |
| The operator (holds the log key and the database) | Sign checkpoints; see which account sent which entry | Rewrite the log without anyone who kept a checkpoint noticing |

## Scenarios and mitigations

**S1. Agent finds a token and runs a destructive call (the PocketOS case).** The only tokens on the machine are `lsh_`
tokens. The destructive call matches the irreversible map and is held. Test: *PocketOS replay* (`test/leash.test.js`).

**S2. Agent tries to approve its own hold.** Approval requires a WebAuthn assertion from a web session. CLI sessions get
`403 passkey_required`. Test: *a CLI session can mint tokens but can never approve a hold*.

**S3. Agent tries to change its own policy to skip holds.** `unattendedIrreversible` rules can only be set in a passkey
ceremony. Same test.

**S4. Approval replay.** An approval is bound to the request hash (method, host, path, query, content type, body) and is
consumed atomically on first use. Test: *a passkey approval lets the exact same request through once*.

**S5. Approval stretching.** Approving `DELETE /repos/acme/app` does not cover `DELETE /repos/acme/billing`.

**S6. Path tricks and parser differentials.** Dot segments are collapsed before routing; encoded separators,
backslashes and whitespace are refused; repeated, case-variant or escaped parameters and keys are read every way or held.
Tests: `test/bypass.test.js`, `test/hardening.test.js`.

**S7. Cross-account access (IDOR).** Every query is scoped by account; foreign ids return 404. Tests cover holds,
tokens, credentials, agent keys, receipts keys and receipts.

**S8. Database theft.** Keys are envelope-encrypted with AAD bound to account, row and provider. Tokens, sessions and
receipts keys are stored as SHA-256 hashes. Agent keys are public keys only.

**S9. Log tampering.** The audit log is hash-chained (`/v1/audit/verify`). The public log is an RFC 6962 Merkle tree in
one Durable Object; every checkpoint is signed; consistency proofs link any two checkpoints. The log pins its name and
signing key at the first append and refuses to sign under others. Tests: `test/receipts.test.js`,
`test/merge-hardening.test.js` (R4).

**S10. Phishing for passkeys.** WebAuthn binds origin and RP ID; user verification is required.

### The joints between the three parts

**J1. Receipt forgery.** A receipts API key holder tries to publish something that looks like a broker decision. The
entry-level `source: "broker"` is set only by the broker; the receipts API builds the entry itself and accepts only the
inner receipt's known fields. A reported receipt that copies the broker's words still lacks `source` and verifiers show it
as reported. Test: *Forgery* (`test/joints.test.js`).

**J2. A stolen token used without its agent.** A bound token needs a `leash-pop` RFC 9421 signature by the bound key on
every request. The check runs before the policy, before the token's rate limit (so a thief cannot spend the agent's
budget) and before anything reaches the provider. The owner's audit log notes it, at most once per token every 10
minutes. Test: *Prove who*.

**J3. Signature replay and stretching.** The signature covers the method, the full URL (`@target-uri`), and with a body,
its SHA-256 (`content-digest`, RFC 9530) and its `content-type`; the window is 5 minutes at most; each `(keyid, nonce)` is
accepted once (D1, atomic). A signature for one request does not verify for another method, path, query, body, content
type or host. Tests: *Prove who*, *R2*.

**J4. Signature downgrade.** A bound token never accepts an unsigned request. A Web Bot Auth signature (tag
`web-bot-auth`) is ignored, and relabelling it fails the profile (covered components) and the signature. A revoked or
missing key fails closed (`agent_key_revoked`). Test: *Signature downgrade and cross-protocol*.

**J5. Replay across the three parts.** One Ed25519 key may sign four kinds of text: an RFC 9421 signature base (starts
with `"@`), a receipt's canonical JSON (starts with `{`), a receipts signer proof (`witness/signer-proof/v2\n`) and an
agent key proof (`leash/agent-key-proof/v1\n`). <!-- brand:history --> Because the first bytes differ, a signature over one
can never verify as another. Proof texts name the server origin or log name and the account, and challenges are single
use and bound to the account. Test: an agent key proof is refused as a signer proof.

**J6. Quota bypass and log exhaustion.** Broker receipts and reported receipts draw on the same counters: 10,000 per
account per month, 2,000 per account per UTC day, 10,000 per UTC day for the log, reserved atomically in one statement
before appending and released if anything after fails. When a limit is reached, the broker still decides and writes the
audit log; the receipt is skipped and counted. Refusals once a counter is full cost no D1 write. Reads that reach the
log's Durable Object are limited to 120 a minute per network (public) and 60 a minute per account (your receipts). Test:
*Quota bypass*, *R1*.

**J7. Privacy leaks in public receipts.** A broker receipt is built from fixed vocabulary only (method and provider host,
decision, rule id, map version, two booleans, time, audit hash). Submitters are salted per entry, so entries cannot be
grouped by account. Test: *Privacy* checks that the path, query, body, key, token, ids, name, email and IP never appear
in the log's storage. Residual: the time of a decision is public, so someone who already knows when an account did
something could guess which receipt it is (stated on the privacy page).

**J8. Turning the record off to act unseen.** Turning receipts off needs a fresh passkey ceremony from a web session and
is written to the audit log. A CLI session or an agent cannot do it.

**J9. A log that is down never blocks a decision.** Sealing runs after the response; a failing, full or misconfigured log
only increments the skipped count. Test: *A log that is misconfigured or down*.

## Residual risks

- Irreversible operations the map does not cover. Mitigation: conservative defaults, versioned map, user `hold` rules.
- The human approves the wrong thing. Mitigation: the approve screen shows method, host, path, rule, reason and a preview.
- A compromised agent machine signs for the attacker, and a CLI session on it can mint tokens and register keys. Prove
  who protects a token that leaks elsewhere (logs, screenshots, CI output), not the machine. Approvals still need a
  passkey.
- A signature does not cover the `Authorization` header, so a signed request that failed before its nonce was recorded
  (for example a wrong-provider token) could be replayed with another token bound to the same key, for the same method,
  URL and body only.
- One key signs the checkpoints. A split view is detectable by anyone who keeps checkpoints, not prevented, until
  external witness cosigning (C2SP tlog-witness).
- Durable Object and D1 daily budgets on Workers Free: a flood from many networks can use up the day's budget and stop
  receipts (not decisions) until 00:00 UTC. A Workers Rate Limiting binding and a WAF rule reduce it (docs/DEPLOY.md).
- Master key or log key compromise via the Cloudflare account. Mitigation: hardware-key 2FA on the account.
