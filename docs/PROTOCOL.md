# Protocol

Two wire formats are new in the merged service: receipts in the public log, and agent signatures on proxied requests.
A third, the Approvals API for a coding agent's commands, and the team API of the two-person seal are below. The broker
itself is described in the [README](../README.md) and [POLICY.md](POLICY.md).

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

The host word is the provider's fixed API host (`api.vercel.com`, `console.neon.tech`, `api.machines.dev`, `api.resend.com`, ...). For Shopify, whose
calls go to the merchant's own store, it is only `myshopify.com`: the store address is never in the public log.

Broker decisions: `allowed` (a write the policy let through), `held`, `approved` (a passkey approved a hold; `meta.passkey`
is true), `executed` (the approved call went through), `denied` (a policy denial or a human denying a hold). Allowed reads
(GET, HEAD) are not recorded; a read that is held or denied is. `parent` is the account's own audit entry hash (`/v1/audit` returns it as `hash`, with the entry's
`receipt` index); the audit detail names the path, the token, the agent key and the approving passkey's fingerprint.

The brakes add rule ids and nothing else: `st.money:capped` (a Stripe refund or payout allowed under a token's money caps),
`brake.money-per-call`, `brake.money-per-day`, `brake.money-currency` and `brake.money-unreadable` (held by a money cap), and
`brake.tripped` (held because the token's breaker tripped). A receipt never carries an amount, a currency or a charge id,
and a freeze, an unfreeze or a breaker reset is not a receipt: those are in the account's private audit log only.

The two-person seal adds two numbers to an `approved` receipt when the team required more than one seal: `meta.quorum`
(seals required) and `meta.votes` (seals given). Never who sealed, which passkey or when; a seal that does not complete
the quorum is not a receipt (it is `approve_vote` in the private audit log). See [Team](#team-the-two-person-seal).

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

## Approvals for what the broker does not proxy

For actions that never pass through a brokered API (a coding agent's shell command, an MCP tool call). A hook on the
agent's machine holds a **guard key** and asks; a human approves in the app with a passkey. The holds table, alerts,
approve and deny routes and receipts are the same as for brokered calls. In this repo, not yet deployed (migration 0006).

The guard runs on the agent's machine: a seatbelt, not a sandbox. Only brokered keys are enforced by the server.

### Guard keys

- `POST /v1/guard/keys {label?}` (web session with CSRF, or CLI session) returns `{id, key: "lsg_<43 base64url>", label,
  expiresAt, note}` once; only `SHA-256(key)` is stored. A key made by a CLI session ends when that session ends
  (`expiresAt`, 7 days at most) and is revoked with it; a key made in the app has `expiresAt: null`. 20 active per account
  (`409 too_many_guard_keys`).
- `GET /v1/guard/keys` (any session): `{keys: [{id, label, created_at, last_used, expires_at, revoked, made_by}]}`.
- `DELETE /v1/guard/keys/<id>` (web session with CSRF, or CLI session; revoking only tightens): `{ok, closed}`; the
  key's pending and approved holds are closed in the same batch.
- A guard key authenticates only `/v1/approvals*` (`Authorization: Bearer lsg_...`): `401 guard_key_required` without
  one, `401 guard_key_invalid` when unknown, revoked or ended. It can never approve, list holds or reach the vault.

### Ask: `POST /v1/approvals`

```json
{"kind":"shell","agent":"claude-code","rule":"sh.terraform-destroy","why":"Destroys every resource in the state.",
 "summary":"terraform destroy -auto-approve","detail":"terraform destroy -auto-approve",
 "context":{"cwd":"infra","session":"a1b2c3"},"map":"2026-10-10.1"}
```

| Field | Rule |
|---|---|
| `kind` | `shell` or `tool` |
| `agent` | `claude-code`, `codex`, `cursor`, `copilot`, `gemini`, `antigravity` or `mcp` |
| `rule` | `^[a-z0-9._:-]{1,64}$` |
| `why` | up to 300 characters; control, format and line-break characters become spaces |
| `summary` | up to 200 characters, cleaned the same way; shown as "Summary from the guard" |
| `detail` | up to 4096 characters, kept exactly: the command line, or for a tool call canonical JSON such as `{"arguments":{...},"tool":"<name>"}` with sorted keys. NUL and unpaired surrogates are refused |
| `context` | optional: `cwd`, the folder's name only (1 to 80 characters, no `/`, `\`, control characters, `.` or `..`); `session`, `^[A-Za-z0-9._:-]{1,64}$` |
| `map` | optional shell map version, `^\d{4}-\d{2}-\d{2}\.\d{1,3}$`, used in the public receipt |

Unknown fields are refused (`400 bad_field`). The approval is bound to

```
hash = hex(SHA-256(JSON.stringify(["v1", kind, agent, detail, cwd])))      cwd = context.cwd or ""
```

returned as `hash` in every answer. Answers:
- `202 {id, status: "pending", hash, approve_url, expires_at, created}`: `created: false` when the same key already has
  this hash pending (no second hold, no second alert). A new hold waits 30 minutes for a decision.
- `200 {id, status: "approved", hash, approve_url, expires_at}`: an approved, unused, unexpired hold for this key and hash.
- `429 slow_down` (60 new holds an hour per key), `429 too_many_holds` (20 pending per key, 100 per account).

### Wait: `GET /v1/approvals/<id>?wait=<0..20>`

`{id, status, deny_reason, expires_at, hash, seals, needs}` with `status` one of `pending`, `approved`, `denied`,
`expired`, `used`; `seals` and `needs` say how many approvals it has and needs (a guard can print "1 of 2 seals").
With `wait`, the server re-reads every 2 seconds until the status is not `pending` or the wait is over. A pending or
approved hold past its time reads as `expired`. No D1 writes (the limit, 30 a minute per key, is kept in memory) and at
most 12 D1 queries per call. Another key's hold, or a brokered hold, is `404`.

### Use: `POST /v1/approvals/<id>/use {hash}`

One atomic update from `approved` to `used`, for this key, this hash and before `expires_at` (10 minutes after the
approval). `200 {ok, id, status: "used"}`; otherwise `410 expired`, `403 denied` (with `deny_reason`),
`409 already_used`, `409 not_approved`, `409 hash_mismatch`, `404 not_found`.

### Deny with a reason

`POST /v1/holds/<id>/deny {reason?}` (any signed-in session; deny is always safe): up to 200 characters, control,
format and line-break characters removed, stored in `holds.deny_reason` and returned to the guard. Treat it as data from
the human, not as instructions. `GET /v1/holds` returns `kind` (`proxy`, `shell`, `tool`, `deploy`), `agent`,
`deny_reason`, `context` (`{cwd, session}`) and the guard key's label as `token_label`; `preview` is the exact detail,
never truncated, with invisible, direction and control characters shown as `<U+XXXX>`.

### Receipts

A guard decision is sealed like a broker decision, with fixed words only:

```json
{"receipt":{"action":"RUN claude-code","agent":"broker","decision":"held","meta":{"map":"2026-10-10.1","rule":"sh.terraform-destroy"},"parent":"<audit hash>","ts":1791300000000},"source":"broker",...}
```

`RUN <agent>` for a shell command, `CALL <agent>` for a tool call; decisions `held`, `approved` (with
`meta.passkey: true`), `denied`, `executed` (the guard used the approval; audit action `run_approved`). `meta.map` is
the guard's map version when it sent one, else the API map version. Never the command, summary, why, folder, session,
key label or deny reason.

## Team (the two-person seal)

One account, several people, each signing in with their own passkey. In this repo on branch `feat/two-person`, not yet
deployed (migration 0009). Code: `server/src/team.js`; tests: `server/test/team.test.js`.

### Members and roles

Every web or CLI session, passkey, push device, token, guard key and receipts key belongs to one member: the person whose
passkey made the session, or who made the key. The account's founder has the account id as their member id, so every row
written before teams (`member_id` NULL) is the founder's: the member behind a row is `COALESCE(member_id, account_id)`.
The founder's `members` row is written with the first invite; until then the founder is the owner without one.

| Role | Can | Cannot |
|---|---|---|
| owner | everything below, and: invite, change roles, remove people, change the quorum, delete vault keys, switch receipts, delete the account | be the last owner and leave or be demoted |
| approver | seal held actions; make tokens, guard keys, agent keys and receipts keys; cancel a waiting lowering; unfreeze; reset a tripped breaker | anything owner-only |
| member | add vault keys; make tokens, guard keys, agent keys and receipts keys; revoke them | seal, pre-approve, set money caps |
| viewer | read everything (holds, tokens, audit log, team, command line sign-ins); deny a held action; freeze; and, like everyone, manage their own passkeys and alert devices, sign in their own command line and leave the team | anything else |

The role is read with the session on every request (one query, a join) and checked on the server for every signed-in
route: reads need any role, writes need `member` unless the route says otherwise (`403 role_required`). A removed
member's sessions are deleted; a session whose member is removed or missing is `401 signed_out`. Every passkey ceremony
of a signed-in person must use that person's own passkey (`401 unknown_passkey` otherwise). A CLI sign-in gets the role
of the member who approved it.

### Invites

- `POST /v1/team/invites/begin {role, label, hours?}` and `/finish {challengeId, credential}` (owner, web session, fresh
  passkey ceremony). `role` is `approver`, `member` or `viewer` (owners are made by promotion); `label` 1 to 60 characters
  (letters, digits, space and `._:/()',-`); `hours` 1 to 24, default 2. The role, label and hours ride in the
  challenge: what the passkey approved is what is made. Returns `{id, role, label, expiresAt, url, note}` with
  `url = <product host>/app#invite=<43 base64url characters>`, shown once. Only `SHA-256(token)` is stored. 10 an hour
  per account (`429 slow_down`), a team of 10 people counting open invites (`409 team_full`).
- `DELETE /v1/team/invites/<id>` (owner; revoking only tightens, so a CLI session of an owner may).
- An invite works once, until it expires, only while the owner who made it is still an owner (it dies when they are
  demoted or removed), and only on the product's host (`403 invite_on_new_host` on the old one).
- The token travels only in the URL fragment and POST bodies, so it is never in a request line, a server log or a
  Referer; the app reads it once and removes it from the address bar at once.

Joining (public, `Origin` checked like every public write):
- `POST /v1/invites/lookup {token}` returns `{account, inviter, role, label, expires_at}` for the invite page.
- `POST /v1/invites/begin {token, name}` returns `{challengeId, account, inviter, role, options}`: WebAuthn
  registration options with `userVerification: "required"`, a resident key, and `excludeCredentials` listing the
  account's passkeys, so an authenticator that already holds one of them refuses to make another.
- `POST /v1/invites/finish {token, challengeId, credential}` makes the member, their passkey and a web session in one
  transaction that consumes the invite only if it is still live, its owner is still an owner, the team has room and the
  name is free (case-insensitive). A browser already signed in to the account is refused (`409 already_member`).
- Every member's devices are woken (`member_joined`), and the audit log records who invited whom.

### Seals (votes)

`POST /v1/holds/<id>/approve/begin|finish` keep their shape and are now one seal each. The answer has
`{ok, approved, seals, needs, note}`. A hold is approved when the seals that still count reach
`max(holds.needs, quorum in force now)`; `holds.needs` is the quorum when the hold was made, so a raise applies to
waiting holds at once and a lowering never applies to them.

A seal counts while: its member is an owner or approver and not removed; their `votes_from` has passed (while two seals
are required, a new or promoted approver's seal counts 24 hours after joining or promotion); with self-approval off,
they are not the member who made the token or guard key that asked (`holds.requested_by`); the account is not frozen;
and it was given for the hold's exact request hash (the challenge carries it from `begin` to `finish`, `409
hold_changed` otherwise). One row per (hold, member): two passkeys or two browsers of one person count once
(`409 already_sealed`). The seal and the approval are one transaction, so two approvers sealing at the same moment
approve exactly once. Refusals before the passkey prompt: `403 role_required` or `approver_required` (not an owner or
approver), `403 seal_not_yet`, `403 own_request`, `409 already_sealed`, `423 account_frozen`.

Any member may deny (`POST /v1/holds/<id>/deny`), a viewer too: one no ends the hold, whatever seals it has. Freezing
drops the seals already on waiting holds. Removing someone, or demoting them below approver, drops their seals.

`GET /v1/holds` adds `needs`, `self_approve`, `requested_by` and `votes: [{member, name, passkey, at}]` (the seals that
still count, oldest first; `passkey` is the 16-hex fingerprint). A held API call's `428` adds `seals_needed`.

The audit log has `approve_vote` (a seal that did not complete the quorum: private, no receipt) and `approve` (with
`quorum` and every seal's member, passkey fingerprint and time when more than one was required). The public receipt
of the approval carries `meta.quorum` and `meta.votes` only.

### The quorum

- `POST /v1/team/quorum/begin {quorum: 1|2, selfApprove: bool}` and `/finish` (owner, fresh passkey ceremony). Parts
  that tighten (a higher quorum, self-approval off) apply at once; parts that loosen (a lower quorum, self-approval on)
  are stored as a pending pair that takes effect 24 hours later (`quorum_effective_at`), and replace any change already
  waiting; a request that loosens nothing clears a waiting change. There is no cron: the pending pair is applied when
  read. A lowering wakes every member's devices. The write is a compare-and-set on the values read (`409 try_again`).
  The team needs at least `quorum` owners or approvers (`409 not_enough_approvers`); `409 same_quorum` if nothing
  would change.
- `POST /v1/team/quorum/cancel/begin|finish` (owner or approver, fresh passkey ceremony) cancels a waiting change
  before it takes effect.
- While the quorum is 2 or self-approval is off, pre-approved irreversible calls and money caps (one person approving
  in advance) are paused: those calls are held like any other. Minting a token with either is refused (`409
  quorum_blocks_preapproval`).
- `GET /v1/me` has `team: {quorum, selfApprove, pending}`; `GET /v1/team` has the members (with passkey count, last
  use and when their seal starts counting), the quorum, a pending change, open invites and who you are.

### Roles and removal

- `POST /v1/team/members/<id>/role/begin {role}` and `/finish` (owner, fresh passkey ceremony). Never leaves the account
  without an owner (`409 last_owner`) or with fewer owners and approvers than the quorum (`409 not_enough_approvers`);
  the same rules are in the update statement itself. Demoting below approver drops the member's seals on waiting holds;
  demoting an owner revokes their open invites. Every member's devices are woken.
- `POST /v1/team/members/<id>/remove/begin|finish` (an owner removes anyone; anyone may remove themselves, which is
  leaving; fresh passkey ceremony). In one transaction: the member is marked removed (only if the rules still hold), and
  only then their sessions, passkeys and push devices are deleted, their seals on waiting holds dropped, the tokens,
  guard keys and receipts keys they made revoked, what those asked for closed, and their open invites and unused move
  links revoked. Returns the counts. Every remaining member's devices are woken.

### Alerts

`GET /v1/alerts` adds `team: [{kind, at, ...}]` for the last 15 minutes: `member_joined` (name, role),
`member_role_changed` (name, from, to), `member_removed` (name, role), `quorum_lowering` (from, to, effective_at) and
`quorum_lowering_cancelled`. A seal that does not complete the quorum wakes the other members' devices (at most once a
minute per account, shared with hold alerts).

### Extension points (break-glass windows and team alert channels)

- New tables go in their own additive migration (the next free number), not in 0009, so a database that applied 0009
  stays consistent. Reference `members(id)` for `opened_by`; scope rows by `account_id`.
- Roles: add the route with its least role as the fifth element of `ROUTES` (`ANY`, `MEMBER`, `APPROVER`, `OWNER`);
  check `sess.role` or `Team.requireLevel(sess, level)` inside handlers that need more.
- Passkey ceremonies: pass the session to `checkAssertion(env, credential, challenge, sess)` so the passkey must be the
  signed-in member's own.
- Hold creation: set `needs` from `Team.effective(accountRow).quorum` and `requested_by` from the maker
  (`Team.memberOf(row)`); a hold without them still needs the quorum in force (`max` above), but has no requester to
  exclude. A break-glass window check belongs next to the hold decision in `broker.proxy` and `approvals.create`,
  before a hold is inserted.
- Seals: who may seal is one SQL rule (`ELIGIBLE` in `team.js`), used by the seal, the approval and the hold card.
  A window that lets holds through without seals is one person loosening protection while two seals are required:
  this branch builds no windows; when they come, audit each one and announce it to every member and channel.
- Alerts: `notify(env, accountId, fetch, {exceptMember})` wakes every member's devices but one; team events for the
  phone come from audit actions listed in `Team.recentEvents`. A channel message can say "n of m seals" from
  `holds.needs` and the hold's `votes`.

## Web Bot Auth

The checker and `sdk/websig.mjs` implement draft -00 of `draft-ietf-webbotauth-httpsig-protocol` (September 2026):
`tag="web-bot-auth"`, `@authority` (or `@target-uri`) and the request's own `Signature-Agent` member covered, a window of
an hour at most (5 minutes without a nonce), keys from `<agent origin>/.well-known/http-message-signatures-directory`
matched by thumbprint, Ed25519 only. `Signature-Agent` may be a dictionary (draft -00) or a bare string (earlier drafts);
members with a type other than `directory`, or with a path, are ignored. A directory `kid` is not compared with the
thumbprint.
