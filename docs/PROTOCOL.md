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

Every web or CLI session, passkey, push device, token, guard key, agent key and receipts key belongs to one member: the person whose
passkey made the session, or who made the key. The account's founder has the account id as their member id, so every row
written before teams (`member_id` NULL) is the founder's: the member behind a row is `COALESCE(member_id, account_id)`.
The founder's `members` row is written with the first invite; until then the founder is the owner without one.

| Role | Can | Cannot |
|---|---|---|
| owner | everything below, and: invite, change roles, remove people, change the quorum, delete vault keys, switch receipts, delete the account | be the last owner and leave or be demoted |
| approver | seal held actions; make tokens (pre-approved ones and money caps too, while one seal is enough), guard keys, agent keys and receipts keys; cancel a waiting lowering; unfreeze; reset a tripped breaker | anything owner-only |
| member | add vault keys; make tokens, guard keys, agent keys and receipts keys | seal, pre-approve, set money caps |
| viewer | read everything (holds, tokens, audit log, team, command line sign-ins); deny a held action; freeze; and, like everyone, manage their own passkeys and alert devices, sign in their own command line and leave the team | anything else |

The role is read with the session on every request (one query, a join) and checked on the server for every signed-in
route: reads need any role, writes need `member` unless the route says otherwise (`403 role_required`). A removed
member's sessions are deleted; a session whose member is removed or missing is `401 signed_out`. Every passkey ceremony
of a signed-in person must use that person's own passkey (`401 unknown_passkey` otherwise). A CLI sign-in gets the role
of the member who approved it.

Revoking a token, guard key, agent key or receipts key is for the person who made it or an owner (`403 role_required`
otherwise, and nothing is closed); anyone else who sees trouble freezes the account. A command line sign-in is revoked
by its own person or an owner.

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

A seal counts while: its member is an owner or approver and not removed; their `votes_from` has passed (if one person
could not approve alone when they joined or were promoted, because two seals were required or self-approval was off,
their seal counts 24 hours later); with self-approval off,
they are not the member who made the token or guard key that asked (`holds.requested_by`); the account is not frozen;
and it was given for the hold's exact request hash (the challenge carries it from `begin` to `finish`, `409
hold_changed` otherwise). One row per (hold, member): two passkeys or two browsers of one person count once
(`409 already_sealed`). The seal and the approval are one transaction, so two approvers sealing at the same moment
approve exactly once. Refusals before the passkey prompt: `403 role_required` or `approver_required` (not an owner or
approver), `403 seal_not_yet`, `403 own_request`, `409 already_sealed`, `423 account_frozen`.

Any member may deny (`POST /v1/holds/<id>/deny`), a viewer too: one no ends the hold, whatever seals it has. Freezing
drops the seals already on waiting holds and voids approvals not yet used. Removing someone, or demoting them below
approver, drops their seals on waiting holds and voids any approval their seal helped complete that is not yet used.

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
  quorum_blocks_preapproval`). They are also paused on a token whose maker can no longer approve (made a member or a
  viewer, or removed): the proxy reads the maker's role in the token's query.
- While one person cannot approve alone, an approver whose seal does not count yet cannot unfreeze the account or
  reset a tripped breaker either (`403 seal_not_yet`).
- `GET /v1/me` has `team: {quorum, selfApprove, pending}`; `GET /v1/team` has the members (with passkey count, last
  use and when their seal starts counting), the quorum, a pending change, open invites and who you are.

### Roles and removal

- `POST /v1/team/members/<id>/role/begin {role}` and `/finish` (owner, fresh passkey ceremony). Never leaves the account
  without an owner (`409 last_owner`) or with fewer owners and approvers than the quorum (`409 not_enough_approvers`);
  the same rules are in the update statement itself. Demoting below approver drops the member's seals on waiting holds
  and voids unused approvals their seal helped complete; demoting an owner revokes their open invites; making someone a
  viewer revokes the tokens, guard keys, agent keys and receipts keys they made and closes what those asked for (a
  viewer runs no agents). Every member's devices are woken.
- `POST /v1/team/members/<id>/remove/begin|finish` (an owner removes anyone; anyone may remove themselves, which is
  leaving; fresh passkey ceremony). In one transaction: the member is marked removed (only if the rules still hold), and
  only then their sessions, passkeys and push devices are deleted, their seals on waiting holds dropped, the tokens,
  guard keys, agent keys and receipts keys they made revoked, what those asked for closed, unused approvals their seal
  helped complete voided, and their open invites and unused move links revoked. Returns the counts. Every remaining
  member's devices are woken, and so are the removed person's (one last push; their phone then reads that it is
  signed out).

### Alerts

`GET /v1/alerts` adds `team: [{kind, at, ...}]` for the last 15 minutes: `member_joined` (name, role),
`member_role_changed` (name, from, to), `member_removed` (name, role), `quorum_lowering` (from, to, effective_at) and
`quorum_lowering_cancelled`, `breakglass_opened` (minutes), `breakglass_closed` and `channel_added` (slack, discord or gchat). Every change to the team or the quorum wakes the devices at once, with no rate limit (each
took a passkey, so none can be hidden behind another). A seal that does not complete the quorum wakes the other
members' devices (at most once a minute per account, shared with hold alerts).

### Break glass (migration 0011)

A window lets what the irreversible map would hold go through, for at most 60 minutes. It is one person loosening protection
while two seals may be required, so it is small and loud.

- `POST /v1/team/breakglass/begin` then `/finish` (an owner or approver, web session, fresh passkey ceremony, never a command
  line session). Body `{minutes, reason, tokenId?}`: `minutes` is a whole number from 5 to 60 (`400 bad_minutes`), `reason` is
  3 to 200 characters after cleaning (`400 bad_reason`), `tokenId` is a live token's id or a guard key's id of this account, or
  absent for every token and guard key (`404 not_found`). The challenge carries exactly these three, so the passkey approves
  this window and no other. Refused with `423 account_frozen`, `403 seal_not_yet` (while one person cannot approve alone, an
  approver whose seal does not count yet), `403 own_request` (self-approval off and the scope is the opener's own token or key),
  `409 window_open` (one at a time; a window cannot be extended, open another when it ends) and `429 too_many_windows` (3 in 24
  hours per account). The insert itself decides the last three again, so two requests at once open one. Returns
  `{id, expires_at, scope}`.
- `DELETE /v1/team/breakglass/<id>` (any member, any session with CSRF; closing only tightens): `{ok}`, or `404`.
- `GET /v1/team` and `GET /v1/me` carry the open window: `windows: [{id, opened_by, opened_by_name, reason, opened_at,
  expires_at, scope}]` (`scope` is `null` or `{token_id, label}`). `GET /v1/team` also has `breakglass: {minMinutes, maxMinutes,
  perDay}`.
- What it does. In `broker.proxy`, after the brakes have had their say, when the map still holds a call (and the rule is not a brake's: `brake.*`) and a window is open
  for the token, the call is allowed with the rule's id plus `:breakglass` (and counted against the breaker like any allowed write); the private log's `proxy` entry carries
  `breakglass: <window id>` and the public receipt `meta.breakglass: true`, nothing else about the window. In
  `approvals.create`, a hold for a guard key that a window covers is inserted already approved (use once within 10 minutes,
  `status: "approved"`, `breakglass: true` in the answer); the later `run_approved` entry carries the window's id. The check costs
  nothing for a call the map does not hold: whether a window is open is read in the token's or guard key's own query.
- What it never does. It is not read for a deploy gate. It does not lift a freeze (423 comes first), a tripped breaker, a rate
  limit or a money cap (`brake.*` rules), or what was already waiting before it opened. With self-approval off it does not
  cover what the opener's own token or guard key asks. It stops applying when its opener is no longer an owner or approver, and
  when it expires or is closed.
- Opening one writes `breakglass_opened` (the opener, minutes, scope and reason, owner-visible only) and wakes every other member's
  devices and every channel at once, with no rate limit (each took a passkey; 3 a day bounds them); closing writes
  `breakglass_closed` and does the same.

### Alert channels (migration 0011)

Slack, Discord and Google Chat are told, never asked: a channel cannot approve anything.

- `POST /v1/team/channels/begin` then `/finish` (an owner, web session, passkey). Body `{kind, url, label}`: `kind` is `slack`,
  `discord` or `gchat`; `label` as for a token; `url` is the webhook address the service gave. The challenge carries the kind, the
  label and the SHA-256 of the address (`409 channel_changed` if finish differs). 3 channels at most (`409 too_many_channels`).
  Returns `{id, kind, name, label, host, created_at, last_ok_at, failures, disabled}`. The address is sealed with the vault key
  (AES-GCM, bound to the account, the row and the kind) and never returned; `GET /v1/team` lists `channels` without it.
- The address must be exactly a webhook of the service: https, no user name or port or fragment, the host `hooks.slack.com`
  (path `/services/T.../B.../secret`), `discord.com` or `discordapp.com` (`/api/webhooks/<id>/<token>`) or `chat.googleapis.com`
  (`/v1/spaces/<space>/messages?key=...&token=...`), no other query, and the address must be byte for byte what a URL parser
  makes of it (`400 bad_url`). It is checked again before every send.
- `POST /v1/team/channels/<id>/test` (an owner, web session; one a minute per account): sends a test and answers `{ok, status}`; a
  working test also turns a stopped channel back on. `DELETE /v1/team/channels/<id>` (an owner): removes it.
- A send is one POST of JSON (`{text}`; Discord `{content, allowed_mentions: {parse: []}}`), no redirect followed, 3 seconds. A
  non-2xx answer, a redirect, a timeout or an error is a failure; ten in a row stop the channel until a test works.
- What is sent: the token's label, the guard key's agent name or the gate's label (only letters, digits, space and `._:/()-`), the
  rule's id, the seals so far and needed, and the approve link (`/app#hold=<id>`). When a held action is created (at most one
  alert a minute per account, the same limit as the phone's), when a seal does not complete the quorum, when break glass opens or
  closes, and when the team or the quorum changes (a fixed sentence with no name or role). Never the path, command, body, amount,
  a person's name or the reason of a window.

### Extension points (break-glass windows and team alert channels)

Built in 0011 (`src/windows.js`, `src/channels.js`); what follows is the contract they were written to.

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
  src/windows.js is that window: audited, announced to every member and channel, at most 60 minutes, 3 a day.
- Alerts: `notify(env, accountId, fetch, {exceptMember, extra})` wakes every member's devices but one (plus `extra`
  devices no longer in the account); team events for the
  phone come from audit actions listed in `Team.recentEvents`. A channel message can say "n of m seals" from
  `holds.needs` and the hold's `votes`.

## Deploy gates

A GitHub Actions job waits for a passkey approval, bound to the claims in GitHub's signed OIDC token. The holds table,
alerts, approve and deny routes and receipts are the same as for brokered calls and commands (hold kind `deploy`). In this
repo, not yet deployed (migration 0007). How to use it: [DEPLOY_GATE.md](DEPLOY_GATE.md). The action that speaks this
protocol is `action/deploy-gate`.

### Gates (the app)

- `GET /v1/gates` (any session): `{gates: [{id, label, repository, workflows, refs, environments, events, bound, publish_repo,
  credential, created_at, last_used, revoked, member_id}], server}`. `member_id` is who made the gate. `bound` is `null` or `{repository_id, repository_owner_id, at}`;
  `credential` is `null` or `{id, provider, label, preapproved}`.
- `POST /v1/gates/passkey/begin` then `POST /v1/gates/passkey/finish` (web session with CSRF, a passkey ceremony; a command
  line session gets `403 passkey_required`). The finish body is `{challengeId, credential, label, repository, workflows, refs,
  environments?, events?, publishRepo?, credentialId?, policy?}` and returns the gate (`id` is `gate_` and 24 hex
  characters; it is public, pasted in workflow files). Unknown fields are refused (`400 bad_field`).

| Field | Rule |
|---|---|
| `label` | 1 to 60 characters of letters, digits, space and `._:/()-` |
| `repository` | `owner/name`: owner `[A-Za-z0-9-]{1,39}`, name `[A-Za-z0-9._-]{1,100}`, not `.` or `..`. No wildcard |
| `workflows` | 1 to 5 workflow files of that repository, `.github/workflows/<name>.yml` or `.yaml`. No wildcard |
| `refs` | 1 to 10 refs: `refs/heads/...` or `refs/tags/...` of `[A-Za-z0-9._/-]` (150 at most), exact, or with one trailing `*` for a prefix. No `//` or `..`; a bare `refs/heads/*` is refused |
| `environments` | optional, up to 10 names, `^[A-Za-z0-9][A-Za-z0-9 ._:/()-]{0,99}$`; if given, the job must run in one of them |
| `events` | from `push`, `workflow_dispatch`, `release`, `deployment`, `merge_group`, `schedule`, `repository_dispatch`; default the first five |
| `publishRepo` | boolean, default false: the repository name goes in this gate's public receipts |
| `credentialId`, `policy` | phase 2: a vault key of this account and the policy of the token handed out (as for a token made with a passkey, so it may pre-approve irreversible calls, if the maker is an owner or approver and one seal is enough). `policy` needs `credentialId` (`400 policy_needs_credential`) |

  Errors: `400 bad_label|bad_repository|bad_workflows|bad_refs|bad_environments|bad_events|bad_publishRepo|bad_policy`,
  `404 not_found` (a key that is not this account's), `409 too_many_gates` (20 active).
- `DELETE /v1/gates/<id>` (a member, session with CSRF; its maker or an owner, `403 role_required` for anyone else; revoking only
  tightens): `{ok, closed, tokens}`: its waiting and approved requests are closed and the tokens it handed out are revoked.

On a team: making or revoking a gate needs the role of a member or more (a viewer gets `403 role_required`); a gate with a key
whose policy pre-approves irreversible calls (or sets money caps) needs an owner or approver, and is refused with
`409 quorum_blocks_preapproval` while the team needs two seals or someone other than the maker. A gate remembers who made it
(`gates.member_id`). A deploy hold is made with `needs` set to the quorum in force and `requested_by` set to the gate's maker, so
it is approved by as many different owners or approvers as the quorum needs, and with self-approval off not by the maker. The
poll answers `pending` until it is approved. Removing the maker, or making them a viewer, revokes their gates, the holds they
asked for and the tokens those handed out (the answer's `revoked` has a `gates` count).

### Ask: `POST /v1/gate/request`

`Authorization: Bearer <GitHub OIDC token>`, body `{"gate": "gate_...", "summary"?: "...", "timeout_minutes"?: 15}`. `summary` is up
to 120 characters after control, format and line-break characters become spaces; `timeout_minutes` is a whole number from
1 to 60 (default 15) and is how long the request lives. The token's audience must be exactly
`<product origin>/gate/<gate id>` (the action asks GitHub for it with the `audience` query parameter on
`ACTIONS_ID_TOKEN_REQUEST_URL`). Checks, in order: the token (`oidc_*` below), the gate exists and is not revoked, the run fits
the gate (`gate_refused`), the account is not frozen, the token's `jti` is unused, then the limits.

Answers:
- `202 {id, status: "pending" | "approved", poll, approve_url, expires_at, rule, created}`. `poll` is the poll secret
  (`gps_` and 43 base64url characters), shown once. `created: false` when the same run (same hash) already had a request
  pending or approved: the same hold, no second alert, a new poll secret. `rule` is `gate.bind` on a gate's first run and
  `gate.deploy` after.
- `401 oidc_required` (no bearer), `oidc_malformed`, `oidc_alg`, `oidc_unknown_kid`, `oidc_bad_signature`, `oidc_issuer`,
  `oidc_audience`, `oidc_expired`, `oidc_not_yet_valid`, `oidc_lifetime`, `oidc_claims`, `oidc_replayed`;
  `503 oidc_keys_unavailable` (GitHub's key set could not be had).
- `403 gate_refused {reason}` with `reason` one of `repository`, `workflow`, `ref`, `environment`, `event`; `404 gate_not_found`;
  `423 account_frozen`; `429 too_many_holds` (10 waiting per gate, 100 per account) or `slow_down` (30 new requests an hour
  per gate); `409 try_again`; `400 bad_gate|bad_summary|bad_timeout|bad_field`.

The hold is bound to

```
hash = hex(SHA-256(JSON.stringify(["v1", "deploy", gate, repository_id, repository_owner_id, run_id, run_attempt, sha,
                                   workflow_ref, job_workflow_ref, ref, environment, check_run_id])))
```

(ids as digit strings; `environment` and `check_run_id` are `""` when absent). Its method word is `DEPLOY`, its host word
`github.com`, its agent `github-actions`, its path `<repository>@<sha7> <environment or ref>`. `GET /v1/holds` returns, for
`kind: "deploy"`, `token_label` (the gate's label) and `context.gate`: `{repository, repository_id, ref, sha, workflow_ref,
job_workflow_ref, environment, event, actor, run_id, run_attempt, visibility, runner, bind, summary, run_url, commit_url}`,
all from the verified token except `summary`, which is the workflow's own text. The context and the preview are dropped
about a day after the hold closes.

### Wait: `GET /v1/gate/status/<id>?wait=<0..20>`

`Authorization: Bearer gps_...` (the poll secret; it reads that one hold). `{id, status, deny_reason, expires_at}` with `status`
`pending`, `approved`, `denied`, `expired` or `used`. With `wait` the server re-reads every 2 seconds until the status is not
`pending` or the wait is over: no D1 writes, at most 12 reads, the limit (30 a minute per secret) in memory. The poll that
finds the hold `approved` spends it in one atomic update (still approved, same hash, in time, the gate not revoked and, if
bound, still the same repository and owner ids, the account not frozen), binds the gate on its first approved run, and returns
`approved`; the next poll reads `used`. For a gate that names a key the same answer carries `token` (`lsh_...`, 15 minutes),
`provider`, `base_url` and `token_expires_at`, once. Errors: `401 poll_secret_required`, `404 not_found`,
`409 hash_mismatch|gate_revoked|gate_bound_elsewhere|credential_gone|too_many_tokens` (the last two leave the approval
unspent), `423 account_frozen`, `400 bad_wait`, `429 slow_down`.

### Cancel: `POST /v1/gate/cancel/<id>`

`Authorization: Bearer gps_...`, body `{}`: `{ok: true, cancelled: boolean}`. Closes the request if it is still pending or approved
(the job gave up). It also works while the account is frozen.

### Receipts

Sealed like any hold, with fixed words only: `{"action": "DEPLOY github.com", "decision": "held" | "approved" | "denied" |
"executed", "meta": {"map": ..., "rule": "gate.deploy" | "gate.bind", "passkey": true}}` (`passkey` on `approved`; `executed` is
the poll that spent the approval, audit action `gate_passed`). `meta.repo` carries `owner/name` only when the gate was made
with `publishRepo`. Never the commit, workflow, run, person, label, summary or deny reason. The private audit log has `hold`
(repository, commit, ref, run, attempt, environment, gate), `approve`, `deny`, `gate_passed`, `gate_cancelled`,
`gate_created` and `gate_revoked`.

## The app, the first run and the privacy center (migration 0012, not yet deployed)

All routes below are signed-in routes with the usual CSRF rules on both hosts (writes need an allow-listed `Origin` equal
to the host and `x-leash: 1`).

| Route | Who | What |
|---|---|---|
| `POST /v1/demo/call` `{}` | any member, browser session | Makes a demo hold (`kind: "demo"`, `DELETE /repos/you/practice-repo` on host `demo`, rule `demo.delete`, 10 minutes), or returns the one already waiting: `{hold_id, status, approve_url, expires_at, created, demo: true}`. 10 an hour per account; 423 while frozen. |
| `POST /v1/demo/call` `{"hold": id}` | the same | The demo agent's retry: uses an approved demo hold once. 200 `{status: "executed", demo: true, response: {status: 204, provider: "demo", note}}`; 409 `not_approved` or `already_used`, 403 `denied`, 410 `expired`, 404. |
| `POST /v1/me/installed` `{}` | any member | The app says it runs installed (display-mode standalone). Sets `installed_at` once. |
| `POST /v1/me/retention` `{"holdDays": 30 \| 90 \| 365}` | owner, browser session | How long closed holds are kept. Audited (`retention_changed`). |
| `POST /v1/me/export/begin`, `/finish` | owner, browser session, passkey ceremony | Everything kept about the account as JSON (`format: "counterseal-data-export/1"`), without secrets (see `never_included` in the answer). 3 an hour; audited (`data_export`). Its `holds` and `audit` are filled by paging the two routes below. |
| `GET /v1/export/holds?after=<n>` | owner, browser session | 200 holds a page, oldest first: `{entries, done, next_after}`. |
| `GET /v1/export/evidence?from=<ms>&to=<ms>&after=<seq>` | any member (as `GET /v1/audit`) | 250 audit entries a page, oldest first, exactly as stored (`detail` is the JSON text the hash covers): `{account_id, entries, done, next_after}`; the first page also has `from_start`, `map_version`, `range` and `log: {origin, verifier_key, checkpoint, tree_size}`. Writes nothing. |

`GET /v1/me` also returns `progress: {token, call, demo, installed, alerts}` (first times, or null) and `retention: {holdDays,
choices, rules}`. A web session ends after an hour without an action: a write, or a read sent with `x-leash-active: 1`;
reads without it (the app's background refresh) do not extend it. The 401 then carries `reason: "idle"`.

The demo's audit actions are `demo_hold`, `demo_approved`, `demo_denied` and `demo_executed`; none is a public decision,
so none is sealed in the public log.

Verifying an evidence pack: for each entry in order, `prev_hash` must equal the previous entry's `hash` (64 zeros before an
account's first entry), and `hash = SHA-256(prev_hash | account_id | at | actor | action | detail)` in lowercase hex, with
`|` between the fields. `site/public/app/evidence.js` does this in the browser.

## Web Bot Auth

The checker and `sdk/websig.mjs` implement draft -00 of `draft-ietf-webbotauth-httpsig-protocol` (September 2026):
`tag="web-bot-auth"`, `@authority` (or `@target-uri`) and the request's own `Signature-Agent` member covered, a window of
an hour at most (5 minutes without a nonce), keys from `<agent origin>/.well-known/http-message-signatures-directory`
matched by thumbprint, Ed25519 only. `Signature-Agent` may be a dictionary (draft -00) or a bare string (earlier drafts);
members with a type other than `directory`, or with a path, are ignored. A directory `kid` is not compared with the
thumbprint.
