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
| Someone holding a leaked `lsh_` token, unbound | Make the calls that token's policy allows, until it expires or is revoked; if the token has money caps, refund or pay out up to its per-call and per-day caps; trip the token's own breaker | Exceed the policy or its caps; get past a hold; read the key; trip or spend any other token |
| Someone holding a leaked `lsh_` token bound to an agent key | Nothing: every request is refused before the policy, the token's rate limit or the upstream | Use it without the agent's private key |
| Someone holding a stolen CLI session | List holds; mint ordinary tokens (with a breaker if it likes); register agent keys and bind tokens to them; make and revoke guard keys; deny holds; freeze the account (which only stops things; the owner is alerted); for at most 7 days | Approve holds; mint pre-approved tokens or tokens with money caps; reset a tripped breaker; unfreeze; read keys; delete vaulted keys; revoke agent keys; turn receipts on or off; approve or revoke CLI sign-ins; delete the account; keep anything it made after the owner revokes it |
| Someone holding a guard key (`lsg_`), for example the agent the guard runs next to | Ask for approvals (60 new an hour, 20 waiting); read and use its own approvals | Approve anything; see another key's or a brokered hold; list holds; reach the vault; outlive the CLI session that made it; alert more than once a minute |
| One person on a team that requires two seals (an owner or approver, or someone who stole one person's phone and passkey) | Give one seal; deny anything; freeze; read everything the team reads | Approve a held action alone; count twice (a second passkey, a second browser, two confirmations at once); seal what their own token or guard key asked for when self-approval is off; pre-approve irreversible calls or set money caps; lower the quorum or turn self-approval on without 24 hours' notice to every member; give a new or promoted approver a seal that counts in those 24 hours |
| A team member with a lower role (member or viewer) | A member: make tokens, guard keys and keys for their agents. A viewer: read and deny | Seal, change roles, invite, remove others, change the quorum, delete vault keys, switch receipts, delete the account (checked on the server on every request) |
| Someone holding a stolen or forwarded invite link | Join the team once, with the invited role, within the invite's life (2 hours by default, 24 at most), with a passkey of their own | Join twice, join after it was used, revoked or expired or after its owner stopped being an owner, join from the old host, join quietly (every member's devices are woken), have their seal count for 24 hours while two seals are required |
| A removed team member | Nothing | Sign in (passkeys deleted), use a session or a CLI session (deleted), get alerts (devices deleted), have a seal count, use a token, guard key or receipts key they made (revoked) |
| A device-code phisher (starts `leashcli login` and sends someone the code) | Get a CLI session in that person's account if they sign in, type the code, ignore the country and network shown, confirm they ran it and approve with their passkey | Put the code in a link the app accepts; reuse a code; keep the session past 7 days or past a revoke; act unseen (audit entry and device alert at sign-in) |
| Someone holding a receipts API key (`lsr_`) | Record receipts within the account's quotas (public, reported, never `source: "broker"`) | Make a broker receipt; record signed receipts without the signer; replay a signed receipt |
| A phishing site | Ask for a passkey | Get an assertion the service accepts (origin and RP ID are bound into it) |
| A malicious web page in the user's browser | Send requests | Write to the API (SameSite=Strict, Origin check, custom header, no CORS on private routes) |
| Anyone on the internet | Read every public log entry, checkpoint and proof; use the signature checker | Learn a path, body, name, email, IP or account id from the log; link entries to each other or to an account through the submitter field (reported receipts carry whatever labels their agent chose) |
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

**S11. Device-code phishing (CLI sign-in).** Passkeys cannot be phished, but a consent can: an attacker runs
`leashcli login` on their own machine and sends someone the code ("verify your account"); used at scale against other
platforms in 2025 (Microsoft on Storm-2372, Volexity, Proofpoint). RFC 8628 section 5.4 and the IETF cross-device flows
BCP call for context on the approving device, short-lived single-use codes, limited scope and lifetime, rate limits, and
detect and remediate. Mitigations:
- *No one-tap link.* `verification_uri` is the plain page (`/app#device`), there is no `verification_uri_complete`, and
  the app never takes a code from its address: a link that carries one shows a warning instead. The person types the
  code from their own terminal. Typing was chosen over "the browser shows a code to type back into the CLI" because the
  published leashcli 0.1.1 can only print a code, and an attacker would always pick the older flow.
- *Context before the passkey.* The page shows what is granted (and what is not), when the sign-in started, the country
  and network it started from next to the approver's own (Cloudflare's `request.cf`, never an IP), a warning when they
  differ, and asks "Did you just run leashcli login yourself?"; the approve button needs that confirmation and "No, deny
  it" comes first (the CLI gets `access_denied`).
- *Small and short.* Codes: single use, 5 minutes, 8 characters from 28 without modulo bias. CLI sessions: 7 days, and
  a token or receipts key a CLI session makes never outlives it. Starts: 10 an hour per network; lookups and denials: 10 per 10 minutes
  per account; approvals: 10 an hour per account.
- *Detect and remediate.* Each sign-in is audited (`cli_signin_approved`, `cli_signed_in`, `cli_signin_denied`) and
  wakes the owner's devices: "A command line was signed in" opens a one-tap revoke, which deletes the session and
  revokes every token, agent key, receipts key and guard key it made, closing the guard keys' open approvals
  (`cli_session_revoked`), also after the session signed itself out or expired (the list and the alert come from the
  audit log). Revoking needs a web session.
- The CLI prints whose account it signed in to, so a person whose own code was approved by someone else (signing them
  into a stranger's vault) notices at once.
Residual: a person who types a code they were sent, ignores the warnings and approves has signed that command line in
for up to 7 days or until they revoke it; it still cannot approve a hold. A VPN can make the country and network match.
CLI sessions made before migration 0005 keep their 30-day lifetime, and the tokens they minted are not revoked with
them (revoke those tokens one by one).
Tests: `test/cli-signin.test.js`.

**S12. Approval fatigue.** Someone holding a leaked, unbound token makes many distinct held requests, each an alert,
hoping a tired human taps approve. A token can have at most 20 requests waiting and an account 100 (`429
too_many_holds`, nothing held or alerted), and held requests wake the owner's devices at most once a minute per
account; the alert says how many are waiting. Test: *approval fatigue* (`test/second-pass.test.js`).

**S13. A forked audit chain.** Parallel writes for one account could both append after the same head, and
`/v1/audit/verify` then reports the chain broken. The insert succeeds only if the head is still the one the entry commits
to, in the same statement, and retries otherwise. Test: *the audit chain does not fork*.

**S14. Losing the account through a passkey.** A stolen cookie could remove the owner's other passkeys, and a browser
signed in with a passkey added through a leaked move link stayed in after that passkey was removed. Removing a passkey
needs a fresh passkey ceremony and signs out every other web session; a passkey added through a move link alerts every
device. Test: *removing a passkey*.

**S15. Unbounded resources and catastrophic backtracking.** Ceilings per account (50 vault keys, 200 live tokens, 20
receipts keys, 20 agent keys, 10 devices) and bounded lists keep one account from using up the shared D1 budget. Policy
globs compile to regular expressions; three `**` against a long path backtracked for seconds, so a glob may use `**` at
most twice and one wildcard per segment. Tests: *ceilings*, *policy globs*.

**S16. A vaulted key sent where an attacker chose (Shopify's store address).** Shopify is the one provider whose upstream
address comes from the user. Someone with a command line session or a script could try to add a Shopify key with an address
of their own (`evil.example.com`, `127.0.0.1`, `store.myshopify.com:443`, `a@b.myshopify.com`, a punycode or Unicode lookalike),
or an address that ends in `.myshopify.com` but is not one store, or point a Shopify token at a storefront page or app proxy
that forwards headers to a third party. Mitigations: `storeHost` accepts only printable ASCII that is exactly one DNS label then
`.myshopify.com` (no port, user info, path, IP address, trailing dot, nested subdomain or punycode); it runs when the key is added
and before every call; the address is part of the key's AES-GCM additional data, so a database row changed to another store
fails to decrypt (`vault_error`) and a row that no longer passes the check stops the call (`bad_host`); migration 0010 adds a
database CHECK; only `/admin/api/<version>/graphql.json` is brokered, everything else is refused with `unsupported_path`
before the key is read; redirects are never followed. Public receipts carry `myshopify.com`, never the store. Tests:
*Shopify store host*, *Shopify store host cannot be changed behind the broker*, *Shopify privacy*.

### Brakes (money caps, the breaker, Freeze)

**S17. Moving more money than the caps allow.** The cap is only as good as the reading of the amount. The amount comes
from the map's strict form parser (`strictForm`, built on the same copies-of-every-parameter reading that holds
`confirm=true` tricks), and anything it cannot read one way is held: a repeated amount (also under a `;` split), an
escaped, bracketed, spaced or other-case name, an escape in a watched value, a raw `;`, space or control character anywhere in the
body (a refund whose amount sits after a `;` has no amount to a server that does not split there, and then refunds everything), a copy in the query string, a JSON or multipart body, a body over 4 KB,
a content type that is not a plain form. An amount is accepted only as `[1-9][0-9]{0,11}`: no sign, zeros in front,
fraction, exponent, space, other digits or empty value; a currency only as three lower case letters. A refund must name
exactly one charge or payment intent in the usual id form and must not come from a customer balance. Only the two calls
are ever let through, spelled exactly (`/v1/Refunds`, `.json`, `/v1/charges/<id>/refund`, application fee refunds,
transfers, charges, top-ups, confirms and captures stay held by the map). A refund's currency and what is left come from
Stripe, looked up with the vaulted key (a failed, redirected, oversized or oddly shaped answer is held); a refund without
an amount counts as everything left. Caps are in one currency, so another currency is held, never compared. A differential fuzz of 60,000 generated bodies checks that
every other way of reading a body (first or last copy, `;` splits, folded case, brackets, trimming, no decoding) agrees with the
reader whenever it reads one. Tests:
*amount tricks*, *the fuzz*, *a lookup that fails*, *currency mismatch*, *every other money call stays held* (`test/brakes-money.test.js`).
Residual: the day is the UTC calendar day, so a total can reach twice the daily cap across midnight; a retry of the same
call counts again; a payment intent's lookup is an upper bound (what it received); a leaked capped token can still move
money up to its caps until it is revoked (a bound token is not usable without its agent).

**S18. Racing the daily cap, or a failure that hands money back twice.** The day's total is reserved by one conditional
statement (`INSERT ... ON CONFLICT DO UPDATE ... WHERE total + amount <= cap RETURNING`), so concurrent calls cannot both
pass; a refused call writes nothing. A reservation is given back only for a definite refusal from Stripe (a status below
500 that is not 2xx) or a call that never left (the vault could not open); a 5xx or no answer keeps it, because the money
may have moved. A cap only ever turns a map hold into an allow when the rest of the token's policy allows the call, and
caps whose stored form cannot be read hold every refund and payout, even a pre-approved one. Tests: *concurrent calls race the daily
cap*, *a refusal from Stripe gives the reservation back*, *caps that cannot be read ... fail closed*.

**S19. Dodging or abusing the breaker.** The breaker counts only writes that would go upstream, after the signature check
and the policy, so a replayed signed request (refused with `agent_signature_replayed`) and a thief without the agent key
(refused with `agent_signature_required`) count for nothing; a repeat is the exact request (method, path, query, content
type and body), so changing headers such as `Idempotency-Key` does not dodge it, and changing the body is caught by the
hourly count when both limits are set. Counters are per token, so one token cannot trip or spend another. A trip is one
conditional update, so concurrent calls trip it once and wake the owner once. A tripped token cannot flood the holds table
or the phone: it is held to the 20 waiting requests per token, and its later holds do not spend the minute's alert.
Resetting needs a passkey ceremony tied to that one token and is on the record. Residual: windows are fixed, so a burst
across a window's end can reach twice the limit; an agent that varies its body and stays under the hourly count is not
stopped by the repeat limit. Tests: `test/brakes-breaker.test.js`.

**S20. Freeze as a weapon, or a freeze that does not hold.** Any signed-in session may freeze, because stopping is always
safe: a stolen CLI session can make the owner's agents stop (a nuisance, not a loss; devices are alerted, and the owner
unfreezes with a passkey). Unfreezing needs a web session and a fresh passkey ceremony bound to the unfreeze, so a stolen
CLI session or cookie cannot undo it. A frozen account is answered `423` before anything else is read or written for the
call (no signature check, no body, no token rate limit row), so a looping agent adds no database writes beyond the
per-network limit every proxied call pays, and one note in the owner's audit log per token every 10 minutes. Approvals nobody
used yet are voided when the freeze starts, and approving is refused while frozen, so nothing a human said yes to earlier
fires after the freeze ends. Not covered: calls already in flight when the freeze lands; receipts API keys (`lsr_`),
which cannot act on a provider. A coding agent's guard is stopped the same way (asking, waiting and using an approval answer
`423`, so it learns why instead of timing out); a module that decides for an account without an `lsh_` token (a deploy gate
later) must check `frozen_at` or call `isFrozen` (`src/brakes.js`). Tests: `test/brakes-freeze.test.js`.

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
with `"`, a quoted component name), a receipt's canonical JSON (starts with `{`), a receipts signer proof (`witness/signer-proof/v2\n`) and an
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

### Approvals for a coding agent's commands (guard keys, migration 0006, not yet deployed)

A hook on the agent's machine (the guard) holds a guard key and asks `POST /v1/approvals` before running a command on its
map; the human approves in the app with a passkey. **The guard is enforced on the agent's machine, not by the server: a
seatbelt, not a sandbox.** Only brokered keys are a hard stop.

**G1. The agent approves its own command.** A guard key authenticates only `/v1/approvals*`; every approve route needs a
web session and a fresh passkey ceremony, as in S2. Test: *a guard key can only ask* (`test/approvals.test.js`).

**G2. Approval stretching and replay.** An approval is bound to `SHA-256(["v1", kind, agent, detail, cwd])`: the exact
command or tool call, the agent and the folder name. It is used once, by one atomic update that also checks the key and
the 10-minute window; another command gets `409 hash_mismatch`. An approved guard hold can never let a brokered request
through (different token ids). Tests: *ask, approve with a passkey, use exactly once*; *expiry*.

**G3. Approval fatigue and alert floods.** A guard key gets 60 new holds an hour, 20 waiting at a time, and an account
100 waiting; the same command asked again is the same hold and no new alert; alerts for held requests go out at most once a
minute per account (the alert says how many are waiting). Test: *limits*.

**G4. A misleading summary.** The `summary` comes from the guard (or from anyone holding its key). The card labels it
"Summary from the guard" and puts it under the exact `detail`, which is what the hash binds, shown in full (never
truncated) with invisible, direction and control characters made visible (`<U+XXXX>`), so an escape sequence or a
carriage return cannot hide part of a command. Test: *the hold card gets the exact command*.

**G5. Prompt injection through a deny reason.** The reason is written by the approver (a web or CLI session of the
account), capped at 200 characters and cleaned of control, format and line-break characters; guards hand it to the agent
as data. A stolen CLI session could deny with a misleading reason; it cannot approve.

**G6. A phished CLI session leaves a guard key behind.** A guard key made by a CLI session ends with that session (at
most 7 days) and is revoked with it, closing its open approvals. Revoking a guard key closes its approvals at once.
Tests: *revoking a guard key closes its open approvals*; `test/cli-signin.test.js`.

**G7. Privacy of held commands.** Commands can carry secrets (a connection string in a `psql` line). The exact command is
kept in the hold's preview, shown only to the account's sessions, and dropped about a day after the hold is closed (the
sweep); the audit log keeps only its SHA-256. The summary and folder name stay with the hold; the deny reason stays with
the hold and in the private audit log. A phone alert shows the
guard's label and the summary, which can appear on a lock screen (privacy page). Public receipts carry only `RUN` or
`CALL`, the agent's name from a fixed list, the decision, the rule id and the map version. Test: *public receipts for a
guard decision carry fixed words only* checks the command, summary, why, folder, session, label and reason never reach
the public log or its storage.

**G8. Waiting must not cost the free plan.** A long poll re-reads every 2 seconds for at most 20 seconds: at most 12 D1
queries and no writes (its limit is in memory). Test: *the long poll*.

Residual: the guard can be bypassed by an agent that edits its hook settings, wraps the command in a script the map does
not read, or calls the tool another way; hook runners that time out may fail open unless set to block (the guard's install
sets that where the agent supports it). Commands not on the map are left to the agent's own permission settings.

### The two-person seal (team, migration 0009, not yet deployed)

An account can have several people (owner, approver, member, viewer), each with their own passkey; a held action can
require seals from two different owners or approvers. Code: `server/src/team.js`. Tests: `server/test/team.test.js`.

**T1. One person counted twice.** A seal is one row per (hold, member), and the member comes from the passkey used (each
passkey belongs to one member; the session's member must match it, `401 unknown_passkey`). A second passkey of the same
person, a second browser, or two confirmations racing each other land on the same row (`409 already_sealed`). The seal
and the approval run in one transaction, so two approvers confirming at once approve exactly once. A person with two
authenticators who accepts two invites is two members to the server: the authenticator that already holds one of the
team's passkeys refuses to make another (`excludeCredentials`), a browser signed in to the account cannot join, every
join wakes every member's devices and is in the audit log, and while two seals are required a new approver's seal counts
only 24 hours after joining. Tests: *two seals*, *two confirmations at once*, *joining*.

**T2. A passkey proves presence, not authority.** Roles are read with the session on every request and checked on the
server for every signed-in route (writes default to `member`); a viewer or member cannot even begin a seal. The seal's
insert checks the role again in the same statement, so an approver demoted between their passkey prompt and their
confirmation does not count, and the approval counts only seals whose members may still seal. Tests: *roles on every
route*, *roles*.

**T3. Separation of duties.** With self-approval off, the member who made the token or guard key that asked
(`holds.requested_by`) cannot be one of the seals (`403 own_request`). With it on (the default, as for one person), they
can be one of two, never both. Test: *self-approval off*.

**T4. Lowering protection quietly or at once.** Raising the quorum or turning self-approval off applies at once, to
waiting holds too (a hold needs `max(the quorum when it was made, the quorum now)`). Lowering it or turning self-approval
on is stored as a pending change that takes effect 24 hours later, wakes every member's devices (and shows a banner on
every page of the app), and can be cancelled by any owner or approver with a passkey; a request that loosens nothing
clears it. The quorum write is a compare-and-set on what was read, so a concurrent raise is never overwritten. The two
switches that let one person approve in advance, pre-approved irreversible calls and money caps, are paused while two
seals are required or self-approval is off, and cannot be made then. Tests: *the quorum*, *the quorum change is what
the passkey approved*, *no one person can get around two seals*, *money caps made at quorum 1*.

**T5. Invite links.** An invite is 32 random bytes, stored as SHA-256, made by an owner with a fresh passkey ceremony
(the role, label and lifetime are bound into its challenge), single use (consumed in the same transaction that writes the
member and their passkey), 2 hours by default and 24 at most, 10 an hour, 10 people a team counting open invites, bound
to the account and dead once its owner is no longer an owner, accepted only on the product's host. It travels in the URL
fragment and POST bodies only; the app removes it from the address bar at once (also when the link opens in a tab where
the app already runs). The invite page shows the account, the inviter and the role before anything is made, and warns
that Counterseal never sends invites itself. The audit log names invites by id, never by token or hash. Residual: anyone
who gets a live link before its person does can join with that role; every member is alerted and an owner can remove
them, and while two seals are required their seal does not count for 24 hours. Tests: *invites*, *invites are
limited*.

**T6. Removing someone.** One transaction marks the member removed (only if the account keeps an owner and enough
approvers for the quorum), and only then deletes their sessions (web and CLI), passkeys and push devices, drops their
seals on waiting holds, revokes the tokens, guard keys and receipts keys they made, closes what those asked for, and
revokes their open invites. The last owner can be neither removed nor demoted, so the account is never left without
someone who can run it. Test: *removing a member*.

**T7. The owner plane.** Owners can invite, change roles (owners included), remove people and lower the quorum, and an
owner can delete the account. A rogue owner is a trust problem the two-person seal does not solve: every one of these
changes needs a fresh passkey ceremony, is in the audit log and wakes every member's devices, and lowering the quorum
takes 24 hours. Collusion between two approvers is out of scope.

**T8. CSRF and hosts.** Team changes need a web session, the `x-leash` header and an Origin equal to the host they were
sent to; the public join routes check the Origin and refuse the old host. Test: *CSRF and hosts*.

**T9. Privacy.** Public receipts of an approval that needed two seals carry `meta.quorum` and `meta.votes` (numbers)
only; a seal that does not complete the quorum is not a receipt. Names, member ids, labels and passkey fingerprints stay
in the account (the team, the hold cards and the private audit log). Inside a team, every member reads the audit log,
the holds and the command line sign-ins (with where each started). Test: *receipts*.

**T10. Freeze and seals.** Nothing is sealed or approved while the account is frozen (checked in the seal's statement),
and freezing drops the seals already on waiting holds, so nothing anyone said yes to before the freeze counts after it.
Test: *Freeze*.

**T11. Budgets.** The proxy reads the quorum in the token's query (no extra query); a seal, a join, a removal and
reading the team each stay well under 50 D1 queries. Test: *budgets*.

### The domain move (two hosts)

**D1. RP ID confusion.** The service answers on counterseal.gautamkhosla.com and leash.gautamkhosla.com. WebAuthn
ceremonies use the RP ID of the host the request came from, chosen from an allow list of exactly these two by the
Origin header (or the URL for clients without one); a client never names it. Each passkey records its RP ID and is
refused on the other host; a challenge records its origin and is refused on the other host; the authenticator data's RP
ID hash and the client data's origin are checked as before. Tests: `test/domain.test.js`.

**D2. Cross-host CSRF.** The two hosts are the same site (gautamkhosla.com), so SameSite alone does not separate them.
Writes need the `x-leash` header (a preflight, refused) and an Origin equal to the origin of the host they were sent to;
cookies are host-only (`__Host-`). Test: *CSRF*.

**D3. The move link.** Whoever holds a live link can add a passkey to that account, so the link is made only on the
old host, by a web session, after a fresh passkey assertion; it is 32 random bytes, stored as SHA-256, bound to the
account, single use (consumed atomically when the new passkey is saved, and only for the account it was made for),
valid 10 minutes, at most 3 an hour per account, and audited. It lives in the URL fragment and POST bodies, so it is not
in request lines, logs or Referer headers, and the page removes it from the address bar at once. Residual: anyone who
sees the link within those 10 minutes (a shoulder, a shared screen) could use it first; the owner would see
`passkey_added` in the audit log and the extra passkey under Account, and can remove it. Tests: *Move to Counterseal*,
*Move link: expiry, replay, wrong account, rate limit*.

**D4. Old clients.** leashcli 0.1.1 and agents keep calling leash.gautamkhosla.com; `/v1` and `/p` are never
redirected there.

## Residual risks

- Irreversible operations the map does not cover. Mitigation: conservative defaults, versioned map, user `hold` rules.
- The coding-agent guard runs on the agent's machine and can be bypassed there (G-section). Mitigation: say so plainly;
  for a hard stop, the agent gets a Counterseal token instead of the real key.
- The human approves the wrong thing. Mitigation: the approve screen shows method, host, path, rule, reason and a preview.
- Two people who agree to act together, or one person with two identities their owner invited, can give two seals
  (T1, T7). Mitigation: every join and role change is announced and audited, a new approver's seal waits 24 hours while
  two are required, and the authenticator that holds one of the team's passkeys cannot make another.
- A person approves a CLI sign-in someone sent them (S11). Mitigation: typed codes, context and warnings, 7-day
  sessions, alerts and one-tap revoke of the session and all it made.
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
