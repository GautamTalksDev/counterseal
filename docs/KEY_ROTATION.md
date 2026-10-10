# Key rotation and recovery drill

Every secret the Worker holds, what rotating it costs, and the exact steps. Run commands from `server/`. Each
`wrangler secret put` or `secret delete` makes a new Worker version at once, with the code that is deployed now, so the
order of the steps below matters. Never paste a secret into a command line: pipe it, as shown, so it stays out of shell
history.

Tested by `server/test/key-rotation.test.js` (the vault parts) and `server/test/admin.test.js` (the operator token).

| Secret | Rotate? | Cost of a rotation |
| --- | --- | --- |
| `LEASH_KEK` (vault master key) | Yes, with the procedure below | None if done in order; done wrong, vaulted keys stop opening |
| `IP_SALT` | Yes, any time | Rate limit counters start again from zero |
| `VAPID_PRIVATE_JWK` | Yes, any time | Every device has to turn alerts on again |
| `STATS_TOKEN` | Yes, any time | None |
| `LOG_KEY_JWK` | **Never** | Breaks the public log for everyone who verifies it |

## LEASH_KEK, the vault master key

Each vaulted key (table `credentials`) and each alert channel webhook (table `channels`) is sealed with its own random
AES-256-GCM data key. Only that 32-byte data key is wrapped with `LEASH_KEK`. A rotation unwraps each data key with the
outgoing key and wraps it again with the new one; the sealed secret itself is never decrypted for this and its
ciphertext does not change (`server/src/vault.js`, `rewrap`).

The code knows three names:

- `LEASH_KEK`: the master key.
- `LEASH_KEK_NEXT`: when set, it wraps every new data key, and `LEASH_KEK` is used only to open rows not moved yet.
- `LEASH_KEK_OLD`: the other way round, for when you still hold a copy of the outgoing key.

Use `LEASH_KEK_NEXT`. It needs no copy of the current key, which `wrangler` cannot show you and the install steps never
saved.

Before you start: the code with `LEASH_KEK_NEXT` support must be deployed (version with `POST /v1/admin/vault/rewrap`),
and `STATS_TOKEN` must be set.

```bash
# 0. a restore point (keep the bookmark it prints)
npx -y wrangler@4 d1 time-travel info leash

# 1. make the new key and keep one offline copy until step 4 is done (a password manager entry, not a file in the repo)
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" > /tmp/kek-next && chmod 600 /tmp/kek-next

# 2. the new key wraps from now on; old rows still open with LEASH_KEK
npx -y wrangler@4 secret put LEASH_KEK_NEXT < /tmp/kek-next

# 3. move every row to the new key; repeat with the "after" cursors it returns until "done" is true
curl -sS -X POST https://counterseal.gautamkhosla.com/v1/admin/vault/rewrap \
  -H "authorization: Bearer $(cat ~/.counterseal-stats-token)" -H 'content-type: application/json' -d '{}'
#   {"credentials":{"checked":N,"rewrapped":N,"failed":0,"next":null},"channels":{...},"rotating":true,"done":true}
#   with "next" set:  -d '{"after":{"credentials":"<next>","channels":"<next>"}}'
#   run it once more: every "rewrapped" must be 0, every "failed" 0

# 4. the new key becomes LEASH_KEK. FIRST put LEASH_KEK, THEN delete LEASH_KEK_NEXT (the other order leaves a
#    version that wraps with the old key while rows are on the new one, and vaulted keys stop opening until step 4 ends)
npx -y wrangler@4 secret put LEASH_KEK < /tmp/kek-next
npx -y wrangler@4 secret delete LEASH_KEK_NEXT

# 5. check: a protected call through a vaulted key works, then remove the copy
shred -u /tmp/kek-next
```

`"failed"` counts rows that open with neither key (a row changed outside the API, so its additional data no longer
matches). They are left untouched and reported, never deleted. Before step 4, look at them: after step 4 they can never
open. The endpoint answers 404 without the right token (as for any unknown path), is rate limited to 30 a minute per
network, and returns counts and row ids only.

If the old key leaked, rotating it is not enough on its own: a copy of the database from before the rotation still opens
with it. Also rotate the provider keys people stored (each user deletes and re-adds them), and treat D1 time travel
points from before the rotation as sealed with the leaked key.

With `LEASH_KEK_OLD` instead (you hold the outgoing key): `secret put LEASH_KEK_OLD` with the current value first, then
`secret put LEASH_KEK` with the new one, run step 3, then `secret delete LEASH_KEK_OLD`.

## IP_SALT

Network addresses are never stored; rate limit buckets are named by `sha256(IP_SALT | address)` (`server/src/ratelimit.js`).
A new salt only renames the buckets, so every limit (sign-ups per network per day included) starts again from zero.

```bash
node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))" | npx -y wrangler@4 secret put IP_SALT
```

## VAPID_PRIVATE_JWK (phone and desktop alerts)

A browser's push subscription is bound to the public key it was made with, so after a rotation the push services refuse
the old subscriptions. The Worker deletes a subscription when its push service answers 404 or 410 (`server/src/push.js`),
and each person turns alerts on again in the app. Holds are not affected; only the alert is.

```bash
node dev/vapid-keygen.mjs | npx -y wrangler@4 secret put VAPID_PRIVATE_JWK
```

## STATS_TOKEN

At least 32 characters; anything shorter is treated as unset. The old token stops working with the new version.

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" | tee ~/.counterseal-stats-token | npx -y wrangler@4 secret put STATS_TOKEN
chmod 600 ~/.counterseal-stats-token
```

## LOG_KEY_JWK: never rotate

This Ed25519 key signs the public log's checkpoints (C2SP signed notes, `server/src/note.js`). The verifier key, made of
the log's name, a hash of the public key and the key itself, is published and pinned by the SDK, the CLI, the verify page
and anyone who saved a receipt. A checkpoint signed with another key does not verify under the pinned one, so a new key
would look exactly like a forked or forged log, which is the attack the log exists to show. Old receipts would not
become false, but nobody could check that new checkpoints extend the old ones.

Keep it as it is. If it ever leaks, do not swap it quietly: start a new log with a new name and a new key, publish both
verifier keys and the last checkpoint of the old log signed by the old key, and say so on the status and security pages.

## Recovery drill

### D1 (accounts, vaulted keys, holds, audit)

D1 time travel keeps 30 days of history (Workers Paid; 7 days on Workers Free). Once a month, and before every
migration:

```bash
# where we are now
npx -y wrangler@4 d1 time-travel info leash
# a restore point for a moment in the past (RFC 3339 or a Unix timestamp)
npx -y wrangler@4 d1 time-travel info leash --timestamp "2026-10-10T12:00:00Z"
# the drill: export, then restore into a scratch database, never into leash itself
npx -y wrangler@4 d1 export leash --remote --output /tmp/leash-drill.sql
npx -y wrangler@4 d1 create leash-drill
npx -y wrangler@4 d1 execute leash-drill --remote --file /tmp/leash-drill.sql
npx -y wrangler@4 d1 execute leash-drill --remote --command "SELECT COUNT(*) FROM accounts"
npx -y wrangler@4 d1 delete leash-drill && shred -u /tmp/leash-drill.sql
```

The export holds sealed rows only (no plaintext keys), but it does hold the names people chose and the audit rows: keep it on an encrypted disk and delete it after the drill.

A real restore (this loses every write after the bookmark, so put the site in maintenance or accept that):

```bash
npx -y wrangler@4 d1 time-travel restore leash --bookmark <bookmark>
```

Vaulted rows restored from before a key rotation are wrapped with the outgoing key: set it as `LEASH_KEK_OLD` again (if
you still have it) and run step 3 of the rotation, or those keys stay sealed for good.

### The public log (Durable Object `ReceiptLog`)

The log lives in a SQLite-backed Durable Object, not in D1, so D1 time travel does not cover it. Cloudflare keeps 30 days
of point-in-time recovery for SQLite-backed Durable Objects, but it is reached only from inside the object's code
(`ctx.storage.getBookmarkForTime()` and `ctx.storage.onNextSessionRestoreBookmark()`), and this code has no route for it.
So today a lost or corrupted log cannot be restored from the command line.

That is acceptable for this log by design: it is append-only and public, every receipt carries its own inclusion proof,
and anyone holding a checkpoint can tell if the log was rolled back. Restoring it to an earlier point would itself look
like a rollback to every verifier. If a restore route is ever added it must be owner-only, passkey-gated, and announced.
