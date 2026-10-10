## What and why

<!-- One topic per pull request. Link the issue if there is one. -->

## How I tested it

<!-- Tests added or changed, commands run. -->

## Checklist

- [ ] `cd server && node --test test/*.test.js ../sdk/*.test.mjs ../cli/test/*.test.mjs` passes
- [ ] `node scripts/sync-guard.mjs --check`, `node scripts/rebrand.mjs --check` and `node scripts/cli-name.mjs --check` pass
- [ ] No secrets, keys, `.dev.vars`, `.env` files or local databases are included
- [ ] Docs and copy claim only what the code and tests show, and say what is not covered
- [ ] No new runtime dependencies (or the reason is in the description)
- [ ] No em dashes or en dashes in docs or user-facing text
