# Contributing to Counterseal

Thanks for helping. Counterseal holds other people's production keys, so the bar for changes is: small, tested, and
honest about what they do.

## Before you start

- **Security problems go to a private channel**, never a public issue. See [SECURITY.md](SECURITY.md).
- Open an issue before a large change, so we can agree on the shape first.
- By contributing you agree that your work is licensed under the [Apache License 2.0](LICENSE) (section 5 of the license).
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Set up

You need Node 22 or later (the CLI itself runs on Node 20 or later). There are no runtime dependencies to install.

```bash
git clone https://github.com/GautamTalksDev/counterseal
cd counterseal/server
node --test test/*.test.js ../sdk/*.test.mjs ../cli/test/*.test.mjs   # the whole suite
node dev/local.js 8790                                                # a local server (passkeys work on localhost)
```

## Checks that CI runs (run them before you push)

```bash
for f in cli/*.mjs sdk/*.mjs scripts/*.mjs plugins/*/scripts/*.mjs action/deploy-gate/*.mjs; do node --check "$f"; done
node scripts/sync-guard.mjs --check     # generated copies of the shell map, SQL block and API map are in step
node scripts/rebrand.mjs --check        # names, domains and the repository URL come from server/src/brand.js
node scripts/cli-name.mjs --check       # every install line names one CLI package
```

Some files are generated copies (the site's copies of the SDK, the plugin's pinned guard). Change the source, then run
`node scripts/sync-guard.mjs` and commit the result. Product names, domains and the repository URL live in
`server/src/brand.js`; change them there and run `node scripts/rebrand.mjs`, never by search and replace.

## Pull requests

- One topic per pull request. Describe what changed and why, and what you tested.
- Add or update tests. The irreversible map has a test for every rule; a new rule needs its reason and the reference page
  it comes from in a comment.
- Keep dependencies at zero for the CLI, SDK and Worker. A new dependency needs a strong reason in the pull request.
- Claims in docs and copy must match the code. If you write that something is protected, point at the test that shows it,
  and say what it does not cover.
- Never commit secrets, `.dev.vars`, `.env` files, keys or local databases. Test fixtures use obviously fake values.
- No em dashes or en dashes in documentation or user-facing text.

## Reporting bugs

Use the bug report template. Include the version (`counterseal --version` or the package version), what you ran, what you
expected and what happened. Remove tokens and keys from anything you paste.
