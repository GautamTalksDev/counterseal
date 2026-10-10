# Release checklist

For the CLI (`counterseal` and its alias `leashcli` on npm) and for the Worker and site. Nothing here runs by itself:
a person follows it.

## One-time setup (before the first release from CI)

1. **The packages exist on npm.** Trusted publishing is configured in each package's settings on npmjs.com, so a package
   has to exist first. `counterseal` 0.3.0 is on npm (checked 10 Oct 2026); `leashcli` 0.1.1 was the first name. For a
   brand new package, publish once by hand from a clean checkout with 2FA (`cd cli && npm publish --access public`), or
   check npm's current docs for configuring a trusted publisher before the first publish.
2. **A trusted publisher for each package** (npmjs.com, the package, Settings, Trusted publishing, GitHub Actions):
   owner `GautamTalksDev`, repository `counterseal` (after the GitHub rename), workflow `publish.yml`, environment `npm`. npm does not check this when you
   save it; a mistake shows only when publishing fails. Source: https://docs.npmjs.com/trusted-publishers (read
   9 Oct 2026: npm CLI 11.5.1 or later, Node 22.14.0 or later, GitHub-hosted runners only).
3. **Provenance needs a public repository and a public package.** If the repository is private, npm cannot show provenance;
   the workflow then fails at publish, on purpose. Make the repository public first, or remove `--provenance` and the
   `provenance` entry of `publishConfig` knowingly.
4. **The `npm` environment** (GitHub, Settings, Environments): add yourself as a required reviewer so no publish happens
   without your click.
5. After the first successful trusted publish, in each package's settings choose **Require two-factor authentication and
   disallow tokens**, and delete any npm automation tokens.

## Every CLI release

1. Bump the version in all four places: `cli/package.json`, `VERSION` in `cli/leash.mjs`, `GUARD_VERSION` in
   `cli/guard.mjs`, and `packages/leashcli/package.json` (its `version` and its `dependencies.counterseal`). Then
   `node scripts/sync-guard.mjs` (the plugin's pinned copies).
2. `cd server && node --test test/*.test.js ../sdk/*.test.mjs ../cli/test/*.test.mjs`: all green.
3. `node scripts/sync-guard.mjs --check && node scripts/rebrand.mjs --check && node scripts/cli-name.mjs --check`.
4. Dry run: Actions, publish, Run workflow (dry run ticked). Read the file list `npm publish --dry-run` prints: only the
   files in `files`, no test files, no keys.
5. Make a GitHub release tagged `cli-v<version>` (for example `cli-v0.3.0`). The workflow checks the tag matches every
   version, runs the suite, writes the CycloneDX SBOM of `counterseal`, publishes it with provenance, then `leashcli`, and
   attaches both SBOMs to the release.
6. Check: `npm view counterseal@<version>` shows the provenance attestation; `npx counterseal@<version> --version` and
   `npx leashcli@<version> --version` print the version on a clean machine; the npm page links back to this repository
   and the workflow run.

## Every Worker and site release

1. Publish the CLI first if the site's install lines name a version that is not on npm yet (docs/DEPLOY.md, "Publishing
   the CLI"). To deploy before it, set `cliInstall` to `leashcli` and run `node scripts/cli-name.mjs`.
2. `security.txt` (served from `server/src/index.js`): `Expires` must be in the future and under a year away; the test
   `security.txt is valid` fails 30 days before it lapses. Move it a year forward when it does.
3. The full suite; `node bench/cpu.mjs` for the CPU of the hot paths (docs/DEPLOY.md).
4. A time-travel bookmark of D1 (`npx -y wrangler@4 d1 time-travel info leash`), then the additive migrations, then
   `wrangler deploy` (docs/DEPLOY.md has the exact commands).
5. After deploying: sign in, run "Try a held call" in the app, check `/v1/meta`, `/v1/stats`, `/.well-known/security.txt`,
   the manifest (`/manifest.webmanifest`) and that the app installs (Chrome: the install icon in the address bar).
6. Update the README's status line with what is now live, checked against the live service, not assumed.
