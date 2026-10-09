// The one place for every user-facing product name, domain and tagline.
//
// Rename: change the values below, then run `node scripts/rebrand.mjs` from the repo root. It rewrites the previous
// values (kept in brand.lock.json) everywhere they appear in the site, the CLI and the docs, regenerates
// site/public/brand.js, and records the new values. CI (server/test/brand.test.js) fails if anything is out of step.
//
// Internal identifiers stay as they are on purpose and are NOT brand: the "leash" Worker and D1 database names, the
// lsh_ / lsc_ / lsd_ / lsr_ token prefixes, the __Host-leash cookie, the x-leash header, the leash_request MCP tool and
// "leash" MCP server key, API paths (/v1/*, /p/*), and the leash-pop signature tag. Changing those would break live
// accounts, live agents and the published CLI (leashcli 0.1.x).
export const BRAND = {
  // "Counterseal" in prose, "COUNTERSEAL" as the wordmark (logo text, nav brand)
  name: 'Counterseal',
  wordmark: 'COUNTERSEAL',
  tagline: 'Every irreversible action gets a second seal.',
  // the line for the Record part (decided 9 Oct 2026)
  recordLine: 'If it was recorded, you can prove it.',
  // Where the product lives. The old host (legacyDomain) keeps serving /v1 and /p exactly as before (the published CLI
  // refuses redirects) and /app for the passkeys made there, and redirects every other page here (docs/DEPLOY.md).
  // The hosts the server accepts are set by ORIGIN / RP_ID and LEGACY_ORIGIN / LEGACY_RP_ID in wrangler.jsonc.
  domain: 'counterseal.gautamkhosla.com',
  origin: 'https://counterseal.gautamkhosla.com',
  legacyDomain: 'leash.gautamkhosla.com',
  // npm. The CLI is published as leashcli; "counterseal" is the planned name (free on npm on 9 Oct 2026, not published).
  // Keep cli at the published name until the new package exists, or every install line on the site breaks.
  cli: 'leashcli',
  cliPlanned: 'counterseal',
  sdk: 'counterseal-sdk',
  repo: 'https://github.com/GautamTalksDev/leash',
  owner: 'Gautam Khosla',
  city: 'Ottawa',
  security: 'security@gautamkhosla.com',
  privacy: 'privacy@gautamkhosla.com',
  hello: 'hello@gautamkhosla.com',
};

// The public log's name, signed into every checkpoint. It is NOT renamed with the brand: once the log has its first
// entry, a new name would make every existing checkpoint and receipt unverifiable, so the log refuses to sign under a
// different name or key (see src/log.js). It already uses the final name. Deploys may override it with the LOG_ORIGIN
// var in wrangler.jsonc, but only before the first receipt.
export const LOG_ORIGIN_DEFAULT = 'counterseal.gautamkhosla.com/log';
