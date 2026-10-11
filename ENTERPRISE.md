# Counterseal for teams and companies

What exists today, and what does not. Every "exists" line points at code or a page you can check. Last updated
10 October 2026.

## Exists

| What | Where to check |
| --- | --- |
| **Self-hosting.** One Cloudflare Worker, one D1 database, one SQLite-backed Durable Object and static assets, Apache 2.0. It fits the Workers Free plan. | [`docs/DEPLOY.md`](docs/DEPLOY.md), `server/wrangler.jsonc` |
| **Passkey approvals.** Every approval (seal) of a held action needs a fresh passkey ceremony by an owner or approver, with their own passkey. Two-person seal (quorum of 2) and separation of duties (self-approval off) per account. | `server/src/team.js`, `server/test/team.test.js` |
| **Single sign-on (OpenID Connect).** An owner picks the team's identity provider with a passkey ceremony. Authorization code flow with PKCE S256, single-use state bound to the browser, nonce, ID token checks (signature by JWKS `kid`, pinned RS256 or ES256, issuer, audience and `azp`, expiry, issue time, `nbf`, verified email), allowed email domains per account, people matched by issuer and subject (never by email). New people join as viewer or member, never owner or approver. JWKS cached 10 minutes per provider, one early refetch a minute for key rotation. Optional client secret, sealed like a vaulted key. | `server/src/sso.js`, `server/migrations/0015_sso.sql`, `server/test/sso.test.js` |
| **SSO in the app.** The team sign-in link (`/app/#sso=<team id>`), the `#sso-error=` and `#sso-joined` returns, the first-passkey prompt for SSO sessions and the owner settings panel in Team. | `site/public/app/app.js` (ssoIn, ssoView) |
| **SSO does not approve.** SSO signs people in and decides team membership. A member who joined through SSO adds their first passkey from that SSO session; every approval still needs that passkey. | `server/src/sso.js` (passkeyBegin, passkeyFinish), test "SSO never approves" |
| **SSO required.** With `enforce` on, members other than owners cannot sign in with a passkey alone (`sso_required`), so someone removed at the identity provider loses access at their next sign-in. Owners keep passkey sign-in, so a provider outage never locks the account out. | `server/src/auth.js` loginFinish |
| **Audit log and receipts.** A hash-chained private audit log of every decision and security change, verifiable in the app (`GET /v1/audit/verify`) and exportable as an evidence pack with the public log's signed checkpoint. Optional public receipts in an append-only Merkle log with no personal data. | `server/src/audit.js`, `server/src/trust.js` (evidence), `server/src/log.js` |
| **Data export and retention.** An owner downloads everything kept about the account (passkey ceremony) and chooses how long closed holds are kept (30, 90 or 365 days). | `server/src/trust.js` |
| **DPA template and subprocessors.** GDPR Article 28 template with the EU Standard Contractual Clauses (2021/914) reference, UK and Swiss notes, Canada PIPEDA section, and a map of where each kind of data lives. One subprocessor: Cloudflare. | [`/privacy/dpa/`](site/public/privacy/dpa/index.html), [`/privacy/subprocessors/`](site/public/privacy/subprocessors/index.html) |
| **Security self-assessment.** OWASP ASVS 5.0 Level 2 (and the Level 3 items met), Top 10 2025, API Top 10 2023, LLM Top 10 2025, Agentic Top 10 2026. Self-assessed, not certified. | [`/security/standards/`](site/public/security/standards/index.html), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |

### SSO API

| Route | Who |
| --- | --- |
| `GET /v1/team/sso` | any member; owners also get who signed in through SSO |
| `POST /v1/team/sso/begin`, `/finish` `{issuer, clientId, clientSecret?, domains[], defaultRole: viewer\|member, enforce}` | owner, web session, passkey |
| `POST /v1/team/sso/off/begin`, `/finish` | owner, web session, passkey |
| `POST /v1/sso/start {team}` | public (Origin checked); returns the provider's URL and sets the binding cookie |
| `GET /v1/sso/callback` | the provider's redirect; answers 303 to `/app/` with a session, or to `/app/#sso-error=<code>` |
| `POST /v1/sso/passkey/begin`, `/finish` | a member in an SSO session who has no passkey yet |

Register `https://<your host>/v1/sso/callback` as the redirect URI at your identity provider. The provider must send
`email` and `email_verified: true` in the ID token, sign it with RS256 or ES256, and support PKCE S256. The team's sign-in
link is `https://<your host>/app/#sso=<team id>` (`GET /v1/team/sso` returns it).

## Does not exist yet

- **SOC 2: planned, not started.** There is no SOC 2 report, no auditor engaged and no Type I or Type II in progress. Do not say or imply otherwise.
- **Other certifications** (ISO 27001 and similar): none.
- **SCIM provisioning** (RFC 7643, RFC 7644): not built. Removing someone at the identity provider stops their next sign-in (and, with SSO required, their passkey-only sign-in); a web session they already hold ends within an hour without activity and after 12 hours at most. Until SCIM exists, remove the person in the Counterseal app too: that ends their sessions at once.
- **SAML**: not built. OpenID Connect only.
- **SIEM export**: no push to a SIEM (no syslog, webhook stream or Splunk or Datadog connector). What exists: the audit log over the API (`GET /v1/audit`, paged) and the evidence pack (JSON), which a script can pull on a schedule. Security events go to the live Workers log stream only and are not stored (request logs are off by choice).
- **External penetration test or audit**: none yet.
- **Signed DPA**: the DPA page is a template. Nothing is agreed until both sides sign a version their lawyers reviewed.
- **Uptime SLA, data residency choice, customer-managed keys**: none.

Contact: Gautam Khosla (GautamTalksDev), developwith.gt@gmail.com.
