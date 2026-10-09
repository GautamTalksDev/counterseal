# Policy reference

Each `lsh_` token carries a policy. A policy can only **narrow** what the underlying key can do.

```json
{
  "allow": [{ "method": "GET", "path": "/repos/acme/**" }],
  "deny":  [{ "path": "/orgs/**" }],
  "hold":  [{ "method": "POST", "path": "/repos/*/*/releases" }],
  "default": "allow",
  "readOnly": false,
  "perMinute": 120,
  "unattendedIrreversible": []
}
```

| Field | Type | Meaning |
|---|---|---|
| `allow` | rules | If present, only these calls pass (plus anything the default allows; see below). |
| `deny` | rules | Always refused with `403 leash_denied`. Checked first. |
| `hold` | rules | Held for approval even though the irreversible map does not require it. |
| `default` | `allow`, `hold`, `deny` | What happens to calls that match no rule. With an `allow` list, `allow` means "refuse the rest". |
| `readOnly` | boolean | Only `GET` and `HEAD`. |
| `perMinute` | 1 to 600 | Rate limit for this token. Default 120. |
| `unattendedIrreversible` | rules | Irreversible calls that may run **without** approval. Only settable in a passkey ceremony. |

A **rule** is `{ "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "*", "path": "<glob>" }`. Paths are relative to
the provider's base (for Cloudflare, after `/client/v4`). Globs: `*` matches one path segment, `**` any depth, `{a,b}`
alternatives (which may contain `*` and `**`; braces cannot nest, and an unbalanced brace is refused with
`400 bad_policy`). A path may use `**` at most twice, and each segment (and each `{a,b}` alternative) at most one
wildcard, so `/repos/*/release-*` and `/**/issues/**` work but `/**/a/**/b/**` and `/*a*b` are refused with
`400 bad_policy`: globs run as regular expressions, and more wildcards than that can backtrack for seconds on a long
path.

Paths are matched in one canonical form, and that exact path is what the broker sends upstream: a path with an empty
segment (`//`, including a doubled trailing slash), a `;` path parameter or an encoded NUL is refused with
`400 bad_path`, one trailing slash is dropped (on requests and on your rules), and on GitHub, where owner and repo names
are case-insensitive, both the path and your rule are lowercased before matching. A `deny` or `hold` rule written for
`GET` also covers `HEAD`.

The irreversible map is stricter than your rules: it ignores case on every provider, also matches a path without a format
suffix such as `.json`, treats `HEAD` as `GET`, and holds any request that carries a method override (`_method`). A
method override hold cannot be pre-approved with `unattendedIrreversible`.

Paths for the newer providers are relative to their base, like Cloudflare's: Neon after `/api/v2`, Fly.io after `/v1`. Shopify is brokered through one path only, `/admin/api/<version>/graphql.json`
(a version such as `2026-07`, or `unstable`); every other path on the store is refused with `404 unsupported_path` before anything is sent. A Shopify key is stored with its store address
(`your-store.myshopify.com`), and a token goes only to that store. Shopify reads are POSTs too, so a `hold` or `deny` rule for Shopify names the GraphQL path, not a resource.

## Order of evaluation

1. `deny`
2. `readOnly`
3. The irreversible map (held, unless the call matches `unattendedIrreversible`)
4. `hold`
5. `allow` list
6. `default`

## Recipes

Read-only access to one GitHub org:

```json
{ "readOnly": true, "allow": [{ "path": "/repos/acme/**" }, { "path": "/orgs/acme/**" }] }
```

Let a release agent delete preview branches unattended, nothing else irreversible:

```json
{ "unattendedIrreversible": [{ "method": "DELETE", "path": "/repos/acme/web/git/refs/heads/preview-*" }] }
```

Hold every write to Stripe, not just the money-moving ones:

```json
{ "hold": [{ "method": "*", "path": "/v1/**" }], "allow": [{ "method": "GET", "path": "/v1/**" }], "default": "hold" }
```
