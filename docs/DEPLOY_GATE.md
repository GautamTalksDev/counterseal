# Deploy Gate

Hold a GitHub Actions job until the owner approves it with a passkey. The approval is bound to the repository, workflow,
commit and run named in the token GitHub signs for the job (an OIDC token), so what is approved is what runs.

Status: a preview. It is on the live service (migration `0007_gates.sql`) but has been tested only against a stand-in issuer
that signs like GitHub, not yet with real GitHub tokens. The action is in
[`action/deploy-gate`](../action/deploy-gate) and is not published to the GitHub Marketplace.

## Why

GitHub's own deployment approvals have a plan limit. Its documentation says that on the Free, Pro and Team plans, required
reviewers are available only for public repositories, and the same for wait timers and for custom deployment protection
rules ([Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
read 9 Oct 2026). A gate does not use those features. It is a step in your workflow that asks Counterseal, and Counterseal
asks you, with your passkey on your phone or laptop.

What is checked and what is not:

- Checked and tested here: the token's signature and claims, the gate's rules, the approval and its one use, the receipts,
  and the action as a program, all against a stand-in for GitHub that signs like GitHub (`server/test/gh.js`).
- Not yet done: a run against real GitHub. The token's shape follows GitHub's documentation, its discovery document and a
  real token shown in a third-party README; the first real run, in a throwaway private repository, is the real test. If a
  claim differs, the server answers `oidc_claims` and names it, and nothing is held. Whether a gate works in a private
  repository on a Free, Pro or Team plan is therefore expected (GitHub's OIDC documentation sets no plan limit) but not yet
  confirmed by a run.

## What a gate is, and is not

A gate is a pause the job asks for. A person who can edit the workflow file can remove the step, so:

- protect the workflow file (branch protection, CODEOWNERS) and list only that file and branch on the gate, or
- use phase 2 ("no approval, no key", below): the deploy key is not in the repository's secrets at all. It stays in the
  Counterseal vault, and the job gets a short-lived token for it only after you approve.

A job that waits is a running job: on a private repository it uses Actions minutes the whole time, so keep
`timeout-minutes` low.

## Set it up

1. **Make a gate.** In the app, Deploy gates, "New gate". Give it the repository (`owner/name`), the workflow files
   (`.github/workflows/deploy.yml`), the branches or tags it deploys from (`refs/heads/main`), optionally the
   environments and the triggers. It asks for your passkey: a gate decides which repository may ask you to approve
   deploys. Nothing is accepted by default; a gate cannot be edited (make a new one and revoke the old).
2. **Copy the action** into the repository: `action/deploy-gate` from this repository to `.github/actions/counterseal-gate`.
   (The action is not on the Marketplace. To use it from this repository directly, pin a full commit:
   `uses: GautamTalksDev/counterseal/action/deploy-gate@<full commit sha>`.)
3. **Add the step** the app shows after you make the gate, to a job with `permissions: id-token: write`. Sample workflows:
   [`deploy.yml`](../action/deploy-gate/examples/deploy.yml) (a gate job, then the deploy job) and
   [`deploy-with-key.yml`](../action/deploy-gate/examples/deploy-with-key.yml) (phase 2).
4. **Run the workflow.** The job prints a link and waits. Your phone is alerted (if you turned alerts on); open the link,
   check the card, approve with your passkey. The job goes on.
5. **The first approved run binds the gate** to GitHub's ids for the repository, so a repository that is renamed keeps
   working and one that is deleted and re-created under the same name does not.

```yaml
jobs:
  approve:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # lets the job ask GitHub for the token the gate checks; it grants nothing else
      contents: read
    steps:
      - uses: ./.github/actions/counterseal-gate
        with:
          gate: gate_0123456789abcdef01234567
          summary: deploy ${{ github.sha }} to production
```

### Inputs and outputs

| Input | Default | |
|---|---|---|
| `gate` | required | The gate's id (`gate_` and 24 hex characters). It is pasted in workflow files, so it is not a secret. |
| `summary` | none | One line shown to the approver as "Text from the workflow (not verified)", 120 characters at most. Use values you trust (the commit hash), not a commit message or a branch name from someone else. |
| `timeout-minutes` | 15 | 1 to 60. The request expires then, the step fails, and the request is withdrawn. |
| `server` | https://counterseal.gautamkhosla.com | Only the host: https, no path or query (http only for a server on this machine). |

| Output | |
|---|---|
| `decision` | `approved`, `denied`, `expired`, `timeout`, `cancelled` or `refused`. The step fails for everything but `approved`. |
| `hold` | The request's id, as in the app. |
| `token`, `base-url`, `provider`, `token-expires-at` | Phase 2 only (below). `token` is masked in the log. |

The step prints the approve link (never a code or a secret), fails on deny, expiry, timeout or refusal, withdraws its request
if the job is cancelled, and retries a short outage with a fresh GitHub token each time. It never prints GitHub's token, its
poll secret or the phase 2 token (they are masked before they are used), and text it receives never starts a log line, so it
cannot become a workflow command.

## What the server checks

A request carries GitHub's OIDC token as `Authorization: Bearer`. The checks run in this order, and a request that fails any
of them before the replay check writes nothing and alerts no one:

| Check | How |
|---|---|
| Signature | RS256 only, pinned (never taken from the token's header); the key comes only from GitHub's own key set by `kid` (`jku`, `jwk`, `x5u`, `x5c` and `crit` are refused); checked with WebCrypto before any claim is read. The key set is fetched from `https://token.actions.githubusercontent.com/.well-known/jwks` at most every 10 minutes per isolate, with one early refetch a minute for an unknown `kid` (rotation); if GitHub cannot be reached, cached keys keep verifying for up to an hour, then the answer is 503. |
| Issuer | exactly `https://token.actions.githubusercontent.com` |
| Audience | exactly one string, `<this service's host>/gate/<gate id>`: a token made for one gate (or for another service) is no use at another. The action asks GitHub for it. |
| Time | `exp`, `nbf` and `iat` with 60 seconds of skew; a token valid for more than an hour from now is refused |
| Shape | every claim the gate uses is checked to a strict shape; a missing or odd one is a refusal, never a guess |
| The gate | the repository (its name until the gate is bound, GitHub's repository and owner ids after), the top-level workflow and the job's own workflow (both must be listed files of that repository; reusable workflows from other repositories are not supported), the ref (exact, or a prefix with one trailing `*`), the environment (if the gate lists any) and the trigger |
| Replay | each token's `jti` is accepted once (a D1 row until the token could no longer verify) |

Triggers a gate may accept: `push`, `workflow_dispatch`, `release`, `deployment`, `merge_group`, `schedule`,
`repository_dispatch`. The default is the first five. `pull_request`, `pull_request_target` and `workflow_run` are never
offered: they run code from a fork or from another workflow. "Every branch" cannot be written (a bare `refs/heads/*` is
refused); list branches, or a prefix such as `refs/heads/release/*`.

A run from another repository gets `403 gate_refused` with `reason: "repository"` and nothing else: it learns nothing about
the repository the gate belongs to.

## What the approver sees

A hold of kind `deploy`, on the same Held list as every other approval. Everything in the table comes from the token GitHub
signed, which Counterseal verified, under a "Signed by GitHub" badge: repository and visibility, commit (short, with a link),
branch or tag, workflow, environment, who started the run and on which trigger, run and attempt (with a link), runner. On a
gate's first run it says that approving also binds the gate to the repository. The `summary` the workflow sent is shown apart,
labelled "Not verified". The links are built by the server from checked values and followed only if they are plain
github.com addresses.

The approval covers exactly one run: it is bound to `SHA-256(["v1", "deploy", gate, repository id, owner id, run id, run
attempt, commit, workflow ref, job workflow ref, ref, environment, check run id])`. A different commit, run, attempt,
workflow, ref, environment or job is a different request and needs its own approval.

Approve with your passkey (web session, user verification required, as for every hold). Deny, optionally with a reason of up
to 200 characters: the job's log shows it, after a fixed label, as text. A command line sign-in can deny but never approve.

## The wait

The step polls `GET /v1/gate/status/<id>?wait=20` with a secret (`gps_`, shown once, stored hashed, good for that one request
until it would have expired and 11 minutes more). Waiting writes nothing to D1 and is at most 12 reads. The poll that finds the
request approved spends it, once: the approval is that run's and nobody else's, and the next poll reads `used`. If the response
to that poll is lost, the job fails (and a re-run asks again): an approval is never replayed.

Two jobs with the same claims (the same job asked twice) share one request, and one approval lets one of them through. Jobs of
a matrix have different `check_run_id`s, so each is its own request.

## On a team (two-person seal)

A gate belongs to the person who made it, and a request from it is held like any other hold of a team. If the team needs two
seals, the job waits until two different owners or approvers have each approved with their own passkey; the first approval
releases nothing. If the team turned self-approval off, the person who made the gate cannot be one of them. A member can make a
gate and ask, but cannot approve; a viewer can deny a request but make nothing. Revoking a gate is for its maker or an owner.
If its maker is removed, or made a viewer, their gates stop at once: the requests waiting at them are closed and the tokens they
handed out are revoked.

A gate that hands out a key with a policy that pre-approves irreversible calls is one person approving in advance, so it needs
an owner or approver and is refused while the team needs two seals (or someone other than the maker). If the team starts
requiring two seals later, those pre-approvals pause: the call is held for approval like any other.

## Phase 2: no approval, no key

A gate may name a key in your vault and a policy. The deploy key is then not in the repository's secrets at all. When you
approve, the poll that spends the approval also returns a fresh Counterseal token (`lsh_`) for that key, valid 15 minutes,
under the policy you gave the gate, and the step puts it in the `token` output (masked), with `base-url` (the proxy address
for the key's provider: use it instead of the provider's own) and `provider`. The real key never leaves the vault. The token
is an ordinary Counterseal token: the irreversible map applies to it, and a call the policy does not pre-approve is held for
you like any other.

Making such a gate needs your passkey (the same ceremony), which is also what allows a policy that pre-approves irreversible
calls. If the key was deleted or the account has 200 live tokens, the approval is not spent; revoking the gate revokes the
tokens it handed out.

## Limits

20 active gates per account. Per gate: 10 requests waiting, 30 new requests an hour. Per account: 100 requests waiting (shared
with brokered calls and commands), one phone alert a minute. A poll secret: 30 polls a minute. Per network: 600 requests a
minute to ask and 600 to poll (hosted runners share networks, so this is generous). A gate's request lasts as long as the job will wait (up to 60
minutes); an approved request must be spent within 10 minutes.

## Receipts and privacy

With public receipts on, a gate's decisions are sealed in the public log with fixed words only: `DEPLOY github.com`, the
decision (`held`, `approved`, `denied`, `executed` when the job went on), the rule (`gate.bind` on a gate's first run,
`gate.deploy` after) and the map version. Never the repository, commit, workflow, run, person, the gate's label, the summary or
a deny reason. If you tick "Show the repository's name in this gate's public receipts" when making the gate (off by default),
`meta.repo` carries `owner/name` and nothing else new; once public, a name stays in the log for good.

Your private audit log has the repository, commit, ref, run and attempt of each request (never the person's name or the
summary text). A deploy hold keeps the facts the card shows, including the GitHub login of whoever started the run, and its
preview, for about a day after it closes; then the sweep drops them. A phone alert's text (the gate's label, `repository@commit`
and the environment or ref) can appear on a lock screen.

## Freeze

While the account is frozen (Brakes), nothing new is asked (`423 account_frozen`, after the run is known to be the gate's,
before anything is written and before the run's token is spent), a wait ends at its next read with the same answer, no
approval is spent and no key is handed out, and approving is refused until you unfreeze with your passkey. Approvals nobody
used yet are void. Denying a request and a job withdrawing its own still work.

## When it fails

| Answer | Meaning |
|---|---|
| `401 oidc_required` | No GitHub token: the job lacks `permissions: id-token: write`, or it is a pull request from a fork (those never get one). |
| `401 oidc_audience` | The token was not made for this gate. Use the action, which asks GitHub for the right audience. |
| `401 oidc_expired`, `oidc_not_yet_valid` | A clock more than 60 seconds off, or a token held too long. The action asks for a fresh one on every try. |
| `401 oidc_replayed` | That token was already used. |
| `401 oidc_unknown_kid`, `503 oidc_keys_unavailable` | GitHub rotated its keys a moment ago, or could not be reached: retry (the action does). |
| `401 oidc_claims` | A claim the gate needs is missing or odd; the message names it. |
| `403 gate_refused` | `reason` is `repository`, `workflow`, `ref`, `environment` or `event`; the message says which value is not on the gate's list. |
| `404 gate_not_found` | No such gate, or it was revoked. |
| `423 account_frozen` | The account is frozen. |
| `429 too_many_holds`, `slow_down` | The limits above. |

The full request and answer shapes are in [PROTOCOL.md](PROTOCOL.md#deploy-gates). The threat model is in
[THREAT_MODEL.md](THREAT_MODEL.md) (section H).
