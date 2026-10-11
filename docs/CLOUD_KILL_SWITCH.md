# Cloud kill switch (design note, not built)

The Budget seal caps what flows through Counterseal. Customer discovery (10 Oct 2026) ranked "no hard spend cap on cloud
and AI bills" first, and much of that pain is cloud usage that never passes a proxy: a loop that calls a Lambda, an
egress spike, a GPU left on. This note is for a later "cloud kill switch". Nothing here is built.

## Shape

Counterseal reads the cloud account's own billing or usage numbers on a schedule and, past a hard limit the owner set,
takes one pre-agreed stopping action. The owner approves every new connection and every raise with a passkey.

## Least privilege, per cloud

Two separate credentials, never one:

1. **A read credential** for cost and usage only.
   - AWS: an IAM role Counterseal assumes with an external id, allowed only `ce:GetCostAndUsage` and
     `budgets:ViewBudget`. No resource access.
   - Google Cloud: a service account with `roles/billing.viewer` on the billing account (or BigQuery billing export
     read on one dataset).
   - Cloudflare: an API token with Account Analytics Read and Billing Read only.
2. **A stop credential** that can do exactly one reversible thing, chosen by the owner at setup:
   - AWS: attach a deny all SCP or policy to one named role or account; or set the concurrency of named Lambda
     functions to zero.
   - Google Cloud: disable billing on one project (this stops everything in it; it is reversible but drastic), or
     scale named services to zero.
   - Cloudflare: route a Worker to a maintenance response, or pause a zone.
   Never delete. Never a credential that can create other credentials.

## The trust problem

This is the hard part, and why it is not built yet:

- **A stranger with write access to your cloud.** Even a narrow stop credential lets Counterseal take production
  offline. Personas in discovery only paid when access was minimal. The stop credential must be scoped to one action
  on named resources, and the owner must be able to read the exact policy before granting it.
- **Billing data is late.** AWS Cost Explorer and GCP billing exports lag by hours. A hard cap built on them is a
  late cap. The kill switch would need usage metrics (invocations, egress) for speed, and billing for truth.
- **Polling needs a schedule.** Workers Free has no spare cron here (the account's cron triggers are used). This needs
  a paid plan or a cron slot, or polling from the owner's own machine or CI.
- **A false stop is an outage.** Two person approval for the first stop, a dry run mode, and a clear "unstop" path with
  a passkey are required.
- **Key custody.** Cloud credentials in Counterseal's vault raise the stakes of the vault. Prefer role assumption with
  external ids and short sessions over long lived keys.

## Smallest honest first step

A read only "late warning" that compares cloud spend to a limit and wakes the owner, with no stop credential at all.
Only after people use it, add one opt in stop action per cloud, behind a passkey and a dry run.
