---
page_title: "Waiting, timeouts and recovery - azureacme provider"
subcategory: ""
description: |-
  What "Still creating..." means, how to watch progress, what a timeout does to state,
  the literal recovery command, rate-limit deferral, and CI guidance.
---

# Waiting, timeouts and recovery

Issuance is not instant. A first issuance takes **3–15 minutes** in the normal case, and the
platform's issuance-latency objective is **p99 = 45 minutes**. Everything on this page follows
from those two numbers.

## `Still creating…` and how to see more

Terraform prints `Still creating... [1m20s elapsed]` and nothing else. That is not the provider
being unhelpful — **the Plugin Framework has no channel for streaming progress into Terraform's
default CLI output.** Progress goes to the `TF_LOG` sink instead, which is off by default.

```console
$ TF_LOG=info terraform apply
```

The provider emits one log line on every phase transition (`accepted`, `validating`,
`issuing`, `publishing`, `published`). `TF_LOG=info` is the documented, supported way to watch
an apply; it is not a debugging hack.

`TF_LOG=trace` additionally logs request and response bodies. That is safe by construction: the
provider's response schema carries no key material at all, and bearer tokens are masked before
they reach the log sink.

## The timeouts

```terraform
resource "azureacme_certificate" "api" {
  # …

  timeouts {
    create = "60m"
    read   = "2m"
    update = "60m"
    delete = "10m"
  }
}
```

These are the defaults. `timeouts` is a **client-only** concern: it is never sent to the API,
never overwritten by a refresh, and changing it makes no API call at all.

-> **`create` defaults to 60 minutes, not 30.** With a p99 issuance time of 45 minutes, a
30-minute default would reach the timeout-recovery path routinely — roughly 1% of creates, plus
every rate-limit-deferred one — rather than rarely.

`request_timeout` on the provider block is a different thing: it bounds a single HTTP request
(default `60s`), not the whole operation.

## What a timeout actually does

When `timeouts.create` expires the provider does **not** immediately fail. It performs one final
`GET` of the registration:

- **If the certificate was published while the client was waiting out its backoff**, the provider
  writes full state and **returns success**. The operation completed; reporting that as a failure
  is what starts a destructive sequence on the next apply.
- **If the operation is genuinely still running**, the provider writes partial state and returns
  an error naming the operation id, its current phase, and the fact that *a client disconnect
  does not cancel the operation* — the service keeps going.

### The recovery command

An error returned from `Create` with non-null state causes Terraform to record the object as
**tainted**. The next plan is therefore `[delete, create]`, annotated
`# azureacme_certificate.api is tainted, so must be replaced` — not an update, and not a no-op.

!> **Do not "just re-run `terraform apply`" after a create timeout.** The natural instinct plans a
**destroy** of a registration whose certificate the service has very probably published in the
meantime. Under `deletion_policy = "delete"` the destroy half soft-deletes the live Key Vault
certificate.

The recovery is to clear the taint first. The provider's error message ends with the literal
command:

```console
$ terraform untaint azureacme_certificate.api && terraform apply
```

where the resource address is the one Terraform names at the top of the error. The next plan is
then a refresh that finds the published certificate and reports no changes.

-> The service also refuses the dangerous destroy from its own side, with
`409 operation_in_flight` while an operation for the current spec is running and
`409 destination_recently_published` for a certificate published since you last observed the
registration. Those two guards are a correctness dependency of this provider, not a nicety — but
they are the second line of defence. `terraform untaint` is the first.

## Rate-limit deferral — the provider fails fast on purpose

Certificate authorities rate-limit per **registered domain**, not per certificate. The service
reserves part of that budget for renewals, so bulk onboarding of many names under one registered
domain is deferred **by design**, and the deferral horizon is measured in **days**.

No `timeouts.create` value accommodates days. When the service reports the operation as
`deferred` with an estimated start beyond `now + timeouts.create`, the provider fails
**immediately, before waiting**:

```
Error: Issuance is queued behind a certificate authority rate limit

  Registered domain example.com has used 46 of its 50 weekly certificates.
  Earliest start 2026-09-14T06:00:00Z, which exceeds timeouts.create (60m).

  The registration HAS been created and will issue automatically when the budget resets.
  Nothing further is required. To let this apply succeed now, set wait_for = "accepted"
  (see the note about versionless_secret_id) and re-run, or re-run after the reset.
```

The registration exists and is not orphaned; the partial state written before the failure holds
its identity. This is a deliberate choice over ten resources each sitting at
`Still creating... [59m50s elapsed]` and then failing anyway.

## `wait_for` — and the trap inside it

```terraform
resource "azureacme_certificate" "api" {
  wait_for = "published" # default
  # wait_for = "accepted"
}
```

| Value | Meaning |
|---|---|
| `published` (default) | Return only once the certificate is in the destination vault. |
| `accepted` | Return as soon as the service has accepted the registration. |

!> **`wait_for = "accepted"` reads as a performance option; it is a correctness option.** A
versionless secret URI is *valid but empty* until a version exists, so Terraform cannot detect
the problem itself: an apply that also creates an `azurerm_application_gateway` referencing the
output succeeds, and the listener binds to an empty secret.

The provider therefore withholds the URIs: when `wait_for != "published"`,
`versionless_secret_id` and `versionless_certificate_id` are **null** until a refresh observes
`delivery_stage = "published"`. A downstream reference then fails loudly at apply instead of
binding to nothing. Once state holds a real URI the provider never retracts it.

`consumer_observed` and `best_effort` are recognised and **rejected** with explanatory messages —
the first because it is a circular dependency, the second because the v1 timeout contract above
replaces it.

## CI guidance

| Concern | Guidance |
|---|---|
| **Job timeout** | Set it above `timeouts.create`, with headroom. A CI job killed at 30 minutes during a 45-minute issuance produces exactly the tainted-resource state above, with nobody watching. |
| **`wait_for`** | Leave it at `published` for anything a consumer binds to in the same apply. Use `accepted` only in workspaces that hand the URI to nothing. |
| **Parallelism** | The default `-parallelism=10` is fine. The service admits work at its own rate; raising parallelism does not make issuance faster and makes rate-limit deferral more likely to be reported for a whole batch at once. |
| **Progress** | `TF_LOG=info`. Store the log; it is the only record of which phase a killed job reached. |
| **Bulk onboarding** | Expect deferral. Onboard a registered domain's names over days, or ask the platform team about the reserved budget before the apply, not after it. |
| **`-detailed-exitcode`** | The day after a renewal, refresh reports drift in `current_certificate` and the planned action is **none**, so the exit code is `0`. Gating CI on this exit code is safe. |
| **Saved plans** | See the [saved-plan secret hygiene](saved-plan-hygiene) guide before archiving `terraform plan -out` artefacts. |

## Reading a failure

Every failure carries a machine-readable `code`, a `next_action`, and a `request_id`. Branch on
the code, never on the HTTP status or the message text. Every code, with who can act on it, is on
the [error reference](error-reference) page.
