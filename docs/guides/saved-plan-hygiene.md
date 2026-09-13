---
page_title: "Saved-plan secret hygiene - azureacme provider"
subcategory: ""
description: |-
  Saved plan files are credential-bearing artefacts. What is and is not in them, and
  what that means for CI.
---

# Saved-plan secret hygiene

!> **Treat `terraform plan -out` files as credential-bearing artefacts.** A saved plan embeds
provider configuration, and CI systems routinely archive plan files as build artefacts with far
weaker retention and access controls than a state backend.

This page exists because the mitigation is a *design* decision in this provider rather than a
warning you are expected to remember.

## What is not in a saved plan, by construction

**There is no `client_secret` attribute on the `azureacme` provider block.** That omission is
deliberate and it is the primary control:

```terraform
provider "azureacme" {
  connection_profile = var.acme_connection_profile

  # client_secret = "…"   ← DOES NOT EXIST. Not undocumented; not present.
}
```

`ARM_CLIENT_SECRET` is accepted from the **environment** for compatibility with existing CI
identities, is documented as discouraged, and emits a warning diagnostic when it is used.
Environment variables are not captured in the plan file.

Prefer, in order:

1. **OIDC federated credentials** (`use_oidc`, or `ARM_OIDC_*` / `ACTIONS_ID_TOKEN_REQUEST_*` in
   GitHub Actions). Nothing long-lived exists to leak.
2. **Managed identity** (`use_msi`) on a self-hosted runner.
3. **Azure CLI** (`use_cli`, default `true`, tried last) for interactive local work.

The provider never uses `DefaultAzureCredential`. It falls through silently to a developer
identity, which in CI means a job that should have failed authenticates as whoever last ran
`az login` on a self-hosted runner — a *wrong-identity success*, not an error. If more than one
explicit credential method is configured, the provider errors rather than guessing.

## What is in a saved plan

The plan contains the planned values of every attribute of every resource: namespaces, names, DNS
names, Key Vault resource ids, thumbprints, serial numbers, expiry timestamps, versionless and
versioned Key Vault URIs.

None of that is key material, and that is guaranteed rather than assumed. The provider's permitted
output surface is fixed, and **private keys, PFX bytes or passwords, ACME account keys, bearer
tokens, client secrets, SAS tokens, storage keys, Key Vault secret values and CSR bytes never
appear in any attribute** — not on the resource, not on any data source, not behind any flag.

The provider also links no Azure data-plane SDK at all, so there is no code path by which a Key
Vault secret value could reach a plan file even accidentally. That is enforced by a CI check on
every build.

~> A plan file is still an **infrastructure map**. Vault ids, subscription ids, principal ids,
hostnames and namespace names together describe your estate precisely enough to be worth
protecting, even with no credential in them.

## Practical CI rules

| Rule | Why |
|---|---|
| **Do not publish `terraform plan -out` files as build artefacts.** Keep them inside the job that created them, or in the same protected storage as your state. | Build artefacts commonly have longer retention, wider read access, and no audit trail. |
| **Pass credentials through the environment or OIDC, never through HCL or a `.tfvars` file.** | HCL and variable files are captured in the plan; the environment is not. |
| **Delete the plan file when the apply completes**, in a step that runs on failure too. | A failed apply is exactly when the file survives longest. |
| **Never commit a `.tfplan`.** Add it to `.gitignore` alongside `*.tfvars` and `*.tfstate*`. | It is the same class of artefact as state. |
| **Restrict who can download workflow artefacts** in the repositories that run these plans. | The control that actually stops the leak. |
| **Do not paste plan output into an issue or a chat channel** without reading it first. | Hostnames and vault ids are the parts people forget. |

## Logging

`TF_LOG=trace` logs request and response bodies. That is safe here for the same structural reason:
the response schema carries no key material at all. Bearer tokens are masked before they reach the
log sink — `Authorization` headers are replaced by the provider's own `tflog` masking, so
`TF_LOG=trace` does not print a token.

Log files are nonetheless subject to the same "infrastructure map" caution as plan files, and they
additionally record request ids that correlate to service-side audit records.

## State

Terraform state is out of scope for this page, but the same allowlist applies: the state file
contains no key material for the same reason the plan file does not. Protect it as you would any
state — remote backend, encryption at rest, restricted access — because it, too, is a precise map
of the estate.
