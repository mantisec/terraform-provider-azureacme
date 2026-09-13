---
page_title: "Version compatibility and upgrade policy - azureacme provider"
subcategory: ""
description: |-
  The provider / service / module matrix, the 90-day deprecation window, the rule that
  apiMinorRequired moves only in a provider major, and the blue/green constraint.
---

# Version compatibility and upgrade policy

Three artefacts version and ship **independently**: this provider, the certificate service, and
the platform Terraform module. That independence is a feature — a platform team must be able to
patch the service without a synchronised, cross-team provider upgrade, and an application team
must be able to upgrade the provider without waiting for a service release.

This page states the rules that keep the independence real rather than nominal.

## How compatibility is decided

The provider embeds three constants: `apiMajor`, `apiMinorRequired` (the minimum API minor its
**unconditional** behaviour needs) and its own version. On `Configure` it calls `/v1/capabilities`
exactly once and applies these rules:

| Situation | Result |
|---|---|
| Service API **major** ≠ the provider's `apiMajor` | **Hard error**, naming both versions and the upgrade required. |
| Service API minor **<** `apiMinorRequired` | **Hard error**, naming the minimum service build. |
| Service API minor **<** the minor a *feature you actually used* needs | **Plan-time attribute error**, naming the feature and the minimum service version. |
| Service API minor **>** anything the provider knows | **Proceed.** Unknown fields, features, enum values and error codes are ignored or rendered verbatim. |
| Provider version **<** `minimum_client_version` | **Hard error**. |
| Provider version **<** `deprecated_client_version` | **Warning**, naming `deprecated_client_deadline`. |

A newer service never breaks an older provider by adding things. That is the whole basis of the
forward-compatibility contract: **unknown is not an error**. An error code the provider has never
heard of is rendered with the service's own `title`, `detail`, `next_action` and `request_id`, and
treated as non-retryable.

## Feature gating is by name, never by version arithmetic

A provider that wants `destination_migration` checks for **the string in
`capabilities.features`**, not for `api_version >= 1.6`. This keeps a service that has back-ported
or feature-flagged a capability honest, and lets your staging and production instances legitimately
differ.

```terraform
data "azureacme_service" "this" {}

output "can_migrate_destinations" {
  value = contains(data.azureacme_service.this.features, "destination_migration")
}
```

Write your own preconditions the same way.

## The 90-day deprecation window

`minimum_client_version` and `apiMinorRequired` are fleet-wide kill switches pointing in opposite
directions. Both are governed:

1. **`minimum_client_version` must not be raised** to a version that was not published as
   `deprecated_client_version` **at least 90 days earlier**. You get a warning diagnostic naming a
   deadline, on every plan, for at least a quarter, before anything hard-fails.
2. **`apiMinorRequired` may only be raised in a provider *major* version.** This is policy enforced
   by a CI check on the constant, not a convention. Raising it in a patch would make a workspace
   unplannable after a routine `terraform init -upgrade` — including certificates that use no new
   feature — until a platform team the consumer does not control deploys a service upgrade.
3. The service records the provider version from every request's `User-Agent`, so your platform
   team can see exactly who would break **before** flipping either switch.

Pin the provider in `required_providers` and upgrade deliberately:

```terraform
terraform {
  required_providers {
    azureacme = {
      source  = "mantisec/azureacme"
      version = "~> 1.0"
    }
  }
}
```

`~> 1.0` accepts patches and minors within major 1 and refuses major 2 — which is exactly the
boundary at which `apiMinorRequired` may move.

## The escape hatches, and why there are two of them

```terraform
provider "azureacme" {
  connection_profile = var.acme_connection_profile

  skip_version_check  = false # skips the version rules above only
  skip_instance_check = false # skips service-instance pinning only
}
```

~> **These are deliberately two flags and not one.** A single `skip_capability_check` would mean
that the officially documented workaround for a version wedge also disabled service-instance
pinning — re-opening the mistyped-endpoint catastrophe in which every certificate is removed from
state and reissued against the wrong service. One flag must never disable both.

Both flags still perform the `/v1/capabilities` call; only the assertions are skipped, and each
emits a warning while it is set. They are for unblocking an incident, not for living in your
configuration.

## The blue/green constraint

!> **A new service instance with new catalogue storage breaks `service_instance_id` pinning for
every consumer simultaneously.**

Every `azureacme_certificate` records the `service_instance_id` it was created against.
A refresh **compares** it and errors on mismatch; it never removes the resource from state. That
is what protects you from a mistyped endpoint, and it is also what makes a blue/green service
cutover a coordinated event rather than a transparent one.

`service_instance_id` is generated once, by the service, on first start, and is bound to the
catalogue storage that holds the registrations. So:

| Cutover style | Effect on consumers |
|---|---|
| **In-place upgrade** of the service, same catalogue storage | None. The instance id is unchanged; nobody notices. |
| **New instance, same catalogue storage** (the supported blue/green shape) | None, provided the instance id travels with the catalogue rather than with the compute. |
| **New instance, new catalogue storage** | Every consumer workspace errors on the next plan until it is told about the new id. |

If a genuinely new instance is unavoidable, the platform team must republish the connection
profile with the new `expected_service_instance_id`, and each consumer must
`terraform state rm` and re-import the affected registrations — or set `skip_instance_check = true`
for exactly one apply, which is the blunt version. Plan the communication before the cutover; the
error is deliberately loud and deliberately refuses to proceed.

## The module

The platform module versions independently too, and it is the module's job to emit the connection
profile as **one object** — `endpoint`, `audience`, `tenant_id`, `publisher_principal_id` — rather
than as separate outputs. If your platform team's module output shape changes, that is a module
major version, and consumer workspaces update their `variable` type at their own pace.

`prevent_destroy` belongs on the runtime identity, the publisher identity and the application
registration, not only on catalogue storage: destroying the identity invalidates every Key Vault
role assignment in the estate, and recreating the application mints a new client id — and
therefore a new audience — breaking every consumer workspace's provider configuration at once.

## What is guaranteed across an upgrade

- **Defaults apply at create only.** A service upgrade that changes a default never
  re-materialises it on an existing registration.
- **`id` never changes.** `{namespace}/{name}` contains no version, thumbprint, serial or expiry,
  so no renewal and no upgrade can turn a refresh into a replacement.
- **Renewal never bumps `spec_revision`.** The ETag covers the spec only.
- **The server never writes into `labels` or trims `description`.** System metadata lives in
  `system_labels`, which is on the data source and not on the resource.

Those four properties are what make `terraform plan` boring on a fleet that is renewing
continuously in the background.
