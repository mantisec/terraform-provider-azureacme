---
page_title: "Quickstart - azureacme provider"
subcategory: ""
description: |-
  Your first certificate in six concepts: namespace, name, DNS names, destination
  vault, the publisher role assignment, and one connection profile.
---

# Quickstart

An `azureacme_certificate` is **a standing instruction to keep a certificate valid, not one
signed artefact**. You declare the instruction once; the service keeps fulfilling it —
issuing, renewing and republishing into your Key Vault — whether or not Terraform ever runs
again. Terraform owns the *instruction*; it does not own the certificate's lifecycle.

That distinction is the one thing to carry into everything below. `terraform plan` showing no
changes the day after a renewal is not Terraform failing to notice; it is the product working.

## The six concepts

There are exactly six things you must understand to get a certificate:

| # | Concept | Where it comes from |
|---|---|---|
| 1 | **Namespace** | Your platform team. It is the authorisation boundary and is never inferred. |
| 2 | **Name** | You choose it. Together with the namespace it is the primary key, `{namespace}/{name}`. |
| 3 | **DNS names** | You choose them, within the domains your namespace is authorised for. |
| 4 | **Destination vault** | Your Key Vault. The certificate is published there. |
| 5 | **The publisher role assignment** | You grant it. Discover the principal id from `azureacme_service`. |
| 6 | **One connection profile** | Your platform team's module output. One object, not four variables. |

Everything else has a default that is correct for every consumer in the supported matrix.

## The configuration

```terraform
provider "azureacme" {
  connection_profile = var.acme_connection_profile
}

# Concept 6. The service is deployed by a SEPARATE Terraform configuration, so the
# endpoint arrives as a variable. See the two-stage bootstrap guide for why this is
# structural rather than a style preference.
variable "acme_connection_profile" {
  type = object({
    endpoint                     = string
    audience                     = string
    tenant_id                    = string
    expected_service_instance_id = optional(string)
  })
}

# Discover the publishing identity from the service itself.
data "azureacme_service" "this" {}

# Concept 5. The one cross-team step: the destination vault's owner grants the
# publishing identity the right to manage certificates in that vault.
resource "azurerm_role_assignment" "acme_publisher" {
  scope                = azurerm_key_vault.payments.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azureacme_service.this.publisher_principal_id
}

resource "azureacme_certificate" "api" {
  namespace    = "payments-prod"      # 1
  name         = "payments-api"       # 2
  dns_names    = ["api.example.com"]  # 3
  key_vault_id = azurerm_key_vault.payments.id # 4

  depends_on = [azurerm_role_assignment.acme_publisher]
}

# The consumption binding point. It is VERSIONLESS, so a renewal never changes it and
# no consumer needs to be re-applied when the certificate rotates.
output "certificate_secret_id" {
  value = azureacme_certificate.api.versionless_secret_id
}
```

~> **There is no `key` block, and there must not be one.** The default is RSA 2048 with an
**exportable** key, which every consumer in the supported matrix requires. Setting
`key.exportable = false` produces an apply that succeeds, a status page that is entirely green,
and an Application Gateway listener that will not start. The provider rejects it at plan time
unless `consumer_profile = "keyvault_crypto_only"`.

The `depends_on` is not decoration. Without it Terraform is free to create the registration
before the role assignment exists, and the service's first publish attempt fails with
`destination_access_denied`.

## Discovering every value

You should never have to ask a human for any of these, and you must never read them out of
another workspace's state.

| What you need | Where to read it |
|---|---|
| The publishing identity's principal id | `data.azureacme_service.this.publisher_principal_id` |
| Service limits (`max_dns_names`, `max_labels`, probe endpoints) | `data.azureacme_service.this` |
| The ACME profiles this instance offers | `data.azureacme_service.this.acme_profiles` |
| Your own roles and the namespaces you can see | `data.azureacme_service.this.caller` |
| Which domains your namespace may certify | `data.azureacme_namespace.this.permitted_domains` |
| Which vaults your namespace may publish to | `data.azureacme_namespace.this.permitted_destinations` |
| Whether wildcards are permitted for a zone | `data.azureacme_validation_binding.zone.wildcards_allowed` |
| Every binding visible to you | `data.azureacme_validation_bindings.all.items` |

!> **Never read the platform workspace's state to find the publisher principal id.** A
remote-state data source pointed at that state grants your workspace read access to its storage
account keys and its entire resource graph, in exchange for one GUID — a privilege escalation
dressed as convenience. `data.azureacme_service.this.publisher_principal_id` exists precisely so
the secure path is also the short one.

## Move authorisation failures from apply time to plan time

The discovery data sources are read during `terraform plan`. Combining them with
`lifecycle { precondition }` turns a `403` that would otherwise land halfway through an apply
into a plan that never starts:

```terraform
data "azureacme_validation_binding" "zone" {
  id = "example-com"
}

data "azureacme_namespace" "payments" {
  name = "payments-prod"
}

resource "azureacme_certificate" "api" {
  namespace    = "payments-prod"
  name         = "payments-api"
  dns_names    = var.dns_names
  key_vault_id = azurerm_key_vault.payments.id

  lifecycle {
    precondition {
      condition     = data.azureacme_validation_binding.zone.wildcards_allowed || !anytrue([for n in var.dns_names : startswith(n, "*.")])
      error_message = "Wildcard names are not permitted by the example-com validation binding."
    }

    precondition {
      condition = contains(
        [for d in data.azureacme_namespace.payments.permitted_destinations : d.key_vault_id],
        azurerm_key_vault.payments.id,
      )
      error_message = "payments-prod is not authorised to publish into this Key Vault."
    }
  }
}
```

Wildcard is its own authorisation axis and is never inferred from a name-scope grant: DNS-01 for
`*.api.example.com` and for `api.example.com` uses the same challenge name, so technical control
of the zone proves nothing that distinguishes them.

## What happens on the first apply

1. The provider calls `/v1/capabilities` once and validates your configuration against it — no
   extra API calls per resource.
2. It `PUT`s the registration and receives `202` with an operation to follow.
3. It writes partial state **immediately**, before any waiting, so a lost connection never
   orphans the registration.
4. It polls until the certificate is published, bounded by `timeouts.create` (default 60m).

`Still creating…` with no further detail is the Plugin Framework's only default output. Run with
`TF_LOG=info` to watch the phase transitions — that is the supported progress channel. See the
[waiting, timeouts and recovery](waiting-timeouts-and-recovery) guide before your first timeout,
not after it.

## Next

- [Two-stage bootstrap](two-stage-bootstrap) — why the endpoint is a variable, and where the
  API's own certificate comes from.
- [Consumer integration](consumer-integration) — which URI form and which identity your consumer
  needs.
- [Destroy and decommission](destroy-and-decommission) — read this **before** you point a
  destroy/recreate CI loop at a production-shaped vault.
- [What this product does not do](what-this-product-does-not-do) — the honest limits.
