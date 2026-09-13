---
page_title: "Destroy and decommission - azureacme provider"
subcategory: ""
description: |-
  retain vs delete, the Key Vault soft-delete name lock, the required non-production
  destination-vault settings, and the Application Gateway listener consequence.
---

# Destroy and decommission

Destroying an `azureacme_certificate` destroys **the standing instruction**. What happens to the
certificate already sitting in your Key Vault is a separate decision, and it is the one
`deletion_policy` makes.

## `retain` versus `delete`

```terraform
resource "azureacme_certificate" "api" {
  # …
  deletion_policy = "retain" # the default
}
```

| Policy | On destroy | Use it when |
|---|---|---|
| `retain` (default) | The registration is removed. **The Key Vault certificate is left exactly where it is** and keeps working until it expires. Renewal stops. | Almost always. It is the default because the failure mode is "a certificate outlives its management", which is recoverable, rather than "a live listener goes down", which is not. |
| `delete` | The registration is removed **and** the Key Vault certificate is soft-deleted. | You genuinely want the artefact gone — a torn-down environment, a decommissioned name. Read the rest of this page first. |

Neither policy ever revokes the certificate. Revocation is a separate, explicit operation.

-> **The server's persisted policy is authoritative, and the request may only narrow it.** If a
platform administrator changes a registration to `retain`, a stale `delete` in one workspace's
state can no longer override it. The provider sends the policy from state and the service decides.

## The purge-protection acknowledgement

```terraform
resource "azureacme_certificate" "api" {
  deletion_policy                 = "delete"
  acknowledge_irreversible_delete = true
}
```

When `deletion_policy = "delete"` and the destination vault has **purge protection** enabled, the
provider raises a plan-time **error** unless `acknowledge_irreversible_delete = true`. Purge
protection makes `delete` conditionally irreversible for up to **90 days**: the certificate is
soft-deleted, cannot be purged, and the name cannot be reused until retention expires.

This is an error rather than a warning because the consequence is invisible at the moment of the
apply and only surfaces the next time somebody tries to recreate the name.

The provider learns the vault's posture from the service — `purge_protection_enabled` on the
namespace's `permitted_destinations` — and never from Azure: it links no Azure control-plane SDK,
so it needs no Key Vault permission in your workspace. The three answers are three different
plans:

| The destination policy says | The plan |
|---|---|
| purge protection **enabled** | **Error**, unless `acknowledge_irreversible_delete = true`. |
| purge protection **disabled** | Nothing. `delete` is reversible here. |
| nothing (an older service, or a destination the projection does not name) | A **warning**. The service still refuses the combination with `acknowledgement_required`. |

## The soft-delete name lock — the CI trap

!> **`terraform destroy` followed by `terraform apply` fails on create** if the destination vault
soft-deletes certificates for the default retention period. This is entirely ordinary in CI and PR
environments, and it is the most-reported operational surprise in this product.

After `policy=delete`, the certificate name is held by Key Vault soft-delete for the vault's
retention period — **a configurable 7 to 90 calendar days, defaulting to 90** — and cannot be
reused. The provider renders this as `destination_soft_deleted`, an actionable error carrying:

- the `scheduled_purge_date`,
- whether purge protection is enabled,
- the `actions/recover-destination` route, which restores the soft-deleted certificate rather than
  waiting for retention, and
- the literal `az keyvault certificate purge` command, with the caveat that **purge is unavailable
  while purge protection holds**.

**The provider never auto-purges.** Purging is irreversible destruction of key material; it is not
something a `terraform apply` gets to decide.

### The required non-production destination-vault settings

```terraform
# A DESTINATION vault for a non-production or ephemeral environment.
resource "azurerm_key_vault" "payments_nonprod" {
  name                = "kv-payments-nonprod"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # THESE TWO LINES ARE THE POINT OF THIS PAGE.
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
}
```

~> `soft_delete_retention_days` **can only be configured when the vault is created and cannot be
changed afterwards.** Getting it wrong is a vault rebuild, not an edit.

The platform module's own worked example defaults to 90 days with purge protection enabled. That
is **correct for the operations vault**, which holds the service's own ACME account key and must
never be destroyable, and **ruinous for a destination vault in a destroy/recreate loop**, which
becomes unusable for 90 days after the first teardown.

Use `retain` in ephemeral environments as well, unless you specifically want to exercise the
delete path. Between `retain` and a 7-day retention you have two independent defences against the
same trap.

## The Application Gateway listener consequence

If an Application Gateway listener is bound to the certificate you are deleting, soft-deleting it
means the gateway *automatically sets the listener to a disabled state*. Traffic to that listener
stops. The gateway does not fail over, and the Azure Advisor recommendation that reports it
("Resolve Azure Key Vault issue for your Application Gateway") is not an alert anybody watches by
default.

The provider emits a plan-time **warning** when a destroy is planned and the last known
`delivery_stage` was `consumer_observed`, naming the observing endpoint. It is a warning and not a
refusal on purpose: refusing the delete would make `terraform destroy` non-idempotent and strand
the resource in state forever.

## Renaming is not decommissioning

`namespace` and `name` are the only two attributes that force replacement. When you change either
of them **and** `deletion_policy = "delete"`, the plan emits a warning naming the Key Vault
certificate that will be soft-deleted and the retention period. Renaming with `delete` is
legitimate, if sharp. Renaming with `retain` leaves the old certificate in place and is what you
almost certainly want.

To stop renewal without deleting anything, do not destroy — suspend:

```terraform
resource "azureacme_certificate" "api" {
  # …
  renewal = {
    mode = "suspended"
  }
}
```

That is the declarative escape hatch. The registration stays, the certificate stays, nothing
renews.

## The decommissioning sequence

For a name you are genuinely retiring:

1. **Repoint or remove the consumers first.** A certificate with no consumer is harmless; a
   consumer with no certificate is an outage.
2. **Wait out the pickup window** for the consumer profile involved — up to 72 hours for Front
   Door. See the [consumer integration](consumer-integration) guide.
3. **Confirm nothing is still serving it**: `data.azureacme_certificate.this.consumers` should be
   empty, or `delivery_stage` should have fallen back from `consumer_observed`.
4. **Then** destroy, with `deletion_policy` set deliberately rather than by default.
5. If you used `delete` and the name may be needed again, note the `scheduled_purge_date`.

## Timeouts on destroy

`timeouts.delete` defaults to 10 minutes. On timeout the provider returns an error and **leaves
the resource in state**; re-running `terraform destroy` retries. That is safe because delete is
idempotent — a `404 registration_not_found` or `410 registration_deleted` is treated as success.
