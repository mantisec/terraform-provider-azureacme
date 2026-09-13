---
page_title: "Destination-change migration - azureacme provider"
subcategory: ""
description: |-
  Changing key_vault_id is a plan-time error, not a replacement. The three-step
  procedure, and the honest statement that in v1 a certificate cannot move vaults.
---

# Destination-change migration

**In v1 a certificate cannot move between Key Vaults.** Editing `key_vault_id`,
`certificate_name` or `destination_id` on an existing registration is a **plan-time error**, not a
replacement, and the plan is refused before anything changes.

That is a deliberate limitation with a real cost, stated here plainly rather than discovered
during a vault consolidation.

## Why it is an error and not a replacement

Terraform's default replacement order is **destroy, then create**. If `key_vault_id` were marked
`RequiresReplace`, the plan would:

1. destroy the registration — and under `deletion_policy = "delete"`, soft-delete the live Key
   Vault certificate that your Application Gateway is currently serving, which *automatically sets
   the listener to a disabled state*;
2. only then create the new registration, which must run a full ACME issuance from scratch;
3. leaving an outage window of the entire issuance time — minutes at best, unbounded if DNS
   validation or a rate limit intervenes.

`create_before_destroy` cannot rescue it. The logical key `{namespace}/{name}` is unchanged, so
the create half collides with the still-existing registration.

## The error you will see

A `ModifyPlan` error aborts the **whole plan**, which means the workspace is unplannable for
everyone — including colleagues running entirely unrelated plans — until somebody reverts the
edit. The message therefore leads with the unblocking instruction:

```
Error: Changing the destination of an existing certificate registration is not supported

  To unblock planning, revert `key_vault_id` to
  "/subscriptions/…/vaults/kv-payments".

  The destination Key Vault or certificate name cannot be changed in place, and replacing the
  registration would delete the live certificate before a replacement is issued.

  To move this certificate:
    1. Add a new azureacme_certificate resource with a new `name` and the new destination.
    2. Apply, and wait for `delivery_stage = published`.
    3. Repoint consumers at the new `versionless_secret_id` and wait out the consumer's
       pickup window (Application Gateway 4h; Front Door up to 72h).
    4. Remove the old resource with a `removed` block; `deletion_policy = "retain"` leaves
       the old certificate in place.
```

**Revert the edit first.** Everything else can wait; an unplannable workspace cannot.

-> **A rename is not a destination change.** `certificate_name` defaults to `name`, so renaming a
registration necessarily changes the effective Key Vault object name. Replacement wins: when the
plan already requires replacement because `namespace` or `name` changed, the destination check
does not fire. A replacement *creates a new object* rather than *moving* an existing one, so none
of the three harms above is in play.

## The three-step migration

### Step 1 — issue into the new destination under a new name

Add a **new** resource. Do not edit the old one.

```terraform
resource "azureacme_certificate" "api" {
  namespace    = "payments-prod"
  name         = "payments-api"
  dns_names    = ["api.example.com"]
  key_vault_id = azurerm_key_vault.old.id

  deletion_policy = "retain"
}

resource "azureacme_certificate" "api_v2" {
  namespace    = "payments-prod"
  name         = "payments-api-v2" # a NEW name: this is a new registration
  dns_names    = ["api.example.com"]
  key_vault_id = azurerm_key_vault.new.id

  depends_on = [azurerm_role_assignment.acme_publisher_new_vault]
}
```

Both registrations cover the same DNS name. That is legitimate, and the service supports it — but
it consumes the certificate authority's duplicate-certificate budget for that exact identifier
set. Roughly three independent registrations of one identifier set is safe; four needs a
conversation with your platform team. Do the migration once, not per environment on the same day.

Apply, and wait for the new registration to reach `delivery_stage = "published"`:

```terraform
data "azureacme_certificate" "api_v2" {
  namespace = azureacme_certificate.api_v2.namespace
  name      = azureacme_certificate.api_v2.name
}

output "v2_stage" {
  value = data.azureacme_certificate.api_v2.delivery_stage
}
```

### Step 2 — repoint the consumers, then wait out the pickup window

Change each consumer to reference `azureacme_certificate.api_v2.versionless_secret_id` (or
`.versionless_certificate_id`, per the [consumer integration](consumer-integration) table). Apply.

Then **wait**. The pickup window is per consumer and it is long:

| Consumer | Wait at least |
|---|---|
| `aks_csi` | 2 minutes |
| `application_gateway` | 4 hours |
| `container_apps` | 12 hours |
| `app_service` | 24 hours |
| `api_management` | 2 days |
| `front_door` | 72 hours |
| `self_managed` | until you have reloaded the listener yourself |

Confirm before proceeding: `data.azureacme_certificate.api_v2.consumers` should show the endpoint
observing the new certificate, and the old registration's `delivery_stage` should have fallen back
from `consumer_observed`.

!> **Do not compress step 2.** Removing the old registration while a consumer is still serving from
the old vault is the outage this whole procedure exists to avoid.

### Step 3 — remove the old registration

```terraform
removed {
  from = azureacme_certificate.api

  lifecycle {
    destroy = true
  }
}
```

With `deletion_policy = "retain"` on the old registration — which is the default, and which step 1
set explicitly — the old Key Vault certificate is **left in place**. Renewal stops; the artefact
stays until it expires. That gives you a rollback: if something was still bound to the old vault,
it keeps working, and you find out before the certificate expires rather than during an outage.

If you want the old certificate gone, do that as a fourth, separate change, once you are confident
— and read [destroy and decommission](destroy-and-decommission) first, because the soft-delete
name lock applies.

## What this costs, honestly

A vault consolidation, a subscription move, or adopting Front Door (which requires the vault to be
in the same subscription as the Front Door profile) is therefore an **estate-wide manual project**,
not a Terraform edit. For a fleet of any size this is the single largest operational limitation in
v1.

A server-side `destination_migration` operation — issue into the new destination, verify, flip the
current certificate, then apply the deletion policy to the old one — is the only mechanism that
would let a certificate move vaults without touching every consumer. It is planned, not shipped.
When a service instance advertises it in `capabilities.features`, this restriction relaxes to an
ordinary in-place update, and the provider will detect it **by feature name**, never by version
arithmetic.

Until then, the procedure above is the supported route, and the plan-time error is the guard rail
that keeps a well-meaning one-line edit from taking a listener down.
