---
page_title: "Security note for a destination vault owner - azureacme provider"
subcategory: ""
description: |-
  Exactly what the publishing identity can and cannot do in your Key Vault, including
  the counter-fact about exportable private keys.
---

# Security note for a destination vault owner

You are being asked to grant **Key Vault Certificates Officer** on your Key Vault to a managed
identity you do not own. This page is what you are entitled to before you approve it. It is
written for the person who signs off, not for the person asking.

## The grant

```terraform
data "azureacme_service" "this" {}

resource "azurerm_role_assignment" "acme_publisher" {
  scope                = azurerm_key_vault.payments.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azureacme_service.this.publisher_principal_id
}
```

The scope is **your vault**, not a subscription or a resource group. Grant it no wider.

## What the publishing identity can do

Within the scope you grant, and nothing else:

- Create a certificate object and its policy.
- Create new **versions** of certificate objects — this is what renewal is.
- Read certificate **metadata**: names, policies, thumbprints, expiry dates, versions.
- Soft-delete a certificate, but only when the registration's `deletion_policy` is `delete`, and
  only for a certificate the service itself created and exclusively owns.

## What it cannot do

- **It cannot read secret values.** The service does not hold, and does not need,
  `Key Vault Secrets User` on a destination vault. It writes certificates; it never reads private
  key material back out of your vault.
- It cannot manage keys, secrets or storage accounts in your vault, or change vault access
  policies, RBAC assignments, firewall rules or network ACLs.
- It cannot **purge** a soft-deleted certificate. Purge is irreversible destruction of key
  material; the service never performs it, under any policy, and the provider never offers it.
- It cannot reach any other vault. The grant is per-vault and there is no path by which a
  registration in another namespace publishes into yours — the destination is checked against the
  namespace's permitted destinations server-side, before authorisation, on every request.
- It cannot take over a certificate somebody else owns. A destination already exclusively owned by
  a different registration is refused with `destination_owned_elsewhere`.

## The counter-fact, stated plainly

!> **Certificates published by this service have an exportable private key. Anyone holding
`Key Vault Secrets User` on your vault can therefore retrieve the private key, in full, as the
PKCS#12 bundle in the certificate's sibling secret object.**

This is not a defect and it is not negotiable in v1. For a Key Vault certificate, the addressable
secret's value **is** the PKCS#12 bundle *including the private key*. Every consumer in the
supported matrix — Application Gateway, Front Door, App Service, API Management, Container Apps,
the AKS CSI driver, self-managed readers — requires that. Application Gateway documents the
requirement explicitly; the rest read the PKCS#12 secret, which contains no private key at all when
the policy is non-exportable.

The practical consequence for you, the vault owner:

1. **Your `Key Vault Secrets User` assignments are your private-key exposure surface**, not the
   Certificates Officer grant you are being asked for. Audit those first.
2. The publishing identity is **not** among them, and must not be added.
3. If you genuinely need a non-exportable key — vault-side signing only, with no TLS consumer —
   the registration must declare `consumer_profile = "keyvault_crypto_only"`. Anything else is
   rejected at plan time, because an apply that succeeds and produces an unusable artefact with no
   error at any layer is worse than a refusal.

## What the provider itself never touches

The Terraform provider your application teams run **links no Azure data-plane SDK at all**. It
holds no Key Vault credential, makes no Key Vault call, and constructs the versionless URIs it
returns purely from the vault id, the certificate name and the cloud environment. A CI check runs
`go list -deps` on every build and fails if any Azure data-plane package appears in the
dependency graph.

That check exists because "just fetch the secret so users can see the chain" is a plausible feature
request, and satisfying it would write private keys into every consumer's Terraform state file and
every archived plan.

Correspondingly, **no private key, PFX byte, ACME account key, bearer token or Key Vault secret
value appears in any resource attribute, any data source attribute, or any log line** — at any
verbosity, under any flag. The permitted output surface is URIs, thumbprints, serial numbers,
timestamps, issuer names and delivery status. `certificate_pem` and `chain_pem` are available on
the data source behind an explicit `include_pem = true`, and they are public certificate material
only.

## Recommended vault settings for a destination vault

```terraform
resource "azurerm_key_vault" "payments" {
  # …
  enable_rbac_authorization = true

  # Production destination vault:
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
}
```

- **RBAC over access policies.** The grant above is an RBAC role assignment; access policies are
  the legacy model and are harder to audit.
- **Purge protection on for production.** It prevents anyone — including a compromised
  Certificates Officer — from destroying certificate history outright.
- **Non-production is different.** A destination vault in a destroy/recreate CI loop needs
  `soft_delete_retention_days = 7` and `purge_protection_enabled = false`, set **at vault
  creation** because retention cannot be changed afterwards. See
  [destroy and decommission](destroy-and-decommission).

## How to revoke

Delete the role assignment. Nothing else is required, and nothing breaks retroactively: the
certificates already in your vault keep working and keep serving traffic until they expire.

What stops is **renewal**. The service will report the failure against the registration with
`destination_access_denied`, and the owning team will see it. If the revocation was deliberate,
tell them — an expiring certificate that nobody is renewing looks identical to a healthy one until
about a fortnight before it dies.

## Questions worth asking before you sign off

1. Which namespace is being granted this, and which domains is that namespace authorised for?
   (`data.azureacme_namespace.<name>.permitted_domains`.)
2. Is my vault on that namespace's permitted destinations list, and who maintains that list?
3. Who owns the registration — which principal can change or delete it?
   (`data.azureacme_certificate.<name>.ownership`.)
4. What is the `deletion_policy`, and does anyone hold `delete` on a certificate my production
   traffic depends on?
5. Who else holds `Key Vault Secrets User` on this vault?
