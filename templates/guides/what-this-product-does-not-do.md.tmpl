---
page_title: "What this product does not do - azureacme provider"
subcategory: ""
description: |-
  The honest limits: Key Vault only, no vault-to-vault moves, one destination per
  certificate, Certificate Transparency, private DNS, and cert-manager.
---

# What this product does not do

Every item on this page is a deliberate boundary, not a backlog entry that slipped. Reading it
takes five minutes; discovering any one of them during an incident takes considerably longer.

## Non-Key-Vault destinations are not supported

The only destination is an **Azure Key Vault**. There is no file output, no Kubernetes `Secret`, no
AWS Certificate Manager, no `local_file`, no Ansible callback, no webhook that hands you a bundle.

The provider is also incapable of producing one: it holds no Azure data-plane credential, links no
Azure data-plane SDK, and never reads a private key. A "just write it to a file" feature would
require all three.

If your consumer cannot read from Key Vault, this product cannot serve it. That is a selection
criterion, not a gap to work around.

## A certificate cannot move between vaults in v1

Editing `key_vault_id` on an existing registration is a **plan-time error**, not a replacement,
because replacing would destroy the live certificate before its replacement exists. The supported
route is issue-new, repoint-consumers, remove-old — three steps and a pickup window that can run to
72 hours.

The consequence, stated plainly: **a vault consolidation, a subscription move, or adopting Front
Door (which requires the vault to be in the same subscription as the profile) is an estate-wide
manual project.** For a fleet of any size this is the largest operational limitation in v1.

See [destination-change migration](destination-change-migration) for the procedure.

## One certificate cannot land in two vaults

A registration has exactly one destination. If two consumers in different subscriptions each need
the same names, that is **two registrations** with two names, publishing into two vaults.

That is legitimate and supported, but it is not free: both consume the certificate authority's
duplicate-certificate budget for the same identifier set. Roughly three independent registrations
of one identifier set is safe; four warrants a conversation with your platform team before you
apply.

## Every SAN is published to Certificate Transparency

!> **Every DNS name you put in `dns_names` becomes public, permanently, the moment the certificate
is issued.** Certificate Transparency logs are append-only, globally readable, and actively
crawled.

Concretely: `dns_names = ["api.example.com", "internal-billing-admin.example.com"]` publishes the
existence of your internal billing admin host to anyone who looks — and people do look,
automatically, within seconds.

This is a property of publicly-trusted certificates, not of this product. But it is this product
that makes issuing them easy, so:

- Do not put internal hostnames in the same certificate as public ones out of convenience.
- Do not treat a hostname as a secret. It never was, but CT removes the last of the obscurity.
- If a name genuinely must not be public, it needs a privately-trusted certificate from a private
  CA, which this product does not issue.

## Private DNS cannot serve validation

Domain control is proven by **DNS-01**: the certificate authority resolves a `_acme-challenge`
TXT record from the **public** internet. An Azure Private DNS zone is not visible to the CA, and no
amount of correct configuration inside your VNet changes that.

Therefore:

- A name that resolves only in private DNS **cannot be validated**, and no publicly-trusted
  certificate can be issued for it.
- A **split-horizon** name works, provided the public zone is the one carrying the delegation the
  validation binding names. The certificate is then valid for a name your users resolve privately —
  and, per the section above, that name is published to CT.
- The name being certified does not have to resolve to a reachable address. Only the
  `_acme-challenge` record has to be publicly resolvable.

Check with `data.azureacme_validation_binding` before you write the resource, not after the
`403`.

## Wildcards are not implied by anything

Wildcard is its own authorisation axis. A grant that permits `api.example.com` never implies
`*.example.com`, and the provider will not infer it: DNS-01 for `*.api.example.com` and for
`api.example.com` uses the **same** challenge name, so technical control of the zone proves nothing
that distinguishes them. Authorisation has to be explicit because the protocol cannot make it
implicit.

## cert-manager is an alternative issuer, not a consumer

If you already run cert-manager in AKS, it is doing the same job as this product, from inside your
cluster, with its own ACME account. It is **not** something that consumes a certificate this
product publishes.

Running both against the same name is the specific mistake worth naming:

- Rate limits are per **registered domain** and are shared. Two independent issuers double your
  consumption of a budget neither of them can see the other using.
- Renewal schedules are independent, so the certificate actually being served flips between two
  issuers' artefacts unpredictably.
- Neither system's status page shows the other's failures.

Choose one issuer per name. Both tools are reasonable; the combination is not.

## Terraform does not manage the certificate's lifecycle

`terraform destroy` removes the **instruction**, not necessarily the artefact — that is what
`deletion_policy` decides. `terraform plan` showing no changes the day after a renewal is correct:
renewal changes the certificate version, never the registration's identity.

The corollary is the one people find surprising: **the service keeps issuing and renewing whether
or not Terraform ever runs again.** A team that deletes its Terraform workspace without destroying
its registrations has not stopped anything.

## Other things this provider deliberately does not have

| Not present | Why |
|---|---|
| A resource that deploys the certificate service | The provider would have to be configured from a resource it manages. Structurally impossible; see [two-stage bootstrap](two-stage-bootstrap). |
| `insecure_skip_tls_verify` | There is no legitimate use for a client that ships bearer tokens to a certificate-issuing service over an unverified channel. |
| `default_namespace` on the provider block | `namespace` is the authorisation boundary. A provider-level default would let a copy-paste error move a certificate between production and non-production invisibly. |
| A provider-level `deletion_policy` default | A per-certificate risk decision. Changing a provider default would silently re-interpret existing configurations. |
| Email notification attributes | No email transport exists in the platform. Shipping the attribute would ship a promise nothing keeps; alerting is the platform's job. |
| Elliptic-curve keys | Representable in the schema, disabled by service policy in v1 — Front Door does not support EC at all. Enabling it later is a service configuration change, not a provider release. |
| `common_name` | Reserved and rejected at plan time pending a verified answer on whether Key Vault and the CA accept a policy subject with no CN. |
| Revocation on destroy | Deletion never implies revocation. Revocation is a separate, explicit operation with different consequences. |
| Any private key, PFX byte or Key Vault secret value, anywhere | See [saved-plan secret hygiene](saved-plan-hygiene) and the [destination vault security note](destination-vault-security). |
