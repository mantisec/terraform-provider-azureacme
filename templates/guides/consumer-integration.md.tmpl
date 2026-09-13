---
page_title: "Consumer integration - azureacme provider"
subcategory: ""
description: |-
  One page per consumer: which URI form, which identity, which Key Vault role, the
  rotation pickup window, and the symptom when it breaks.
---

# Consumer integration

Publication into your Key Vault is where this product's job ends. **Whether the thing in front of
your traffic has picked the new certificate up is a separate question**, it is answered
differently by every Azure service, and the answers differ by two orders of magnitude — two
minutes for the AKS CSI driver, up to seventy-two hours for Front Door.

You cannot interpret a `consumer_stale` condition, or set a sensible `expected_pickup`, without
the table on this page.

## The four questions, for every consumer

1. **Which URI form does it want?** Certificate identifier or secret identifier, versionless or
   pinned. Getting this wrong is the most common integration failure and it usually presents as
   "rotation silently stopped working".
2. **Which identity reads the vault?** Frequently *not* the identity you expect — App Service uses
   a Microsoft-owned resource provider service principal, not your app's managed identity.
3. **Which Key Vault role does that identity need?** Certificates User, Secrets User, or both.
4. **How long until it picks up a new version?** This is the pickup window, and it is what
   `consumer_profile` sets.

## The matrix

| `consumer_profile` | Object referenced | URI / reference form | Reading identity | Key Vault role | Pickup window | Symptom when Key Vault access breaks |
|---|---|---|---|---|---|---|
| `application_gateway` | **Secret** | **Versionless secret URI** — `versionless_secret_id`. A pinned version never rotates. | A **user-assigned** managed identity on the gateway (only one MI per gateway) | Key Vault Secrets User (or `Get` on secrets under access policies) | **4 hours** | The gateway *automatically sets the listener to a disabled state*. Surfaced through Resource Health and an Azure Advisor recommendation. |
| `front_door` | **Certificate** — must be uploaded as a certificate object, not a secret | Select version **Latest** for auto-rotation; a pinned version requires manual reselection | The AFD managed identity (recommended) or the Front Door service principal | `Get` on **both** certificates and secrets | **up to 72 hours** | Domain or certificate provisioning failure. **Hard constraint: the vault must be in the same subscription as the Front Door profile.** |
| `app_service` | Certificate imported into `Microsoft.Web/certificates`; App Service reads the **PKCS#12 secret** | Vault plus certificate name | The **App Service resource provider** service principal — **not** the app's own managed identity. ARM/Bicep assignments need its object id. | Key Vault Certificate User (or secret `Get` + certificate `Get`) | **within 24 hours**, plus a manual **Sync** | App Service cannot sync the web app with the latest Key Vault certificate version. |
| `api_management` | **Certificate** — insert it as a certificate, not a secret | **Versionless certificate identifier** — `versionless_certificate_id`. With version information it will not rotate. | System- or user-assigned MI on the APIM instance. **With the Key Vault firewall enabled the user-assigned identity does not work; the system-assigned identity is required.** | Key Vault Secrets User (or secrets `get` + `list`) | **1–2 days; design for 2** | APIM keeps serving a cached certificate. When the cached certificate expires, runtime traffic to the gateway is blocked. |
| `container_apps` | Certificate imported into the **environment** | Key Vault certificate reference plus identity; versionless | **Environment-level** system- or user-assigned MI | Key Vault Secrets User | **up to 12 hours** | Import or binding failure at the environment level. |
| `aks_csi` | **Secret**, via `objectType: secret` in a `SecretProviderClass` (returns key and full chain in PEM) | `keyvaultName` + `objectName`; omit `objectVersion` for latest | Workload identity (recommended) or the add-on's user-assigned identity | Key Vault Secrets User | **2 minutes** (the default rotation poll interval) | Mount fails or content goes stale. Mounted files and synced `kubernetes.io/tls` secrets update, but **env-var consumers need a pod restart**. |
| `self_managed` | **Secret** (base64 PKCS#12) | `versionless_secret_id` | The workload's own managed identity | Key Vault Secrets User | **none automatic** | This is the class where "published ≠ serving" is most dangerous: nginx and haproxy need a reload, .NET and Java need a listener restart. |
| `keyvault_crypto_only` | Certificate; the key never leaves the vault | Vault-side signing only | Whatever performs the crypto operation | Key Vault Crypto User | n/a | The only profile for which `key.exportable = false` is legal. |
| *(unset)* | — | — | — | — | unknown | **No consumer-specific validation and no consumer-rotation alerting.** Omission is never a block, but you also get no safety net. |

~> **`aks_csi` with `objectType: cert` returns the leaf only, with no private key**, and
`objectType: key` returns the public key. Only `objectType: secret` returns something a TLS
listener can use.

## Declaring the profile

```terraform
resource "azureacme_certificate" "api" {
  namespace    = "payments-prod"
  name         = "payments-api"
  dns_names    = ["api.example.com"]
  key_vault_id = azurerm_key_vault.payments.id

  consumer_profile = "application_gateway"

  verification = {
    consumer_probe = {
      enabled   = true
      endpoints = [{ host = "api.example.com", port = 443, sni = "api.example.com" }]
      # expected_pickup defaults from consumer_profile; override only with evidence.
    }
  }
}
```

`consumer_profile` is optional and omitting it is never a block — it means *no consumer-specific
validation*. What you give up is the `exportable` check, the destination-compatibility checks, and
a correct default for `expected_pickup`.

The profile list is served by the **service**, not compiled into the provider, so a new profile is
a service configuration change. Read the current list from
`data.azureacme_service.this.consumer_profiles` rather than from this page if you need to be
certain.

`verification.consumer_probe.enabled` defaults to `false` because reachability depends on your
networking mode, and a probe that cannot connect produces a false `consumer_stale`. `endpoints`
is a list because one certificate frequently fronts several listeners.

## Binding to the right URI

```terraform
# Application Gateway, AKS CSI, self-managed: the versionless SECRET id.
listener_ssl_certificate = azureacme_certificate.api.versionless_secret_id

# API Management: the versionless CERTIFICATE id.
key_vault_id = azureacme_certificate.api.versionless_certificate_id
```

Both are stable across every renewal. That is the whole point of them: **a consumer bound to a
versionless URI never needs to be re-applied when the certificate rotates**, and a consumer bound
to a pinned version stops rotating and nobody notices until the certificate expires.

The pinned, per-version identifiers are available as
`azureacme_certificate.api.current_certificate.version_secret_id` and `.version_certificate_id`.
Use them for auditing and diagnostics, never for binding.

## Reading delivery state

Delivery status is deliberately **not** on the resource — it changes for reasons unrelated to your
configuration, and putting it on the resource would print `Objects have changed outside of
Terraform` on nearly every plan until teams learned to ignore drift notes. It is on the data
source:

```terraform
data "azureacme_certificate" "api" {
  namespace = "payments-prod"
  name      = "payments-api"
}

output "delivery" {
  value = {
    stage     = data.azureacme_certificate.api.delivery_stage
    consumers = data.azureacme_certificate.api.consumers
    not_after = data.azureacme_certificate.api.current_certificate.not_after
  }
}
```

`delivery_stage = "published"` means the certificate is in the vault. `consumer_observed` means a
probe has seen the new certificate actually being served. The gap between the two is the pickup
window in the table above.

## `consumer_stale`, and what to do about it

`consumer_stale` means: the certificate was published, the pickup window (twice the profile's
documented figure) has passed, and a probe still observes the **old** certificate being served.

Work down this list:

1. **Is the binding versionless?** A pinned version is the single most common cause. Check the
   consumer's configuration against the URI-form column above.
2. **Can the reading identity still read the vault?** Role assignments get removed by cleanup
   scripts and by vault migrations. The symptom column tells you what that looks like for your
   consumer.
3. **Does the consumer need a restart?** For `self_managed` and for env-var consumers under
   `aks_csi`, publication alone does nothing. Reload the listener.
4. **Is the probe reachable at all?** An unreachable probe reports `unverifiable`, not
   `consumer_stale`. If you are seeing `consumer_stale` the probe connected and saw the wrong
   certificate.
5. **Is the window right?** If you overrode `expected_pickup` below the documented figure for your
   profile, you are alerting on normal behaviour.

## cert-manager is not a consumer

If you run cert-manager in AKS, it is an **alternative ACME issuer**, not something that consumes
a certificate from this product. Pointing both at the same name doubles your consumption of the
certificate authority's rate-limit budget for that registered domain, and neither system knows the
other exists. Choose one per name. See
[what this product does not do](what-this-product-does-not-do).
