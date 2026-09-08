# THE SIX-CONCEPT CONFIGURATION (terraform-provider-contract.md §5.1).
#
# Six concepts: namespace, name, DNS names, destination vault, the publisher role
# assignment, and one connection profile. Everything else has a default that is
# correct for every consumer in the v1 matrix.
#
# NOTE THE ABSENCE OF A `key` BLOCK. That is deliberate and load-bearing. The
# default is RSA 2048 with an EXPORTABLE key, which every consumer in the
# supported matrix requires: Application Gateway needs an exportable private key,
# and every other consumer reads the Key Vault PKCS#12 secret, which contains no
# private key at all when the policy is non-exportable. An example that showed
# `exportable = false` would be copied, and the result is an apply that succeeds,
# a status page that is entirely green, and a listener that will not start.

provider "azureacme" {
  connection_profile = var.acme_connection_profile
}

# Discover the publishing identity from the service itself. NEVER through
# terraform_remote_state against the platform state: that grants this workspace
# read access to the platform's storage account keys and its whole resource graph.
data "azureacme_service" "this" {}

# The destination vault owner grants the publishing identity the right to manage
# certificates in their vault. This is the one cross-team step.
resource "azurerm_role_assignment" "acme_publisher" {
  scope                = azurerm_key_vault.payments.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azureacme_service.this.publisher_principal_id
}

resource "azureacme_certificate" "api" {
  namespace    = "payments-prod"
  name         = "payments-api"
  dns_names    = ["api.example.com"]
  key_vault_id = azurerm_key_vault.payments.id

  depends_on = [azurerm_role_assignment.acme_publisher]
}

# The consumption binding point. It is VERSIONLESS, so a renewal never changes it
# and no consumer needs to be re-applied when the certificate rotates.
output "certificate_secret_id" {
  value = azureacme_certificate.api.versionless_secret_id
}
