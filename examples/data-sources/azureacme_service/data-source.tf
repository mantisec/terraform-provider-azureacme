# The SECURE way to discover the publishing identity.
#
# Every terraform_remote_state example has been deleted from this provider's
# documentation on purpose: reading the platform's state to find one principal id
# grants the reading workspace access to storage account keys and the full
# platform resource graph — a privilege escalation dressed as convenience.

data "azureacme_service" "this" {}

resource "azurerm_role_assignment" "acme_publisher" {
  scope                = azurerm_key_vault.payments.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azureacme_service.this.publisher_principal_id
}

output "service_limits" {
  value = {
    instance      = data.azureacme_service.this.instance_name
    max_dns_names = data.azureacme_service.this.max_dns_names
    profiles      = data.azureacme_service.this.acme_profiles
  }
}
