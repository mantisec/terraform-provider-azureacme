# The precondition pattern from the quickstart.
#
# Wildcard is its own authorisation axis and is NEVER inferred from a name-scope
# grant: DNS-01 for *.api.example.com and for api.example.com uses the SAME
# challenge name, so technical control of the zone proves nothing that
# distinguishes them.

data "azureacme_validation_binding" "zone" {
  id = "example-com"
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
  }
}
