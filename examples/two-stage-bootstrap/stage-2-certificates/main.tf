# STAGE 2 — an application team's workspace.
#
# The connection details arrive as an INPUT VARIABLE. They must never arrive as
# terraform_remote_state against stage 1's state: reading that state to find one
# endpoint and one principal id grants this workspace the platform's storage
# account keys and its entire resource graph — a privilege escalation dressed as
# convenience.
#
# Supply the variable however your organisation already moves cross-workspace
# values: a tfvars file, a CI variable, a parameter store. Or set the
# MANTISEC_ACME_* environment variables and omit it entirely.

terraform {
  required_providers {
    azureacme = {
      source  = "mantisec/azureacme"
      version = "~> 1.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "acme_connection_profile" {
  description = "The `acme_connection_profile` output of the stage-1 workspace, verbatim."
  type = object({
    endpoint                     = string
    audience                     = string
    tenant_id                    = string
    expected_service_instance_id = optional(string)
  })
}

provider "azurerm" {
  features {}
}

provider "azureacme" {
  connection_profile = var.acme_connection_profile
}

resource "azurerm_key_vault" "payments" {
  name                       = "kv-payments-prod"
  resource_group_name        = "rg-payments-prod"
  location                   = "australiaeast"
  tenant_id                  = var.acme_connection_profile.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
}

# Discover the publishing identity from the service itself. This data source is
# read at PLAN time, which is the second reason stage 1 and stage 2 cannot share
# a configuration: in one apply it would be read before the service existed.
data "azureacme_service" "this" {}

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

  # Without this, Terraform is free to create the registration before the role
  # assignment exists and the first publish fails with destination_access_denied.
  depends_on = [azurerm_role_assignment.acme_publisher]
}

output "certificate_secret_id" {
  description = "Versionless, so a renewal never changes it and no consumer is re-applied."
  value       = azureacme_certificate.api.versionless_secret_id
}
