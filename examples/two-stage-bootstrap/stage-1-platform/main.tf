# STAGE 1 — the platform team's workspace.
#
# This root module deploys the certificate service and publishes ONE object
# describing how to reach it. It declares no `azureacme` provider and no
# azureacme resource: at this point the service does not exist yet, so nothing
# here could talk to it.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "endpoint_hostname" {
  description = <<-EOT
    The platform-owned custom domain bound to the service.

    A custom domain is recommended regardless of anything else here. Azure's
    unique-default-hostname behaviour appends a random token to new
    *.azurewebsites.net names, so `default_hostname` is NOT derivable from this
    module's inputs — a platform team that publishes the default hostname has to
    read it back out of the deployed resource, which reintroduces the dependency
    this whole two-stage split exists to remove. A custom domain is a value the
    platform chooses in advance and publishes as a constant.
  EOT
  type        = string
  default     = "certs.platform.example.com"
}

# NOT YET PUBLISHED. The platform module is not on the Terraform Registry, so
# this block does not initialise as written. It shows the SHAPE of stage 1: deploy
# the service by whatever means you have, then publish the connection profile
# below with the same four fields.
module "acme_platform" {
  source  = "mantisec/azureacme/azure"
  version = "~> 1.0"

  # Whatever the platform module requires: resource group, location, the
  # operations Key Vault, the DNS zones it may write challenge records into, the
  # namespaces it serves. Elided here because this example is about the SHAPE of
  # the two stages, not about the module's own inputs.
  endpoint_hostname = var.endpoint_hostname
}

# ---------------------------------------------------------------------------
# WHERE THE API'S OWN ENDPOINT CERTIFICATE COMES FROM.
#
# The honest answer, and the question nobody asks until the first deployment:
# THE PRODUCT CANNOT ISSUE ITS OWN FIRST CERTIFICATE. The service's endpoint
# needs TLS before any client — including this provider — can talk to it, and
# issuing that certificate through the service would mean calling the service
# over the endpoint that has no certificate. No ordering resolves it.
#
# The default answer is an Azure-managed certificate on the custom domain: free,
# auto-renewed by Azure, no Key Vault involved, no external dependency and no
# renewal a human has to remember. Check its constraints (apex and wildcard
# support, and the DNS record it requires) against your domain first.
#
# The alternatives, in order of preference:
#   * a certificate from the corporate PKI you already operate, published to the
#     operations vault and bound here;
#   * a second, minimal instance of this service used only to issue the
#     production instance's endpoint certificate — almost never worth it, since
#     it doubles the thing you are trying to operate.
#
# Whichever you choose, its expiry MUST be alerted on by something that does not
# depend on the service being reachable. A monitor that calls the API to check
# the API's own certificate is not a monitor.
# ---------------------------------------------------------------------------
resource "azurerm_app_service_managed_certificate" "endpoint" {
  custom_hostname_binding_id = module.acme_platform.endpoint_hostname_binding_id
}

# ONE object, not four outputs. Three values copied by hand are three chances to
# paste a staging endpoint into production — which is precisely the catastrophe
# expected_service_instance_id exists to catch, so it travels inside the object
# and the safety rail is on by default for anyone who copies this output.
output "acme_connection_profile" {
  description = "Pass this whole object to a stage-2 workspace as an input variable."
  value       = module.acme_platform.connection_profile
}
