# tfplugindocs input. The path is fixed by the tool: this snippet becomes the
# usage section of the generated provider index page.

terraform {
  required_providers {
    azureacme = {
      source = "mantisec/azureacme"
    }
  }
}

# Preferred: one object emitted by the platform module. Because
# expected_service_instance_id travels inside it, the mistyped-endpoint safety
# rail is on by default for anyone who copies the module output.
provider "azureacme" {
  connection_profile = var.acme_connection_profile
}

# The service is deployed by a SEPARATE Terraform configuration. A provider
# cannot be configured from a resource created in the same apply, so the
# endpoint arrives here as a variable — never as module.platform.endpoint.
variable "acme_connection_profile" {
  type = object({
    endpoint                     = string
    audience                     = string
    tenant_id                    = string
    expected_service_instance_id = optional(string)
  })
}
