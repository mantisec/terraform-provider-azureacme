# The cross-workspace CONSUMPTION path. Strictly read-only: it never claims
# ownership, cannot create, and requires only Certificates.Read — so an
# application workspace can consume a certificate registered by a platform
# workspace without gaining the ability to change it.
#
# Every volatile field deliberately kept off the resource lives here: status,
# delivery_stage, consumers[], operation, previous_certificate, renewal status,
# ownership, audit, system_labels, conditions and the dns_names AS ISSUED.

data "azureacme_certificate" "api" {
  namespace = "payments-prod"
  name      = "payments-api"
}

output "delivery" {
  value = {
    stage     = data.azureacme_certificate.api.delivery_stage
    not_after = data.azureacme_certificate.api.current_certificate.not_after
    consumers = data.azureacme_certificate.api.consumers
  }
}
