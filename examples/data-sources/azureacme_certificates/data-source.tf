# Pagination is handled internally, so `items` is complete.
#
# Data sources are read at PLAN TIME on every run, so this one defaults to the
# summary view. Keep it that way unless you need the full projection.

data "azureacme_certificates" "expiring" {
  namespace       = "payments-prod"
  expiring_within = "30d"
}

output "expiring_soon" {
  value = [for c in data.azureacme_certificates.expiring.items : c.name]
}
