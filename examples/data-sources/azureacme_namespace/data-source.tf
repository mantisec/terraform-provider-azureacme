# Move authorisation failures from APPLY time to PLAN time.
#
# Without a precondition, the only feedback channel for an unapproved domain, a
# forbidden wildcard or a non-permitted destination is a 403 after
# `terraform apply` has already begun changing other resources.

data "azureacme_namespace" "payments" {
  name = "payments-prod"
}

output "permitted_destinations" {
  value = [for d in data.azureacme_namespace.payments.permitted_destinations : d.key_vault_id]
}
