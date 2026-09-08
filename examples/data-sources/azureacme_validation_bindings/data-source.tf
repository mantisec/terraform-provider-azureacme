# Every binding visible to the caller.
#
# The plural form exists because without it a team cannot enumerate the bindings
# available to them from Terraform at all — only from a raw API call they have no
# tooling for.

data "azureacme_validation_bindings" "all" {}

output "healthy_bindings" {
  value = [
    for b in data.azureacme_validation_bindings.all.items : b.id
    if b.healthy
  ]
}
