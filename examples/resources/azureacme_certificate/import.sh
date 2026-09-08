# The import id is the Terraform-visible primary key, {namespace}/{name}.
#
# It carries no version, thumbprint, serial or expiry: an id that changed on
# renewal would make every renewal a replacement.
#
# Import requires Certificates.Manage on the namespace, not merely
# Certificates.Read — the provider proves management intent explicitly, so a
# reader cannot import a registration into their own state and then manage it.
terraform import azureacme_certificate.api payments-prod/payments-api
