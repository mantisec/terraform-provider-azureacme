---
page_title: "Two-stage bootstrap - azureacme provider"
subcategory: ""
description: |-
  Why the service and the certificates that use it cannot live in one configuration, the
  two sanctioned patterns, and where the TLS certificate for the API's own endpoint
  comes from.
---

# Two-stage bootstrap

The `azureacme` provider is a **client of a service that some other Terraform configuration
deploys**. Those two things cannot be the same configuration, and the reason is structural
rather than stylistic.

## Why one configuration cannot work

If the Function App running the service were managed by the same configuration that declares
`azureacme_certificate` resources, the `provider "azureacme"` block's `endpoint` would depend on
an attribute of a resource created by that same apply. That is the one pattern Terraform cannot
express, and each of the four failure modes below is separate:

1. **Plan.** Terraform Core calls `ConfigureProvider` during plan, so an endpoint derived from a
   resource attribute arrives **unknown**. The provider raises an attribute error naming this
   constraint.
2. **Data sources are the hard failure.** `data "azureacme_…"` blocks are read during plan, so any
   discovery data source fails on the very first apply — including the
   `data "azureacme_service"` lookup the quickstart depends on.
3. **Refresh works from the second apply onward.** This is the dangerous part: once the endpoint
   is in state, the pattern *appears* to work. It then breaks on a fresh clone, in a new
   workspace, or in CI, in a way nobody can reproduce from the configuration.
4. **Destroy.** Removing the Function App from configuration while certificate resources still
   exist produces `provider configuration not present to destroy`, and the certificates are
   stranded in state.

!> **`terraform apply -target=module.platform` is not a supported path.** It is the workaround
that appears to work when someone puts the platform module and their certificates in one
configuration, and it is exactly how teams arrive at states 3 and 4 above. The provider's
unknown-endpoint diagnostic names `-target` explicitly for this reason.

## The two sanctioned patterns

### Two root modules, endpoint passed as a variable

Stage 1 deploys the service. Stage 2 consumes it. The connection details cross the boundary as
plain input — through a `tfvars` file, a CI variable, a parameter store, whatever your
organisation already uses for cross-workspace values. They must **not** cross through a
remote-state data source pointed at stage 1's state file: that grants every certificate-consuming
workspace read access to the platform's storage account keys and its full resource graph.

The full worked configuration is in
[`examples/two-stage-bootstrap/`](https://github.com/mantisec/terraform-provider-azureacme/tree/main/examples/two-stage-bootstrap)
in the provider repository.

> **The platform module is not yet published** on the Terraform Registry, so the
> `mantisec/azureacme/azure` block below shows the shape of stage 1 rather than a configuration
> you can initialise today. Deploy the service by whatever means you have, and publish the same
> four-field connection profile from stage 1.

In outline:

```terraform
# ---------- stage 1: the platform team's workspace ----------
module "acme_platform" {
  source = "mantisec/azureacme/azure"
  # …
}

# ONE object, not four values. Three variables copied by hand are three chances to
# paste a staging endpoint into production.
output "acme_connection_profile" {
  value = module.acme_platform.connection_profile
  # {
  #   endpoint                     = "https://certs.platform.example.com"
  #   audience                     = "api://mantisec-acme"
  #   tenant_id                    = "00000000-0000-0000-0000-000000000000"
  #   expected_service_instance_id = "01J9K3M7QW8ZC5VN0X4P6R2TAB"
  # }
}
```

```terraform
# ---------- stage 2: an application team's workspace ----------
variable "acme_connection_profile" {
  type = object({
    endpoint                     = string
    audience                     = string
    tenant_id                    = string
    expected_service_instance_id = optional(string)
  })
}

provider "azureacme" {
  connection_profile = var.acme_connection_profile
}
```

-> **`expected_service_instance_id` travels inside the object on purpose.** It makes the
mistyped-endpoint safety rail **on by default** for anyone who copies the platform module's
output, rather than something each team has to opt into. A stale endpoint variable would
otherwise make every `GET` legitimately return `registration_not_found`, and Terraform would
remove the whole fleet from state and reissue it against the wrong service.

### `MANTISEC_ACME_ENDPOINT` for CI ergonomics

Every provider argument has an environment fallback (`MANTISEC_ACME_ENDPOINT`,
`MANTISEC_ACME_AUDIENCE`, `MANTISEC_ACME_TENANT_ID`,
`MANTISEC_ACME_SERVICE_INSTANCE_ID`). This is convenient in CI, where the values are already
job configuration. It is the same two-stage split, expressed through the environment.

## Bind a platform-owned custom domain as the endpoint

Recommended regardless of which pattern you use. Azure's unique-default-hostname behaviour
appends a random token to new `*.azurewebsites.net` names, so `default_hostname` is **not**
derivable from the module's inputs — a platform team that publishes the default hostname must
read it back out of the deployed resource, which reintroduces a dependency for every downstream
consumer. A custom domain the platform owns is a value the platform can choose in advance and
publish as a constant.

## Where the API's own endpoint certificate comes from

This is the question nobody asks until the first deployment, and the answer is the honest one:
**the product cannot issue its own first certificate.**

The service's custom-domain endpoint needs a TLS certificate before any client — including this
provider — can talk to it. Issuing that certificate through the service would require calling
the service over the endpoint that does not yet have a certificate. There is no ordering that
resolves it, and no amount of Terraform sequencing changes that.

Three ways out, in the order you should consider them:

| Option | What it is | When to choose it |
|---|---|---|
| **App Service managed certificate** | Azure issues and renews a free certificate for a custom domain bound to the Function App, with no Key Vault involvement. | The default. It is the only option with no external dependency and no renewal that a human must remember. Check its constraints against your domain (apex/wildcard support and the DNS record it requires) before committing. |
| **A certificate from your existing corporate PKI or CA** | Whatever your organisation already uses for internal endpoints, published to the operations Key Vault and bound to the Function App by the platform module. | You already have a working issuance path and want the endpoint inside it. |
| **A second, minimal instance of this service** | A bootstrap instance whose own endpoint is on a managed certificate, used only to issue the production instance's endpoint certificate. | Almost never. It doubles the thing you are trying to operate and moves the problem rather than solving it. |

Whichever you choose, **it is a platform-team responsibility, tracked separately from the
certificates the service manages**, and its expiry must be alerted on by something that does not
depend on the service being reachable. A monitor that calls the API to check the API's own
certificate is not a monitor.

-> The certificate on the service's endpoint is also what `expected_service_instance_id` cannot
protect you from. Instance pinning catches a request that reaches the *wrong* service; it says
nothing about a request that reaches no service at all because the endpoint's own certificate
expired.
