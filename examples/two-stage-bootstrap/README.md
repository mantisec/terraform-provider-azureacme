# Two-stage bootstrap

The worked example for `terraform-provider-contract.md` §12 item 2. The rendered prose is the
[two-stage bootstrap guide](../../templates/guides/two-stage-bootstrap.md.tmpl); this directory is
the configuration that guide describes.

**These are two separate root modules, applied by two separate workspaces, in this order.** They
are not a module and a caller, and they are deliberately not composable into one apply:

| Directory | Owned by | Produces |
|---|---|---|
| [`stage-1-platform/`](stage-1-platform/) | The platform team | The certificate service, and **one** `connection_profile` object describing how to reach it. |
| [`stage-2-certificates/`](stage-2-certificates/) | An application team | Certificate registrations, using that object as an input variable. |

## Why they cannot be one configuration

If stage 2's `provider "azureacme"` block took its `endpoint` from a resource created in stage 1's
own apply, four separate things break — Terraform Core calls `ConfigureProvider` during plan so the
endpoint arrives unknown; data sources are read at plan time and fail on the first apply; refresh
makes it *appear* to work from the second apply onward; and destroy strands every certificate with
"provider configuration not present to destroy".

`terraform apply -target=module.platform` appears to fix this and is **not a supported path**.

## Where the API's own endpoint certificate comes from

The product cannot issue its own first certificate — doing so would require calling the service
over the endpoint that does not yet have one. `stage-1-platform/main.tf` shows the default answer
(an Azure-managed certificate on the custom domain) and names the alternatives. This is a platform
responsibility tracked outside the service, and its expiry must be alerted on by something that
does not depend on the service being reachable.
