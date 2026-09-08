// Package provider holds the provider type, its configuration schema, and every
// resource and data source (one per file).
//
// Configure implements terraform-provider-contract.md §2.5: it resolves the
// configuration (§2.1, §2.4), builds the HTTP client with the redirect and
// content-type rules, makes the ONE /v1/capabilities call, and runs the
// negotiation and instance-pinning assertions of §3 — all before any resource is
// touched.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
)

// ProviderTypeName is the local name Terraform gives this provider, and therefore
// the resource type prefix (`azureacme_`). See terraform-provider-contract.md §1.1.
const ProviderTypeName = "azureacme"

// ModulePath is the Go module path this provider is built from. It is the MIRROR
// repository path (release-engineering.md §2); a test asserts go.mod agrees.
const ModulePath = "github.com/mantisec/terraform-provider-azureacme"

var (
	_ provider.Provider = (*azureACMEProvider)(nil)
)

type azureACMEProvider struct {
	version string
	// tokenSource is an injection point for tests. Production leaves it nil and
	// the credential SELECTION of §2.4 applies.
	tokenSource client.TokenSource
}

// NewWithTokenSource builds a provider that authenticates with a supplied token
// source. It exists for the acceptance suite, which drives a real
// `terraform plan` against the in-process fake service.
func NewWithTokenSource(version string, tokens client.TokenSource) func() provider.Provider {
	return func() provider.Provider {
		return &azureACMEProvider{version: version, tokenSource: tokens}
	}
}

// New returns the provider constructor consumed by providerserver.Serve.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &azureACMEProvider{version: version}
	}
}

// Model is the parsed provider configuration. Field order follows §2.2.
type Model struct {
	ConnectionProfile types.Object `tfsdk:"connection_profile"`

	Endpoint                  types.String `tfsdk:"endpoint"`
	Audience                  types.String `tfsdk:"audience"`
	TenantID                  types.String `tfsdk:"tenant_id"`
	ExpectedServiceInstanceID types.String `tfsdk:"expected_service_instance_id"`

	ClientID                  types.String `tfsdk:"client_id"`
	UseOIDC                   types.Bool   `tfsdk:"use_oidc"`
	OIDCToken                 types.String `tfsdk:"oidc_token"`
	OIDCTokenFilePath         types.String `tfsdk:"oidc_token_file_path"`
	OIDCRequestURL            types.String `tfsdk:"oidc_request_url"`
	OIDCRequestToken          types.String `tfsdk:"oidc_request_token"`
	UseMSI                    types.Bool   `tfsdk:"use_msi"`
	ClientCertificatePath     types.String `tfsdk:"client_certificate_path"`
	ClientCertificatePassword types.String `tfsdk:"client_certificate_password"`
	UseCLI                    types.Bool   `tfsdk:"use_cli"`

	Environment       types.String `tfsdk:"environment"`
	RequestTimeout    types.String `tfsdk:"request_timeout"`
	MaxRetries        types.Int64  `tfsdk:"max_retries"`
	SkipVersionCheck  types.Bool   `tfsdk:"skip_version_check"`
	SkipInstanceCheck types.Bool   `tfsdk:"skip_instance_check"`
}

func (p *azureACMEProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = ProviderTypeName
	resp.Version = p.version
}

func (p *azureACMEProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages durable certificate registrations through a Mantisec ACME certificate service. " +
			"An `azureacme_certificate` is a standing instruction to keep a certificate valid, not one signed artefact.",
		Attributes: map[string]schema.Attribute{
			"connection_profile": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "The connection object emitted by the platform module. " +
					"Mutually exclusive with `endpoint`, `audience`, `tenant_id` and `expected_service_instance_id`.",
				Attributes: map[string]schema.Attribute{
					"endpoint":                     schema.StringAttribute{Required: true, MarkdownDescription: "Base URL of the service."},
					"audience":                     schema.StringAttribute{Required: true, MarkdownDescription: "Token audience. Operator-configured; never derived from an unauthenticated capabilities call."},
					"tenant_id":                    schema.StringAttribute{Required: true, MarkdownDescription: "Entra tenant id."},
					"expected_service_instance_id": schema.StringAttribute{Optional: true, MarkdownDescription: "Pre-flight assertion that the endpoint is the instance you meant."},
				},
			},

			"endpoint":                     schema.StringAttribute{Optional: true, MarkdownDescription: "Base URL of the service. Falls back to `MANTISEC_ACME_ENDPOINT`."},
			"audience":                     schema.StringAttribute{Optional: true, MarkdownDescription: "Token audience. Operator-configured; MUST NOT be derived from an unauthenticated `/v1/capabilities` call."},
			"tenant_id":                    schema.StringAttribute{Optional: true, MarkdownDescription: "Entra tenant id. Falls back to `MANTISEC_ACME_TENANT_ID`, `ARM_TENANT_ID`, `AZURE_TENANT_ID`."},
			"expected_service_instance_id": schema.StringAttribute{Optional: true, MarkdownDescription: "Checked once at Configure, before any resource is touched."},

			"client_id":                   schema.StringAttribute{Optional: true, MarkdownDescription: "Entra client id of the calling identity."},
			"use_oidc":                    schema.BoolAttribute{Optional: true, MarkdownDescription: "Authenticate with a federated OIDC token."},
			"oidc_token":                  schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "OIDC token. Prefer the environment variable."},
			"oidc_token_file_path":        schema.StringAttribute{Optional: true, MarkdownDescription: "Path to a file containing the OIDC token."},
			"oidc_request_url":            schema.StringAttribute{Optional: true, MarkdownDescription: "GitHub Actions OIDC request URL."},
			"oidc_request_token":          schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "GitHub Actions OIDC request token."},
			"use_msi":                     schema.BoolAttribute{Optional: true, MarkdownDescription: "Authenticate with a managed identity."},
			"client_certificate_path":     schema.StringAttribute{Optional: true, MarkdownDescription: "Path to a client certificate."},
			"client_certificate_password": schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "Password for the client certificate."},
			"use_cli":                     schema.BoolAttribute{Optional: true, MarkdownDescription: "Fall back to the Azure CLI identity. Tried last. Defaults to `true`."},

			"environment":         schema.StringAttribute{Optional: true, MarkdownDescription: "`public`, `usgovernment` or `china`. Drives the authority host and the Key Vault DNS suffix."},
			"request_timeout":     schema.StringAttribute{Optional: true, MarkdownDescription: "Per-HTTP-request timeout, not per operation. Defaults to `60s`."},
			"max_retries":         schema.Int64Attribute{Optional: true, MarkdownDescription: "Defaults to `5`."},
			"skip_version_check":  schema.BoolAttribute{Optional: true, MarkdownDescription: "Skips the version assertions only. Emits a warning."},
			"skip_instance_check": schema.BoolAttribute{Optional: true, MarkdownDescription: "Skips service-instance pinning only. Emits a warning."},
		},
	}
}

func (p *azureACMEProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg Model
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// §2.3: there is no `client_secret` HCL attribute, because provider
	// configuration IS captured in saved plan files, which CI systems routinely
	// archive. The environment variable is accepted for compatibility and warned
	// about.
	if os.Getenv("ARM_CLIENT_SECRET") != "" {
		resp.Diagnostics.AddWarning("Authenticating with a client secret from the environment ("+DiagClientSecretFromEnvironment+")",
			"`ARM_CLIENT_SECRET` is set. Client secrets are accepted for compatibility and are DISCOURAGED: prefer workload "+
				"identity federation (`use_oidc`) or a managed identity, neither of which puts a long-lived secret on a "+
				"CI runner.\n\nThere is deliberately no `client_secret` provider attribute: provider configuration is "+
				"captured in saved plan files (`terraform plan -out`), which CI systems routinely archive.")
	}

	resolved := resolveConfig(ctx, cfg, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tokens := p.tokenSource
	if tokens == nil {
		tokens = buildTokenSource(resolved.CredentialMethod, resolved.Audience)
	}

	terraformVersion := req.TerraformVersion
	if terraformVersion == "" {
		terraformVersion = "unknown"
	}
	apiClient, err := client.New(client.Config{
		Endpoint: resolved.Endpoint,
		Audience: resolved.Audience,
		Tokens:   tokens,
		// The service's minimum_client_version enforcement and its
		// client.version_observed telemetry key on this string.
		UserAgent: fmt.Sprintf("terraform-provider-azureacme/%s (+terraform/%s) Go/%s",
			p.version, terraformVersion, runtime.Version()),
		RequestTimeout: resolved.RequestTimeout,
		MaxRetries:     resolved.MaxRetries,
	})
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Could not build the service client", err.Error())
		return
	}

	// tflog masking. TF_LOG=TRACE MUST NOT print a token.
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "authorization", "Authorization", "token", "oidc_token", "client_secret")
	ctx = tflog.MaskAllFieldValuesRegexes(ctx, bearerTokenPattern)

	data := &providerData{
		Client:            apiClient,
		Environment:       resolved.Environment,
		SkipVersionCheck:  resolved.SkipVersionCheck,
		SkipInstanceCheck: resolved.SkipInstanceCheck,
	}

	// ONE capabilities call, cached for the provider's lifetime (§3.1), so
	// plan-time validation costs no extra API calls.
	caps, _, err := apiClient.GetCapabilities(ctx)
	if err != nil {
		addCapabilitiesError(&resp.Diagnostics, apiClient, err)
		return
	}
	data.Capabilities = caps
	negotiateCapabilities(ctx, data, p.version, resolved.ExpectedServiceInstanceID, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.DataSourceData = data
	resp.ResourceData = data
}

// bearerTokenPattern masks anything that looks like a bearer token in a log line.
var bearerTokenPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)

func addCapabilitiesError(diags *diag.Diagnostics, c *client.Client, err error) {
	if tErr, ok := client.AsTransportError(err); ok {
		switch tErr.Reason {
		case client.ReasonRedirect:
			diags.AddError("The endpoint redirected instead of answering",
				fmt.Sprintf("%s returned HTTP %d to %q when asked for its capabilities.\n\n"+
					"The provider never follows redirects: Easy Auth's default for an unauthenticated request is a "+
					"redirect to an interactive sign-in page, and following it would turn an authentication failure into "+
					"an HTML 200.\n\nConfigure the service with `unauthenticatedClientAction = Return401` and no "+
					"`redirectToProvider`.", c.Endpoint(), tErr.Status, tErr.Location))
			return
		case client.ReasonContentType:
			diags.AddError("The endpoint is not the certificate service API",
				fmt.Sprintf("%s answered with %s rather than JSON — it is probably an authentication portal or an "+
					"unrelated service.\n\nCheck `endpoint`.", c.Endpoint(), tErr.ContentType))
			return
		}
	}
	if apiErr, ok := client.AsAPIError(err); ok {
		diags.AddError(fmt.Sprintf("Could not read the service capabilities (HTTP %d)", apiErr.Status),
			fmt.Sprintf("%s\n\nCredential method: %q.\n\n%s\n\nRequest id: %s",
				apiErr.Title(), c.CredentialMethod(), nextActionLine(apiErr), apiErr.RequestID()))
		return
	}
	diags.AddError("Could not reach the certificate service",
		fmt.Sprintf("%v\n\nEndpoint: %s\nCredential method: %q", err, c.Endpoint(), c.CredentialMethod()))
}

// ReservedResourceTypeNames are the four POLICY-PLANE resource type names
// reserved by §1.3 pending decision D-19.
//
// PROVISIONAL(D-19): taken as branch (a) — policy is authored ONLY by the
// platform Terraform pipeline, the API has no policy write path, and these four
// resources are NEVER BUILT. The names are reserved anyway so that if D-19 is
// ever reopened as (b) or (c) the change is ADDITIVE rather than breaking.
//
// Terraform keeps resource and data-source type names in separate namespaces, so
// the `azureacme_namespace` DATA SOURCE and a future `azureacme_namespace`
// RESOURCE can coexist. Reserving them therefore costs nothing today.
//
// TestReservedResourceTypeNamesAreNotRegistered asserts no resource claims one.
var ReservedResourceTypeNames = []string{
	"azureacme_namespace",
	"azureacme_dns_binding",
	"azureacme_destination_policy",
	"azureacme_role_binding",
}

// Resources returns every managed resource. `azureacme_certificate` is the ONLY
// resource in v1.
func (p *azureACMEProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
	}
}

// DataSources returns the six read-only data sources of §1.2. They are identical
// under all three branches of D-19, so none of them is blocked by it.
func (p *azureACMEProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewServiceDataSource,
		NewCertificateDataSource,
		NewCertificatesDataSource,
		NewNamespaceDataSource,
		NewValidationBindingDataSource,
		NewValidationBindingsDataSource,
	}
}
