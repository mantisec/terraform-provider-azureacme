// Package provider holds the provider type, its configuration schema, and every
// resource and data source (one per file).
//
// SCAFFOLD (SCAFFOLD-PROVIDER-MODULE): this file establishes the provider type
// and the configuration surface of terraform-provider-contract.md §2.1/§2.2 so
// that the toolchain is provably working. Configure() deliberately does no work
// beyond publishing the parsed configuration: the credential chain (§2.4), the
// capabilities pre-flight and the HTTP client (§2.5) belong to
// AUTH-PROVIDER-CREDENTIAL-CHAIN and the provider-client items, not here.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	// SCAFFOLD: no client is built and no credential is acquired yet. The
	// unknown-endpoint diagnostic (§2.5 step 1), the credential chain (§2.4) and
	// the capabilities pre-flight are owned by their own backlog items.
	resp.DataSourceData = &cfg
	resp.ResourceData = &cfg
}

// Resources is empty by design in this item — SCAFFOLD-PROVIDER-MODULE ships no
// resource. `azureacme_certificate` is the provider-domain items' work.
func (p *azureACMEProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

// DataSources is empty by design in this item.
func (p *azureACMEProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
