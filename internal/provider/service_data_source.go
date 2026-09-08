package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*serviceDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*serviceDataSource)(nil)
)

// NewServiceDataSource exposes the service's identity, limits and — critically —
// the PUBLISHER IDENTITY.
//
// `publisher_principal_id` exists to kill an insecure pattern. The only worked
// example in the source reviews obtained the publishing identity through
// `terraform_remote_state` against the platform state, which grants every
// certificate-consuming workspace read access to storage account keys and the
// full resource graph — a privilege escalation dressed as convenience.
// Publishing the id here makes the secure path the copy-pastable one.
func NewServiceDataSource() datasource.DataSource { return &serviceDataSource{} }

type serviceDataSource struct{ data *providerData }

func (d *serviceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (d *serviceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

type serviceDataSourceModel struct {
	InstanceID               types.String `tfsdk:"instance_id"`
	InstanceName             types.String `tfsdk:"instance_name"`
	APIVersion               types.String `tfsdk:"api_version"`
	APIVersionsSupported     types.List   `tfsdk:"api_versions_supported"`
	Features                 types.List   `tfsdk:"features"`
	MinimumClientVersion     types.String `tfsdk:"minimum_client_version"`
	DeprecatedClientVersion  types.String `tfsdk:"deprecated_client_version"`
	DeprecatedClientDeadline types.String `tfsdk:"deprecated_client_deadline"`
	PublisherPrincipalID     types.String `tfsdk:"publisher_principal_id"`
	PublisherClientID        types.String `tfsdk:"publisher_client_id"`
	ACMEDirectoryURL         types.String `tfsdk:"acme_directory_url"`
	ACMEEnvironment          types.String `tfsdk:"acme_environment"`
	ACMEDefaultProfile       types.String `tfsdk:"acme_default_profile"`
	ACMEProfiles             types.List   `tfsdk:"acme_profiles"`
	KeyAlgorithms            types.List   `tfsdk:"key_algorithms"`
	KeyRSASizes              types.List   `tfsdk:"key_rsa_sizes"`
	KeyCurves                types.List   `tfsdk:"key_curves"`
	ConsumerProfiles         types.List   `tfsdk:"consumer_profiles"`
	MaxDNSNames              types.Int64  `tfsdk:"max_dns_names"`
	MaxLabels                types.Int64  `tfsdk:"max_labels"`
	MaxProbeEndpoints        types.Int64  `tfsdk:"max_probe_endpoints"`
	MaxPageSize              types.Int64  `tfsdk:"max_page_size"`
	CallerPrincipalID        types.String `tfsdk:"caller_principal_id"`
	CallerPrincipalType      types.String `tfsdk:"caller_principal_type"`
	CallerRoles              types.List   `tfsdk:"caller_roles"`
	CallerNamespaces         types.List   `tfsdk:"caller_namespaces"`
}

func (d *serviceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Identity, capabilities and limits of the certificate service this provider is configured " +
			"against, plus the caller's own identity and roles.\n\n" +
			"Use `publisher_principal_id` to grant the publishing identity `Key Vault Certificates Officer` on your own " +
			"vault. **Never** obtain it with `terraform_remote_state` against the platform state: that grants this " +
			"workspace read access to the platform's storage account keys and its entire resource graph.",
		Attributes: map[string]schema.Attribute{
			"instance_id":            schema.StringAttribute{Computed: true, MarkdownDescription: "The service instance ULID. Data, not configuration: it survives redeploys, slot swaps and host replacement, and changes only when the catalogue storage account changes."},
			"instance_name":          schema.StringAttribute{Computed: true, MarkdownDescription: "A human-readable label. A DIFFERENT field from `instance_id`."},
			"api_version":            schema.StringAttribute{Computed: true},
			"api_versions_supported": schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"features": schema.ListAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "Feature gating is by NAME, never by version arithmetic."},
			"minimum_client_version":     schema.StringAttribute{Computed: true},
			"deprecated_client_version":  schema.StringAttribute{Computed: true},
			"deprecated_client_deadline": schema.StringAttribute{Computed: true},
			"publisher_principal_id": schema.StringAttribute{Computed: true,
				MarkdownDescription: "The publishing identity every application team grants `Key Vault Certificates Officer` on their own vault."},
			"publisher_client_id":   schema.StringAttribute{Computed: true},
			"acme_directory_url":    schema.StringAttribute{Computed: true},
			"acme_environment":      schema.StringAttribute{Computed: true},
			"acme_default_profile":  schema.StringAttribute{Computed: true},
			"acme_profiles":         schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"key_algorithms":        schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"key_rsa_sizes":         schema.ListAttribute{Computed: true, ElementType: types.Int64Type},
			"key_curves":            schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"consumer_profiles":     schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"max_dns_names":         schema.Int64Attribute{Computed: true},
			"max_labels":            schema.Int64Attribute{Computed: true},
			"max_probe_endpoints":   schema.Int64Attribute{Computed: true},
			"max_page_size":         schema.Int64Attribute{Computed: true},
			"caller_principal_id":   schema.StringAttribute{Computed: true},
			"caller_principal_type": schema.StringAttribute{Computed: true},
			"caller_roles":          schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"caller_namespaces":     schema.ListAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *serviceDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil || d.data.Capabilities == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no capabilities document.")
		return
	}
	// Served entirely from the CACHE (§3.1): a data source read at plan time on
	// every run must stay cheap.
	caps := d.data.Capabilities
	svc := caps.Service

	var profileNames []string
	for _, p := range svc.ACME.Profiles {
		if raw, ok := p["name"]; ok {
			profileNames = append(profileNames, strings.Trim(string(raw), `"`))
		}
	}
	consumerNames := make([]string, 0, len(svc.ConsumerProfiles))
	for _, p := range svc.ConsumerProfiles {
		consumerNames = append(consumerNames, p.Name)
	}

	m := serviceDataSourceModel{
		InstanceID:               types.StringValue(svc.InstanceID),
		InstanceName:             types.StringValue(svc.InstanceName),
		APIVersion:               types.StringValue(svc.APIVersion),
		MinimumClientVersion:     types.StringValue(svc.MinimumClientVersion),
		DeprecatedClientVersion:  stringOrNull(svc.DeprecatedClientVersion),
		DeprecatedClientDeadline: stringOrNull(svc.DeprecatedClientDeadline),
		PublisherPrincipalID:     stringOrNull(svc.PublisherPrincipalID),
		PublisherClientID:        stringOrNull(svc.PublisherClientID),
		ACMEDirectoryURL:         types.StringValue(svc.ACME.DirectoryURL),
		ACMEEnvironment:          types.StringValue(svc.ACME.Environment),
		ACMEDefaultProfile:       types.StringValue(svc.ACME.DefaultProfile),
		MaxDNSNames:              int64OrNull(svc.Limits.MaxDNSNames),
		MaxLabels:                int64OrNull(svc.Limits.MaxLabels),
		MaxProbeEndpoints:        int64OrNull(svc.Limits.MaxProbeEndpoints),
		MaxPageSize:              int64OrNull(svc.Limits.MaxPageSize),
		CallerPrincipalID:        types.StringValue(caps.Caller.PrincipalID),
		CallerPrincipalType:      types.StringValue(caps.Caller.PrincipalType),
	}
	m.APIVersionsSupported = stringList(ctx, svc.APIVersionsSupported, &resp.Diagnostics)
	m.Features = stringList(ctx, svc.Features, &resp.Diagnostics)
	m.ACMEProfiles = stringList(ctx, profileNames, &resp.Diagnostics)
	m.KeyAlgorithms = stringList(ctx, svc.KeyPolicies.Algorithms, &resp.Diagnostics)
	m.KeyCurves = stringList(ctx, svc.KeyPolicies.Curves, &resp.Diagnostics)
	m.ConsumerProfiles = stringList(ctx, consumerNames, &resp.Diagnostics)
	m.CallerRoles = stringList(ctx, caps.Caller.Roles, &resp.Diagnostics)
	m.CallerNamespaces = stringList(ctx, caps.Caller.Namespaces, &resp.Diagnostics)
	sizes, diags := types.ListValueFrom(ctx, types.Int64Type, svc.KeyPolicies.RSASizes)
	resp.Diagnostics.Append(diags...)
	m.KeyRSASizes = sizes

	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

var _ = json.Marshal
var _ = fmt.Sprintf
