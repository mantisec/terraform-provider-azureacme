package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
)

var (
	_ datasource.DataSource              = (*namespaceDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*namespaceDataSource)(nil)
)

// NewNamespaceDataSource publishes what a namespace permits, so an authorisation
// mistake lands in the PLAN rather than as a 403 after apply has already begun
// changing other resources.
//
// NOTE ON THE RESERVED NAME. Terraform keeps resource and data-source type names
// in separate namespaces, so this data source does not collide with the reserved
// RESOURCE name `azureacme_namespace` (§1.3, D-19).
func NewNamespaceDataSource() datasource.DataSource { return &namespaceDataSource{} }

type namespaceDataSource struct{ data *providerData }

func (d *namespaceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (d *namespaceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

type namespaceDataSourceModel struct {
	Name                         types.String `tfsdk:"name"`
	Enabled                      types.Bool   `tfsdk:"enabled"`
	PolicyRevision               types.Int64  `tfsdk:"policy_revision"`
	CallerRoles                  types.List   `tfsdk:"caller_roles"`
	MaxIdentifiersPerCertificate types.Int64  `tfsdk:"max_identifiers_per_certificate"`
	DefaultDeletionPolicy        types.String `tfsdk:"default_deletion_policy"`
	AllowedDeletionPolicies      types.List   `tfsdk:"allowed_deletion_policies"`
	PermittedDomains             types.List   `tfsdk:"permitted_domains"`
	PermittedDestinations        types.List   `tfsdk:"permitted_destinations"`
	AllowedKeyPolicies           types.List   `tfsdk:"allowed_key_policies"`
	WildcardPolicyJSON           types.String `tfsdk:"wildcard_policy_json"`
}

func domainRuleTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"base": types.StringType, "kind": types.StringType, "effect": types.StringType,
		"max_labels_below": types.Int64Type,
	}
}

func destinationPolicyTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"destination_id": types.StringType, "key_vault_id": types.StringType,
		"certificate_name_allow": types.ListType{ElemType: types.StringType},
	}
}

func allowedKeyPolicyTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"algorithm": types.StringType,
		"sizes":     types.ListType{ElemType: types.Int64Type},
		"curves":    types.ListType{ElemType: types.StringType},
	}
}

func (d *namespaceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "What one namespace permits: domains, destinations, wildcard policy, key policies and the " +
			"caller's roles. Use it in a `lifecycle { precondition }` so an authorisation mistake fails the plan.",
		Attributes: map[string]schema.Attribute{
			"name":                            schema.StringAttribute{Required: true},
			"enabled":                         schema.BoolAttribute{Computed: true},
			"policy_revision":                 schema.Int64Attribute{Computed: true},
			"caller_roles":                    schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"max_identifiers_per_certificate": schema.Int64Attribute{Computed: true},
			"default_deletion_policy":         schema.StringAttribute{Computed: true},
			"allowed_deletion_policies":       schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"permitted_domains": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"base": schema.StringAttribute{Computed: true},
					"kind": schema.StringAttribute{Computed: true,
						MarkdownDescription: "`exact`, `subtree` or `wildcard`. **`subtree` does not match its own base**: " +
							"authorising `api.example.com` itself requires an `exact` rule."},
					"effect":           schema.StringAttribute{Computed: true},
					"max_labels_below": schema.Int64Attribute{Computed: true},
				}}},
			"permitted_destinations": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"destination_id":         schema.StringAttribute{Computed: true},
					"key_vault_id":           schema.StringAttribute{Computed: true},
					"certificate_name_allow": schema.ListAttribute{Computed: true, ElementType: types.StringType},
				}}},
			"allowed_key_policies": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"algorithm": schema.StringAttribute{Computed: true},
					"sizes":     schema.ListAttribute{Computed: true, ElementType: types.Int64Type},
					"curves":    schema.ListAttribute{Computed: true, ElementType: types.StringType},
				}}},
			"wildcard_policy_json": schema.StringAttribute{Computed: true,
				MarkdownDescription: "The wildcard policy document, verbatim as JSON. Wildcard is its own axis and is " +
					"NEVER inferred from a name-scope grant."},
		},
	}
}

func (d *namespaceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg namespaceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.data == nil || d.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client.")
		return
	}
	detail, err := d.data.Client.GetNamespace(ctx, cfg.Name.ValueString())
	if err != nil {
		if apiErr, ok := client.AsAPIError(err); ok {
			resp.Diagnostics.AddError(fmt.Sprintf("Could not read namespace %q (HTTP %d)", cfg.Name.ValueString(), apiErr.Status),
				fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()))
			return
		}
		resp.Diagnostics.AddError(fmt.Sprintf("Could not read namespace %q", cfg.Name.ValueString()), err.Error())
		return
	}

	cfg.Enabled = types.BoolValue(detail.Enabled)
	cfg.PolicyRevision = types.Int64Value(detail.PolicyRevision)
	cfg.MaxIdentifiersPerCertificate = types.Int64Value(detail.MaxIdentifiersPerCertificate)
	cfg.DefaultDeletionPolicy = types.StringValue(string(detail.DefaultDeletionPolicy))
	cfg.CallerRoles = stringList(ctx, detail.CallerRoles, &resp.Diagnostics)

	policies := make([]string, 0, len(detail.AllowedDeletionPolicies))
	for _, p := range detail.AllowedDeletionPolicies {
		policies = append(policies, string(p))
	}
	cfg.AllowedDeletionPolicies = stringList(ctx, policies, &resp.Diagnostics)

	domains := make([]attr.Value, 0, len(detail.PermittedDomains))
	for _, r := range detail.PermittedDomains {
		obj, diags := types.ObjectValue(domainRuleTypes(), map[string]attr.Value{
			"base": types.StringValue(r.Base), "kind": types.StringValue(r.Kind),
			"effect": stringOrNull(r.Effect), "max_labels_below": int64OrNull(r.MaxLabelsBelow),
		})
		resp.Diagnostics.Append(diags...)
		domains = append(domains, obj)
	}
	dl, diags := types.ListValue(types.ObjectType{AttrTypes: domainRuleTypes()}, domains)
	resp.Diagnostics.Append(diags...)
	cfg.PermittedDomains = dl

	dests := make([]attr.Value, 0, len(detail.PermittedDestinations))
	for _, p := range detail.PermittedDestinations {
		allow := stringList(ctx, p.CertificateNameAllow, &resp.Diagnostics)
		obj, diags := types.ObjectValue(destinationPolicyTypes(), map[string]attr.Value{
			"destination_id": types.StringValue(p.DestinationID), "key_vault_id": types.StringValue(p.KeyVaultID),
			"certificate_name_allow": allow,
		})
		resp.Diagnostics.Append(diags...)
		dests = append(dests, obj)
	}
	destList, diags := types.ListValue(types.ObjectType{AttrTypes: destinationPolicyTypes()}, dests)
	resp.Diagnostics.Append(diags...)
	cfg.PermittedDestinations = destList

	keys := make([]attr.Value, 0, len(detail.AllowedKeyPolicies))
	for _, k := range detail.AllowedKeyPolicies {
		sizes, d := types.ListValueFrom(ctx, types.Int64Type, k.Sizes)
		resp.Diagnostics.Append(d...)
		obj, d2 := types.ObjectValue(allowedKeyPolicyTypes(), map[string]attr.Value{
			"algorithm": types.StringValue(k.Algorithm), "sizes": sizes,
			"curves": stringList(ctx, k.Curves, &resp.Diagnostics),
		})
		resp.Diagnostics.Append(d2...)
		keys = append(keys, obj)
	}
	keyList, diags := types.ListValue(types.ObjectType{AttrTypes: allowedKeyPolicyTypes()}, keys)
	resp.Diagnostics.Append(diags...)
	cfg.AllowedKeyPolicies = keyList

	if raw, err := json.Marshal(detail.WildcardPolicy); err == nil {
		cfg.WildcardPolicyJSON = types.StringValue(string(raw))
	} else {
		cfg.WildcardPolicyJSON = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
