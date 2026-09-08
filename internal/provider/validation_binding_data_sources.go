package provider

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// This file holds BOTH validation-binding data sources, singular and plural.
// They project the same wire type and differ only in selection, so keeping them
// together keeps one projection rather than two that can drift.
//
// The PLURAL form is not a convenience. Without it an application team cannot
// enumerate the bindings available to them from Terraform AT ALL — only from a
// raw API call they have no tooling for.

var (
	_ datasource.DataSource              = (*validationBindingDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*validationBindingDataSource)(nil)
	_ datasource.DataSource              = (*validationBindingsDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*validationBindingsDataSource)(nil)
)

func validationBindingTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id": types.StringType, "zone_id": types.StringType, "mode": types.StringType,
		"wildcards_allowed": types.BoolType, "healthy": types.BoolType,
		"required_cname": types.StringType, "last_checked_at": types.StringType,
		"permitted_name_patterns": types.ListType{ElemType: types.StringType},
		"delegation_targets":      types.ListType{ElemType: types.StringType},
	}
}

func validationBindingAttributes(withID bool) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"zone_id": schema.StringAttribute{Computed: true},
		"mode":    schema.StringAttribute{Computed: true},
		"wildcards_allowed": schema.BoolAttribute{Computed: true,
			MarkdownDescription: "Wildcard is its own axis and is never inferred from a name-scope grant: DNS-01 for " +
				"`*.api.example.com` and for `api.example.com` uses the SAME challenge name."},
		"healthy": schema.BoolAttribute{Computed: true},
		"required_cname": schema.StringAttribute{Computed: true,
			MarkdownDescription: "When unhealthy, the EXACT record to create."},
		"last_checked_at":         schema.StringAttribute{Computed: true},
		"permitted_name_patterns": schema.ListAttribute{Computed: true, ElementType: types.StringType},
		"delegation_targets":      schema.ListAttribute{Computed: true, ElementType: types.StringType},
	}
	if withID {
		attrs["id"] = schema.StringAttribute{Required: true}
	} else {
		attrs["id"] = schema.StringAttribute{Computed: true}
	}
	return attrs
}

func bindingObject(ctx context.Context, b contracts.ValidationBinding, diags *diagsAccumulator) attr.Value {
	patterns := stringList(ctx, b.PermittedNamePatterns, diags.d)
	targets := stringList(ctx, b.DelegationTargets, diags.d)
	obj, d := types.ObjectValue(validationBindingTypes(), map[string]attr.Value{
		"id": types.StringValue(b.ID), "zone_id": stringOrNull(b.ZoneID),
		"mode": types.StringValue(b.Mode), "wildcards_allowed": types.BoolValue(b.WildcardsAllowed),
		"healthy": types.BoolValue(b.Healthy), "required_cname": stringOrNull(b.RequiredCname),
		"last_checked_at":         stringOrNull(b.LastCheckedAt),
		"permitted_name_patterns": patterns, "delegation_targets": targets,
	})
	diags.d.Append(d...)
	return obj
}

// ------------------------------------------------------------------ singular

// NewValidationBindingDataSource reads one validation binding.
func NewValidationBindingDataSource() datasource.DataSource { return &validationBindingDataSource{} }

type validationBindingDataSource struct{ data *providerData }

func (d *validationBindingDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_validation_binding"
}

func (d *validationBindingDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

func (d *validationBindingDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One DNS validation binding. Use `wildcards_allowed` in a `lifecycle { precondition }` so a " +
			"forbidden wildcard fails the plan rather than the apply.",
		Attributes: validationBindingAttributes(true),
	}
}

type validationBindingModel struct {
	ID                    types.String `tfsdk:"id"`
	ZoneID                types.String `tfsdk:"zone_id"`
	Mode                  types.String `tfsdk:"mode"`
	WildcardsAllowed      types.Bool   `tfsdk:"wildcards_allowed"`
	Healthy               types.Bool   `tfsdk:"healthy"`
	RequiredCname         types.String `tfsdk:"required_cname"`
	LastCheckedAt         types.String `tfsdk:"last_checked_at"`
	PermittedNamePatterns types.List   `tfsdk:"permitted_name_patterns"`
	DelegationTargets     types.List   `tfsdk:"delegation_targets"`
}

func (d *validationBindingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg validationBindingModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.data == nil || d.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client.")
		return
	}
	b, err := d.data.Client.GetValidationBinding(ctx, cfg.ID.ValueString())
	if err != nil {
		if apiErr, ok := client.AsAPIError(err); ok {
			resp.Diagnostics.AddError(fmt.Sprintf("Could not read validation binding %q (HTTP %d)", cfg.ID.ValueString(), apiErr.Status),
				fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()))
			return
		}
		resp.Diagnostics.AddError(fmt.Sprintf("Could not read validation binding %q", cfg.ID.ValueString()), err.Error())
		return
	}
	cfg.ZoneID = stringOrNull(b.ZoneID)
	cfg.Mode = types.StringValue(b.Mode)
	cfg.WildcardsAllowed = types.BoolValue(b.WildcardsAllowed)
	cfg.Healthy = types.BoolValue(b.Healthy)
	cfg.RequiredCname = stringOrNull(b.RequiredCname)
	cfg.LastCheckedAt = stringOrNull(b.LastCheckedAt)
	cfg.PermittedNamePatterns = stringList(ctx, b.PermittedNamePatterns, &resp.Diagnostics)
	cfg.DelegationTargets = stringList(ctx, b.DelegationTargets, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

// -------------------------------------------------------------------- plural

// NewValidationBindingsDataSource returns EVERY binding visible to the caller.
func NewValidationBindingsDataSource() datasource.DataSource { return &validationBindingsDataSource{} }

type validationBindingsDataSource struct{ data *providerData }

func (d *validationBindingsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_validation_bindings"
}

func (d *validationBindingsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

type validationBindingsModel struct {
	Items types.List `tfsdk:"items"`
}

func (d *validationBindingsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Every DNS validation binding visible to the caller. Without this, a team cannot enumerate " +
			"the bindings available to them from Terraform at all.",
		Attributes: map[string]schema.Attribute{
			"items": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: validationBindingAttributes(false),
			}},
		},
	}
}

func (d *validationBindingsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil || d.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client.")
		return
	}
	acc := &diagsAccumulator{d: &resp.Diagnostics}
	var items []attr.Value
	pageToken := ""
	for {
		q := url.Values{}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		page, err := d.data.Client.ListValidationBindings(ctx, q)
		if err != nil {
			if apiErr, ok := client.AsAPIError(err); ok {
				resp.Diagnostics.AddError(fmt.Sprintf("Could not list validation bindings (HTTP %d)", apiErr.Status),
					fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()))
				return
			}
			resp.Diagnostics.AddError("Could not list validation bindings", err.Error())
			return
		}
		for _, b := range page.Items {
			items = append(items, bindingObject(ctx, b, acc))
		}
		if page.NextPageToken == nil || *page.NextPageToken == "" {
			break
		}
		pageToken = *page.NextPageToken
	}
	list, diags := types.ListValue(types.ObjectType{AttrTypes: validationBindingTypes()}, items)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &validationBindingsModel{Items: list})...)
}
