package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
)

var (
	_ datasource.DataSource              = (*certificatesDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*certificatesDataSource)(nil)
)

// NewCertificatesDataSource lists registration SUMMARIES, paginating INTERNALLY.
//
// It defaults to `view = "summary"` because data sources are read at PLAN time on
// every run and must stay cheap.
func NewCertificatesDataSource() datasource.DataSource { return &certificatesDataSource{} }

type certificatesDataSource struct{ data *providerData }

func (d *certificatesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificates"
}

func (d *certificatesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

type certificatesDataSourceModel struct {
	Namespace      types.String `tfsdk:"namespace"`
	Labels         types.Map    `tfsdk:"labels"`
	ExpiringWithin types.String `tfsdk:"expiring_within"`
	Status         types.String `tfsdk:"status"`
	View           types.String `tfsdk:"view"`
	Items          types.List   `tfsdk:"items"`
}

func certificateSummaryTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"namespace": types.StringType, "name": types.StringType, "id": types.StringType,
		"registration_id": types.StringType, "lifecycle_state": types.StringType,
		"delivery_stage": types.StringType, "not_after": types.StringType,
		"versionless_secret_id": types.StringType,
	}
}

func (d *certificatesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Every certificate registration visible to the caller, optionally filtered. Pagination is " +
			"handled internally: the `items` list is complete.",
		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Restrict to one namespace. With no namespace, only namespaces the caller can read are listed."},
			"labels":          schema.MapAttribute{Optional: true, ElementType: types.StringType},
			"expiring_within": schema.StringAttribute{Optional: true, MarkdownDescription: "A duration such as `30d`."},
			"status":          schema.StringAttribute{Optional: true},
			"view": schema.StringAttribute{Optional: true,
				MarkdownDescription: "`summary` (default) or `full`. Data sources are read on every plan; keep them cheap."},
			"items": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"namespace": schema.StringAttribute{Computed: true}, "name": schema.StringAttribute{Computed: true},
					"id": schema.StringAttribute{Computed: true}, "registration_id": schema.StringAttribute{Computed: true},
					"lifecycle_state": schema.StringAttribute{Computed: true}, "delivery_stage": schema.StringAttribute{Computed: true},
					"not_after": schema.StringAttribute{Computed: true}, "versionless_secret_id": schema.StringAttribute{Computed: true},
				}}},
		},
	}
}

func (d *certificatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg certificatesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.data == nil || d.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client.")
		return
	}

	namespaces := []string{}
	if !cfg.Namespace.IsNull() && cfg.Namespace.ValueString() != "" {
		namespaces = append(namespaces, cfg.Namespace.ValueString())
	} else if d.data.Capabilities != nil {
		namespaces = append(namespaces, d.data.Capabilities.Caller.Namespaces...)
	}

	view := cfg.View.ValueString()
	if view == "" {
		view = "summary"
	}

	var items []attr.Value
	for _, ns := range namespaces {
		pageToken := ""
		for {
			q := url.Values{"view": []string{view}}
			if pageToken != "" {
				q.Set("page_token", pageToken)
			}
			if !cfg.ExpiringWithin.IsNull() && cfg.ExpiringWithin.ValueString() != "" {
				q.Set("expiring_within", cfg.ExpiringWithin.ValueString())
			}
			if !cfg.Status.IsNull() && cfg.Status.ValueString() != "" {
				q.Set("status", cfg.Status.ValueString())
			}
			if !cfg.Labels.IsNull() {
				labels := map[string]string{}
				resp.Diagnostics.Append(cfg.Labels.ElementsAs(ctx, &labels, false)...)
				for k, v := range labels {
					q.Add("labels", k+"="+v)
				}
			}
			page, err := d.data.Client.ListRegistrations(ctx, ns, q)
			if err != nil {
				if apiErr, ok := client.AsAPIError(err); ok {
					resp.Diagnostics.AddError(fmt.Sprintf("Could not list certificates in %q (HTTP %d)", ns, apiErr.Status),
						fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()))
					return
				}
				resp.Diagnostics.AddError(fmt.Sprintf("Could not list certificates in %q", ns), err.Error())
				return
			}
			for _, item := range page.Items {
				obj, diags := types.ObjectValue(certificateSummaryTypes(), map[string]attr.Value{
					"namespace":             types.StringValue(item.Namespace),
					"name":                  types.StringValue(item.Name),
					"id":                    types.StringValue(item.Namespace + "/" + item.Name),
					"registration_id":       types.StringValue(item.RegistrationID),
					"lifecycle_state":       rawString(item.Status, "lifecycle_state"),
					"delivery_stage":        rawString(item.Status, "delivery_stage"),
					"not_after":             rawNestedString(item.Status, "current_certificate", "not_after"),
					"versionless_secret_id": rawNestedString(item.Status, "current_certificate", "versionless_secret_id"),
				})
				resp.Diagnostics.Append(diags...)
				items = append(items, obj)
			}
			if page.NextPageToken == nil || *page.NextPageToken == "" {
				break
			}
			pageToken = *page.NextPageToken
		}
	}
	list, diags := types.ListValue(types.ObjectType{AttrTypes: certificateSummaryTypes()}, items)
	resp.Diagnostics.Append(diags...)
	cfg.Items = list
	cfg.View = types.StringValue(view)
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

func rawString(m map[string]json.RawMessage, key string) types.String {
	raw, ok := m[key]
	if !ok {
		return types.StringNull()
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func rawNestedString(m map[string]json.RawMessage, outer, inner string) types.String {
	raw, ok := m[outer]
	if !ok {
		return types.StringNull()
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return types.StringNull()
	}
	return rawString(nested, inner)
}

var _ = strconv.Itoa
