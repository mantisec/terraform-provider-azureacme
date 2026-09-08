package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// configureDataSource is the identical Configure body every data source needs.
func configureDataSource(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *providerData {
	if req.ProviderData == nil {
		return nil
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data",
			fmt.Sprintf("expected *providerData, got %T. This is a provider defect.", req.ProviderData))
		return nil
	}
	return data
}

func stringList(ctx context.Context, values []string, diags *diag.Diagnostics) types.List {
	if values == nil {
		values = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, values)
	diags.Append(d...)
	return list
}

// diagsAccumulator lets a shared projection helper append diagnostics without
// taking a *diag.Diagnostics through every signature.
type diagsAccumulator struct{ d *diag.Diagnostics }
