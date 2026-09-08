package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// readDataSource drives one data source end to end against the fake.
func readDataSource(t *testing.T, srv *fakeservice.Server, ds datasource.DataSource, config func(context.Context, dsschema.Schema) tfsdk.Config) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	c := newFakeClient(t, srv)
	caps, _, err := c.GetCapabilities(ctx)
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	data := &providerData{Client: c, Capabilities: caps, Environment: "public"}

	if cfgAware, ok := ds.(datasource.DataSourceWithConfigure); ok {
		var resp datasource.ConfigureResponse
		cfgAware.Configure(ctx, datasource.ConfigureRequest{ProviderData: data}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("Configure: %v", resp.Diagnostics)
		}
	}
	var sresp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("Schema: %v", sresp.Diagnostics)
	}
	cfg := config(ctx, sresp.Schema)
	state := tfsdk.State{Schema: sresp.Schema, Raw: tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), nil)}
	resp := &datasource.ReadResponse{State: state}
	srv.ResetRequests()
	ds.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}
	// A DATA SOURCE MUST NEVER CAUSE ISSUANCE, RENEWAL OR AN ACME ORDER.
	for _, req := range srv.Requests() {
		if req.Method != http.MethodGet {
			t.Fatalf("the data source issued a %s %s; data sources are GET only", req.Method, req.Path)
		}
	}
	return resp.State
}

// configWith builds a data-source config in which every attribute is a TYPED
// null except the ones named. Building it from the schema's Terraform type
// avoids having to hand-null thirty fields of a model, which is where these
// helpers otherwise go wrong.
func configWith(ctx context.Context, s dsschema.Schema, attrs map[string]tftypes.Value) tfsdk.Config {
	objType, ok := s.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		panic("a data-source schema type is always an object")
	}
	values := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for name, typ := range objType.AttributeTypes {
		if v, given := attrs[name]; given {
			values[name] = v
			continue
		}
		values[name] = tftypes.NewValue(typ, nil)
	}
	return tfsdk.Config{Schema: s, Raw: tftypes.NewValue(objType, values)}
}

func emptyConfig(ctx context.Context, s dsschema.Schema) tfsdk.Config {
	return configWith(ctx, s, nil)
}

// TestServiceDataSourcePublishesThePublisherIdentity.
//
// It exists to kill an insecure pattern: the only worked example in the source
// reviews obtained the publishing identity through `terraform_remote_state`
// against the platform state, which grants every certificate-consuming workspace
// read access to storage account keys and the full resource graph.
func TestServiceDataSourcePublishesThePublisherIdentity(t *testing.T) {
	srv := fakeservice.New(t)
	state := readDataSource(t, srv, NewServiceDataSource(), func(ctx context.Context, s dsschema.Schema) tfsdk.Config {
		return emptyConfig(ctx, s)
	})
	var m serviceDataSourceModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	if m.PublisherPrincipalID.IsNull() || m.PublisherPrincipalID.ValueString() == "" {
		t.Fatal("publisher_principal_id is empty; without it the secure path is not the copy-pastable one")
	}
	if m.InstanceID.ValueString() != fakeservice.DefaultInstanceID {
		t.Errorf("instance_id = %q", m.InstanceID.ValueString())
	}
	if m.MaxDNSNames.IsNull() {
		t.Error("the limits are not exposed, so plan-time validators would have nothing to read")
	}
}

// TestCertificateDataSourceCarriesTheVolatileStatusAndNoPEMByDefault.
func TestCertificateDataSourceCarriesTheVolatileStatusAndNoPEMByDefault(t *testing.T) {
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{
		Namespace: testNamespace, Name: testName, DeliveryStage: "consumer_observed",
	})
	state := readDataSource(t, srv, NewCertificateDataSource(), func(ctx context.Context, s dsschema.Schema) tfsdk.Config {
		return configWith(ctx, s, map[string]tftypes.Value{
			"namespace": tftypes.NewValue(tftypes.String, testNamespace),
			"name":      tftypes.NewValue(tftypes.String, testName),
		})
	})

	var m certificateDataSourceModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	if m.DeliveryStage.ValueString() != "consumer_observed" {
		t.Errorf("delivery_stage = %q; the volatile status belongs on the data source", m.DeliveryStage.ValueString())
	}
	if m.Ownership.IsNull() {
		t.Error("ownership is absent; import's ownership check documents it and users need to see it")
	}
	if m.Audit.IsNull() {
		t.Error("audit is absent")
	}
	if !m.CertificatePEM.IsNull() || !m.ChainPEM.IsNull() {
		t.Error("include_pem defaults to false, so certificate_pem and chain_pem must be null")
	}
	if m.IssuedDNSNames.IsNull() {
		t.Error("the dns_names AS ISSUED are absent; they are the whole reason this field is on the data source")
	}
}

// TestCertificatesDataSourcePaginatesInternally.
func TestCertificatesDataSourcePaginatesInternally(t *testing.T) {
	srv := fakeservice.New(t, func(o *fakeservice.Options) { o.PageSize = 50 })
	for i := 0; i < 260; i++ {
		srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: fmt.Sprintf("cert-%04d", i)})
	}
	state := readDataSource(t, srv, NewCertificatesDataSource(), func(ctx context.Context, s dsschema.Schema) tfsdk.Config {
		return configWith(ctx, s, map[string]tftypes.Value{
			"namespace": tftypes.NewValue(tftypes.String, testNamespace),
		})
	})
	var m certificatesDataSourceModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	if got := len(m.Items.Elements()); got != 260 {
		t.Fatalf("items = %d, want 260 — pagination must be internal so `items` is complete", got)
	}
	if got := srv.RequestCount(http.MethodGet, "/certificates"); got < 2 {
		t.Fatalf("the listing made %d request(s); a 260-item collection must page", got)
	}
	if m.View.ValueString() != "summary" {
		t.Errorf("view = %q, want the cheap default %q: data sources are read on every plan",
			m.View.ValueString(), "summary")
	}
}

// TestValidationBindingsDataSourceReturnsEveryVisibleBinding.
func TestValidationBindingsDataSourceReturnsEveryVisibleBinding(t *testing.T) {
	srv := fakeservice.New(t)
	state := readDataSource(t, srv, NewValidationBindingsDataSource(), func(ctx context.Context, s dsschema.Schema) tfsdk.Config {
		return emptyConfig(ctx, s)
	})
	var m validationBindingsModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	if got := len(m.Items.Elements()); got != 2 {
		t.Fatalf("items = %d, want the 2 bindings the fake advertises", got)
	}
	for _, elem := range m.Items.Elements() {
		obj, ok := elem.(types.Object)
		if !ok {
			t.Fatalf("element is %T, want an object", elem)
		}
		for _, field := range []string{"mode", "wildcards_allowed", "healthy"} {
			if _, present := obj.Attributes()[field]; !present {
				t.Errorf("a binding is missing %q", field)
			}
		}
	}
}

// TestNamespaceDataSourceExposesPolicyForPreconditions.
func TestNamespaceDataSourceExposesPolicyForPreconditions(t *testing.T) {
	srv := fakeservice.New(t)
	state := readDataSource(t, srv, NewNamespaceDataSource(), func(ctx context.Context, s dsschema.Schema) tfsdk.Config {
		return configWith(ctx, s, map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, testNamespace),
		})
	})
	var m namespaceDataSourceModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	if len(m.PermittedDomains.Elements()) == 0 {
		t.Error("permitted_domains is empty; without it an unapproved domain fails at apply, not at plan")
	}
	if len(m.PermittedDestinations.Elements()) == 0 {
		t.Error("permitted_destinations is empty")
	}
	if m.WildcardPolicyJSON.IsNull() {
		t.Error("wildcard_policy_json is null; wildcard is its own authorisation axis and must be visible")
	}
}
