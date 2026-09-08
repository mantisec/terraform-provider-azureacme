package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

func providerSchema(t *testing.T) fwprovider.SchemaResponse {
	t.Helper()
	var resp fwprovider.SchemaResponse
	New("test")().Schema(context.Background(), fwprovider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema: %v", resp.Diagnostics)
	}
	return resp
}

func connectionProfileObject(t *testing.T, endpoint, audience, tenant, instance string) types.Object {
	t.Helper()
	attrTypes := map[string]attr.Type{
		"endpoint": types.StringType, "audience": types.StringType,
		"tenant_id": types.StringType, "expected_service_instance_id": types.StringType,
	}
	str := func(v string) attr.Value {
		if v == "" {
			return types.StringNull()
		}
		return types.StringValue(v)
	}
	obj, diags := types.ObjectValue(attrTypes, map[string]attr.Value{
		"endpoint": str(endpoint), "audience": str(audience),
		"tenant_id": str(tenant), "expected_service_instance_id": str(instance),
	})
	if diags.HasError() {
		t.Fatalf("building connection_profile: %v", diags)
	}
	return obj
}

func nullProviderModel(t *testing.T) Model {
	t.Helper()
	attrTypes := map[string]attr.Type{
		"endpoint": types.StringType, "audience": types.StringType,
		"tenant_id": types.StringType, "expected_service_instance_id": types.StringType,
	}
	return Model{
		ConnectionProfile:         types.ObjectNull(attrTypes),
		Endpoint:                  types.StringNull(),
		Audience:                  types.StringNull(),
		TenantID:                  types.StringNull(),
		ExpectedServiceInstanceID: types.StringNull(),
		ClientID:                  types.StringNull(),
		UseOIDC:                   types.BoolNull(),
		OIDCToken:                 types.StringNull(),
		OIDCTokenFilePath:         types.StringNull(),
		OIDCRequestURL:            types.StringNull(),
		OIDCRequestToken:          types.StringNull(),
		UseMSI:                    types.BoolNull(),
		ClientCertificatePath:     types.StringNull(),
		ClientCertificatePassword: types.StringNull(),
		UseCLI:                    types.BoolNull(),
		Environment:               types.StringNull(),
		RequestTimeout:            types.StringNull(),
		MaxRetries:                types.Int64Null(),
		SkipVersionCheck:          types.BoolNull(),
		SkipInstanceCheck:         types.BoolNull(),
	}
}

func configureWith(t *testing.T, m Model, tokens client.TokenSource) *fwprovider.ConfigureResponse {
	t.Helper()
	ctx := context.Background()
	s := providerSchema(t).Schema
	cfg := providerConfigFrom(t, ctx, s, m)
	p := NewWithTokenSource("1.2.3", tokens)()
	resp := &fwprovider.ConfigureResponse{}
	p.Configure(ctx, fwprovider.ConfigureRequest{TerraformVersion: "1.12.2", Config: cfg}, resp)
	return resp
}

// TestConfigure_ConnectionProfileIsMutuallyExclusive.
func TestConfigure_ConnectionProfileIsMutuallyExclusive(t *testing.T) {
	srv := fakeservice.New(t)

	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "api://mantisec-acme", "tenant", "")
	m.Endpoint = types.StringValue(srv.URL())
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if !resp.Diagnostics.HasError() {
		t.Fatal("setting both connection_profile and endpoint must be an error")
	}
	combined := ""
	for _, d := range resp.Diagnostics.Errors() {
		combined += d.Summary() + " " + d.Detail()
	}
	if !strings.Contains(combined, "connection_profile") || !strings.Contains(combined, "endpoint") {
		t.Errorf("the error must name both; got: %s", combined)
	}
}

// TestConfigure_ConnectionProfilePopulatesAllFourValues.
func TestConfigure_ConnectionProfilePopulatesAllFourValues(t *testing.T) {
	srv := fakeservice.New(t)
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "api://mantisec-acme", "tenant-id", fakeservice.DefaultInstanceID)
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure: %v", resp.Diagnostics)
	}
	data, ok := resp.ResourceData.(*providerData)
	if !ok {
		t.Fatalf("ResourceData = %T, want *providerData", resp.ResourceData)
	}
	if data.Client.Endpoint() != srv.URL() {
		t.Errorf("endpoint = %q, want %q", data.Client.Endpoint(), srv.URL())
	}
	if data.ServiceInstanceID() != fakeservice.DefaultInstanceID {
		t.Errorf("the capabilities call did not run or did not cache")
	}
}

// TestConfigure_ExpectedInstanceMismatchFailsBeforeAnyResourceIsTouched.
func TestConfigure_ExpectedInstanceMismatchFailsBeforeAnyResourceIsTouched(t *testing.T) {
	srv := fakeservice.New(t)
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", otherInstanceID)
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if !resp.Diagnostics.HasError() {
		t.Fatal("a mismatched expected_service_instance_id must fail at Configure")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagServiceInstanceMismatch) {
			found = true
			if !strings.Contains(d.Detail(), otherInstanceID) || !strings.Contains(d.Detail(), fakeservice.DefaultInstanceID) {
				t.Errorf("the diagnostic must name both instance ids; got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected %s; got %v", DiagServiceInstanceMismatch, resp.Diagnostics)
	}
}

// TestConfigure_SkipFlagsAreIndependent.
//
// One flag must NEVER disable both. As originally specified, a single
// `skip_capability_check` skipped "all of the above", so the documented
// workaround for a version wedge also disabled service-instance pinning —
// re-opening the mistyped-endpoint catastrophe.
func TestConfigure_SkipFlagsAreIndependent(t *testing.T) {
	t.Run("skip_version_check leaves instance pinning ACTIVE", func(t *testing.T) {
		srv := fakeservice.New(t, func(o *fakeservice.Options) {
			o.MinimumClientVersion = "99.0.0" // would hard-error without the skip
		})
		m := nullProviderModel(t)
		m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", otherInstanceID)
		m.SkipVersionCheck = types.BoolValue(true)
		resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
		if !resp.Diagnostics.HasError() {
			t.Fatal("skip_version_check must NOT disable instance pinning")
		}
		found := false
		for _, d := range resp.Diagnostics.Errors() {
			if strings.Contains(d.Summary(), DiagServiceInstanceMismatch) {
				found = true
			}
			if strings.Contains(d.Summary(), "below the service's minimum") {
				t.Error("skip_version_check did not skip the version assertion")
			}
		}
		if !found {
			t.Fatalf("instance pinning did not fire; got %v", resp.Diagnostics)
		}
	})

	t.Run("skip_instance_check leaves version checking ACTIVE", func(t *testing.T) {
		srv := fakeservice.New(t, func(o *fakeservice.Options) {
			o.MinimumClientVersion = "99.0.0"
		})
		m := nullProviderModel(t)
		m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", otherInstanceID)
		m.SkipInstanceCheck = types.BoolValue(true)
		resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
		if !resp.Diagnostics.HasError() {
			t.Fatal("skip_instance_check must NOT disable the version assertions")
		}
		found := false
		for _, d := range resp.Diagnostics.Errors() {
			if strings.Contains(d.Summary(), "below the service's minimum") {
				found = true
			}
			if strings.Contains(d.Summary(), DiagServiceInstanceMismatch) {
				t.Error("skip_instance_check did not skip instance pinning")
			}
		}
		if !found {
			t.Fatalf("version checking did not fire; got %v", resp.Diagnostics)
		}
	})
}

// TestConfigure_EitherSkipFlagWarns.
func TestConfigure_EitherSkipFlagWarns(t *testing.T) {
	for _, which := range []string{"version", "instance"} {
		t.Run(which, func(t *testing.T) {
			srv := fakeservice.New(t)
			m := nullProviderModel(t)
			m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
			if which == "version" {
				m.SkipVersionCheck = types.BoolValue(true)
			} else {
				m.SkipInstanceCheck = types.BoolValue(true)
			}
			resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
			if resp.Diagnostics.HasError() {
				t.Fatalf("Configure: %v", resp.Diagnostics)
			}
			found := false
			for _, d := range resp.Diagnostics.Warnings() {
				if strings.Contains(d.Summary(), DiagCapabilityCheckSkipped) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected the %s warning; got %v", DiagCapabilityCheckSkipped, resp.Diagnostics)
			}
		})
	}
}

// TestConfigure_UnknownEndpointNamesTheBootstrapConstraintAndTarget is §2.5 step 1.
func TestConfigure_UnknownEndpointNamesTheBootstrapConstraintAndTarget(t *testing.T) {
	ctx := context.Background()
	s := providerSchema(t).Schema
	m := nullProviderModel(t)
	m.Endpoint = types.StringUnknown()
	cfg := providerConfigFrom(t, ctx, s, m)
	p := New("1.2.3")()
	resp := &fwprovider.ConfigureResponse{}
	p.Configure(ctx, fwprovider.ConfigureRequest{TerraformVersion: "1.12.2", Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("an unknown endpoint must be a plan-time error")
	}
	var detail, summary string
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagEndpointUnknownAtPlan) {
			summary, detail = d.Summary(), d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected %s; got %v", DiagEndpointUnknownAtPlan, resp.Diagnostics)
	}
	_ = summary
	for _, want := range []string{"MANTISEC_ACME_ENDPOINT", "-target", "Two root modules", "custom domain", "ConfigureProvider"} {
		if !strings.Contains(strings.ToLower(detail), strings.ToLower(want)) {
			t.Errorf("the diagnostic must contain %q; got:\n%s", want, detail)
		}
	}
}

// TestConfigure_ClientSecretIsNotAnAttributeButWarnsFromTheEnvironment is §2.3.
func TestConfigure_ClientSecretIsNotAnAttributeButWarnsFromTheEnvironment(t *testing.T) {
	// There is no `client_secret` attribute at all, so HCL carrying one fails
	// Terraform's own schema validation. Assert the absence directly.
	s := providerSchema(t).Schema
	if _, ok := s.Attributes["client_secret"]; ok {
		t.Fatal("the provider declares a `client_secret` attribute; §2.3 forbids it because provider configuration is " +
			"captured in saved plan files, which CI systems routinely archive")
	}

	srv := fakeservice.New(t)
	t.Setenv("ARM_CLIENT_SECRET", "a-secret-that-should-never-be-logged")
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if resp.Diagnostics.HasError() {
		t.Fatalf("ARM_CLIENT_SECRET must be accepted for compatibility: %v", resp.Diagnostics)
	}
	found := false
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagClientSecretFromEnvironment) {
			found = true
			if strings.Contains(d.Detail(), "a-secret-that-should-never-be-logged") {
				t.Fatal("the warning echoed the secret value")
			}
		}
	}
	if !found {
		t.Fatalf("expected the %s warning; got %v", DiagClientSecretFromEnvironment, resp.Diagnostics)
	}
}

// TestConfigure_MoreThanOneExplicitCredentialMethodIsAnError is §2.4 rule 1.
func TestConfigure_MoreThanOneExplicitCredentialMethodIsAnError(t *testing.T) {
	srv := fakeservice.New(t)
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
	m.UseOIDC = types.BoolValue(true)
	m.UseMSI = types.BoolValue(true)
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if !resp.Diagnostics.HasError() {
		t.Fatal("configuring two explicit credential methods must be an error: determinism beats convenience")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "More than one credential method") {
			found = true
			if !strings.Contains(d.Detail(), "DefaultAzureCredential") {
				t.Errorf("the diagnostic should say why DefaultAzureCredential is not used; got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected the multi-credential error; got %v", resp.Diagnostics)
	}
}

// TestConfigure_EnvironmentPrecedence covers the §2.4 chains.
func TestConfigure_EnvironmentPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		mutate func(*Model)
		check  func(*testing.T, resolvedConfig)
	}{
		{
			name: "MANTISEC_ACME_TENANT_ID beats ARM_TENANT_ID and AZURE_TENANT_ID",
			env: map[string]string{
				"MANTISEC_ACME_TENANT_ID": "mantisec", "ARM_TENANT_ID": "arm", "AZURE_TENANT_ID": "azure",
			},
			check: func(t *testing.T, c resolvedConfig) {
				if c.TenantID != "mantisec" {
					t.Errorf("tenant_id = %q, want %q", c.TenantID, "mantisec")
				}
			},
		},
		{
			name: "ARM_TENANT_ID beats AZURE_TENANT_ID",
			env:  map[string]string{"ARM_TENANT_ID": "arm", "AZURE_TENANT_ID": "azure"},
			check: func(t *testing.T, c resolvedConfig) {
				if c.TenantID != "arm" {
					t.Errorf("tenant_id = %q, want %q", c.TenantID, "arm")
				}
			},
		},
		{
			name:   "HCL beats every environment variable",
			env:    map[string]string{"MANTISEC_ACME_TENANT_ID": "mantisec"},
			mutate: func(m *Model) { m.TenantID = types.StringValue("from-hcl") },
			check: func(t *testing.T, c resolvedConfig) {
				if c.TenantID != "from-hcl" {
					t.Errorf("tenant_id = %q, want %q", c.TenantID, "from-hcl")
				}
			},
		},
		{
			name: "MANTISEC_ACME_ENDPOINT supplies the endpoint",
			env:  map[string]string{"MANTISEC_ACME_ENDPOINT": "https://certs.example.com"},
			check: func(t *testing.T, c resolvedConfig) {
				if c.Endpoint != "https://certs.example.com" {
					t.Errorf("endpoint = %q", c.Endpoint)
				}
			},
		},
		{
			name: "MANTISEC_ACME_SERVICE_INSTANCE_ID supplies the pin",
			env: map[string]string{
				"MANTISEC_ACME_ENDPOINT": "https://certs.example.com", "MANTISEC_ACME_SERVICE_INSTANCE_ID": "01ABC",
			},
			check: func(t *testing.T, c resolvedConfig) {
				if c.ExpectedServiceInstanceID != "01ABC" {
					t.Errorf("expected_service_instance_id = %q", c.ExpectedServiceInstanceID)
				}
			},
		},
		{
			name: "ARM_ENVIRONMENT drives the Key Vault DNS suffix",
			env: map[string]string{
				"MANTISEC_ACME_ENDPOINT": "https://certs.example.com", "ARM_ENVIRONMENT": "usgovernment",
			},
			check: func(t *testing.T, c resolvedConfig) {
				if c.Environment != "usgovernment" {
					t.Errorf("environment = %q", c.Environment)
				}
				if got := KeyVaultDNSSuffix(c.Environment); got != "vault.usgovcloudapi.net" {
					t.Errorf("Key Vault DNS suffix = %q", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{
				"MANTISEC_ACME_TENANT_ID", "ARM_TENANT_ID", "AZURE_TENANT_ID", "MANTISEC_ACME_ENDPOINT",
				"MANTISEC_ACME_SERVICE_INSTANCE_ID", "ARM_ENVIRONMENT", "AZURE_ENVIRONMENT", "MANTISEC_ACME_ENVIRONMENT",
			} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			m := nullProviderModel(t)
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			var diags diagsHolder
			resolved := resolveConfig(context.Background(), m, &diags.d)
			tc.check(t, resolved)
		})
	}
}

// TestTraceLoggingNeverPrintsABearerToken is the §2.5 masking obligation,
// tested by capturing an actual TF_LOG=TRACE sink.
func TestTraceLoggingNeverPrintsABearerToken(t *testing.T) {
	const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.THIS-MUST-NEVER-APPEAR.signature"

	logPath := filepath.Join(t.TempDir(), "trace.log")
	t.Setenv("TF_LOG", "TRACE")
	t.Setenv("TF_LOG_PATH", logPath)

	ctx := tfsdklog.ContextWithTestLogging(context.Background(), t.Name())
	ctx = tfsdklog.NewRootProviderLogger(ctx)

	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})

	s := providerSchema(t).Schema
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "api://mantisec-acme", "tenant", "")
	cfg := providerConfigFrom(t, ctx, s, m)
	p := NewWithTokenSource("1.2.3", client.StaticTokenSource{Value: token, MethodName: "workload_identity"})()
	presp := &fwprovider.ConfigureResponse{}
	p.Configure(ctx, fwprovider.ConfigureRequest{TerraformVersion: "1.12.2", Config: cfg}, presp)
	if presp.Diagnostics.HasError() {
		t.Fatalf("Configure: %v", presp.Diagnostics)
	}

	// Exercise a refresh so the resource-level logging runs too.
	r := &certificateResource{data: presp.ResourceData.(*providerData), sleep: testSleep}
	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	rresp := readResponseFor(state)
	r.Read(ctx, readRequestFor(state), &rresp)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Skipf("no TF_LOG sink was produced (%v); the masking configuration is still asserted by the regex test", err)
	}
	log := string(raw)
	// Prove the sink actually captured provider output, or this test passes
	// vacuously and asserts nothing at all.
	if !strings.Contains(log, "negotiated service capabilities") {
		t.Fatalf("the TF_LOG sink captured no provider output, so the masking assertion below would be vacuous.\n\nlog:\n%s", log)
	}
	if strings.Contains(log, token) {
		t.Fatalf("TF_LOG=TRACE printed the bearer token. Marking a field sensitive hides display; it does not keep the "+
			"value out of a log.\n\nlog:\n%s", log)
	}
	if strings.Contains(strings.ToLower(log), "bearer ey") {
		t.Fatalf("TF_LOG=TRACE printed an Authorization header value:\n%s", log)
	}
}

// TestBearerTokenPatternMasks proves the regex the provider installs actually
// matches a realistic Authorization value.
func TestBearerTokenPatternMasks(t *testing.T) {
	for _, in := range []string{
		"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.abc.def",
		"bearer AbC123-_.~+/=",
		"Authorization: Bearer eyJhbGciOi",
	} {
		if !bearerTokenPattern.MatchString(in) {
			t.Errorf("bearerTokenPattern does not match %q", in)
		}
	}
}

type diagsHolder struct{ d diag.Diagnostics }

func readResponseFor(state tfsdk.State) fwresource.ReadResponse {
	return fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
}

func readRequestFor(state tfsdk.State) fwresource.ReadRequest {
	return fwresource.ReadRequest{State: state}
}

// providerConfigFrom builds a tfsdk.Config for the provider schema. tfsdk.Config
// has no Set method, so the value is built through a State and the raw value
// carried across.
func providerConfigFrom(t *testing.T, ctx context.Context, s providerschema.Schema, m Model) tfsdk.Config {
	t.Helper()
	st := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if diags := st.Set(ctx, &m); diags.HasError() {
		t.Fatalf("building provider config: %v", diags)
	}
	return tfsdk.Config{Schema: s, Raw: st.Raw}
}
