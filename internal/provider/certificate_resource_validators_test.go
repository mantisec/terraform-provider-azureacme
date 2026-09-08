package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

func validateConfig(t *testing.T, ctx context.Context, mutate func(*certificateResourceModel)) fwresource.ValidateConfigResponse {
	t.Helper()
	plan := planFor(t, ctx, mutate)
	cfg := tfsdk.Config(plan)
	resp := fwresource.ValidateConfigResponse{}
	for _, v := range (&certificateResource{}).ConfigValidators(ctx) {
		v.ValidateResource(ctx, fwresource.ValidateConfigRequest{Config: cfg}, &resp)
	}
	return resp
}

func keyObject(t *testing.T, ctx context.Context, algorithm string, size int64, curve string, exportable bool) types.Object {
	t.Helper()
	sizeVal := types.Int64Null()
	if size > 0 {
		sizeVal = types.Int64Value(size)
	}
	curveVal := types.StringNull()
	if curve != "" {
		curveVal = types.StringValue(curve)
	}
	obj, diags := types.ObjectValue(keyAttrTypes(), map[string]attr.Value{
		"algorithm": types.StringValue(algorithm), "size": sizeVal,
		"curve": curveVal, "exportable": types.BoolValue(exportable),
	})
	if diags.HasError() {
		t.Fatalf("building a key object: %v", diags)
	}
	return obj
}

// TestValidate_ExportableFalseIsRejectedBeforeAnyAPICall is §5.6 — the single
// most dangerous line in the source design.
//
// Take `false` and the apply succeeds, `versionless_secret_id` is populated,
// `delivery_stage` reads `published`, every status field is green — and then the
// Application Gateway listener will not start, hours later, in a DIFFERENT
// Terraform configuration, as an Azure error about a Key Vault secret.
func TestValidate_ExportableFalseIsRejectedBeforeAnyAPICall(t *testing.T) {
	ctx := context.Background()

	t.Run("without keyvault_crypto_only it is a plan-time ERROR", func(t *testing.T) {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "RSA", 2048, "", false)
		})
		if !resp.Diagnostics.HasError() {
			t.Fatal("key.exportable = false must be a plan-time ERROR, not a warning")
		}
		combined := ""
		for _, d := range resp.Diagnostics.Errors() {
			combined += d.Summary() + "\n" + d.Detail() + "\n"
		}
		for _, want := range []string{"PKCS#12", "NO PRIVATE KEY", "Application Gateway", ConsumerProfileCryptoOnly} {
			if !strings.Contains(combined, want) {
				t.Errorf("the diagnostic must contain %q; got:\n%s", want, combined)
			}
		}
	})

	t.Run("with keyvault_crypto_only it is permitted", func(t *testing.T) {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "RSA", 2048, "", false)
			m.ConsumerProfile = types.StringValue(ConsumerProfileCryptoOnly)
		})
		if resp.Diagnostics.HasError() {
			t.Fatalf("the documented crypto-only case must be permitted: %v", resp.Diagnostics)
		}
	})

	t.Run("the default is exportable and validates cleanly", func(t *testing.T) {
		resp := validateConfig(t, ctx, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("the default configuration must validate: %v", resp.Diagnostics)
		}
	})
}

// TestValidate_WaitForRejectsTheReservedValuesWithExplanations.
func TestValidate_WaitForRejectsTheReservedValuesWithExplanations(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		value    string
		wantText []string
	}{
		{"consumer_observed", []string{"circular dependency", "data.azureacme_certificate"}},
		{"best_effort", []string{"reserved", "timeout contract"}},
		{"nonsense", []string{"Invalid `wait_for` value"}},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
				m.WaitFor = types.StringValue(tc.value)
			})
			if !resp.Diagnostics.HasError() {
				t.Fatalf("wait_for = %q must be rejected", tc.value)
			}
			combined := ""
			for _, d := range resp.Diagnostics.Errors() {
				combined += d.Summary() + "\n" + d.Detail() + "\n"
			}
			for _, want := range tc.wantText {
				if !strings.Contains(combined, want) {
					t.Errorf("the diagnostic must contain %q; got:\n%s", want, combined)
				}
			}
		})
	}
	for _, ok := range []string{WaitForPublished, WaitForAccepted} {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) { m.WaitFor = types.StringValue(ok) })
		if resp.Diagnostics.HasError() {
			t.Errorf("wait_for = %q must be accepted: %v", ok, resp.Diagnostics)
		}
	}
}

// TestValidate_CommonNameIsReserved.
func TestValidate_CommonNameIsReserved(t *testing.T) {
	ctx := context.Background()
	resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
		m.CommonName = types.StringValue("api.example.com")
	})
	if !resp.Diagnostics.HasError() {
		t.Fatal("common_name is reserved and must be rejected at plan time in v1")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Detail(), "D-30") {
			found = true
		}
		if !strings.Contains(d.Summary(), "api.example.com") {
			t.Errorf("the summary must carry the offending value; got %q", d.Summary())
		}
	}
	if !found {
		t.Fatalf("the diagnostic must name decision D-30; got %v", resp.Diagnostics)
	}
}

// TestValidate_LabelCharacterClassRejectsAComma.
//
// Reviewer 04 published `[A-Za-z0-9 +-./:=_]`, in which `+-.` is the RANGE
// U+002B–U+002E and therefore silently admits `,`.
func TestValidate_LabelCharacterClassRejectsAComma(t *testing.T) {
	ctx := context.Background()
	labels, diags := types.MapValueFrom(ctx, types.StringType, map[string]string{"teams": "payments,billing"})
	if diags.HasError() {
		t.Fatal(diags)
	}
	resp := validateConfig(t, ctx, func(m *certificateResourceModel) { m.Labels = labels })
	if !resp.Diagnostics.HasError() {
		t.Fatal("a label value containing a comma must be rejected")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "payments,billing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the diagnostic must carry the offending value; got %v", resp.Diagnostics)
	}

	ok, diags := types.MapValueFrom(ctx, types.StringType, map[string]string{
		"team": "payments", "cost-centre": "cc/1234", "env": "prod_1.0+eu", "owner": "a:b=c",
	})
	if diags.HasError() {
		t.Fatal(diags)
	}
	if resp := validateConfig(t, ctx, func(m *certificateResourceModel) { m.Labels = ok }); resp.Diagnostics.HasError() {
		t.Fatalf("the permitted character class rejected a legitimate label: %v", resp.Diagnostics)
	}
}

// TestValidate_KeyAlgorithmExclusivity.
func TestValidate_KeyAlgorithmExclusivity(t *testing.T) {
	ctx := context.Background()
	t.Run("RSA with a curve is rejected", func(t *testing.T) {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "RSA", 2048, "P-256", true)
		})
		if !resp.Diagnostics.HasError() {
			t.Fatal("key.curve is meaningless for RSA")
		}
	})
	t.Run("EC with a size is rejected", func(t *testing.T) {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "EC", 256, "P-256", true)
		})
		if !resp.Diagnostics.HasError() {
			t.Fatal("key.size is meaningless for EC")
		}
	})
	t.Run("EC without a curve is rejected", func(t *testing.T) {
		resp := validateConfig(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "EC", 0, "", true)
		})
		if !resp.Diagnostics.HasError() {
			t.Fatal("key.curve is required for EC")
		}
	})
}

// TestValidate_ECIsStructurallyAcceptedButPolicyRejectedInV1.
//
// EC stays REPRESENTABLE so enabling it later is a SERVICE POLICY change, not a
// provider release. The second half proves exactly that: the same configuration
// passes against a capabilities fixture that advertises EC.
func TestValidate_ECIsStructurallyAcceptedButPolicyRejectedInV1(t *testing.T) {
	ctx := context.Background()

	t.Run("rejected against a v1 service", func(t *testing.T) {
		srv := fakeservice.New(t)
		r := newTestResource(t, srv)
		plan := planFor(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "EC", 0, "P-256", true)
		})
		resp := &fwresource.ModifyPlanResponse{Plan: plan}
		r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: emptyState(t, ctx), Plan: plan, Config: tfsdk.Config(plan)}, resp)
		if !resp.Diagnostics.HasError() {
			t.Fatal("EC must be rejected against a service that advertises RSA only")
		}
		combined := ""
		for _, d := range resp.Diagnostics.Errors() {
			combined += d.Summary() + "\n" + d.Detail() + "\n"
		}
		if !strings.Contains(combined, "Front Door") {
			t.Errorf("the diagnostic must name Front Door's lack of EC support; got:\n%s", combined)
		}
		if !strings.Contains(combined, "SERVICE POLICY change") {
			t.Errorf("the diagnostic must say enabling EC is a service policy change; got:\n%s", combined)
		}
	})

	t.Run("accepted against a service that advertises EC", func(t *testing.T) {
		srv := fakeservice.New(t, func(o *fakeservice.Options) {
			o.KeyPolicies = &contracts.KeyPolicies{
				Algorithms: []string{"RSA", "EC"},
				RSASizes:   []int64{2048, 3072, 4096},
				Curves:     []string{"P-256", "P-384"},
				Exportable: []bool{true},
			}
		})
		r := newTestResource(t, srv)
		plan := planFor(t, ctx, func(m *certificateResourceModel) {
			m.Key = keyObject(t, ctx, "EC", 0, "P-256", true)
		})
		resp := &fwresource.ModifyPlanResponse{Plan: plan}
		r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: emptyState(t, ctx), Plan: plan, Config: tfsdk.Config(plan)}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("the SCHEMA must accept EC structurally, so enabling it is a policy change: %v", resp.Diagnostics)
		}
	})
}

// TestValidate_CapabilityBackedChecksRunAtPlanTimeWithNoExtraAPICall.
func TestValidate_CapabilityBackedChecksRunAtPlanTimeWithNoExtraAPICall(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	r := newTestResource(t, srv)
	srv.ResetRequests()

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.ACMEProfile = types.StringValue("no-such-profile")
		m.ConsumerProfile = types.StringValue("no-such-consumer")
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: emptyState(t, ctx), Plan: plan, Config: tfsdk.Config(plan)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("an unknown acme_profile and consumer_profile must fail at plan time")
	}
	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("plan-time validation issued %d API requests; §3.1 caches /v1/capabilities so validation costs none: %v",
			got, srv.Requests())
	}
	combined := ""
	for _, d := range resp.Diagnostics.Errors() {
		combined += d.Summary() + "\n" + d.Detail() + "\n"
	}
	if !strings.Contains(combined, "never from a\nprovider constant") && !strings.Contains(combined, "never from a provider constant") {
		t.Errorf("the consumer-profile diagnostic must say the list comes from capabilities, not a provider constant; got:\n%s", combined)
	}
}

// TestWirePathToAttributePath is the §5.5 map.
func TestWirePathToAttributePath(t *testing.T) {
	cases := map[string]string{
		"spec.destination.key_vault_id":            "key_vault_id",
		"spec.destination.certificate_name":        "certificate_name",
		"spec.destination.destination_id":          "destination_id",
		"spec.key.exportable":                      "key.exportable",
		"spec.acme_profile":                        "acme_profile",
		"spec.validation_binding":                  "validation_binding",
		"spec.consumer_profile":                    "consumer_profile",
		"spec.renewal.mode":                        "renewal.mode",
		"spec.renewal.use_ari":                     "renewal.use_ari",
		"spec.deletion_policy":                     "deletion_policy",
		"spec.acknowledge_irreversible_delete":     "acknowledge_irreversible_delete",
		"spec.description":                         "description",
		"spec.labels":                              "labels",
		"spec.common_name":                         "common_name",
		"spec.verification.consumer_probe.enabled": "verification.consumer_probe.enabled",
	}
	for wire, want := range cases {
		p, ok := WirePathToAttributePath(wire)
		if !ok {
			t.Errorf("%q has no mapping", wire)
			continue
		}
		if got := p.String(); got != want {
			t.Errorf("%q -> %q, want %q", wire, got, want)
		}
	}
	if _, ok := WirePathToAttributePath("spec.some_future_field"); ok {
		t.Error("an unmapped wire path must report false, so the caller reports it verbatim rather than guessing")
	}
}

var _ = tftypes.NewValue
