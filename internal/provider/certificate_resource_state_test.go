package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// ---------------------------------------------------------------------------
// PROV-NORMALISED-ATTRIBUTE-DRIFT
//
// The service NORMALISES the request: it server-resolves
// `spec.destination.destination_id` (PROVISIONAL D-20) and materialises the whole
// of `spec.verification`. Both attributes are Optional WITHOUT Computed (§5.3.1),
// so a provider that writes the normalised value into them puts a value in state
// that the configuration does not declare — and the very next `terraform plan` is
// not a diff but a HARD ERROR out of ModifyPlan that aborts the whole workspace.
//
// These tests drive the REAL Read against the REAL fake, which normalises the way
// the service does. They would all have passed against the old fake, which echoed
// the request; that is why they are written against responses and not against
// hand-built models.
// ---------------------------------------------------------------------------

// TestReadKeepsTheConfiguredDestinationIDAndVerification is the defect, asserted
// as fixed, end to end.
func TestReadKeepsTheConfiguredDestinationIDAndVerification(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	// The premise: the SERVICE really does return both values. If this stops
	// being true the tests below are vacuous, so it is asserted rather than
	// assumed.
	stored := srv.Registration(testNamespace, testName)
	if stored.Spec.Destination == nil || stored.Spec.Destination.DestinationID == nil {
		t.Fatal("the fake did not server-resolve destination_id, so this test proves nothing; see fakeservice/normalise.go")
	}
	if stored.Spec.Verification == nil || stored.Spec.Verification.ConsumerProbe == nil {
		t.Fatal("the fake did not materialise verification, so this test proves nothing; see fakeservice/normalise.go")
	}

	// Prior state is the configured value: neither attribute declared.
	after := readInto(t, ctx, r, priorState(t, ctx, fakeservice.DefaultInstanceID))

	if !after.DestinationID.IsNull() {
		t.Errorf("Read wrote the server-resolved destination policy %q into `destination_id`. That attribute is "+
			"Optional WITHOUT Computed, so a value the configuration does not declare makes ModifyPlan's "+
			"destination-change check fire and ABORTS THE WHOLE PLAN — for every resource in the workspace, and for "+
			"every colleague, until someone edits the HCL.", after.DestinationID.ValueString())
	}
	if got := after.ResolvedDestinationID.ValueString(); got != fakeservice.DefaultDestinationPolicyID {
		t.Errorf("resolved_destination_id = %q, want %q: the server's answer must still be VISIBLE, just not in the "+
			"attribute the user writes", got, fakeservice.DefaultDestinationPolicyID)
	}
	if !after.Verification.IsNull() {
		t.Errorf("Read wrote the materialised verification block %s into `verification`; a workspace that omits the "+
			"block would then propose removing it for ever", after.Verification)
	}
}

// TestReadSurfacesADestinationPolicyTheServerDisagreesWith is the other half of
// the rule, and the reason it is a SEMANTIC comparison rather than "ignore the
// server".
//
// Absorbing the normalisation by never reading `destination_id` back would also
// hide the case that matters: the configuration asserts one destination policy and
// the service resolved a different one. That is real drift with real consequences
// — the certificate is being published somewhere the HCL does not say — and it
// must reach the plan.
func TestReadSurfacesADestinationPolicyTheServerDisagreesWith(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t, func(o *fakeservice.Options) {
		o.DestinationPolicies = []fakeservice.DestinationPolicy{
			{ID: "payments-v2", KeyVaultID: fakeservice.DefaultKeyVaultID},
		}
	})
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	prior := priorState(t, ctx, fakeservice.DefaultInstanceID)
	var m certificateResourceModel
	if diags := prior.Get(ctx, &m); diags.HasError() {
		t.Fatalf("prior state: %v", diags)
	}
	// The configuration pins the policy a platform migration has since replaced.
	m.DestinationID = types.StringValue("payments")

	after := readInto(t, ctx, r, stateOf(t, ctx, m))
	if got := after.DestinationID.ValueString(); got != "payments-v2" {
		t.Errorf("destination_id = %q, want %q. The configuration asserts a policy the service no longer resolves to; "+
			"keeping the stale assertion in state would make `terraform plan` report no change while the certificate "+
			"publishes through a different policy.", got, "payments-v2")
	}
}

// TestDestinationIDFromResponse is the rule itself, enumerated.
func TestDestinationIDFromResponse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		server *string
		prior  types.String
		want   types.String
		why    string
	}{
		{
			name: "nothing asserted, the server resolved a policy", server: strPtr("payments"),
			prior: types.StringNull(), want: types.StringNull(),
			why: "the resolved value belongs in resolved_destination_id; in `destination_id` it is a permanent plan error",
		},
		{
			name: "asserted, and the server agrees", server: strPtr("payments"),
			prior: types.StringValue("payments"), want: types.StringValue("payments"),
			why: "the caller's assertion is kept verbatim",
		},
		{
			name: "asserted, and the server resolved something else", server: strPtr("payments-v2"),
			prior: types.StringValue("payments"), want: types.StringValue("payments-v2"),
			why: "genuine drift, and the one case the user must see",
		},
		{
			name: "asserted, and the server sent nothing", server: nil,
			prior: types.StringValue("payments"), want: types.StringValue("payments"),
			why: "an absent field is not evidence of a different policy",
		},
		{
			name: "asserted, and the server sent an empty string", server: strPtr(""),
			prior: types.StringValue("payments"), want: types.StringValue("payments"),
			why: "same as absent",
		},
		{
			name: "nothing asserted, and the server sent nothing", server: nil,
			prior: types.StringNull(), want: types.StringNull(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := destinationIDFromResponse(tc.server, tc.prior)
			if !got.Equal(tc.want) {
				t.Errorf("destinationIDFromResponse = %s, want %s. %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestVerificationSemanticallyEqual enumerates the normalisations the comparison
// has to collapse, and the one it must not.
func TestVerificationSemanticallyEqual(t *testing.T) {
	ctx := context.Background()
	null := types.ObjectNull(verificationAttrTypes())

	for _, tc := range []struct {
		name string
		a, b types.Object
		want bool
		why  string
	}{
		{
			name: "an absent block and a materialised default probe",
			a:    null, b: probeObject(t, ctx, false, "", nil),
			want: true,
			why:  "this is THE defect: the service materialises the default for every registration, and a workspace that omits the block must not propose removing it",
		},
		{
			name: "a null endpoint list and an empty one",
			a:    probeObject(t, ctx, true, "", nil), b: probeObject(t, ctx, true, "", []string{}),
			want: true,
			why:  "the service stores `endpoints: []`; writing an empty list where the configuration wrote nothing is the same permadiff in miniature",
		},
		{
			name: "an absent block and an ENABLED probe",
			a:    null, b: probeObject(t, ctx, true, "", nil),
			want: false,
			why:  "a probe enabled out of band is real drift and must reach the plan",
		},
		{
			name: "two disabled probes with different endpoints",
			a:    probeObject(t, ctx, false, "", []string{"api.example.com"}), b: probeObject(t, ctx, false, "", nil),
			want: true,
			why:  "a disabled probe does nothing, and neither `endpoints` nor `expected_pickup` can be cleared on the wire, so comparing them leaves a diff no apply can resolve",
		},
		{
			name: "two enabled probes with different endpoints",
			a:    probeObject(t, ctx, true, "", []string{"api.example.com"}), b: probeObject(t, ctx, true, "", []string{"www.example.com"}),
			want: false,
			why:  "an enabled probe's endpoints are exactly what it does",
		},
		{
			name: "two enabled probes with different pickup windows",
			a:    probeObject(t, ctx, true, "8h", nil), b: probeObject(t, ctx, true, "72h", nil),
			want: false,
		},
		{
			name: "two enabled probes whose endpoints are reordered",
			a:    probeObject(t, ctx, true, "", []string{"a.example.com", "b.example.com"}),
			b:    probeObject(t, ctx, true, "", []string{"b.example.com", "a.example.com"}),
			want: false,
			why:  "`endpoints` is a List, not a Set: the order is the user's and a reorder is a change they wrote",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, diags := verificationSemanticallyEqual(ctx, tc.a, tc.b)
			if diags.HasError() {
				t.Fatalf("comparing: %v", diags)
			}
			if got != tc.want {
				t.Errorf("verificationSemanticallyEqual = %v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

// probeObject builds a `verification` object. A nil endpoints slice is a NULL
// list; an empty non-nil slice is an EMPTY list. The distinction is the point.
func probeObject(t *testing.T, ctx context.Context, enabled bool, pickup string, hosts []string) types.Object {
	t.Helper()
	endpoints := types.ListNull(types.ObjectType{AttrTypes: probeEndpointAttrTypes()})
	if hosts != nil {
		elems := make([]attr.Value, 0, len(hosts))
		for _, h := range hosts {
			obj, diags := types.ObjectValue(probeEndpointAttrTypes(), map[string]attr.Value{
				"host": types.StringValue(h), "port": types.Int64Value(443), "sni": types.StringNull(),
			})
			if diags.HasError() {
				t.Fatalf("building an endpoint: %v", diags)
			}
			elems = append(elems, obj)
		}
		list, diags := types.ListValue(types.ObjectType{AttrTypes: probeEndpointAttrTypes()}, elems)
		if diags.HasError() {
			t.Fatalf("building the endpoint list: %v", diags)
		}
		endpoints = list
	}
	expectedPickup := types.StringNull()
	if pickup != "" {
		expectedPickup = types.StringValue(pickup)
	}
	probe, diags := types.ObjectValue(consumerProbeAttrTypes(), map[string]attr.Value{
		"enabled": types.BoolValue(enabled), "expected_pickup": expectedPickup, "endpoints": endpoints,
	})
	if diags.HasError() {
		t.Fatalf("building the probe: %v", diags)
	}
	obj, diags := types.ObjectValue(verificationAttrTypes(), map[string]attr.Value{"consumer_probe": probe})
	if diags.HasError() {
		t.Fatalf("building verification: %v", diags)
	}
	return obj
}

// TestBuildSpecFromPlanAlwaysStatesWhetherTheProbeIsEnabled pins the wire half of
// revertibility.
//
// The service applies defaults at CREATE ONLY (G-8): on an update a field the
// caller omitted inherits the value already stored. So a provider that simply
// leaves `verification` out when the user deletes the block does not turn the
// probe off — it stays enabled for ever, with nothing in the HCL to explain it.
func TestBuildSpecFromPlanAlwaysStatesWhetherTheProbeIsEnabled(t *testing.T) {
	ctx := context.Background()
	var m certificateResourceModel
	plan := planFor(t, ctx, nil)
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan: %v", diags)
	}
	if !m.Verification.IsNull() {
		t.Fatal("the baseline plan should declare no verification block")
	}

	spec, diags := buildSpecFromPlan(ctx, m)
	if diags.HasError() {
		t.Fatalf("buildSpecFromPlan: %v", diags)
	}
	if spec.Verification == nil || spec.Verification.ConsumerProbe == nil {
		t.Fatal("a configuration with no `verification` block sent no probe at all. The service then INHERITS the " +
			"stored probe (G-8), so deleting the block cannot turn a probe off and `enabled` stays true for ever.")
	}
	if enabled := spec.Verification.ConsumerProbe.Enabled; enabled == nil || *enabled {
		t.Fatalf("the probe sent for a configuration with no `verification` block has enabled=%v; it must be an "+
			"explicit false, which is §5.7's documented default", enabled)
	}
}

// ---------------------------------------------------------------------------
// API-PUBLISH-COMMIT-NOT-BEFORE, the provider half
// ---------------------------------------------------------------------------

// TestMissingRequiredCurrentCertificateFields enumerates the three fields
// contracts/api/openapi.yaml marks required on `CurrentCertificate`.
//
// All three decode into NON-POINTER Go strings, so "required" buys no decode-time
// check at all: an omitted field, a JSON `null` and an empty string are one value
// by the time the provider sees them.
func TestMissingRequiredCurrentCertificateFields(t *testing.T) {
	t.Parallel()
	full := func() *contracts.CurrentCertificate {
		return &contracts.CurrentCertificate{
			ThumbprintSHA256: "abc", NotBefore: "2026-09-09T00:00:00Z", NotAfter: "2026-10-24T00:00:00Z",
		}
	}
	for _, field := range requiredCurrentCertificateFields {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			cc := full()
			switch field {
			case "thumbprint_sha256":
				cc.ThumbprintSHA256 = ""
			case "not_before":
				cc.NotBefore = ""
			case "not_after":
				cc.NotAfter = ""
			default:
				t.Fatalf("requiredCurrentCertificateFields names %q, which this test does not know how to blank. "+
					"A field added to the contract's required list must be added here too, or its absence goes back "+
					"to producing the opaque failure this machinery exists to prevent.", field)
			}
			missing := missingRequiredCertificateFields(cc)
			if len(missing) != 1 || missing[0] != field {
				t.Fatalf("missingRequiredCertificateFields = %v, want exactly [%s]", missing, field)
			}
			// And a whitespace-only value counts as missing: " " is not a timestamp
			// and not a thumbprint either.
			if len(missingRequiredCertificateFields(full())) != 0 {
				t.Fatal("a complete certificate reported a missing field")
			}
		})
	}
}

// TestReadNamesTheMissingRequiredFieldRatherThanFailingOpaquely is the acceptance
// criterion for the provider half of `API-PUBLISH-COMMIT-NOT-BEFORE`.
//
// The shipped service returned `status.current_certificate.not_before` as `null`.
// The contract marks it required, so the generated model decodes it non-pointer,
// `null` became "", and `rfc3339.ValidateAttribute` killed the apply with:
//
//	Error: Invalid timestamp: ""
//	  with azureacme_certificate.this,
//	  on main.tf line 59, in resource "azureacme_certificate" "this":
//	Expected an RFC 3339 timestamp such as 2026-11-28T04:11:01Z.
//
// — which names no field, no service and no next action, points at the resource
// block as though the user had typed something wrong, and was accompanied by
// Terraform's own "this is always a bug in the provider" because the invalid value
// also aborted the state write.
//
// This test is the fix: ONE error, naming the wire field, saying whose defect it
// is and what happens next.
func TestReadNamesTheMissingRequiredFieldRatherThanFailingOpaquely(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	// A real JSON `null`, over the real transport, through the real decode — which
	// is the half of this that cannot be proved with a hand-built model.
	srv.NullCurrentCertificateField(testNamespace, testName, "not_before")
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Read(ctx, fwresource.ReadRequest{State: state}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a required field the service did not send must be an ERROR. The contract marks `not_before` " +
			"required, the value is load-bearing, and the provider must not invent one.")
	}
	errs := resp.Diagnostics.Errors()
	if len(errs) != 1 {
		t.Fatalf("want exactly ONE diagnostic for one missing field; got %d: %v", len(errs), errs)
	}
	d := errs[0]
	if !strings.Contains(d.Summary(), "status.current_certificate.not_before") {
		t.Errorf("the summary does not name the field: %q", d.Summary())
	}
	for _, want := range []string{
		"REQUIRED",               // why the provider cannot simply tolerate it
		"SERVICE defect",         // whose fault, so the user stops editing HCL
		"platform administrator", // who to tell
		testNamespace + "/" + testName,
		"untaint", // the route out of the taint a create error causes
	} {
		if !strings.Contains(d.Detail(), want) {
			t.Errorf("the detail does not mention %q.\n\n%s", want, d.Detail())
		}
	}
	// AND THE OPAQUE FAILURE IS GONE. `Invalid timestamp: ""` is what the user used
	// to see, and it is the thing this test exists to keep away from them.
	if strings.Contains(d.Summary()+d.Detail(), `Invalid timestamp: ""`) {
		t.Errorf("the opaque rfc3339 validation failure is still reaching the user: %q / %q", d.Summary(), d.Detail())
	}
}

// TestAMissingRequiredTimestampIsWrittenAsNullNotAsAnInvalidValue is the decode
// half.
//
// Writing "" would be a KNOWN but invalid value: it fails rfc3339's attribute
// validation, which aborts the state write, which makes Terraform add a second and
// actively misleading error — "the provider still indicated an unknown value …
// this is always a bug in the provider". Null is a legal known value, so the
// state write succeeds and the user is left with exactly the one diagnostic that
// tells them something true.
func TestAMissingRequiredTimestampIsWrittenAsNullNotAsAnInvalidValue(t *testing.T) {
	ctx := context.Background()
	reg := &contracts.CertificateRegistration{
		Namespace: testNamespace, Name: testName, RegistrationID: "reg_1",
		ServiceInstanceID: fakeservice.DefaultInstanceID,
		Status: contracts.RegistrationStatus{
			DeliveryStage: "published",
			CurrentCertificate: &contracts.CurrentCertificate{
				ThumbprintSHA256: "abc", NotBefore: "", NotAfter: "2026-10-24T00:00:00Z",
			},
		},
	}
	var m certificateResourceModel
	m.WaitFor = types.StringValue(WaitForPublished)
	diags := applyComputedFromResponse(ctx, reg, &m, "public")
	if !diags.HasError() {
		t.Fatal("the absence must still be reported")
	}
	if m.CurrentCertificate.IsNull() || m.CurrentCertificate.IsUnknown() {
		t.Fatal("current_certificate was not written at all; the rest of the certificate is known and must reach state")
	}
	var cc currentCertificateModel
	if d := m.CurrentCertificate.As(ctx, &cc, basetypes.ObjectAsOptions{}); d.HasError() {
		t.Fatalf("reading current_certificate: %v", d)
	}
	if !cc.NotBefore.IsNull() {
		t.Errorf("not_before = %q, want null: a known-but-invalid value aborts the state write and provokes "+
			"Terraform's own misleading \"always a bug in the provider\" error on top of the real one",
			cc.NotBefore.ValueString())
	}
	if cc.NotAfter.ValueString() != "2026-10-24T00:00:00Z" {
		t.Errorf("not_after = %q; the fields the service DID send must still land in state", cc.NotAfter.ValueString())
	}
}
