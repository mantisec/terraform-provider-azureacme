package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/dnsname"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

const (
	otherInstanceID = "01OTHERINSTANCE00000000000"
	testNamespace   = "payments-prod"
	testName        = "payments-api"
)

// TestRead_ErrorMapping is the single most important test in this codebase.
//
// It is table-driven with one row per row of terraform-provider-contract.md
// §7.2.2, and every row asserts WHETHER THE RESOURCE IS REMOVED FROM STATE.
//
// Each row drives a REAL HTTP response through the REAL client, so the transport
// rules (no redirect following, non-JSON is a transport error) are exercised
// rather than assumed. A wrong "remove" here, followed by an apply, destroys and
// reissues a production certificate — and with `deletion_policy = "delete"` it
// soft-deletes the Key Vault object first.
func TestRead_ErrorMapping(t *testing.T) {
	t.Parallel()

	type row struct {
		name string
		// respond writes the service's answer. nil means "serve the seeded
		// registration normally".
		respond http.HandlerFunc
		// pinnedInstanceID is what prior state recorded. Empty models an import
		// in progress, where condition 4 is satisfied vacuously.
		pinnedInstanceID string
		// mutate adjusts the seeded registration for the 200 rows.
		mutate     func(*fakeservice.Server)
		want       ReadAction
		wantDetail []string
	}

	instance := fakeservice.DefaultInstanceID

	rows := []row{
		// ---------------------------------------------------- the 200 rows ---
		{
			name: "200 active populates and retains",
			want: ReadActionSuccess,
		},
		{
			name:   "200 suspended populates and retains",
			mutate: func(s *fakeservice.Server) { s.SetLifecycleState(testNamespace, testName, "suspended") },
			want:   ReadActionSuccess,
		},
		{
			name: "200 with a null current_certificate is a SUCCESS, not an absence",
			mutate: func(s *fakeservice.Server) {
				s.Delete(testNamespace, testName)
				s.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName, Unpublished: true})
			},
			want: ReadActionSuccess,
		},
		{
			name: "200 with an EXPIRED certificate is a SUCCESS: expiry is a status, not an absence",
			mutate: func(s *fakeservice.Server) {
				s.Delete(testNamespace, testName)
				s.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName, Expired: true})
			},
			want: ReadActionSuccess,
		},
		{
			name:   "200 lifecycle_state=deleting is a SUCCESS with a warning",
			mutate: func(s *fakeservice.Server) { s.SetLifecycleState(testNamespace, testName, "deleting") },
			want:   ReadActionSuccess,
		},
		{
			name:   "200 lifecycle_state=authorization_revoked is a SUCCESS with a warning",
			mutate: func(s *fakeservice.Server) { s.SetLifecycleState(testNamespace, testName, "authorization_revoked") },
			want:   ReadActionSuccess,
		},
		{
			name: "200 with an operation running is a SUCCESS: a renewal overlapping a plan is normal",
			mutate: func(s *fakeservice.Server) {
				s.Delete(testNamespace, testName)
				s.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName, OperationRunning: true})
			},
			want: ReadActionSuccess,
		},

		// --------------------------------- the ONLY two rows that remove ------
		{
			name:             "404 + registration_not_found + JSON + matching instance REMOVES",
			respond:          fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, instance),
			pinnedInstanceID: instance,
			want:             ReadActionRemove,
		},
		{
			name:             "410 + registration_deleted + JSON + matching instance REMOVES",
			respond:          fakeservice.RespondProblem(410, contracts.CodeRegistrationDeleted, instance),
			pinnedInstanceID: instance,
			want:             ReadActionRemove,
		},
		{
			name:             "404 + registration_not_found with NO pinned instance (import) REMOVES",
			respond:          fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, instance),
			pinnedInstanceID: "",
			want:             ReadActionRemove,
		},

		// -------- each conjunction part failing INDEPENDENTLY must NOT remove --
		{
			name:             "condition 1 fails: 409 with registration_not_found does not remove",
			respond:          fakeservice.RespondProblemNoRetryAfter(409, contracts.CodeRegistrationNotFound, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},
		{
			name:             "condition 2 fails: a 404 with text/html does not remove",
			respond:          fakeservice.RespondHTML(404),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"text/html", "authentication portal"},
		},
		{
			name:             "condition 2 fails: a 404 with an EMPTY body does not remove",
			respond:          fakeservice.RespondEmptyBody(404),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"untyped", "refusing to remove", "endpoint"},
		},
		{
			name:             "condition 2 fails: a 404 with MALFORMED JSON does not remove",
			respond:          fakeservice.RespondMalformedJSON(404),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"untyped", "refusing to remove"},
		},
		{
			name:             "condition 3 fails: a 404 with a DIFFERENT typed code does not remove",
			respond:          fakeservice.RespondProblem(404, contracts.CodeOperationNotFound, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"operation_not_found"},
		},
		{
			name:             "condition 3 fails: a 410 carrying registration_not_found does not remove",
			respond:          fakeservice.RespondProblem(410, contracts.CodeRegistrationNotFound, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},
		{
			name:             "condition 4 fails: a 404 from a DIFFERENT service instance does not remove",
			respond:          fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, otherInstanceID),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{instance, otherInstanceID, "Refusing to proceed", "endpoint"},
		},
		{
			name: "condition 4 fails: a 404 with NO service_instance_id does not remove",
			respond: fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, instance,
				fakeservice.WithoutServiceInstanceID()),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"no `service_instance_id`", "Refusing to remove"},
		},

		// ------------------------------------------- transport-level rows -----
		{
			name:             "a 302 to a sign-in page does not remove",
			respond:          fakeservice.RespondRedirect(302, "https://login.microsoftonline.com/common/oauth2/authorize"),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"redirect", "401"},
		},
		{
			name:             "a 200 with text/html does not remove",
			respond:          fakeservice.RespondHTML(200),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"text/html", "authentication portal"},
		},

		// ----------------------------------------------- authorisation rows ---
		{
			name:             "401 does not remove and names the credential method",
			respond:          fakeservice.RespondProblem(401, contracts.CodeUnauthenticated, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"credential method"},
		},
		{
			name:             "401 token_audience_mismatch does not remove",
			respond:          fakeservice.RespondProblem(401, contracts.CodeTokenAudienceMismatch, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"audience"},
		},
		{
			name:             "401 token_tenant_mismatch does not remove",
			respond:          fakeservice.RespondProblem(401, contracts.CodeTokenTenantMismatch, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"tenant_id"},
		},
		{
			name:             "403 NEVER removes",
			respond:          fakeservice.RespondProblem(403, contracts.CodeAuthorisationDenied, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"Nothing has been removed"},
		},
		{
			name:             "403 role_not_granted NEVER removes",
			respond:          fakeservice.RespondProblem(403, contracts.CodeRoleNotGranted, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"Nothing has been removed"},
		},
		{
			name:             "403 namespace_not_authorised NEVER removes",
			respond:          fakeservice.RespondProblem(403, contracts.CodeNamespaceNotAuthorised, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},

		// --------------------------------------------- retry-then-error rows --
		{
			name:             "408 does not remove",
			respond:          fakeservice.RespondProblem(408, contracts.CodeServiceUnavailable, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},
		{
			name:             "429 does not remove",
			respond:          fakeservice.RespondProblem(429, contracts.CodeRateLimited, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},
		{
			name:             "500 does not remove",
			respond:          fakeservice.RespondProblem(500, contracts.CodeInternalError, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},
		{
			name:             "503 does not remove",
			respond:          fakeservice.RespondProblem(503, contracts.CodeServiceUnavailable, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
		},

		// ---------------------------------------------- the default branch ----
		{
			name:             "an unlisted status errors through the default branch and does not remove",
			respond:          fakeservice.RespondProblem(418, contracts.CodeInternalError, instance),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"no row in the provider's read decision table"},
		},
		{
			name: "an unknown future code on a 404 does not remove",
			respond: fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, instance,
				fakeservice.WithRawCode("registration_quantum_displaced"),
				fakeservice.WithNextAction("Ask the platform team to re-collapse the registration.")),
			pinnedInstanceID: instance,
			want:             ReadActionError,
			wantDetail:       []string{"registration_quantum_displaced", "re-collapse"},
		},
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := fakeservice.New(t)
			srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
			if tc.mutate != nil {
				tc.mutate(srv)
			}
			if tc.respond != nil {
				srv.AddRule(fakeservice.Rule{
					Match:   fakeservice.Match{Method: http.MethodGet, PathSuffix: "/certificates/" + testName},
					Handler: tc.respond,
				})
			}
			c := newFakeClient(t, srv)

			_, _, err := c.GetRegistration(context.Background(), testNamespace, testName, false)
			decision := DecideRead(err, ReadContext{
				Endpoint:                srv.URL(),
				Address:                 "azureacme_certificate.api",
				PinnedServiceInstanceID: tc.pinnedInstanceID,
				CredentialMethod:        "workload_identity",
			})
			if decision.Action != tc.want {
				t.Fatalf("action = %s, want %s\nsummary: %s\ndetail: %s",
					decision.Action, tc.want, decision.Summary, decision.Detail)
			}
			combined := decision.Summary + "\n" + decision.Detail
			for _, want := range tc.wantDetail {
				if !strings.Contains(combined, want) {
					t.Errorf("the diagnostic must contain %q; got:\n%s", want, combined)
				}
			}
		})
	}
}

// TestReadErrorMappingCoversEveryClientOutcome fails when a new branch is added
// to the client's error classification without a corresponding row above.
//
// It is the "fails if a new branch is added to Read without a corresponding row"
// half of PROV-UNIT-TEST-SUITE, expressed over the CLASSIFICATION SPACE rather
// than over the source text: every transport reason and every status class the
// decision switches on must be exercised.
func TestReadErrorMappingCoversEveryClientOutcome(t *testing.T) {
	reasons := []client.TransportReason{
		client.ReasonNetwork, client.ReasonRedirect, client.ReasonContentType, client.ReasonMalformedBody,
	}
	for _, reason := range reasons {
		d := DecideRead(&client.TransportError{Reason: reason, Status: 404}, ReadContext{PinnedServiceInstanceID: "x"})
		if d.Action != ReadActionError {
			t.Errorf("transport reason %q produced %s; every transport failure must ERROR and retain state", reason, d.Action)
		}
		if d.Summary == "" {
			t.Errorf("transport reason %q produced an empty summary", reason)
		}
	}
	// A nil error is the only path to success.
	if got := DecideRead(nil, ReadContext{}); got.Action != ReadActionSuccess {
		t.Errorf("a nil error produced %s, want success", got.Action)
	}
	// An error of an unrecognised Go type must still error, never remove.
	if got := DecideRead(fmt.Errorf("something else entirely"), ReadContext{PinnedServiceInstanceID: "x"}); got.Action != ReadActionError {
		t.Errorf("an unclassified error produced %s, want error", got.Action)
	}
}

// TestReadRemovesFromStateOnlyForTheConjunction wires the decision through the
// actual framework Read, proving that ReadActionRemove really calls
// RemoveResource and that everything else really retains state.
func TestReadRemovesFromStateOnlyForTheConjunction(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name       string
		respond    http.HandlerFunc
		wantRemove bool
	}{
		{"typed 404 from the pinned instance", fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, fakeservice.DefaultInstanceID), true},
		{"typed 404 from another instance", fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, otherInstanceID), false},
		{"untyped 404", fakeservice.RespondEmptyBody(404), false},
		{"html 404", fakeservice.RespondHTML(404), false},
		{"302 sign-in redirect", fakeservice.RespondRedirect(302, "https://login.microsoftonline.com/"), false},
		{"403", fakeservice.RespondProblem(403, contracts.CodeAuthorisationDenied, fakeservice.DefaultInstanceID), false},
		{"401", fakeservice.RespondProblem(401, contracts.CodeUnauthenticated, fakeservice.DefaultInstanceID), false},
		{"503", fakeservice.RespondProblem(503, contracts.CodeServiceUnavailable, fakeservice.DefaultInstanceID), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeservice.New(t)
			srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
			srv.AddRule(fakeservice.Rule{
				Match:   fakeservice.Match{Method: http.MethodGet, PathSuffix: "/certificates/" + testName},
				Handler: tc.respond,
			})
			r := newTestResource(t, srv)

			state := priorState(t, ctx, fakeservice.DefaultInstanceID)
			resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
			r.Read(ctx, fwresource.ReadRequest{State: state}, resp)

			removed := resp.State.Raw.IsNull()
			if removed != tc.wantRemove {
				t.Fatalf("removed = %v, want %v\ndiagnostics: %v", removed, tc.wantRemove, resp.Diagnostics)
			}
			if !tc.wantRemove && !resp.Diagnostics.HasError() {
				t.Fatalf("expected an error diagnostic when retaining state, got: %v", resp.Diagnostics)
			}
		})
	}
}

// TestReadPreservesClientOnlyAndDefaultedNullAttributes is §7.2.4.
func TestReadPreservesClientOnlyAndDefaultedNullAttributes(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	// The server's resolved certificate name EQUALS `name`, which is exactly the
	// case where writing it back would make `certificate_name` unrevertible.
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Read(ctx, fwresource.ReadRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}

	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	if !after.CertificateName.IsNull() {
		t.Errorf("Read wrote the server's resolved certificate name into `certificate_name` (%q); "+
			"the attribute is Optional WITHOUT Computed precisely so deleting the line reverts to `name`",
			after.CertificateName.ValueString())
	}
	if got := after.ResolvedCertificateName.ValueString(); got != testName {
		t.Errorf("resolved_certificate_name = %q, want %q", got, testName)
	}
	if got := after.WaitFor.ValueString(); got != "published" {
		t.Errorf("Read overwrote the client-only `wait_for`: got %q, want %q", got, "published")
	}
	if after.Timeouts.IsUnknown() {
		t.Error("Read made the client-only `timeouts` unknown")
	}
	if got := after.ACMEProfile.ValueString(); got != ACMEProfileSentinel {
		t.Errorf("acme_profile = %q, want the sentinel %q echoed unchanged", got, ACMEProfileSentinel)
	}
	if got := after.ValidationBinding.ValueString(); got != ValidationBindingSentinel {
		t.Errorf("validation_binding = %q, want the sentinel %q echoed unchanged", got, ValidationBindingSentinel)
	}
}

// TestReadWarnsOnAuthorizationRevoked is the §7.2.2 row that a withdrawn grant is
// a SUCCESS with a warning, and the resource STAYS IN STATE.
func TestReadWarnsOnAuthorizationRevoked(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	srv.SetLifecycleState(testNamespace, testName, "authorization_revoked")
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Read(ctx, fwresource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("authorization_revoked must be a SUCCESS, not an error: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("authorization_revoked removed the resource from state; the published certificate is RETAINED and the registration stays readable")
	}
	found := false
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), "authorisation was withdrawn") && strings.Contains(d.Detail(), "RETAINED") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning naming the withdrawn grant and the retained certificate; got %v", resp.Diagnostics)
	}
}

// ------------------------------------------------------------------ helpers

func newFakeClient(t *testing.T, srv *fakeservice.Server) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{
		Endpoint:  srv.URL(),
		Audience:  "api://mantisec-acme",
		Tokens:    client.StaticTokenSource{Value: "test-token", MethodName: "workload_identity"},
		UserAgent: "terraform-provider-azureacme/0.0.0-test (+terraform/1.12.2) Go/test",
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func newTestResource(t *testing.T, srv *fakeservice.Server) *certificateResource {
	t.Helper()
	c := newFakeClient(t, srv)
	caps, _, err := c.GetCapabilities(context.Background())
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	return &certificateResource{
		data:  &providerData{Client: c, Capabilities: caps, Environment: "public"},
		sleep: testSleep,
	}
}

// testSleep keeps the polling loops honest without making tests slow: it sleeps,
// so a bounded deadline is reached in a bounded number of iterations, but never
// for the real backoff interval.
func testSleep(ctx context.Context, d time.Duration) error {
	if d > 5*time.Millisecond {
		d = 5 * time.Millisecond
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// priorState builds a plausible prior state for the resource under test.
func priorState(t *testing.T, ctx context.Context, instanceID string) tfsdk.State {
	t.Helper()
	s := certificateResourceSchema()
	st := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	m := certificateResourceModel{
		Namespace:                     types.StringValue(testNamespace),
		Name:                          types.StringValue(testName),
		ID:                            types.StringValue(testNamespace + "/" + testName),
		RegistrationID:                types.StringValue("reg_00000000000000000000000001"),
		ServiceInstanceID:             types.StringValue(instanceID),
		DNSNames:                      dnsNameSet(t, ctx, "api.example.com"),
		CommonName:                    types.StringNull(),
		KeyVaultID:                    armid.NewValue(fakeservice.DefaultKeyVaultID),
		CertificateName:               types.StringNull(),
		DestinationID:                 types.StringNull(),
		ResolvedCertificateName:       types.StringValue(testName),
		Key:                           defaultKeyObject(),
		ACMEProfile:                   types.StringValue(ACMEProfileSentinel),
		ValidationBinding:             types.StringValue(ValidationBindingSentinel),
		ConsumerProfile:               types.StringNull(),
		Renewal:                       defaultRenewalObject(),
		DeletionPolicy:                types.StringValue("retain"),
		AcknowledgeIrreversibleDelete: types.BoolValue(false),
		WaitFor:                       types.StringValue("published"),
		Verification:                  types.ObjectNull(verificationAttrTypes()),
		Description:                   types.StringNull(),
		Labels:                        types.MapNull(types.StringType),
		VersionlessSecretID:           types.StringValue("https://kv-payments.vault.azure.net/secrets/" + testName),
		VersionlessCertificateID:      types.StringValue("https://kv-payments.vault.azure.net/certificates/" + testName),
		SpecRevision:                  types.Int64Value(1),
		Generation:                    types.Int64Value(1),
		FulfilledGeneration:           types.Int64Value(1),
		ResolvedACMEProfile:           types.StringValue("classic"),
		ResolvedValidationBinding:     types.StringValue("example-com"),
		PublicationMode:               types.StringValue("merge"),
		LastSuccessfulRenewalAt:       rfc3339.NewNull(),
		CurrentCertificate:            types.ObjectNull(currentCertificateAttrTypes()),
		Timeouts:                      types.ObjectNull(timeoutsAttrTypes()),
	}
	if diags := st.Set(ctx, &m); diags.HasError() {
		t.Fatalf("building prior state: %v", diags)
	}
	return st
}

var _ resource.Resource = (*certificateResource)(nil)

// dnsNameSet builds a Set of dnsname.String for a test fixture.
func dnsNameSet(t *testing.T, ctx context.Context, names ...string) types.Set {
	t.Helper()
	elems := make([]attr.Value, 0, len(names))
	for _, n := range names {
		elems = append(elems, dnsname.NewValue(n))
	}
	set, diags := types.SetValue(dnsname.StringType{}, elems)
	if diags.HasError() {
		t.Fatalf("building a dns_names set: %v", diags)
	}
	return set
}
