package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// TestCreate_TimeoutAfterTheOperationSucceededReturnsSuccess is the heart of the
// §7.1.4 timeout contract.
//
// The service KEEPS WORKING after Terraform gives up, so between the timeout and
// the next apply the operation usually SUCCEEDS. The old design reported that as
// a failure, and the next apply then destroyed a published, live certificate and
// reissued it — soft-deleting the Key Vault object first under
// `deletion_policy = "delete"`.
func TestCreate_TimeoutAfterTheOperationSucceededReturnsSuccess(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SetBehaviour(fakeservice.Behaviour{
		PollsBeforeTerminal:                2,
		OperationNeverCompletes:            true,
		CompleteRegistrationDespiteTimeout: true,
	})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "300ms", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("the operation record still says running, but the REGISTRATION published while the client was waiting "+
			"out its backoff. That must be SUCCESS, not an error: %v", resp.Diagnostics)
	}
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	if after.CurrentCertificate.IsNull() {
		t.Fatal("state has no current_certificate; a successful create must write full state")
	}
	if after.VersionlessSecretID.IsNull() {
		t.Fatal("versionless_secret_id is null after a successful publication")
	}
	if got := after.FulfilledGeneration.ValueInt64(); got < 1 {
		t.Fatalf("fulfilled_generation = %d, want >= 1", got)
	}

	// AND THE NEXT PLAN IS EMPTY. A create that returns success but leaves state
	// disagreeing with the service would produce a change on the very next plan,
	// which is the same fleet-wide noise a renewal diff would cause.
	srv.SetBehaviour(fakeservice.Behaviour{})
	refreshed := readInto(t, ctx, r, stateOf(t, ctx, after))
	if !specEqual(ctx, after, refreshed) {
		t.Fatalf("the state written by a successful create disagrees with the service, so the next plan would not be empty.\n"+
			"after create: dns=%v desc=%v labels=%v\nafter refresh: dns=%v desc=%v labels=%v",
			after.DNSNames, after.Description, after.Labels,
			refreshed.DNSNames, refreshed.Description, refreshed.Labels)
	}
}

// TestCreate_TimeoutWithTheOperationStillRunningWritesPartialStateAndTheUntaintCommand
// is §7.1.4 case 3.
func TestCreate_TimeoutWithTheOperationStillRunningWritesPartialStateAndTheUntaintCommand(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SetBehaviour(fakeservice.Behaviour{OperationNeverCompletes: true})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "200ms", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a genuinely still-running operation past the timeout must error")
	}
	// Partial state must be present, or the registration is orphaned server-side.
	if resp.State.Raw.IsNull() {
		t.Fatal("no state was written; the registration exists on the service and would be orphaned")
	}
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatalf("reading partial state back: %v", diags)
	}
	for name, v := range map[string]types.String{
		"id": after.ID, "registration_id": after.RegistrationID, "service_instance_id": after.ServiceInstanceID,
	} {
		if v.IsNull() || v.ValueString() == "" {
			t.Errorf("partial state is missing %s", name)
		}
	}

	var detail string
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagCreateTimeoutStillRunning) {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected a %s diagnostic; got %v", DiagCreateTimeoutStillRunning, resp.Diagnostics)
	}
	// The recovery command. The Plugin Framework does not hand a resource its
	// Terraform ADDRESS in Create, so the provider renders a placeholder and says
	// where to find the real address — Terraform prints it at the head of the
	// diagnostic. Guessing the local name would print a command that silently
	// does not match the user's configuration.
	wantEnding := "terraform untaint <address> && terraform apply"
	if !strings.Contains(detail, wantEnding) {
		t.Errorf("the diagnostic must carry the recovery command %q; got:\n%s", wantEnding, detail)
	}
	if !strings.Contains(detail, "resource address Terraform names at the top of this error") {
		t.Errorf("the diagnostic must say where to find the address; got:\n%s", detail)
	}
	if !strings.Contains(detail, "STILL RUNNING") || !strings.Contains(detail, "does not cancel") {
		t.Errorf("the diagnostic must say the operation is still running server-side and that a disconnect does not "+
			"cancel it; got:\n%s", detail)
	}
	if !strings.Contains(detail, testNamespace+"/"+testName) {
		t.Errorf("the diagnostic must name the registration; got:\n%s", detail)
	}
	if !strings.Contains(detail, "Operation: op_") {
		t.Errorf("the diagnostic must name the operation id; got:\n%s", detail)
	}
	if !strings.Contains(detail, "Phase:") {
		t.Errorf("the diagnostic must name the phase; got:\n%s", detail)
	}
}

// TestCreate_DeferredBeyondTheTimeoutFailsFast is §7.1.6.
//
// A bulk onboarding is deferred BY DESIGN and the horizon is DAYS. The
// alternative is ten resources each sitting at "Still creating... [59m50s
// elapsed]" and then failing.
func TestCreate_DeferredBeyondTheTimeoutFailsFast(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	resetAt := time.Now().UTC().Add(5 * 24 * time.Hour)
	srv.SetBehaviour(fakeservice.Behaviour{DeferOperation: true, DeferEstimatedStart: resetAt})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "60m", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}

	started := time.Now()
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)
	elapsed := time.Since(started)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a deferral beyond timeouts.create must fail immediately")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the create waited %s before failing; §7.1.6 requires failing BEFORE waiting", elapsed)
	}
	var detail, summary string
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagCreateDeferredBeyondTimeout) {
			summary, detail = d.Summary(), d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected a %s diagnostic; got %v", DiagCreateDeferredBeyondTimeout, resp.Diagnostics)
	}
	if !strings.Contains(summary, "rate limit") {
		t.Errorf("the summary must name the rate limit; got %q", summary)
	}
	if !strings.Contains(detail, resetAt.Format("2006-01-02")) {
		t.Errorf("the diagnostic must name the reset time; got:\n%s", detail)
	}
	if !strings.Contains(detail, "HAS BEEN CREATED") {
		t.Errorf("the diagnostic must say the registration was created and will issue automatically; got:\n%s", detail)
	}
	// The partial state from step 4 must still be written, or the registration is
	// orphaned.
	if resp.State.Raw.IsNull() {
		t.Fatal("no state was written; the created registration would be orphaned")
	}
}

// TestCreate_DeferralDiagnosticNamesTheBudgetByValue is §7.1.6's other half,
// closed by `API-PROVIDER-VISIBILITY-FIELDS`.
//
// §7.1.6's example text quotes "46 of its 50 weekly certificates". The provider
// holds no ledger and cannot compute either number, so until the `202` carried
// `deferral_budget` the diagnostic could name the reset time and nothing else —
// and "queued behind a rate limit until Friday" reads as a service fault, which
// sends the operator to raise a support ticket rather than to stage the rollout.
func TestCreate_DeferralDiagnosticNamesTheBudgetByValue(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	resetAt := time.Now().UTC().Add(5 * 24 * time.Hour)
	srv.SetBehaviour(fakeservice.Behaviour{
		DeferOperation:      true,
		DeferEstimatedStart: resetAt,
		DeferBudget:         &contracts.RateLimitBudget{Used: 46, Limit: 40, Window: "168h"},
	})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "60m", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	detail := ""
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagCreateDeferredBeyondTimeout) {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected a %s diagnostic; got %v", DiagCreateDeferredBeyondTimeout, resp.Diagnostics)
	}
	// The three values, by value. "46 used of 40 permitted per 7 days."
	for _, want := range []string{"46", "40", "7 days"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the diagnostic must name the budget by value (missing %q); got:\n%s", want, detail)
		}
	}
	// And it must say WHICH limit, because 40 is not the number the certificate
	// authority publishes and an operator comparing them will otherwise conclude
	// the service is wrong.
	if !strings.Contains(detail, "EFFECTIVE limit") {
		t.Errorf("the diagnostic must say the limit is the effective one, not the CA's headline; got:\n%s", detail)
	}
}

// TestCreate_DeferralDiagnosticOmitsAnAbsentBudget is the §2.1 half: a service
// that predates `deferral_budget` still gets a fail-fast diagnostic, and it must
// not contain a rendered nil.
func TestCreate_DeferralDiagnosticOmitsAnAbsentBudget(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	resetAt := time.Now().UTC().Add(5 * 24 * time.Hour)
	srv.SetBehaviour(fakeservice.Behaviour{DeferOperation: true, DeferEstimatedStart: resetAt})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "60m", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	detail := ""
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagCreateDeferredBeyondTimeout) {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected a %s diagnostic; got %v", DiagCreateDeferredBeyondTimeout, resp.Diagnostics)
	}
	if strings.Contains(detail, "Registered-domain budget") {
		t.Errorf("no budget was reported, so no budget sentence may be printed; got:\n%s", detail)
	}
}

// TestHumaniseWindow pins the one piece of arithmetic in the budget sentence.
//
// The wire carries a Go duration and the certificate authority publishes days.
// A window that is not a whole number of days is printed VERBATIM rather than
// rounded: rounding would make "46 of 40 per 7 days" a statement about a window
// the service did not use.
func TestHumaniseWindow(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"168h", "7 days"},
		{"24h", "1 day"},
		{"720h", "30 days"},
		{"3h", "3h"},
		{"90m", "90m"},
		{"", ""},
		{"P7D", "P7D"},
	} {
		if got := humaniseWindow(tc.in); got != tc.want {
			t.Errorf("humaniseWindow(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCreate_WaitForAcceptedWithholdsTheURIs is §7.1.5.
//
// The versionless secret URI is VALID BUT EMPTY until a version exists, so
// Terraform cannot detect the problem itself: the apply succeeds and the listener
// binds to nothing.
func TestCreate_WaitForAcceptedWithholdsTheURIs(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SetBehaviour(fakeservice.Behaviour{OperationNeverCompletes: true})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.WaitFor = types.StringValue(WaitForAccepted)
		m.VersionlessSecretID = types.StringNull()
		m.VersionlessCertificateID = types.StringNull()
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("wait_for = accepted must return quickly and succeed: %v", resp.Diagnostics)
	}
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	if !after.VersionlessSecretID.IsNull() {
		t.Errorf("versionless_secret_id = %q; it MUST be null until publication, or a downstream reference binds a "+
			"listener to an empty secret", after.VersionlessSecretID.ValueString())
	}
	if !after.VersionlessCertificateID.IsNull() {
		t.Errorf("versionless_certificate_id = %q; it must be null until publication", after.VersionlessCertificateID.ValueString())
	}
	found := false
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagUnpublishedURIWithheld) {
			found = true
			if !strings.Contains(d.Detail(), "EMPTY") {
				t.Errorf("the warning must explain that the URI is valid but empty; got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected the %s warning; got %v", DiagUnpublishedURIWithheld, resp.Diagnostics)
	}

	// A later refresh, once published, populates it.
	srv.SetBehaviour(fakeservice.Behaviour{})
	if reg := srv.Registration(testNamespace, testName); reg != nil {
		srv.SimulateRenewal(testNamespace, testName)
	}
}

// TestCreate_RetriesDestinationAccessDeniedOnlyWithRetryAfter.
//
// Azure role assignments take several minutes to propagate. Without the retry,
// the FIRST apply of every new application fails on a race that resolves itself.
// Without the Retry-After condition, the provider would hammer a conflict the
// service never told it to retry.
func TestCreate_RetriesDestinationAccessDeniedOnlyWithRetryAfter(t *testing.T) {
	ctx := context.Background()

	t.Run("with Retry-After the create eventually succeeds", func(t *testing.T) {
		srv := fakeservice.New(t)
		srv.AddRule(fakeservice.Rule{
			Match: fakeservice.Match{Method: http.MethodPut, PathSuffix: "/certificates/" + testName},
			Times: 2,
			Handler: fakeservice.RespondProblem(409, contracts.CodeDestinationAccessDenied,
				fakeservice.DefaultInstanceID, fakeservice.WithRetryAfterSeconds(1)),
		})
		r := newTestResource(t, srv)
		plan := planFor(t, ctx, nil)
		resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
		r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("the create should have retried past the propagating role assignment: %v", resp.Diagnostics)
		}
		if got := srv.RequestCount(http.MethodPut, "/certificates/"+testName); got < 3 {
			t.Fatalf("PUT was issued %d times; expected the two refusals plus a success", got)
		}
	})

	t.Run("without Retry-After the create fails immediately", func(t *testing.T) {
		srv := fakeservice.New(t)
		srv.AddRule(fakeservice.Rule{
			Match:   fakeservice.Match{Method: http.MethodPut, PathSuffix: "/certificates/" + testName},
			Handler: fakeservice.RespondProblemNoRetryAfter(409, contracts.CodeDestinationAccessDenied, fakeservice.DefaultInstanceID),
		})
		r := newTestResource(t, srv)
		plan := planFor(t, ctx, nil)
		resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
		started := time.Now()
		r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)
		if !resp.Diagnostics.HasError() {
			t.Fatal("a 409 with no Retry-After must not be retried")
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("the create spent %s retrying a conflict the service did not mark retryable", elapsed)
		}
		if got := srv.RequestCount(http.MethodPut, "/certificates/"+testName); got != 1 {
			t.Fatalf("PUT was issued %d times; a 409 without Retry-After must be issued once", got)
		}
	})
}

// TestCreate_OperationExpiredFallsBackToTheRegistration is §7.1.3 rule 3 — the
// single most valuable robustness property of the polling design.
func TestCreate_OperationExpiredFallsBackToTheRegistration(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SetBehaviour(fakeservice.Behaviour{PollsBeforeTerminal: 1, OperationExpiresAfterPolls: 1})
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, func(m *certificateResourceModel) {
		m.Timeouts = timeoutsObject(t, ctx, "5s", "", "", "")
	})
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("losing the operation record must not fail the apply: %v", resp.Diagnostics)
	}
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	if after.CurrentCertificate.IsNull() {
		t.Fatal("the fallback did not observe publication")
	}
}

// TestCreate_AlwaysSendsAPreconditionAndAnIdempotencyKey.
//
// The fake returns 428 when a PUT carries neither precondition, so a provider
// that forgets one fails HERE rather than silently in production.
func TestCreate_AlwaysSendsAPreconditionAndAnIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	r := newTestResource(t, srv)
	plan := planFor(t, ctx, nil)
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}
	var puts int
	for _, req := range srv.Requests() {
		if req.Method != http.MethodPut {
			continue
		}
		puts++
		if req.IfNoneMatch != "*" {
			t.Errorf("create PUT sent If-None-Match=%q, want %q", req.IfNoneMatch, "*")
		}
		if req.IfMatch != "" {
			t.Errorf("create PUT also sent If-Match=%q; exactly one precondition is permitted", req.IfMatch)
		}
		if len(req.IdempotencyKey) != 26 {
			t.Errorf("Idempotency-Key %q is not a ULID", req.IdempotencyKey)
		}
	}
	if puts == 0 {
		t.Fatal("no PUT was issued")
	}
}

// TestCreate_RegistrationExistsPointsAtImport.
func TestCreate_RegistrationExistsPointsAtImport(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	// Seed a registration with a DIFFERENT spec, so the create-idempotency path
	// does not apply and the service returns 409.
	srv.SeedRegistration(fakeservice.RegistrationSeed{
		Namespace: testNamespace, Name: testName, DNSNames: []string{"other.example.com"},
	})
	r := newTestResource(t, srv)
	plan := planFor(t, ctx, nil)
	resp := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a conflict")
	}
	want := "terraform import azureacme_certificate." + testName + " " + testNamespace + "/" + testName
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Detail(), want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the conflict diagnostic must carry the literal import command %q; got %v", want, resp.Diagnostics)
	}
}

// TestCreate_IdempotentPutReturns200AndIsAdopted covers the create-idempotency
// case: the caller already owns an identical registration.
func TestCreate_IdempotentPutReturns200AndIsAdopted(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	r := newTestResource(t, srv)

	plan := planFor(t, ctx, nil)
	first := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, first)
	if first.Diagnostics.HasError() {
		t.Fatalf("first create: %v", first.Diagnostics)
	}

	second := &fwresource.CreateResponse{State: emptyState(t, ctx)}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, second)
	if second.Diagnostics.HasError() {
		t.Fatalf("an identical create by the same owner is the 200 idempotency case, not a conflict: %v", second.Diagnostics)
	}
}

// ------------------------------------------------------------------ helpers

func planFor(t *testing.T, ctx context.Context, mutate func(*certificateResourceModel)) tfsdk.Plan {
	t.Helper()
	s := certificateResourceSchema()
	m := certificateResourceModel{
		Namespace:                     types.StringValue(testNamespace),
		Name:                          types.StringValue(testName),
		ID:                            types.StringUnknown(),
		RegistrationID:                types.StringUnknown(),
		ServiceInstanceID:             types.StringUnknown(),
		DNSNames:                      dnsNameSet(t, ctx, "api.example.com"),
		CommonName:                    types.StringNull(),
		KeyVaultID:                    armid.NewValue(fakeservice.DefaultKeyVaultID),
		CertificateName:               types.StringNull(),
		DestinationID:                 types.StringNull(),
		ResolvedCertificateName:       types.StringUnknown(),
		Key:                           defaultKeyObject(),
		ACMEProfile:                   types.StringValue(ACMEProfileSentinel),
		ValidationBinding:             types.StringValue(ValidationBindingSentinel),
		ConsumerProfile:               types.StringNull(),
		Renewal:                       defaultRenewalObject(),
		DeletionPolicy:                types.StringValue("retain"),
		AcknowledgeIrreversibleDelete: types.BoolValue(false),
		WaitFor:                       types.StringValue(WaitForPublished),
		Verification:                  types.ObjectNull(verificationAttrTypes()),
		Description:                   types.StringNull(),
		Labels:                        types.MapNull(types.StringType),
		VersionlessSecretID:           types.StringUnknown(),
		VersionlessCertificateID:      types.StringUnknown(),
		SpecRevision:                  types.Int64Unknown(),
		Generation:                    types.Int64Unknown(),
		FulfilledGeneration:           types.Int64Unknown(),
		ResolvedACMEProfile:           types.StringUnknown(),
		ResolvedValidationBinding:     types.StringUnknown(),
		PublicationMode:               types.StringUnknown(),
		LastSuccessfulRenewalAt:       rfc3339.NewUnknown(),
		CurrentCertificate:            types.ObjectUnknown(currentCertificateAttrTypes()),
		Timeouts:                      types.ObjectNull(timeoutsAttrTypes()),
	}
	if mutate != nil {
		mutate(&m)
	}
	plan := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if diags := plan.Set(ctx, &m); diags.HasError() {
		t.Fatalf("building a plan: %v", diags)
	}
	return plan
}

func emptyState(t *testing.T, ctx context.Context) tfsdk.State {
	t.Helper()
	s := certificateResourceSchema()
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
}

func timeoutsObject(t *testing.T, ctx context.Context, create, read, update, del string) types.Object {
	t.Helper()
	str := func(v string) attr.Value {
		if v == "" {
			return types.StringNull()
		}
		return types.StringValue(v)
	}
	obj, diags := types.ObjectValue(timeoutsAttrTypes(), map[string]attr.Value{
		"create": str(create), "read": str(read), "update": str(update), "delete": str(del),
	})
	if diags.HasError() {
		t.Fatalf("building timeouts: %v", diags)
	}
	return obj
}
