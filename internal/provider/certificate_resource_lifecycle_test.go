package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// TestUpdate_ClientOnlyChangeMakesNoHTTPRequest is the §7.3 short circuit.
//
// `wait_for` and `timeouts` are never sent to the API. Sending a PUT for either
// would bump spec.revision for nothing and invalidate every other workspace's
// If-Match.
func TestUpdate_ClientOnlyChangeMakesNoHTTPRequest(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.WaitFor = types.StringValue(WaitForAccepted)
	})
	srv.ResetRequests()
	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Update(ctx, fwresource.UpdateRequest{Plan: plan, State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}
	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("a wait_for-only change issued %d HTTP requests; §7.3 requires NONE: %v", got, srv.Requests())
	}
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatal(diags)
	}
	if after.WaitFor.ValueString() != WaitForAccepted {
		t.Fatalf("wait_for = %q, want %q", after.WaitFor.ValueString(), WaitForAccepted)
	}
}

// TestUpdate_RevisionConflictNamesBothRevisionsAndNeverRetriesUnconditionally.
func TestUpdate_RevisionConflictNamesBothRevisionsAndNeverRetriesUnconditionally(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	var priorModel certificateResourceModel
	if diags := state.Get(ctx, &priorModel); diags.HasError() {
		t.Fatal(diags)
	}
	// Terraform planned against a revision the service has moved past.
	priorModel.SpecRevision = types.Int64Value(99)
	if diags := state.Set(ctx, &priorModel); diags.HasError() {
		t.Fatal(diags)
	}
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.Description = types.StringValue("edited concurrently")
	})
	srv.ResetRequests()
	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Update(ctx, fwresource.UpdateRequest{Plan: plan, State: state}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a stale If-Match must fail the update")
	}
	var detail string
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "changed since this plan") {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected the revision-conflict diagnostic; got %v", resp.Diagnostics)
	}
	for _, want := range []string{"spec_revision = 99", "spec_revision = 1", "Last changed by", "will NOT retry"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the diagnostic must contain %q; got:\n%s", want, detail)
		}
	}
	// Exactly ONE re-GET, and NEVER an If-Match: * retry.
	gets, puts := 0, 0
	for _, req := range srv.Requests() {
		switch req.Method {
		case http.MethodGet:
			gets++
		case http.MethodPut:
			puts++
			if req.IfMatch == "*" || req.IfNoneMatch == "*" {
				t.Fatalf("the provider retried with an unconditional precondition (%q/%q); that silently overwrites the "+
					"other writer's change", req.IfMatch, req.IfNoneMatch)
			}
		}
	}
	if gets != 1 {
		t.Errorf("expected exactly one re-GET after the 412, got %d", gets)
	}
	if puts != 1 {
		t.Errorf("expected exactly one PUT, got %d", puts)
	}

	// After a failed update, state must hold the SERVER's spec, not the plan.
	var after certificateResourceModel
	if diags := resp.State.Get(ctx, &after); diags.HasError() {
		t.Fatal(diags)
	}
	if after.Description.ValueString() == "edited concurrently" {
		t.Error("state holds the PLANNED description after a failed update; Terraform would believe the change landed. " +
			"§7.3: write the server's current representation, so the next plan correctly re-proposes it.")
	}
	// ...and the change is therefore STILL PENDING: the next plan re-proposes it.
	var planned certificateResourceModel
	if diags := plan.Get(ctx, &planned); diags.HasError() {
		t.Fatal(diags)
	}
	if specEqual(ctx, after, planned) {
		t.Error("state and plan agree after a FAILED update, so the next plan would propose nothing and the change " +
			"would be silently lost")
	}
}

// TestDelete_IsIdempotent — a DELETE that can refuse makes `terraform destroy`
// non-idempotent and strands the resource in state forever.
func TestDelete_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)
	state := priorState(t, ctx, fakeservice.DefaultInstanceID)

	first := &fwresource.DeleteResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Delete(ctx, fwresource.DeleteRequest{State: state}, first)
	if first.Diagnostics.HasError() {
		t.Fatalf("first destroy: %v", first.Diagnostics)
	}
	second := &fwresource.DeleteResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Delete(ctx, fwresource.DeleteRequest{State: state}, second)
	if second.Diagnostics.HasError() {
		t.Fatalf("a second destroy must succeed through the 404/410 idempotency path: %v", second.Diagnostics)
	}
}

// TestDelete_TypedConflictsRenderActionableDiagnostics.
func TestDelete_TypedConflictsRenderActionableDiagnostics(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		code     contracts.Code
		detail   string
		wantText []string
	}{
		{
			name: "destination_soft_deleted", code: contracts.CodeDestinationSoftDeleted,
			detail:   "scheduled_purge_date=2026-12-07T00:00:00Z purge_protection_enabled=true",
			wantText: []string{"2026-12-07", "purge_protection_enabled", "recover-destination", "never purges automatically"},
		},
		{
			name: "deletion_policy_conflict", code: contracts.CodeDeletionPolicyConflict,
			detail:   "persisted=retain requested=delete set_by=platform-admin@example.com",
			wantText: []string{"persisted=retain", "requested=delete", "platform-admin@example.com", "only\nNARROW"},
		},
		{
			name: "operation_in_flight", code: contracts.CodeOperationInFlight,
			detail:   "operation op_01ABC is still running",
			wantText: []string{"op_01ABC", "terraform untaint"},
		},
		{
			name: "destination_recently_published", code: contracts.CodeDestinationRecentlyPublished,
			detail:   "published at 2026-09-08T10:00:00Z",
			wantText: []string{"terraform refresh", "2026-09-08"},
		},
		{
			name: "destination_shared", code: contracts.CodeDestinationShared,
			detail:   "kv-payments/payments-api is also claimed by payments-prod/legacy-api",
			wantText: []string{"legacy-api", `deletion_policy = "retain"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeservice.New(t)
			srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
			srv.AddRule(fakeservice.Rule{
				Match: fakeservice.Match{Method: http.MethodDelete, PathSuffix: "/certificates/" + testName},
				Handler: fakeservice.RespondProblem(409, tc.code, fakeservice.DefaultInstanceID,
					fakeservice.WithDetail(tc.detail)),
			})
			r := newTestResource(t, srv)
			state := priorState(t, ctx, fakeservice.DefaultInstanceID)
			resp := &fwresource.DeleteResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
			r.Delete(ctx, fwresource.DeleteRequest{State: state}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error")
			}
			combined := ""
			for _, d := range resp.Diagnostics.Errors() {
				combined += d.Summary() + "\n" + d.Detail() + "\n"
			}
			for _, want := range tc.wantText {
				normalised := strings.ReplaceAll(want, "\n", " ")
				if !strings.Contains(combined, want) && !strings.Contains(strings.ReplaceAll(combined, "\n", " "), normalised) {
					t.Errorf("the diagnostic must contain %q; got:\n%s", want, combined)
				}
			}
		})
	}
}

// TestImport_ParsesTheCompositeID.
func TestImport_ParsesTheCompositeID(t *testing.T) {
	for _, bad := range []string{"payments-api", "payments-prod/payments-api/extra", "/payments-api", "payments-prod/", "PAYMENTS/api"} {
		if _, _, err := ParseImportID(bad); err == nil {
			t.Errorf("%q was accepted as an import id", bad)
		} else {
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("the error must echo the value received (%q); got %q", bad, err.Error())
			}
		}
	}
	if _, _, err := ParseImportID("payments-prod/payments-api"); err != nil {
		t.Fatalf("a well-formed import id was rejected: %v", err)
	}
	if err := func() error { _, _, e := ParseImportID("nope"); return e }(); !strings.Contains(err.Error(), "{namespace}/{name}") {
		t.Errorf("the error must name the expected form; got %q", err.Error())
	}
}

// TestImport_SendsIntentManageAndNeverIssues.
func TestImport_SendsIntentManageAndNeverIssues(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)
	srv.ResetRequests()

	s := certificateResourceSchema()
	resp := &fwresource.ImportStateResponse{State: emptyState(t, ctx)}
	resp.State.Schema = s
	r.ImportState(ctx, fwresource.ImportStateRequest{ID: testNamespace + "/" + testName}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState: %v", resp.Diagnostics)
	}

	sawIntentManage := false
	for _, req := range srv.Requests() {
		if req.Method != http.MethodGet {
			t.Errorf("import issued a %s request; import is GET ONLY and must never issue", req.Method)
		}
		if strings.Contains(req.Query, "intent=manage") {
			sawIntentManage = true
		}
	}
	if !sawIntentManage {
		t.Fatal("import did not send ?intent=manage; without it any principal holding only Certificates.Read could " +
			"import a registration into their own state and manage it")
	}

	var m certificateResourceModel
	if diags := resp.State.Get(ctx, &m); diags.HasError() {
		t.Fatal(diags)
	}
	if m.WaitFor.ValueString() != WaitForPublished {
		t.Errorf("wait_for = %q after import, want %q — otherwise the first plan shows a spurious null -> published diff",
			m.WaitFor.ValueString(), WaitForPublished)
	}
	if !m.Timeouts.IsNull() {
		t.Errorf("timeouts should be left null after import; got %v", m.Timeouts)
	}
}

// TestImport_ReaderOnlyPrincipalIsRefused.
func TestImport_ReaderOnlyPrincipalIsRefused(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	srv.AddRule(fakeservice.Rule{
		Match:   fakeservice.Match{Method: http.MethodGet, QueryHas: "intent=manage"},
		Handler: fakeservice.RespondProblem(403, contracts.CodeAuthorisationDenied, fakeservice.DefaultInstanceID),
	})
	r := newTestResource(t, srv)

	resp := &fwresource.ImportStateResponse{State: emptyState(t, ctx)}
	r.ImportState(ctx, fwresource.ImportStateRequest{ID: testNamespace + "/" + testName}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("a Certificates.Read-only principal must not be able to import")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "Not authorised to MANAGE") && strings.Contains(d.Detail(), "Certificates.Manage") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an authorisation error naming Certificates.Manage; got %v", resp.Diagnostics)
	}
}

// TestImport_ForeignOwnerRequiresAClaim.
func TestImport_ForeignOwnerRequiresAClaim(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{
		Namespace: testNamespace, Name: testName,
		OwnerPrincipalID: "00000000-dead-beef-0000-000000000000",
	})
	r := newTestResource(t, srv)

	resp := &fwresource.ImportStateResponse{State: emptyState(t, ctx)}
	r.ImportState(ctx, fwresource.ImportStateRequest{ID: testNamespace + "/" + testName}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("importing a registration owned by another principal must fail; ownership transfer is never implicit")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), DiagOwnershipTransferRequired) {
			found = true
			if !strings.Contains(d.Detail(), "actions/claim") {
				t.Errorf("the message must name the claim endpoint; got:\n%s", d.Detail())
			}
			if !strings.Contains(d.Detail(), "00000000-dead-beef-0000-000000000000") {
				t.Errorf("the message must name the current owner; got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected %s; got %v", DiagOwnershipTransferRequired, resp.Diagnostics)
	}
}
