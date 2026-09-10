package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// TestModifyPlan_DestinationChangeIsAPlanTimeError is §6.2.1.
//
// RequiresReplace would plan DESTROY-THEN-CREATE, which under
// `deletion_policy = "delete"` soft-deletes the live certificate BEFORE its
// replacement is issued — and `create_before_destroy` cannot rescue it, because
// the logical key {namespace}/{name} is unchanged so the create half collides
// with the still-existing registration.
func TestModifyPlan_DestinationChangeIsAPlanTimeError(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	const newVault = "/subscriptions/8b1e6a2c-4f3d-4a5b-9c7e-1d2f3a4b5c6d/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-other"

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.KeyVaultID = armid.NewValue(newVault)
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("changing key_vault_id must fail the PLAN, not be planned as a replacement")
	}
	if len(resp.RequiresReplace) != 0 {
		t.Fatalf("the plan requires replacement of %v; a destination change must NEVER plan a destroy", resp.RequiresReplace)
	}
	var detail string
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "Changing the destination") {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected the destination-change error; got %v", resp.Diagnostics)
	}
	// The FIRST LINE must instruct the user to revert, because a ModifyPlan error
	// aborts the WHOLE plan and the workspace is unplannable for everyone —
	// including colleagues running unrelated plans — until someone reverts.
	firstLine := strings.TrimSpace(strings.SplitN(strings.TrimSpace(detail), "\n", 2)[0])
	if !strings.Contains(firstLine, "To unblock planning, revert `key_vault_id`") {
		t.Errorf("the message must LEAD with the revert instruction; first line was:\n%s", firstLine)
	}
	if !strings.Contains(detail, fakeservice.DefaultKeyVaultID) {
		t.Errorf("the message must name the value to revert TO; got:\n%s", detail)
	}
	for _, want := range []string{"new `name`", "delivery_stage = published", "removed` block", DiagDestinationChangeUnsupported} {
		if !strings.Contains(detail, want) {
			t.Errorf("the migration instructions must contain %q; got:\n%s", want, detail)
		}
	}
}

// TestModifyPlan_CertificateNameChangeIsAlsoADestinationChange.
func TestModifyPlan_CertificateNameChangeIsAlsoADestinationChange(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.CertificateName = types.StringValue("renamed-object")
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("changing certificate_name must fail the plan")
	}
}

// TestModifyPlan_DestinationCasingChangeIsNotAChange proves the armid semantic
// equality reaches the plan: a segment-casing difference must not read as a
// destination move.
func TestModifyPlan_DestinationCasingChangeIsNotAChange(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	recased := strings.Replace(fakeservice.DefaultKeyVaultID, "/resourceGroups/", "/resourcegroups/", 1)
	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.KeyVaultID = armid.NewValue(recased)
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("a segment-casing difference is not a destination change: %v", resp.Diagnostics)
	}
}

// TestModifyPlan_RenameIsNotADestinationChange.
//
// `certificate_name` defaults to `name`, so renaming necessarily changes the
// effective Key Vault object name. That is a REPLACEMENT — a new object — not a
// MOVE of an existing one, and treating it as a destination change would make
// renaming impossible, contradicting §6.1's "RequiresReplace appears on exactly
// `namespace` and `name`".
func TestModifyPlan_RenameIsNotADestinationChange(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	for _, tc := range []struct {
		name   string
		mutate func(*certificateResourceModel)
	}{
		{"name changes", func(m *certificateResourceModel) { m.Name = types.StringValue("payments-api-v2") }},
		{"namespace changes", func(m *certificateResourceModel) { m.Namespace = types.StringValue("payments-staging") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := priorState(t, ctx, fakeservice.DefaultInstanceID)
			plan := planFrom(t, ctx, state, tc.mutate)
			resp := &fwresource.ModifyPlanResponse{
				Plan:            plan,
				RequiresReplace: path.Paths{path.Root("name")},
			}
			r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("a rename must plan a replacement, not fail as a destination change: %v", resp.Diagnostics)
			}
		})
	}
}

// TestModifyPlan_ReplacementWithDeletePolicyWarns is §6.2.2.
func TestModifyPlan_ReplacementWithDeletePolicyWarns(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		policy   string
		wantWarn bool
	}{{"delete", true}, {"retain", false}} {
		t.Run(tc.policy, func(t *testing.T) {
			srv := fakeservice.New(t)
			srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
			r := newTestResource(t, srv)

			state := priorState(t, ctx, fakeservice.DefaultInstanceID)
			var priorModel certificateResourceModel
			if diags := state.Get(ctx, &priorModel); diags.HasError() {
				t.Fatal(diags)
			}
			priorModel.DeletionPolicy = types.StringValue(tc.policy)
			if diags := state.Set(ctx, &priorModel); diags.HasError() {
				t.Fatal(diags)
			}
			plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
				m.Namespace = types.StringValue("payments-staging")
			})
			resp := &fwresource.ModifyPlanResponse{
				Plan: plan,
				// The attribute-level RequiresReplace has already fired by the time
				// ModifyPlan runs; reproduce that here.
				RequiresReplace: path.Paths{path.Root("namespace")},
			}
			r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)

			warned := false
			for _, d := range resp.Diagnostics.Warnings() {
				if strings.Contains(d.Summary(), DiagReplacementWillDeleteCert) {
					warned = true
					if !strings.Contains(d.Detail(), testName) {
						t.Errorf("the warning must name the Key Vault certificate; got:\n%s", d.Detail())
					}
					if !strings.Contains(d.Detail(), "7 to 90 days") {
						t.Errorf("the warning must name the retention period; got:\n%s", d.Detail())
					}
				}
			}
			if warned != tc.wantWarn {
				t.Fatalf("warned = %v, want %v (diagnostics: %v)", warned, tc.wantWarn, resp.Diagnostics)
			}
		})
	}
}

// TestModifyPlan_MetadataOnlyChangeKeepsCurrentCertificateKnown is §6.3
// refinement 2, and it is what stops a one-word description edit from rendering
// six fields including `thumbprint_sha256` as `(known after apply)` — which to a
// plan reviewer looks like a certificate replacement.
func TestModifyPlan_MetadataOnlyChangeKeepsCurrentCertificateKnown(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := stateWithCurrentCertificate(t, ctx, srv)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.Description = types.StringValue("a one-word edit")
		m.CurrentCertificate = types.ObjectUnknown(currentCertificateAttrTypes())
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan: %v", resp.Diagnostics)
	}

	var planned certificateResourceModel
	if diags := resp.Plan.Get(ctx, &planned); diags.HasError() {
		t.Fatal(diags)
	}
	if planned.CurrentCertificate.IsUnknown() {
		t.Fatal("a description-only change left current_certificate as (known after apply)")
	}
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagReissueExpected) {
			t.Errorf("a description-only change must not warn about a reissue")
		}
	}
}

// TestModifyPlan_IssuanceRelevantChangeWarnsAndLeavesCertificateUnknown is
// §6.2.3. Without it, a one-word description edit and a full reissue render
// identically as `~ update in place`.
func TestModifyPlan_IssuanceRelevantChangeWarnsAndLeavesCertificateUnknown(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	state := stateWithCurrentCertificate(t, ctx, srv)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.DNSNames = dnsNameSet(t, ctx, "api.example.com", "www.example.com")
		m.CurrentCertificate = types.ObjectUnknown(currentCertificateAttrTypes())
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan: %v", resp.Diagnostics)
	}

	warned := false
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagReissueExpected) {
			warned = true
			if !strings.Contains(d.Detail(), "remains in service") {
				t.Errorf("the reissue warning must say the current certificate remains in service; got:\n%s", d.Detail())
			}
		}
	}
	if !warned {
		t.Fatalf("changing dns_names must emit the reissue warning; got %v", resp.Diagnostics)
	}
	var planned certificateResourceModel
	if diags := resp.Plan.Get(ctx, &planned); diags.HasError() {
		t.Fatal(diags)
	}
	if !planned.CurrentCertificate.IsUnknown() {
		t.Fatal("an issuance-relevant change must leave current_certificate unknown; it genuinely changes")
	}
	// The consumption URI must NOT change: it is versionless.
	if planned.VersionlessSecretID.IsUnknown() {
		t.Error("versionless_secret_id became unknown for a dns_names change; it is derived from the destination, which cannot change")
	}
}

// TestModifyPlan_VersionlessURIsAreKnownAtPlanTime is §6.3 refinement 1 — the
// single most visible plan-quality win available.
func TestModifyPlan_VersionlessURIsAreKnownAtPlanTime(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	r := newTestResource(t, srv)

	t.Run("wait_for published gives a KNOWN uri on first create", func(t *testing.T) {
		plan := planFor(t, ctx, nil)
		resp := &fwresource.ModifyPlanResponse{Plan: plan}
		r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: emptyState(t, ctx), Plan: plan, Config: tfsdk.Config(plan)}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("ModifyPlan: %v", resp.Diagnostics)
		}
		var planned certificateResourceModel
		if diags := resp.Plan.Get(ctx, &planned); diags.HasError() {
			t.Fatal(diags)
		}
		if planned.VersionlessSecretID.IsUnknown() {
			t.Fatal("versionless_secret_id is unknown at plan time; every consumer resource then cascades to unknown on the first apply")
		}
		want := "https://kv-payments.vault.azure.net/secrets/" + testName
		if got := planned.VersionlessSecretID.ValueString(); got != want {
			t.Fatalf("versionless_secret_id = %q, want %q", got, want)
		}
	})

	t.Run("wait_for accepted plans the uri as NULL", func(t *testing.T) {
		plan := planFor(t, ctx, func(m *certificateResourceModel) {
			m.WaitFor = types.StringValue(WaitForAccepted)
		})
		resp := &fwresource.ModifyPlanResponse{Plan: plan}
		r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: emptyState(t, ctx), Plan: plan, Config: tfsdk.Config(plan)}, resp)
		var planned certificateResourceModel
		if diags := resp.Plan.Get(ctx, &planned); diags.HasError() {
			t.Fatal(diags)
		}
		if !planned.VersionlessSecretID.IsNull() {
			t.Fatalf("versionless_secret_id = %v; with wait_for = accepted it must be planned NULL, so a downstream "+
				"reference fails loudly instead of binding a listener to an empty secret", planned.VersionlessSecretID)
		}
	})
}

// TestModifyPlan_ConsumerInServiceWarningOnDestroy is §6.2.4.
func TestModifyPlan_ConsumerInServiceWarningOnDestroy(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{
		Namespace: testNamespace, Name: testName, DeliveryStage: "consumer_observed",
	})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	s := certificateResourceSchema()
	nullPlan := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	resp := &fwresource.ModifyPlanResponse{Plan: nullPlan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: nullPlan}, resp)

	found := false
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagConsumerInServiceOnDestroy) {
			found = true
			if !strings.Contains(d.Detail(), "NOT refused") {
				t.Errorf("the warning must say the destroy is not refused (refusing strands the resource in state forever); got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected the %s warning; got %v", DiagConsumerInServiceOnDestroy, resp.Diagnostics)
	}
}

// TestPlanStability_RenewalProducesNoSpecChange is the PLAN-STABILITY PROOF at
// unit level: the acceptance suite proves it end to end with
// plancheck.ExpectEmptyPlan, and this proves the mechanism without a Terraform
// binary.
//
// A renewal changes the CERTIFICATE, never the SPEC. If any spec attribute
// changed here, every consumer would see a planned change roughly eight times
// per certificate per year, fleet-wide, with no configuration change to blame.
func TestPlanStability_RenewalProducesNoSpecChange(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)

	// First refresh: establish the baseline.
	before := readInto(t, ctx, r, priorState(t, ctx, fakeservice.DefaultInstanceID))

	// The service renews. New thumbprint, new serial, new version URIs, new
	// validity — and NOTHING in the spec.
	srv.SimulateRenewal(testNamespace, testName)

	after := readInto(t, ctx, r, stateOf(t, ctx, before))

	if !specEqual(ctx, before, after) {
		t.Fatalf("a renewal changed a SPEC attribute, which would plan a change on every certificate in the fleet.\n"+
			"before: dns=%v key_vault=%v cert_name=%v profile=%v binding=%v labels=%v desc=%v\n"+
			"after:  dns=%v key_vault=%v cert_name=%v profile=%v binding=%v labels=%v desc=%v",
			before.DNSNames, before.KeyVaultID, before.CertificateName, before.ACMEProfile, before.ValidationBinding, before.Labels, before.Description,
			after.DNSNames, after.KeyVaultID, after.CertificateName, after.ACMEProfile, after.ValidationBinding, after.Labels, after.Description)
	}
	if before.SpecRevision.ValueInt64() != after.SpecRevision.ValueInt64() {
		t.Errorf("a renewal bumped spec_revision (%d -> %d). The ETag covers the SPEC ONLY, or every client's If-Match "+
			"fails after every renewal.", before.SpecRevision.ValueInt64(), after.SpecRevision.ValueInt64())
	}
	if before.Generation.ValueInt64() != after.Generation.ValueInt64() {
		t.Errorf("a renewal bumped generation (%d -> %d); generation moves only when the issuance hash changes",
			before.Generation.ValueInt64(), after.Generation.ValueInt64())
	}
	if before.VersionlessSecretID.ValueString() != after.VersionlessSecretID.ValueString() {
		t.Errorf("a renewal changed versionless_secret_id (%q -> %q); every consumer binds to it and it is VERSIONLESS",
			before.VersionlessSecretID.ValueString(), after.VersionlessSecretID.ValueString())
	}
	// The certificate itself DID change, or the fake is not simulating a renewal
	// and this test proves nothing.
	beforeThumb := before.CurrentCertificate.Attributes()["thumbprint_sha256"]
	afterThumb := after.CurrentCertificate.Attributes()["thumbprint_sha256"]
	if beforeThumb.Equal(afterThumb) {
		t.Fatal("the fake did not actually renew: the thumbprint is unchanged, so this test proves nothing")
	}
}

// TestPlanStability_ServerInjectedLabelIsCaughtNotAbsorbed.
//
// The server MUST NOT write into `labels` (guarantee G-6). If it does, the
// provider must SURFACE it as drift rather than silently merging it — a silent
// merge would hide plan-stability failure 5 of §6.4 forever.
func TestPlanStability_ServerInjectedLabelIsCaughtNotAbsorbed(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{
		Namespace: testNamespace, Name: testName, Labels: map[string]string{"team": "payments"},
	})
	r := newTestResource(t, srv)

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	var m certificateResourceModel
	if diags := state.Get(ctx, &m); diags.HasError() {
		t.Fatal(diags)
	}
	labels, diags := types.MapValueFrom(ctx, types.StringType, map[string]string{"team": "payments"})
	if diags.HasError() {
		t.Fatal(diags)
	}
	m.Labels = labels
	if diags := state.Set(ctx, &m); diags.HasError() {
		t.Fatal(diags)
	}

	before := readInto(t, ctx, r, state)
	srv.InjectServerLabel(testNamespace, testName, "managed-by", "mantisec")
	after := readInto(t, ctx, r, stateOf(t, ctx, before))

	if before.Labels.Equal(after.Labels) {
		t.Fatal("the provider absorbed a server-injected label. Guarantee G-6 says the server never writes into `labels`; " +
			"a provider that silently merges one hides the violation and the drift note that would expose it.")
	}
	if _, ok := after.Labels.Elements()["managed-by"]; !ok {
		t.Fatal("the injected label did not reach state, so the violation would be invisible in the plan")
	}
}

// ------------------------------------------------------------------ helpers

func planFrom(t *testing.T, ctx context.Context, state tfsdk.State, mutate func(*certificateResourceModel)) tfsdk.Plan {
	t.Helper()
	var m certificateResourceModel
	if diags := state.Get(ctx, &m); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}
	if mutate != nil {
		mutate(&m)
	}
	s := certificateResourceSchema()
	plan := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if diags := plan.Set(ctx, &m); diags.HasError() {
		t.Fatalf("building a plan: %v", diags)
	}
	return plan
}

func stateWithCurrentCertificate(t *testing.T, ctx context.Context, srv *fakeservice.Server) tfsdk.State {
	t.Helper()
	r := newTestResource(t, srv)
	m := readInto(t, ctx, r, priorState(t, ctx, fakeservice.DefaultInstanceID))
	return stateOf(t, ctx, m)
}

func readInto(t *testing.T, ctx context.Context, r *certificateResource, state tfsdk.State) certificateResourceModel {
	t.Helper()
	resp := &fwresource.ReadResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
	r.Read(ctx, fwresource.ReadRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}
	var m certificateResourceModel
	if diags := resp.State.Get(ctx, &m); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	return m
}

func stateOf(t *testing.T, ctx context.Context, m certificateResourceModel) tfsdk.State {
	t.Helper()
	s := certificateResourceSchema()
	st := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if diags := st.Set(ctx, &m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}
	return st
}

// TestDestinationIDMoves enumerates §6.2.1 for `destination_id` under
// PROVISIONAL(D-20)'s server-resolved destination.
//
// A `ModifyPlan` error aborts the WHOLE plan, so every false positive here makes a
// workspace unplannable for every resource in it and for every colleague until
// someone edits the HCL. Three of the four transitions move nothing, and only an
// assertion naming a DIFFERENT policy from the one in effect is a move.
func TestDestinationIDMoves(t *testing.T) {
	t.Parallel()
	model := func(configured, resolved string) certificateResourceModel {
		m := certificateResourceModel{
			DestinationID:         types.StringNull(),
			ResolvedDestinationID: types.StringNull(),
		}
		if configured != "" {
			m.DestinationID = types.StringValue(configured)
		}
		if resolved != "" {
			m.ResolvedDestinationID = types.StringValue(resolved)
		}
		return m
	}
	for _, tc := range []struct {
		name        string
		state, plan certificateResourceModel
		want        bool
		why         string
	}{
		{
			name:  "nothing asserted, nothing asserted",
			state: model("", "payments"), plan: model("", ""),
			want: false,
		},
		{
			name:  "the assertion is DELETED",
			state: model("payments", "payments"), plan: model("", ""),
			want: false,
			why: "the user stops asserting; the service resolves the same vault to the same policy, so nothing moves. " +
				"Calling this a move makes the attribute impossible to delete once written — the §5.3.1 trap " +
				"re-entering through ModifyPlan",
		},
		{
			name:  "the assertion is ADDED, naming the policy already in effect",
			state: model("", "payments"), plan: model("payments", ""),
			want: false,
			why: "the most likely first edit after reading `resolved_destination_id`, and it moves nothing — refusing " +
				"it would abort the workspace for a no-op",
		},
		{
			name:  "the assertion is ADDED, naming a DIFFERENT policy",
			state: model("", "payments"), plan: model("payments-v2", ""),
			want: true,
			why:  "this is the case the §6.2.1 error exists for",
		},
		{
			name:  "the assertion CHANGES",
			state: model("payments", "payments"), plan: model("payments-v2", ""),
			want: true,
		},
		{
			name:  "the assertion is unchanged",
			state: model("payments", "payments"), plan: model("payments", ""),
			want: false,
		},
		{
			name:  "added, with no resolved value to compare against",
			state: model("", ""), plan: model("payments", ""),
			want: false,
			why: "an older state, or an import that has not refreshed. Aborting the whole plan on a value that may " +
				"well be right is worse than letting the service reject it with a field error",
		},
		{
			name:  "the planned value is unknown",
			state: model("payments", "payments"), plan: certificateResourceModel{DestinationID: types.StringUnknown()},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := destinationIDMoves(tc.state, tc.plan); got != tc.want {
				t.Errorf("destinationIDMoves = %v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}
