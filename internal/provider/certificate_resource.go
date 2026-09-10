package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
)

var (
	_ resource.Resource                     = (*certificateResource)(nil)
	_ resource.ResourceWithConfigure        = (*certificateResource)(nil)
	_ resource.ResourceWithImportState      = (*certificateResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*certificateResource)(nil)
	_ resource.ResourceWithConfigValidators = (*certificateResource)(nil)
)

// NewCertificateResource is the constructor registered in Resources().
func NewCertificateResource() resource.Resource { return &certificateResource{} }

type certificateResource struct {
	data *providerData
	// sleep is overridable so the polling tests do not take real seconds.
	sleep func(ctx context.Context, d time.Duration) error
}

func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = certificateResourceSchema()
}

func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data",
			fmt.Sprintf("expected *providerData, got %T. This is a provider defect.", req.ProviderData))
		return
	}
	r.data = data
	if r.sleep == nil {
		r.sleep = sleepContext
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
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

// ---------------------------------------------------------------------- Create

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.data == nil || r.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client. This is a provider defect.")
		return
	}

	spec, diags := buildSpecFromPlan(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout := r.timeoutFor(ctx, plan, "create", DefaultCreateTimeout, &resp.Diagnostics)
	deadline := time.Now().Add(createTimeout)
	ns, name := plan.Namespace.ValueString(), plan.Name.ValueString()

	// The Idempotency-Key is STABLE for this apply attempt, so a retry inside the
	// client cannot create two registrations.
	idempotencyKey := client.NewULID()

	result, err := r.putWithAccessDeniedRetry(ctx, ns, name, spec, client.PutOptions{
		IfNoneMatchAny: true, IdempotencyKey: idempotencyKey,
	}, deadline)
	if err != nil {
		r.addCreateError(ctx, &resp.Diagnostics, plan, err)
		return
	}

	reg := result.Registration
	if reg == nil {
		resp.Diagnostics.AddError("The service accepted the create but returned no registration",
			"Every 200, 201 and 202 must carry the full representation. This is a service defect; nothing was written to state.")
		return
	}

	// --- step 4: WRITE PARTIAL STATE IMMEDIATELY, before any waiting ---------
	//
	// If the process dies, or the wait fails, or the user interrupts, the
	// registration must not be orphaned: it exists server-side and Terraform has
	// to know about it.
	partial := plan
	partial.ID = types.StringValue(ns + "/" + name)
	partial.RegistrationID = types.StringValue(reg.RegistrationID)
	partial.ServiceInstanceID = types.StringValue(reg.ServiceInstanceID)
	partial.SpecRevision = types.Int64Value(reg.Spec.Revision)
	partial.Generation = types.Int64Value(reg.Spec.Generation)
	partial.FulfilledGeneration = types.Int64Value(reg.Status.ObservedGeneration)
	partial.ResolvedACMEProfile = stringOrNull(reg.Status.ResolvedACMEProfile)
	partial.ResolvedValidationBinding = stringOrNull(reg.Status.ResolvedValidationBinding)
	partial.ResolvedCertificateName = stringOrNull(reg.Status.ResolvedCertificateName)
	partial.PublicationMode = stringOrNull(reg.Status.PublicationMode)
	// Every Computed attribute must be KNOWN here: partial state is written
	// mid-apply and an unknown in state is not a legal value.
	partial.ResolvedDestinationID = types.StringNull()
	if reg.Spec.Destination != nil {
		partial.ResolvedDestinationID = stringOrNull(reg.Spec.Destination.DestinationID)
	}
	partial.VersionlessSecretID = types.StringNull()
	partial.VersionlessCertificateID = types.StringNull()
	partial.LastSuccessfulRenewalAt = rfc3339.NewNull()
	partial.CurrentCertificate = types.ObjectNull(currentCertificateAttrTypes())
	resp.Diagnostics.Append(resp.State.Set(ctx, &partial)...)
	if resp.Diagnostics.HasError() {
		return
	}

	targetGeneration := reg.Spec.Generation
	operationID := ""
	if result.Accepted != nil {
		targetGeneration = result.Accepted.TargetGeneration
		operationID = result.Accepted.OperationID

		// --- step 5: rate-limit deferral, FAIL FAST -------------------------
		if result.Accepted.EstimatedStart != nil {
			if stop, d := r.deferralFailsFast(*result.Accepted.EstimatedStart, deadline, createTimeout, ns); stop {
				resp.Diagnostics.Append(d)
				return
			}
		}
	}

	// --- step 6: wait_for = "accepted" --------------------------------------
	if plan.WaitFor.ValueString() == WaitForAccepted {
		fresh, _, err := r.data.Client.GetRegistration(ctx, ns, name, false)
		if err == nil {
			reg = fresh
		}
		final := plan
		resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &final, r.data.Environment)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
		resp.Diagnostics.AddWarning(
			"The certificate is not published yet, so its Key Vault URIs are withheld ("+DiagUnpublishedURIWithheld+")",
			"`wait_for = \"accepted\"` returned as soon as the service accepted the registration.\n\n"+
				"`versionless_secret_id` and `versionless_certificate_id` are NULL until a later refresh observes "+
				"`delivery_stage = \"published\"`. They are withheld deliberately: the versionless secret URI is valid but "+
				"EMPTY until a version exists, so a downstream resource referencing it would apply successfully and bind a "+
				"listener to nothing — a failure Terraform cannot detect for you.\n\n"+
				"Run `terraform refresh` (or the next plan) once issuance completes. Watch progress with `TF_LOG=info`.")
		return
	}

	// --- step 7/8: poll to terminal, or apply the timeout contract -----------
	outcome := r.waitForCompletion(ctx, waitRequest{
		Namespace: ns, Name: name, OperationID: operationID,
		TargetGeneration: targetGeneration, Deadline: deadline,
	})
	if outcome.Registration != nil {
		reg = outcome.Registration
	}

	switch {
	case outcome.Published:
		final := plan
		resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &final, r.data.Environment)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
		return

	case outcome.Failed:
		final := plan
		resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &final, r.data.Environment)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
		resp.Diagnostics.AddError(
			"Issuance failed",
			fmt.Sprintf("The registration was created and its specification is recorded, but issuance failed.\n\n"+
				"Operation: %s\nPhase: %s\nCode: %s\n%s\n\n%s\n\nThe registration has NOT been removed. Fix the cause and "+
				"re-run `terraform apply`; the service will retry.",
				orNone(outcome.OperationID), orNone(outcome.LastPhase), orNone(string(outcome.FailCode)),
				optionalLine("Detail: ", outcome.FailMessage), outcome.FailNextAction))
		return

	case outcome.Err != nil:
		resp.Diagnostics.AddError("Waiting for issuance failed",
			fmt.Sprintf("%v\n\nThe registration WAS created and will continue to be fulfilled by the service. Partial "+
				"state has been written; re-run `terraform apply` to resume.", outcome.Err))
		return

	default:
		// TIMED OUT with the operation genuinely still running (§7.1.4 case 3).
		//
		// The final GET has already happened inside waitForCompletion and did NOT
		// show the certificate published; if it had, outcome.Published would be
		// true and this apply would have SUCCEEDED. That distinction is the whole
		// point: reporting a completed issuance as a failure is what starts the
		// destructive sequence.
		//
		// NOTE ON THE RECOVERY COMMAND. The specification asks for the LITERAL
		// command `terraform untaint azureacme_certificate.api && terraform apply`.
		// The Plugin Framework does not give a resource its Terraform ADDRESS in
		// Create — `CreateRequest` carries the plan and nothing else — so the
		// provider cannot render the local name. Guessing it from the registration
		// name would print a command that silently does not match the user's
		// configuration, which is worse than a placeholder. Terraform prints the
		// address at the head of this diagnostic, so the placeholder is
		// unambiguous.
		resp.Diagnostics.AddError(
			"Timed out waiting for the certificate to be published ("+DiagCreateTimeoutStillRunning+")",
			fmt.Sprintf(
				"The operation is STILL RUNNING on the service. A client disconnect does not cancel it.\n\n"+
					"Registration: %s/%s\nOperation: %s\nPhase: %s\nTimeout: %s (`timeouts.create`)\n\n"+
					"The registration exists and the service will finish issuing it. Do NOT destroy and recreate: that "+
					"would abandon work already in progress, and under `deletion_policy = \"delete\"` it would soft-delete "+
					"a certificate that is about to be published.\n\n"+
					"Watch progress with `TF_LOG=info terraform plan`, then resume with:\n\n"+
					"    terraform untaint <address> && terraform apply\n\n"+
					"where <address> is the resource address Terraform names at the top of this error "+
					"(for example azureacme_certificate.api).",
				ns, name, orNone(outcome.OperationID), orNone(outcome.LastPhase), createTimeout))
		return
	}
}

// putWithAccessDeniedRetry retries `409 destination_access_denied` for up to five
// minutes inside timeouts.create.
//
// Azure role assignments take several minutes to propagate, so without this the
// FIRST apply of every new application fails on a race that resolves itself.
func (r *certificateResource) putWithAccessDeniedRetry(
	ctx context.Context, ns, name string, spec contracts.CertificateSpecFields,
	opts client.PutOptions, deadline time.Time,
) (*client.PutResult, error) {
	const accessDeniedBudget = 5 * time.Minute
	budgetEnd := time.Now().Add(accessDeniedBudget)
	if budgetEnd.After(deadline) {
		budgetEnd = deadline
	}
	for {
		result, err := r.data.Client.PutRegistration(ctx, ns, name, spec, opts)
		if err == nil {
			return result, nil
		}
		apiErr, ok := client.AsAPIError(err)
		if !ok || apiErr.Code() != contracts.CodeDestinationAccessDenied || !apiErr.HasRetryAfter {
			return nil, err
		}
		wait := apiErr.RetryAfter
		if wait <= 0 {
			wait = 10 * time.Second
		}
		if time.Now().Add(wait).After(budgetEnd) {
			return nil, err
		}
		tflog.Info(ctx, "the publishing identity cannot yet manage the destination vault; retrying while the role assignment propagates",
			map[string]any{"retry_after_seconds": wait.Seconds()})
		if err := r.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// deferralFailsFast implements §7.1.6.
//
// A bulk onboarding is deferred BY DESIGN and the deferral horizon is DAYS. No
// timeouts.create accommodates that, and the alternative is ten resources each
// sitting at "Still creating... [59m50s elapsed]" and then failing.
func (r *certificateResource) deferralFailsFast(estimatedStart string, deadline time.Time, timeout time.Duration, ns string) (bool, diag.Diagnostic) {
	start, err := time.Parse(time.RFC3339, estimatedStart)
	if err != nil {
		return false, nil
	}
	if !start.After(deadline) {
		return false, nil
	}
	return true, diag.NewErrorDiagnostic(
		"Issuance is queued behind a certificate authority rate limit ("+DiagCreateDeferredBeyondTimeout+")",
		fmt.Sprintf(
			"The service deferred this issuance until %s, which is beyond `timeouts.create` (%s).\n\n"+
				"THE REGISTRATION HAS BEEN CREATED and will issue automatically when the budget resets. Nothing further "+
				"is required, and re-running `terraform apply` will not make it happen sooner.\n\n"+
				"To let this apply succeed now, set `wait_for = \"accepted\"` (see the note about "+
				"`versionless_secret_id` being withheld until publication) and re-run, or re-run after the reset.\n\n"+
				"Namespace: %s",
			estimatedStart, timeout, ns))
}

func (r *certificateResource) addCreateError(ctx context.Context, diags *diag.Diagnostics, plan certificateResourceModel, err error) {
	apiErr, ok := client.AsAPIError(err)
	if !ok {
		diags.AddError("Could not create the certificate registration", err.Error())
		return
	}
	switch {
	case apiErr.Status == http.StatusConflict && apiErr.Code() == contracts.CodeRegistrationExists:
		diags.AddError("A registration with this name already exists in this namespace",
			fmt.Sprintf("%s\n\nImport it instead of creating it:\n\n    terraform import azureacme_certificate.%s %s/%s\n\n%s",
				apiErr.Title(), plan.Name.ValueString(), plan.Namespace.ValueString(), plan.Name.ValueString(),
				nextActionLine(apiErr)))
	case apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusForbidden ||
		apiErr.Status == http.StatusUnprocessableEntity:
		addFieldErrors(ctx, diags, apiErr, plan)
	default:
		diags.AddError(fmt.Sprintf("Could not create the certificate registration (HTTP %d)", apiErr.Status),
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	}
}

// ------------------------------------------------------------------------ Read

func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.data == nil || r.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client. This is a provider defect.")
		return
	}

	ns, name := state.Namespace.ValueString(), state.Name.ValueString()
	reg, _, err := r.data.Client.GetRegistration(ctx, ns, name, false)

	decision := DecideRead(err, ReadContext{
		Endpoint:                  r.data.Client.Endpoint(),
		Address:                   "azureacme_certificate " + ns + "/" + name,
		PinnedServiceInstanceID:   state.ServiceInstanceID.ValueString(),
		PinnedServiceInstanceName: r.data.ServiceInstanceName(),
		SkipInstanceCheck:         r.data.SkipInstanceCheck,
		CredentialMethod:          r.data.Client.CredentialMethod(),
	})

	switch decision.Action {
	case ReadActionRemove:
		tflog.Info(ctx, "the registration is gone; removing it from state", map[string]any{
			"namespace": ns, "name": name,
		})
		resp.State.RemoveResource(ctx)
		return
	case ReadActionError:
		resp.Diagnostics.AddError(decision.Summary, decision.Detail)
		return
	case ReadActionSuccess:
		// fall through
	default:
		// The zero value must never reach here. If it does, the safe answer is an
		// error that retains state.
		resp.Diagnostics.AddError("The provider could not classify the refresh result",
			"This is a provider defect. Nothing has been removed from state.")
		return
	}

	// --- the 200 rows of §7.2.2 ---------------------------------------------
	switch reg.Status.LifecycleState {
	case "deleting":
		resp.Diagnostics.AddWarning("This registration is being decommissioned ("+DiagRegistrationDecommissioning+")",
			fmt.Sprintf("`%s/%s` has `lifecycle_state = \"deleting\"`: a decommissioning operation is in progress on the "+
				"service. The resource remains in state; remove it from configuration once the decommission completes.", ns, name))
	case "authorization_revoked":
		resp.Diagnostics.AddWarning("Renewal has stopped: this registration's authorisation was withdrawn ("+DiagAuthorizationRevoked+")",
			fmt.Sprintf("`%s/%s` has `lifecycle_state = \"authorization_revoked\"`. The grant that authorised these "+
				"identifiers or this destination has been withdrawn, so RENEWAL HAS STOPPED. The published certificate is "+
				"RETAINED and remains in service until it expires, and the registration stays in Terraform state.\n\n"+
				"Ask your platform administrator to restore the authorisation, or remove this resource deliberately.", ns, name))
	}

	prior := state
	newState := state
	resp.Diagnostics.Append(applySpecFromResponse(ctx, reg, &newState, prior)...)
	resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &newState, r.data.Environment)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// ---------------------------------------------------------------------- Update

func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// --- short circuit: wait_for and timeouts are CLIENT-ONLY ---------------
	//
	// They are never sent to the API, so a change to either must make NO HTTP
	// request at all. Sending one would bump spec.revision for nothing.
	if onlyClientOnlyChanged(ctx, state, plan) {
		merged := state
		merged.WaitFor = plan.WaitFor
		merged.Timeouts = plan.Timeouts
		resp.Diagnostics.Append(resp.State.Set(ctx, &merged)...)
		return
	}

	spec, diags := buildSpecFromPlan(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	revision := state.SpecRevision.ValueInt64()
	updateTimeout := r.timeoutFor(ctx, plan, "update", DefaultUpdateTimeout, &resp.Diagnostics)
	deadline := time.Now().Add(updateTimeout)
	ns, name := plan.Namespace.ValueString(), plan.Name.ValueString()

	result, err := r.data.Client.PutRegistration(ctx, ns, name, spec, client.PutOptions{
		IfMatchRevision: &revision, IdempotencyKey: client.NewULID(),
	})
	if err != nil {
		r.addUpdateError(ctx, resp, plan, state, revision, err)
		return
	}

	reg := result.Registration
	if result.Accepted != nil {
		outcome := r.waitForCompletion(ctx, waitRequest{
			Namespace: ns, Name: name, OperationID: result.Accepted.OperationID,
			TargetGeneration: result.Accepted.TargetGeneration, Deadline: deadline,
		})
		if outcome.Registration != nil {
			reg = outcome.Registration
		}
		if !outcome.Published {
			// On failure or timeout, write THE SERVER'S current representation,
			// not the plan. Update failures do not taint, so the safest state is a
			// truthful one: the next plan then correctly re-proposes the change.
			// Writing the PLANNED spec would make Terraform believe the change
			// landed.
			r.writeServerTruth(ctx, resp, ns, name, state)
			resp.Diagnostics.AddError("The update did not complete",
				fmt.Sprintf("Operation: %s\nPhase: %s\n\nState now reflects what the SERVICE reports, not the planned "+
					"change, so the next plan will correctly re-propose it.",
					orNone(outcome.OperationID), orNone(outcome.LastPhase)))
			return
		}
	}
	if reg == nil {
		r.writeServerTruth(ctx, resp, ns, name, state)
		resp.Diagnostics.AddError("The service returned no registration for the update",
			"State now reflects what the service reports.")
		return
	}

	final := plan
	resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &final, r.data.Environment)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

func (r *certificateResource) writeServerTruth(ctx context.Context, resp *resource.UpdateResponse, ns, name string, prior certificateResourceModel) {
	reg, _, err := r.data.Client.GetRegistration(ctx, ns, name, false)
	if err != nil || reg == nil {
		return
	}
	truth := prior
	resp.Diagnostics.Append(applySpecFromResponse(ctx, reg, &truth, prior)...)
	resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &truth, r.data.Environment)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &truth)...)
}

func (r *certificateResource) addUpdateError(ctx context.Context, resp *resource.UpdateResponse, plan, state certificateResourceModel, revision int64, err error) {
	apiErr, ok := client.AsAPIError(err)
	if !ok {
		resp.Diagnostics.AddError("Could not update the certificate registration", err.Error())
		return
	}
	ns, name := plan.Namespace.ValueString(), plan.Name.ValueString()
	switch apiErr.Code() {
	case contracts.CodeSpecRevisionConflict:
		// Re-GET ONCE, name both revisions and the last actor, and NEVER retry
		// with If-Match: *. An unconditional retry is how one workspace silently
		// overwrites another's change.
		current := int64(-1)
		lastActor := "unknown"
		if reg, _, gerr := r.data.Client.GetRegistration(ctx, ns, name, false); gerr == nil && reg != nil {
			current = reg.Spec.Revision
			if reg.Status.Audit != nil && reg.Status.Audit.UpdatedBy != nil {
				lastActor = *reg.Status.Audit.UpdatedBy
			}
			truth := state
			resp.Diagnostics.Append(applySpecFromResponse(ctx, reg, &truth, state)...)
			resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &truth, r.data.Environment)...)
			resp.Diagnostics.Append(resp.State.Set(ctx, &truth)...)
		}
		resp.Diagnostics.AddError("The registration changed since this plan was made",
			fmt.Sprintf("Terraform planned against `spec_revision = %d`; the service is at `spec_revision = %d`.\n\n"+
				"Last changed by: %s.\n\n%s\n\nThe provider will NOT retry unconditionally: doing so would silently "+
				"overwrite whatever the other writer changed. Re-run `terraform plan` to see the current state and decide.",
				revision, current, lastActor, detailLine(apiErr)))
	case contracts.CodeDestinationOwnedElsewhere, contracts.CodeOwnershipConflict:
		resp.Diagnostics.AddError("Another registration owns this destination",
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRequest id: %s", apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	case contracts.CodeDeletionPolicyConflict:
		resp.Diagnostics.AddError("The deletion policy conflicts with the one the service has persisted",
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nA `?policy=` may only NARROW the persisted policy, never widen it.\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	case contracts.CodeInvalidSpec:
		addFieldErrors(ctx, &resp.Diagnostics, apiErr, plan)
	default:
		resp.Diagnostics.AddError(fmt.Sprintf("Could not update the certificate registration (HTTP %d)", apiErr.Status),
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRequest id: %s", apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	}
}

// ---------------------------------------------------------------------- Delete

func (r *certificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ns, name := state.Namespace.ValueString(), state.Name.ValueString()
	deleteTimeout := r.timeoutFor(ctx, state, "delete", DefaultDeleteTimeout, &resp.Diagnostics)
	deadline := time.Now().Add(deleteTimeout)

	opts := client.DeleteOptions{Policy: state.DeletionPolicy.ValueString()}
	// If-Match is OMITTED rather than failing a destroy on a stale revision.
	_, accepted, err := r.data.Client.DeleteRegistration(ctx, ns, name, opts)
	if err != nil {
		apiErr, ok := client.AsAPIError(err)
		if !ok {
			resp.Diagnostics.AddError("Could not delete the certificate registration", err.Error())
			return
		}
		// 404 and 410 are IDEMPOTENT SUCCESS: a DELETE that can refuse makes
		// `terraform destroy` non-idempotent and strands the resource forever.
		if apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusGone {
			return
		}
		r.addDeleteError(&resp.Diagnostics, apiErr, ns, name)
		return
	}
	if accepted != nil {
		outcome := r.waitForCompletion(ctx, waitRequest{
			Namespace: ns, Name: name, OperationID: accepted.OperationID,
			TargetGeneration: accepted.TargetGeneration, Deadline: deadline,
			OperationTerminalIsSuccess: true,
		})
		if outcome.Err == nil && !outcome.Failed && !outcome.Published && outcome.TimedOut {
			resp.Diagnostics.AddError("Timed out waiting for the registration to be decommissioned",
				fmt.Sprintf("Operation: %s\n\nThe resource has been left in state. Re-running `terraform destroy` retries; "+
					"delete is idempotent, so a second attempt is safe.", orNone(outcome.OperationID)))
			return
		}
	}
}

func (r *certificateResource) addDeleteError(diags *diag.Diagnostics, apiErr *client.APIError, ns, name string) {
	addr := "azureacme_certificate." + name
	switch apiErr.Code() {
	case contracts.CodeOperationInFlight:
		diags.AddError("An operation is still in flight for this registration",
			fmt.Sprintf("%s\n\n%s\n\nThis guard is what makes recovery from a create timeout safe: the service refuses to "+
				"destroy a registration whose issuance is still running.\n\nWait for the operation to finish, then:\n\n"+
				"    terraform untaint %s && terraform apply\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), addr, apiErr.RequestID()))
	case contracts.CodeDestinationRecentlyPublished:
		diags.AddError("The certificate was published after this workspace last observed it",
			fmt.Sprintf("%s\n\n%s\n\nRefresh before destroying:\n\n    terraform refresh\n\nThen re-plan. The service "+
				"refuses the delete because destroying now would discard a certificate this workspace has never seen.\n\n"+
				"Request id: %s", apiErr.Title(), detailLine(apiErr), apiErr.RequestID()))
	case contracts.CodeDeletionPolicyConflict:
		diags.AddError("The requested deletion policy conflicts with the persisted one",
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nThe server's persisted policy is authoritative and `?policy=` may only "+
				"NARROW it, so a stale `delete` in one workspace's state can no longer override a platform "+
				"administrator's later change to `retain`.\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	case contracts.CodeDestinationShared:
		diags.AddError("This registration does not exclusively own its destination",
			fmt.Sprintf("%s\n\n%s\n\nSet `deletion_policy = \"retain\"` and destroy again: deleting a shared destination "+
				"would remove a certificate another registration is publishing to.\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), apiErr.RequestID()))
	case contracts.CodeDestinationSoftDeleted:
		diags.AddError("The destination certificate is soft-deleted",
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRecovery route: POST .../actions/recover-destination.\n\n"+
				"Key Vault soft-delete holds the certificate NAME for the vault's retention period (7 to 90 days, "+
				"configurable only at vault creation), so the name cannot be reused until it expires or is purged. "+
				"`az keyvault certificate purge` is unavailable while purge protection is enabled. The provider never "+
				"purges automatically.\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	default:
		diags.AddError(fmt.Sprintf("Could not delete the certificate registration (HTTP %d)", apiErr.Status),
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRequest id: %s", apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
	}
}

// ----------------------------------------------------------------- ImportState

// ImportState parses the COMPOSITE id explicitly. resource.ImportStatePassthroughID
// is not used: the id is `{namespace}/{name}`, and passthrough would write the
// whole string into `id` and leave `namespace` and `name` empty.
func (r *certificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ns, name, err := ParseImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id", err.Error())
		return
	}
	if r.data == nil || r.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client. This is a provider defect.")
		return
	}

	// The explicit MANAGEMENT-INTENT call. ImportState is followed by Read, which
	// the service cannot distinguish from an ordinary refresh — so without this,
	// any principal holding only `Certificates.Read` could import a registration
	// into their own state and manage it. That is a silent ownership transfer.
	reg, _, err := r.data.Client.GetRegistration(ctx, ns, name, true)
	if err != nil {
		if apiErr, ok := client.AsAPIError(err); ok && apiErr.Status == http.StatusForbidden {
			resp.Diagnostics.AddError("Not authorised to MANAGE this registration",
				fmt.Sprintf("%s\n\nImport requires `Certificates.Manage` on namespace %q, not merely `Certificates.Read`. "+
					"The provider proves management intent with `?intent=manage` precisely so that a reader cannot import a "+
					"registration into their own state and then manage it.\n\n%s\n\nRequest id: %s",
					apiErr.Title(), ns, nextActionLine(apiErr), apiErr.RequestID()))
			return
		}
		decision := DecideRead(err, ReadContext{
			Endpoint: r.data.Client.Endpoint(), Address: ns + "/" + name,
			SkipInstanceCheck: r.data.SkipInstanceCheck, CredentialMethod: r.data.Client.CredentialMethod(),
		})
		if decision.Action == ReadActionRemove {
			resp.Diagnostics.AddError("There is no such registration to import",
				fmt.Sprintf("The service reports that %q does not exist in namespace %q.", name, ns))
			return
		}
		resp.Diagnostics.AddError(decision.Summary, decision.Detail)
		return
	}

	// Ownership. Importing a registration owned by another principal would move
	// management silently.
	caller := r.data.CallerPrincipalID()
	if reg.Status.Ownership != nil && reg.Status.Ownership.OwnerPrincipalID != nil && caller != "" &&
		*reg.Status.Ownership.OwnerPrincipalID != caller {
		owner := *reg.Status.Ownership.OwnerPrincipalID
		display := ""
		if reg.Status.Ownership.OwnerDisplayName != nil {
			display = " (" + *reg.Status.Ownership.OwnerDisplayName + ")"
		}
		resp.Diagnostics.AddError("This registration is owned by a different principal ("+DiagOwnershipTransferRequired+")",
			fmt.Sprintf("`%s/%s` is owned by %s%s; this workspace authenticates as %s.\n\n"+
				"Ownership transfer is never implicit. To take ownership, the current owner or a platform administrator "+
				"must run:\n\n    POST /v1/namespaces/%s/certificates/%s/actions/claim\n        {\"acknowledge_transfer\": true}\n\n"+
				"which requires `Certificates.Manage` in the namespace and a registration marked `transferable`.",
				ns, name, owner, display, caller, ns, name))
		return
	}

	var m certificateResourceModel
	// Client-only seeding: without this the first plan shows a spurious
	// `null -> "published"` diff on wait_for.
	m.WaitFor = types.StringValue(WaitForPublished)
	m.Timeouts = types.ObjectNull(timeoutsAttrTypes())
	m.CertificateName = types.StringNull()
	m.Labels = types.MapNull(types.StringType)
	m.Verification = types.ObjectNull(verificationAttrTypes())

	resp.Diagnostics.Append(applySpecFromResponse(ctx, reg, &m, m)...)
	resp.Diagnostics.Append(applyComputedFromResponse(ctx, reg, &m, r.data.Environment)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ParseImportID splits `{namespace}/{name}`.
func ParseImportID(id string) (namespace, name string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf(
			"expected an import id of the form {namespace}/{name}, for example:\n\n"+
				"    terraform import azureacme_certificate.api payments-prod/payments-api\n\n"+
				"received: %q", id)
	}
	if !nameRE.MatchString(parts[0]) {
		return "", "", fmt.Errorf("the namespace %q in import id %q does not match %s", parts[0], id, nameRE.String())
	}
	if !nameRE.MatchString(parts[1]) {
		return "", "", fmt.Errorf("the name %q in import id %q does not match %s", parts[1], id, nameRE.String())
	}
	return parts[0], parts[1], nil
}

// ------------------------------------------------------------------- helpers

func (r *certificateResource) timeoutFor(ctx context.Context, m certificateResourceModel, which, fallback string, diags *diag.Diagnostics) time.Duration {
	raw := fallback
	if !m.Timeouts.IsNull() && !m.Timeouts.IsUnknown() {
		attrs := m.Timeouts.Attributes()
		if v, ok := attrs[which]; ok {
			if s, ok := v.(basetypes.StringValue); ok && !s.IsNull() && !s.IsUnknown() && s.ValueString() != "" {
				raw = s.ValueString()
			}
		}
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		diags.AddAttributeError(path.Root("timeouts").AtName(which),
			fmt.Sprintf("Invalid timeout %q", raw),
			fmt.Sprintf("Expected a Go duration such as %q. %v", fallback, err))
		d, _ = time.ParseDuration(fallback)
	}
	return d
}

// onlyClientOnlyChanged decides the Update short-circuit.
func onlyClientOnlyChanged(ctx context.Context, state, plan certificateResourceModel) bool {
	specState := state
	specPlan := plan
	// Neutralise the client-only and computed halves, then compare what is left.
	specState.WaitFor, specPlan.WaitFor = types.StringNull(), types.StringNull()
	specState.Timeouts, specPlan.Timeouts = types.ObjectNull(timeoutsAttrTypes()), types.ObjectNull(timeoutsAttrTypes())
	return specEqual(ctx, specState, specPlan)
}

func orNone(s string) string {
	if s == "" {
		return "(none reported)"
	}
	return s
}

func optionalLine(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

var _ = schema.Schema{}
