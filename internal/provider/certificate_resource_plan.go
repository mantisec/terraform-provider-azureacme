package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
)

// ModifyPlan implements terraform-provider-contract.md §6.2 and the two §6.3
// refinements.
func (r *certificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// ---------------------------------------------------------------- destroy
	if req.Plan.Raw.IsNull() {
		r.warnConsumerInServiceOnDestroy(ctx, req, resp)
		return
	}

	var plan certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// -------------------------------------------- capability-backed validation
	//
	// These run at PLAN time against the CACHED capabilities response, so an
	// authorisation or policy mistake lands in the plan rather than after
	// `terraform apply` has already changed other resources (F-066).
	r.validateAgainstCapabilities(ctx, plan, &resp.Diagnostics)

	isCreate := req.State.Raw.IsNull()
	if !isCreate {
		var state certificateResourceModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// --- §6.2.1 destination change: a plan-time ERROR, not a replacement ---
		//
		// SKIPPED ON A REPLACEMENT. When `namespace` or `name` changes the
		// registration is being REPLACED, and `certificate_name` defaults to
		// `name`, so the effective Key Vault object name changes as a
		// consequence. That is a new object, not a MOVE of an existing one, and
		// treating it as a destination change would make renaming impossible —
		// contradicting §6.1, which makes `namespace` and `name` the only two
		// RequiresReplace attributes.
		replacing := len(resp.RequiresReplace) > 0 ||
			!state.Namespace.Equal(plan.Namespace) || !state.Name.Equal(plan.Name)
		if !replacing {
			if diags := destinationChangeDiagnostics(state, plan, r.data.HasFeature("destination_migration")); len(diags) > 0 {
				resp.Diagnostics.Append(diags...)
				return
			}
		}

		// --- §6.2.2 replacement with deletion_policy = "delete" --------------
		if len(resp.RequiresReplace) > 0 && plan.DeletionPolicy.ValueString() == "delete" {
			certName := state.ResolvedCertificateName.ValueString()
			if certName == "" {
				certName = state.effectiveCertificateName()
			}
			resp.Diagnostics.AddWarning(
				"This change replaces the registration and will SOFT-DELETE the live certificate ("+DiagReplacementWillDeleteCert+")",
				fmt.Sprintf("Changing `namespace` or `name` replaces the registration. Because `deletion_policy = \"delete\"`, "+
					"destroying the old one soft-deletes the Key Vault certificate %q in %s.\n\n"+
					"Key Vault soft-delete holds the NAME for the vault's retention period (7 to 90 days, configurable only "+
					"at vault creation), during which the name cannot be reused. Any Application Gateway listener bound to it "+
					"is disabled.\n\nUse `deletion_policy = \"retain\"` if you want the old certificate left in place.",
					certName, state.KeyVaultID.ValueString()))
		}

		// --- §6.2.3 reissue warning — plan honesty ---------------------------
		if issuanceRelevantChanged(ctx, state, plan) {
			resp.Diagnostics.AddWarning(
				"This change will issue a new certificate ("+DiagReissueExpected+")",
				"The current certificate remains in service until the new one is published. Expect 3–15 minutes, longer if "+
					"the registered domain's rate-limit budget is constrained.\n\n"+
					"Without this warning a one-word `description` edit and a full reissue render identically as "+
					"`~ update in place`.")
		} else {
			// --- §6.3 refinement 2: conditional UseStateForUnknown ------------
			//
			// When the only changes are metadata or client-only, the certificate
			// cannot change — so carrying the state value forward keeps a
			// description edit from rendering six fields including
			// `thumbprint_sha256` and `not_after` as `(known after apply)`, which
			// to a plan reviewer looks like a certificate replacement.
			plan.CurrentCertificate = state.CurrentCertificate
			plan.ResolvedACMEProfile = state.ResolvedACMEProfile
			plan.ResolvedValidationBinding = state.ResolvedValidationBinding
			plan.FulfilledGeneration = state.FulfilledGeneration
			plan.Generation = state.Generation
			plan.LastSuccessfulRenewalAt = state.LastSuccessfulRenewalAt
		}
	}

	// --- §6.3 refinement 1: compute the versionless URIs at PLAN time --------
	r.planVersionlessURIs(ctx, &plan, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// planVersionlessURIs fills the two consumption URIs from values all known at
// plan time, removing an unknown-value cascade from every consumer resource on
// the first apply.
//
// EXCEPTION (§7.1.5): when wait_for != "published" the URIs are planned as NULL,
// not as the constructed value. The versionless secret URI is valid but EMPTY
// until a version exists, so handing it out early produces a successful apply and
// a listener bound to nothing.
func (r *certificateResource) planVersionlessURIs(ctx context.Context, plan *certificateResourceModel, diags *diag.Diagnostics) {
	if plan.WaitFor.ValueString() != WaitForPublished {
		// §7.1.5 withholds the URIs "UNTIL A READ OBSERVES delivery_stage =
		// published" — not forever. Once state holds a real URI, retracting it
		// would plan a spurious change on every run and, worse, would null out a
		// value consumers are already bound to. Only an UNKNOWN (nothing observed
		// yet) is withheld.
		if plan.VersionlessSecretID.IsUnknown() {
			plan.VersionlessSecretID = types.StringNull()
		}
		if plan.VersionlessCertificateID.IsUnknown() {
			plan.VersionlessCertificateID = types.StringNull()
		}
		return
	}
	if !plan.VersionlessSecretID.IsUnknown() && !plan.VersionlessSecretID.IsNull() {
		return
	}
	if plan.KeyVaultID.IsUnknown() || plan.KeyVaultID.IsNull() || plan.Name.IsUnknown() {
		return
	}
	if !plan.CertificateName.IsNull() && plan.CertificateName.IsUnknown() {
		return
	}
	environment := "public"
	if r.data != nil && r.data.Environment != "" {
		environment = r.data.Environment
	}
	secretURI, certURI, ok := buildVersionlessURIs(plan.KeyVaultID.ValueString(), plan.effectiveCertificateName(), environment)
	if !ok {
		return
	}
	plan.VersionlessSecretID = types.StringValue(secretURI)
	plan.VersionlessCertificateID = types.StringValue(certURI)
	plan.ResolvedCertificateName = types.StringValue(plan.effectiveCertificateName())
}

// destinationChangeDiagnostics implements §6.2.1.
//
// Terraform's default replacement order is DESTROY THEN CREATE. Marking
// `key_vault_id` RequiresReplace would destroy the registration — with
// `deletion_policy = "delete"`, soft-deleting the live certificate an Application
// Gateway is currently serving, which disables the listener — and only THEN
// create the replacement, which must run a full ACME issuance. That is an outage
// of the entire issuance time. `create_before_destroy` cannot rescue it: the
// logical key {namespace}/{name} is unchanged, so the create half collides with
// the still-existing registration.
//
// The message LEADS WITH THE UNBLOCKING INSTRUCTION, because a ModifyPlan error
// aborts the WHOLE plan and the workspace is unplannable for everyone — including
// colleagues running unrelated plans — until someone reverts the edit.
func destinationChangeDiagnostics(state, plan certificateResourceModel, migrationSupported bool) diag.Diagnostics {
	var diags diag.Diagnostics
	if migrationSupported {
		// When the service advertises `destination_migration` this relaxes to an
		// in-place update. NOTE FOR WHOEVER SHIPS THAT: the UseStateForUnknown on
		// versionless_secret_id and versionless_certificate_id is justified today
		// only by "derived solely from a destination that cannot change in place",
		// and MUST be removed in the same release, or a moved certificate silently
		// keeps the old vault's URI in state.
		return diags
	}
	type change struct {
		attribute string
		was, now  string
	}
	var changes []change
	if !state.KeyVaultID.IsNull() && !plan.KeyVaultID.IsUnknown() &&
		armid.Canonical(state.KeyVaultID.ValueString()) != armid.Canonical(plan.KeyVaultID.ValueString()) {
		changes = append(changes, change{"key_vault_id", state.KeyVaultID.ValueString(), plan.KeyVaultID.ValueString()})
	}
	if !plan.CertificateName.IsUnknown() && state.effectiveCertificateName() != plan.effectiveCertificateName() {
		changes = append(changes, change{"certificate_name", state.effectiveCertificateName(), plan.effectiveCertificateName()})
	}
	if destinationIDMoves(state, plan) {
		changes = append(changes, change{"destination_id", state.DestinationID.ValueString(), plan.DestinationID.ValueString()})
	}
	if len(changes) == 0 {
		return diags
	}
	first := changes[0]
	var b strings.Builder
	if first.was == "" {
		// A destination attribute that was NOT SET before. "revert to \"\"" is not
		// an instruction anyone can follow, and this message is the only thing
		// standing between the reader and an unplannable workspace, so it leads
		// with the edit that actually unblocks them: delete the line.
		fmt.Fprintf(&b, "  To unblock planning, REMOVE `%s` from this resource; it was not set before this change.\n\n",
			first.attribute)
	} else {
		fmt.Fprintf(&b, "  To unblock planning, revert `%s` to\n  %q.\n\n", first.attribute, first.was)
	}
	if len(changes) > 1 {
		b.WriteString("  Other changed destination attributes: ")
		for i, c := range changes[1:] {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "`%s` (was %q)", c.attribute, c.was)
		}
		b.WriteString("\n\n")
	}
	b.WriteString("  The destination Key Vault or certificate name cannot be changed in place, and replacing the\n" +
		"  registration would delete the live certificate before a replacement is issued.\n\n" +
		"  To move this certificate:\n" +
		"    1. Add a new azureacme_certificate resource with a new `name` and the new destination.\n" +
		"    2. Apply, and wait for `delivery_stage = published`.\n" +
		"    3. Repoint consumers at the new `versionless_secret_id` and wait out the consumer's\n" +
		"       pickup window (Application Gateway 4h; Front Door up to 72h).\n" +
		"    4. Remove the old resource with a `removed` block; `deletion_policy = \"retain\"` leaves\n" +
		"       the old certificate in place.\n\n" +
		"  In v1 a certificate cannot move between vaults. (" + DiagDestinationChangeUnsupported + ")")
	diags.AddAttributeError(path.Root(first.attribute),
		"Changing the destination of an existing certificate registration is not supported", b.String())
	return diags
}

// destinationIDMoves answers the only question §6.2.1 actually cares about for
// `destination_id`: does this edit MOVE the certificate to a different
// destination policy?
//
// PROVISIONAL(D-20) makes the destination server-resolved, so three of the four
// transitions are not moves and must not abort the plan:
//
//   - null → null: nothing asserted, nothing changed.
//   - value → null: the user STOPS asserting a policy. The service goes on
//     resolving the same vault to the same policy, so nothing moves. Treating
//     this as a move would make `destination_id` impossible to delete once
//     written — the §5.3.1 trap re-entering through ModifyPlan rather than
//     through the schema.
//   - null → the policy the server already resolved: the user STARTS asserting
//     the status quo, which is the single most likely first edit after reading
//     `resolved_destination_id`. Refusing it would make adding the attribute
//     abort the workspace for a change that moves nothing.
//
// Only an assertion that names a DIFFERENT policy from the one in effect is a
// move, and that is the case the §6.2.1 error is for.
func destinationIDMoves(state, plan certificateResourceModel) bool {
	if plan.DestinationID.IsUnknown() {
		return false
	}
	if plan.DestinationID.IsNull() {
		return false
	}
	proposed := plan.DestinationID.ValueString()
	if !state.DestinationID.IsNull() && !state.DestinationID.IsUnknown() {
		return proposed != state.DestinationID.ValueString()
	}
	// Nothing was asserted before. The server's resolved policy is the value in
	// effect, so asserting it is a no-op and asserting anything else is a move.
	if state.ResolvedDestinationID.IsNull() || state.ResolvedDestinationID.IsUnknown() {
		// Nothing to compare against (an older state, or an import that has not
		// refreshed). Do not abort the whole plan on a value that may well be
		// correct; the service rejects a mismatched assertion at apply with a
		// field error on `spec.destination.destination_id`.
		return false
	}
	return proposed != state.ResolvedDestinationID.ValueString()
}

func (r *certificateResource) warnConsumerInServiceOnDestroy(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.data == nil || r.data.Client == nil || req.State.Raw.IsNull() {
		return
	}
	var state certificateResourceModel
	if diags := req.State.Get(ctx, &state); diags.HasError() {
		return
	}
	reg, _, err := r.data.Client.GetRegistration(ctx, state.Namespace.ValueString(), state.Name.ValueString(), false)
	if err != nil || reg == nil {
		return
	}
	if reg.Status.DeliveryStage != "consumer_observed" {
		return
	}
	endpoints := make([]string, 0, len(reg.Status.Consumers))
	for _, c := range reg.Status.Consumers {
		endpoints = append(endpoints, c.Host)
	}
	where := "an observing endpoint"
	if len(endpoints) > 0 {
		where = strings.Join(endpoints, ", ")
	}
	resp.Diagnostics.AddWarning(
		"A consumer is currently serving this certificate ("+DiagConsumerInServiceOnDestroy+")",
		fmt.Sprintf("The last observation showed `delivery_stage = \"consumer_observed\"` at %s.\n\n"+
			"Destroying this registration stops renewal. With `deletion_policy = \"delete\"` it also soft-deletes the Key "+
			"Vault certificate, which disables any Application Gateway listener bound to it.\n\n"+
			"The destroy is NOT refused: refusing would make `terraform destroy` non-idempotent and strand the resource in "+
			"state forever. Confirm this is intended.", where))
}

// issuanceRelevantChanged mirrors the server's issuance hash: only these fields
// can cause a reissue.
func issuanceRelevantChanged(ctx context.Context, state, plan certificateResourceModel) bool {
	if !setSemanticallyEqual(ctx, state.DNSNames, plan.DNSNames) {
		return true
	}
	if !objectEqualIgnoringUnknown(state.Key, plan.Key) {
		return true
	}
	if !state.CommonName.Equal(plan.CommonName) {
		return true
	}
	if !state.ACMEProfile.Equal(plan.ACMEProfile) {
		return true
	}
	if !state.ValidationBinding.Equal(plan.ValidationBinding) {
		return true
	}
	return false
}

// specEqual compares every SPEC attribute, ignoring computed values. It is what
// the Update short-circuit uses to decide that no API call is needed at all.
func specEqual(ctx context.Context, a, b certificateResourceModel) bool {
	if issuanceRelevantChanged(ctx, a, b) {
		return false
	}
	if armid.Canonical(a.KeyVaultID.ValueString()) != armid.Canonical(b.KeyVaultID.ValueString()) {
		return false
	}
	if a.effectiveCertificateName() != b.effectiveCertificateName() {
		return false
	}
	for _, pair := range [][2]interface {
		Equal(v interface {
			Type(context.Context) interface{}
		}) bool
	}{} {
		_ = pair
	}
	if !a.DestinationID.Equal(b.DestinationID) ||
		!a.ConsumerProfile.Equal(b.ConsumerProfile) ||
		!a.DeletionPolicy.Equal(b.DeletionPolicy) ||
		!a.AcknowledgeIrreversibleDelete.Equal(b.AcknowledgeIrreversibleDelete) ||
		!a.Description.Equal(b.Description) ||
		!a.Namespace.Equal(b.Namespace) ||
		!a.Name.Equal(b.Name) {
		return false
	}
	if !objectEqualIgnoringUnknown(a.Renewal, b.Renewal) {
		return false
	}
	if !objectEqualIgnoringUnknown(a.Verification, b.Verification) {
		return false
	}
	if !a.Labels.Equal(b.Labels) {
		return false
	}
	return true
}

func objectEqualIgnoringUnknown(a, b types.Object) bool {
	if a.IsUnknown() || b.IsUnknown() {
		return false
	}
	return a.Equal(b)
}

// setSemanticallyEqual compares two dns_names sets by CANONICAL form, so a
// case-varied or trailing-dotted spelling is not a change.
func setSemanticallyEqual(ctx context.Context, a, b types.Set) bool {
	if a.IsUnknown() || b.IsUnknown() {
		return false
	}
	if a.IsNull() != b.IsNull() {
		return false
	}
	var av, bv []string
	if diags := a.ElementsAs(ctx, &av, false); diags.HasError() {
		return a.Equal(b)
	}
	if diags := b.ElementsAs(ctx, &bv, false); diags.HasError() {
		return a.Equal(b)
	}
	if len(av) != len(bv) {
		return false
	}
	seen := map[string]int{}
	for _, s := range av {
		seen[canonicalDNS(s)]++
	}
	for _, s := range bv {
		seen[canonicalDNS(s)]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------ field mapping

// wirePathToAttribute is §5.5. Any wire path NOT in this table produces a
// resource-level error naming the path verbatim, rather than being silently
// dropped.
var wirePathToAttribute = map[string]path.Path{
	"spec.common_name":                     path.Root("common_name"),
	"spec.destination.key_vault_id":        path.Root("key_vault_id"),
	"spec.destination.certificate_name":    path.Root("certificate_name"),
	"spec.destination.destination_id":      path.Root("destination_id"),
	"spec.key.algorithm":                   path.Root("key").AtName("algorithm"),
	"spec.key.size":                        path.Root("key").AtName("size"),
	"spec.key.curve":                       path.Root("key").AtName("curve"),
	"spec.key.exportable":                  path.Root("key").AtName("exportable"),
	"spec.acme_profile":                    path.Root("acme_profile"),
	"spec.validation_binding":              path.Root("validation_binding"),
	"spec.consumer_profile":                path.Root("consumer_profile"),
	"spec.renewal.mode":                    path.Root("renewal").AtName("mode"),
	"spec.renewal.use_ari":                 path.Root("renewal").AtName("use_ari"),
	"spec.deletion_policy":                 path.Root("deletion_policy"),
	"spec.acknowledge_irreversible_delete": path.Root("acknowledge_irreversible_delete"),
	"spec.description":                     path.Root("description"),
	"spec.labels":                          path.Root("labels"),
}

// WirePathToAttributePath exposes the §5.5 map for testing.
func WirePathToAttributePath(wire string) (path.Path, bool) {
	if p, ok := wirePathToAttribute[wire]; ok {
		return p, true
	}
	if strings.HasPrefix(wire, "spec.verification.consumer_probe.") {
		leaf := strings.TrimPrefix(wire, "spec.verification.consumer_probe.")
		return path.Root("verification").AtName("consumer_probe").AtName(leaf), true
	}
	return path.Empty(), false
}

// addFieldErrors maps the service's `errors[].field` wire paths onto HCL
// attributes, so the user sees the error against the right line.
//
// `dns_names` is resolved BY VALUE: Set indices are meaningless in Terraform, so
// the server sends the offending value and the client finds the element.
//
// The SUMMARY line carries the offending value, not only the detail: a user
// debugging one bad name in a twenty-name set driven by a `for_each` gets no line
// number otherwise.
func addFieldErrors(ctx context.Context, diags *diag.Diagnostics, apiErr *client.APIError, m certificateResourceModel) {
	if len(apiErr.Problem.Errors) == 0 {
		diags.AddError(fmt.Sprintf("The service rejected the specification (HTTP %d)", apiErr.Status),
			fmt.Sprintf("%s\n\n%s\n\n%s\n\nRequest id: %s",
				apiErr.Title(), detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID()))
		return
	}
	for _, fe := range apiErr.Problem.Errors {
		value := decodeFieldValue(fe.Value)
		switch {
		case fe.Field == "spec.dns_names":
			p := dnsNameElementPath(ctx, m, value)
			summary := "Invalid DNS name"
			if value != "" {
				summary = fmt.Sprintf("Invalid DNS name: %s", value)
			}
			diags.AddAttributeError(p, summary,
				fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", fe.Message, nextActionLine(apiErr), apiErr.RequestID()))
		default:
			if p, ok := WirePathToAttributePath(fe.Field); ok {
				summary := fe.Message
				if value != "" {
					summary = fmt.Sprintf("%s: %s", fe.Message, value)
				}
				diags.AddAttributeError(p, summary,
					fmt.Sprintf("Code: %s\n\n%s\n\nRequest id: %s", fe.Code, nextActionLine(apiErr), apiErr.RequestID()))
			} else {
				diags.AddError(fmt.Sprintf("The service rejected %s", fe.Field),
					fmt.Sprintf("%s\n\nCode: %s\n\nThis field has no mapping to a Terraform attribute in this provider "+
						"build, so it is reported verbatim.\n\n%s\n\nRequest id: %s",
						fe.Message, fe.Code, nextActionLine(apiErr), apiErr.RequestID()))
			}
		}
	}
}

func decodeFieldValue(raw *json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(*raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(*raw))
}

// dnsNameElementPath resolves a Set element by VALUE, because Set indices are
// meaningless.
func dnsNameElementPath(ctx context.Context, m certificateResourceModel, value string) path.Path {
	base := path.Root("dns_names")
	if value == "" || m.DNSNames.IsNull() || m.DNSNames.IsUnknown() {
		return base
	}
	var names []string
	if diags := m.DNSNames.ElementsAs(ctx, &names, false); diags.HasError() {
		return base
	}
	target := canonicalDNS(value)
	for _, n := range names {
		if canonicalDNS(n) == target {
			return base.AtSetValue(basetypes.NewStringValue(n))
		}
	}
	return base
}

var _ = contracts.CodeInvalidSpec
