package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/dnsname"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
)

type currentCertificateModel struct {
	VersionSecretID      types.String   `tfsdk:"version_secret_id"`
	VersionCertificateID types.String   `tfsdk:"version_certificate_id"`
	ThumbprintSHA256     types.String   `tfsdk:"thumbprint_sha256"`
	SerialNumber         types.String   `tfsdk:"serial_number"`
	NotBefore            rfc3339.String `tfsdk:"not_before"`
	NotAfter             rfc3339.String `tfsdk:"not_after"`
	IssuedAt             rfc3339.String `tfsdk:"issued_at"`
	PublishedAt          rfc3339.String `tfsdk:"published_at"`
	Issuer               types.String   `tfsdk:"issuer"`
	ACMEProfile          types.String   `tfsdk:"acme_profile"`
}

// KeyVaultDNSSuffix maps the `environment` argument to the Key Vault DNS suffix
// used to construct versionless URIs (§2.2, §6.3 refinement 1). Getting this
// wrong hands every consumer a URI in the wrong cloud.
func KeyVaultDNSSuffix(environment string) string {
	switch strings.ToLower(environment) {
	case "usgovernment", "usgov", "usgovernmentcloud":
		return "vault.usgovcloudapi.net"
	case "china", "chinacloud":
		return "vault.azure.cn"
	default:
		return "vault.azure.net"
	}
}

// vaultNameFromID extracts the Key Vault name. An unparseable id yields "" and
// the caller then declines to construct a URI rather than constructing a wrong
// one.
func vaultNameFromID(id string) string {
	parsed, err := armid.Parse(id)
	if err != nil {
		return ""
	}
	return parsed.ResourceName()
}

// buildVersionlessURIs constructs the two consumption URIs from values all known
// at PLAN time: the vault id, the effective certificate name and the
// environment-derived DNS suffix. This is §6.3 refinement 1 — it removes an
// unknown-value cascade from every consumer resource on the first apply.
func buildVersionlessURIs(keyVaultID, certificateName, environment string) (secretURI, certURI string, ok bool) {
	vault := vaultNameFromID(keyVaultID)
	if vault == "" || certificateName == "" {
		return "", "", false
	}
	suffix := KeyVaultDNSSuffix(environment)
	return fmt.Sprintf("https://%s.%s/secrets/%s", vault, suffix, certificateName),
		fmt.Sprintf("https://%s.%s/certificates/%s", vault, suffix, certificateName),
		true
}

// applyComputedFromResponse writes the COMPUTED half of the state from the
// service's representation.
//
// Rule R-3 (§7.1.2): after Create and Update only Computed attributes may come
// from the response — Terraform Core rejects any apply whose result differs from
// a known planned value. Read is the opposite and additionally calls
// applySpecFromResponse.
func applyComputedFromResponse(
	ctx context.Context,
	reg *contracts.CertificateRegistration,
	m *certificateResourceModel,
	environment string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(reg.Namespace + "/" + reg.Name)
	m.RegistrationID = types.StringValue(reg.RegistrationID)
	m.ServiceInstanceID = types.StringValue(reg.ServiceInstanceID)
	m.SpecRevision = types.Int64Value(reg.Spec.Revision)
	m.Generation = types.Int64Value(reg.Spec.Generation)
	m.FulfilledGeneration = types.Int64Value(reg.Status.ObservedGeneration)
	m.ResolvedACMEProfile = stringOrNull(reg.Status.ResolvedACMEProfile)
	m.ResolvedValidationBinding = stringOrNull(reg.Status.ResolvedValidationBinding)
	m.ResolvedCertificateName = stringOrNull(reg.Status.ResolvedCertificateName)
	m.PublicationMode = stringOrNull(reg.Status.PublicationMode)

	// PROVISIONAL(D-20): the server's resolved destination policy. It lives HERE,
	// on a Computed attribute, and never in `destination_id` — see
	// destinationIDFromResponse.
	m.ResolvedDestinationID = types.StringNull()
	if reg.Spec.Destination != nil {
		m.ResolvedDestinationID = stringOrNull(reg.Spec.Destination.DestinationID)
	}

	m.LastSuccessfulRenewalAt = rfc3339.NewNull()
	if reg.Status.Renewal != nil {
		m.LastSuccessfulRenewalAt = rfc3339.NewValueFromPointer(reg.Status.Renewal.LastSuccessfulRenewalAt)
	}

	// --- current_certificate -------------------------------------------------
	if reg.Status.CurrentCertificate == nil {
		m.CurrentCertificate = types.ObjectNull(currentCertificateAttrTypes())
	} else {
		cc := reg.Status.CurrentCertificate
		// `thumbprint_sha256`, `not_before` and `not_after` are REQUIRED on
		// `CurrentCertificate` in contracts/api/openapi.yaml, so the generated
		// model decodes them into non-pointer strings and a field the service
		// omitted — or sent as `null` — arrives here as "".
		//
		// Left alone, "" reaches rfc3339.ValidateAttribute as a KNOWN, INVALID
		// timestamp, and the apply dies with `Invalid timestamp: ""` pointed at the
		// resource block. That names no field, no service, and no next action; it
		// reads as a provider bug; and because the value never lands in state it
		// also provokes Terraform's own "the provider still indicated an unknown
		// value … this is always a bug in the provider" on top. Two errors, one of
		// them actively misleading, for a missing field in a response.
		//
		// So the absence is diagnosed HERE, by name, and the attribute is written
		// null — which is a legal known value, so the misleading second error
		// disappears and the user is left with exactly one actionable one.
		missing := missingRequiredCertificateFields(cc)
		diags.Append(missingCertificateFieldDiagnostics(reg, missing)...)
		obj, d := types.ObjectValueFrom(ctx, currentCertificateAttrTypes(), currentCertificateModel{
			VersionSecretID:      stringOrNull(cc.VersionSecretID),
			VersionCertificateID: stringOrNull(cc.VersionCertificateID),
			ThumbprintSHA256:     requiredWireString(cc.ThumbprintSHA256),
			SerialNumber:         stringOrNull(cc.SerialNumber),
			NotBefore:            requiredWireTimestamp(cc.NotBefore),
			NotAfter:             requiredWireTimestamp(cc.NotAfter),
			IssuedAt:             rfc3339.NewValueFromPointer(cc.IssuedAt),
			PublishedAt:          rfc3339.NewValueFromPointer(cc.PublishedAt),
			Issuer:               stringOrNull(cc.Issuer),
			ACMEProfile:          stringOrNull(cc.ACMEProfile),
		})
		diags.Append(d...)
		m.CurrentCertificate = obj
	}

	// --- the two versionless URIs -------------------------------------------
	//
	// §7.1.5: when wait_for != "published" the URIs are NULL, not constructed.
	// The versionless secret URI is VALID BUT EMPTY until a version exists, so a
	// downstream reference would bind an Application Gateway listener to nothing
	// and Terraform could not detect it. Null makes the reference fail loudly.
	published := reg.Status.DeliveryStage != "pending" && reg.Status.CurrentCertificate != nil
	waitFor := m.WaitFor.ValueString()
	if waitFor == "" {
		waitFor = WaitForPublished
	}
	switch {
	case reg.Status.CurrentCertificate != nil && reg.Status.CurrentCertificate.VersionlessSecretID != nil:
		m.VersionlessSecretID = types.StringValue(*reg.Status.CurrentCertificate.VersionlessSecretID)
		m.VersionlessCertificateID = stringOrNull(reg.Status.CurrentCertificate.VersionlessCertificateID)
	case waitFor != WaitForPublished && !published:
		m.VersionlessSecretID = types.StringNull()
		m.VersionlessCertificateID = types.StringNull()
	default:
		certName := reg.Name
		if reg.Status.ResolvedCertificateName != nil {
			certName = *reg.Status.ResolvedCertificateName
		}
		vaultID := ""
		if reg.Spec.Destination != nil {
			vaultID = reg.Spec.Destination.KeyVaultID
		}
		if secretURI, certURI, ok := buildVersionlessURIs(vaultID, certName, environment); ok {
			m.VersionlessSecretID = types.StringValue(secretURI)
			m.VersionlessCertificateID = types.StringValue(certURI)
		} else {
			m.VersionlessSecretID = types.StringNull()
			m.VersionlessCertificateID = types.StringNull()
		}
	}
	return diags
}

// applySpecFromResponse writes the SPEC half of the state FROM THE SERVER.
//
// This is the opposite of rule R-3 and it is deliberate: it is how genuine
// out-of-band drift becomes visible. Cosmetic round-trip differences are absorbed
// by the semantic-equality types of §4, never by ignoring the server.
//
// Two carve-outs (§7.2.4):
//   - CLIENT-ONLY attributes (`wait_for`, `timeouts`) are never overwritten.
//     They are not sent to the API and the server has no opinion about them.
//   - DEFAULTED-NULL attributes are preserved: if `certificate_name` is null in
//     prior state and the server's resolved value equals `name`, it STAYS null.
//     Writing the resolved value would make the attribute impossible to revert.
func applySpecFromResponse(
	ctx context.Context,
	reg *contracts.CertificateRegistration,
	m *certificateResourceModel,
	prior certificateResourceModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.Namespace = types.StringValue(reg.Namespace)
	m.Name = types.StringValue(reg.Name)

	elems := make([]attr.Value, 0, len(reg.Spec.DNSNames))
	for _, n := range reg.Spec.DNSNames {
		elems = append(elems, dnsname.NewValue(n))
	}
	set, d := types.SetValue(dnsname.StringType{}, elems)
	diags.Append(d...)
	m.DNSNames = set

	m.CommonName = stringOrNull(reg.Spec.CommonName)

	if reg.Spec.Destination != nil {
		m.KeyVaultID = armid.NewValue(reg.Spec.Destination.KeyVaultID)

		// The defaulted-null rule. `certificate_name` is Optional WITHOUT
		// Computed precisely so that removing it reverts to `name`; writing the
		// server's resolved value back would defeat that.
		serverName := reg.Spec.Destination.CertificateName
		switch {
		case prior.CertificateName.IsNull() && serverName == reg.Name:
			m.CertificateName = types.StringNull()
		case serverName == "":
			m.CertificateName = types.StringNull()
		default:
			m.CertificateName = types.StringValue(serverName)
		}

		// THE SAME RULE, FOR `destination_id`, AND FOR THE SAME REASON.
		//
		// PROVISIONAL(D-20) makes the destination SERVER-RESOLVED: the caller
		// names a vault and the service answers with the destination POLICY it
		// resolved, whether or not the caller supplied one. Writing that answer
		// into `destination_id` — which is Optional WITHOUT Computed (§5.3.1) —
		// puts a value in state that the configuration does not declare, and the
		// very next `terraform plan` is not a diff but a HARD ERROR out of
		// ModifyPlan's destination-change check, which aborts the WHOLE plan: one
		// certificate makes the workspace unplannable for every resource in it and
		// for every colleague.
		//
		// So state holds the CONFIGURED value and the two are compared
		// semantically: when the caller asserted nothing, nothing is stored; when
		// the caller asserted a policy and the server resolved the same one, the
		// assertion is kept verbatim; and only a server answer that DISAGREES with
		// the assertion is written back, because that is genuine drift and is the
		// one case a user must see.
		m.DestinationID = destinationIDFromResponse(reg.Spec.Destination.DestinationID, prior.DestinationID)
	}

	keyObj, d := types.ObjectValueFrom(ctx, keyAttrTypes(), keyModel{
		Algorithm:  stringOrDefault(specKeyAlgorithm(reg), "RSA"),
		Size:       int64OrNull(specKeySize(reg)),
		Curve:      stringOrNull(specKeyCurve(reg)),
		Exportable: boolOrDefault(specKeyExportable(reg), true),
	})
	diags.Append(d...)
	m.Key = keyObj

	m.ACMEProfile = stringOrDefault(reg.Spec.ACMEProfile, ACMEProfileSentinel)
	m.ValidationBinding = stringOrDefault(reg.Spec.ValidationBinding, ValidationBindingSentinel)
	m.ConsumerProfile = stringOrNull(reg.Spec.ConsumerProfile)
	m.Description = stringOrNull(reg.Spec.Description)

	if reg.Spec.DeletionPolicy != nil {
		m.DeletionPolicy = types.StringValue(string(*reg.Spec.DeletionPolicy))
	} else {
		m.DeletionPolicy = types.StringValue("retain")
	}
	m.AcknowledgeIrreversibleDelete = boolOrDefault(reg.Spec.AcknowledgeIrreversibleDelete, false)

	renewalObj, d := types.ObjectValueFrom(ctx, renewalAttrTypes(), renewalModel{
		Mode:   stringOrDefault(specRenewalMode(reg), "automatic"),
		UseARI: boolOrDefault(specRenewalUseARI(reg), true),
	})
	diags.Append(d...)
	m.Renewal = renewalObj

	if len(reg.Spec.Labels) == 0 {
		if prior.Labels.IsNull() {
			m.Labels = types.MapNull(types.StringType)
		} else {
			mv, d := types.MapValueFrom(ctx, types.StringType, map[string]string{})
			diags.Append(d...)
			m.Labels = mv
		}
	} else {
		mv, d := types.MapValueFrom(ctx, types.StringType, reg.Spec.Labels)
		diags.Append(d...)
		m.Labels = mv
	}

	verification, d := verificationObjectFrom(ctx, reg.Spec.Verification, prior.Verification)
	diags.Append(d...)
	m.Verification = verification

	// Client-only, carried forward verbatim.
	m.WaitFor = prior.WaitFor
	m.Timeouts = prior.Timeouts
	return diags
}

// destinationIDFromResponse applies the defaulted-null rule of §7.2.4 to
// `destination_id`.
//
// `server` is the policy id the service resolved (PROVISIONAL D-20); `prior` is
// what the configuration asserted, carried in prior state. The configured value
// wins unless the server's answer contradicts it.
func destinationIDFromResponse(server *string, prior types.String) types.String {
	if prior.IsNull() || prior.IsUnknown() {
		// The caller asserted nothing. The server always has an answer, and
		// storing it would make the attribute unrevertible and the next plan a
		// hard error. The answer is in `resolved_destination_id`.
		return types.StringNull()
	}
	if server == nil || *server == "" || *server == prior.ValueString() {
		return prior
	}
	// The server resolved a DIFFERENT policy from the one the configuration
	// asserts. That is real drift and the user has to see it, so the server's
	// value goes into state and the next plan proposes putting it back.
	return types.StringValue(*server)
}

// verificationObjectFrom maps the service's `spec.verification` onto the
// `verification` attribute, PRESERVING THE CONFIGURED SHAPE whenever the two are
// semantically equal.
//
// The service's `apply_defaults` MATERIALISES this block: a request with no
// `verification` at all is stored as
// `{consumer_probe: {enabled: false, expected_pickup: null, endpoints: []}}`.
// `verification` is Optional WITHOUT Computed, so writing that materialised
// object into state makes every workspace that omits the block propose removing
// it — for ever. `Optional + Computed` is not the fix: a user who enabled a probe
// and then deleted the block would keep a probe running against endpoints their
// HCL no longer mentions, producing `consumer_stale` alerts with no visible cause
// (§5.3.1).
//
// So the server's object is built and then compared semantically against prior
// state. If they say the same thing, prior state is kept verbatim — which is what
// makes deleting the block genuinely revert it.
func verificationObjectFrom(ctx context.Context, spec *contracts.VerificationSpec, prior types.Object) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics
	if spec == nil || spec.ConsumerProbe == nil {
		// Nothing server-side. Null, not prior: an absent block and a default
		// block are the same statement, and prior is either null already or was
		// genuinely removed out of band.
		return types.ObjectNull(verificationAttrTypes()), diags
	}
	probe := spec.ConsumerProbe
	endpointValues := make([]attr.Value, 0, len(probe.Endpoints))
	for _, e := range probe.Endpoints {
		obj, d := types.ObjectValueFrom(ctx, probeEndpointAttrTypes(), probeEndpointModel{
			Host: types.StringValue(e.Host),
			Port: int64OrDefault(e.Port, 443),
			SNI:  stringOrNull(e.SNI),
		})
		diags.Append(d...)
		endpointValues = append(endpointValues, obj)
	}
	endpoints, d := types.ListValue(types.ObjectType{AttrTypes: probeEndpointAttrTypes()}, endpointValues)
	diags.Append(d...)

	probeObj, d := types.ObjectValueFrom(ctx, consumerProbeAttrTypes(), consumerProbeModel{
		Enabled:        boolOrDefault(probe.Enabled, false),
		ExpectedPickup: stringOrNull(probe.ExpectedPickup),
		Endpoints:      endpoints,
	})
	diags.Append(d...)

	obj, d := types.ObjectValue(verificationAttrTypes(), map[string]attr.Value{"consumer_probe": probeObj})
	diags.Append(d...)
	if diags.HasError() {
		return obj, diags
	}
	// THE SEMANTIC COMPARISON. Same meaning ⇒ keep what the configuration wrote.
	if equal, d := verificationSemanticallyEqual(ctx, prior, obj); d.HasError() {
		diags.Append(d...)
	} else if equal {
		return prior, diags
	}
	return obj, diags
}

// verificationSemanticallyEqual answers whether two `verification` objects say
// the same thing, across the three normalisations the service applies:
//
//   - an ABSENT block and a default probe (`enabled = false`, no pickup, no
//     endpoints) are the same statement;
//   - a NULL `endpoints` list and an EMPTY one are the same statement;
//   - a null `enabled` and `false` are the same statement.
//
// It is deliberately not `types.Object.Equal`: that is presence equality, and
// presence is exactly what the service rewrites.
func verificationSemanticallyEqual(ctx context.Context, a, b types.Object) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	if a.IsUnknown() || b.IsUnknown() {
		return false, diags
	}
	av, d := consumerProbeFacts(ctx, a)
	diags.Append(d...)
	bv, d := consumerProbeFacts(ctx, b)
	diags.Append(d...)
	if diags.HasError() {
		return false, diags
	}
	return av.equal(bv), diags
}

// probeFacts is the MEANING of a `verification` block, with every
// null-versus-empty-versus-absent distinction already collapsed.
type probeFacts struct {
	enabled        bool
	expectedPickup string
	endpoints      []probeEndpointFacts
}

type probeEndpointFacts struct {
	host string
	port int64
	sni  string
}

func (a probeFacts) equal(b probeFacts) bool {
	if a.enabled != b.enabled {
		return false
	}
	if !a.enabled {
		// A DISABLED PROBE DOES NOTHING, so its endpoints and pickup window are
		// inert and two disabled probes are the same statement however they are
		// spelled. This matters because neither `endpoints` nor `expected_pickup`
		// can be CLEARED on the wire — both are `omitempty` in the generated model
		// — so a probe that is turned off keeps whatever endpoints it last had.
		// Comparing them would leave a permanent diff proposing a removal that no
		// apply can perform, for values that have no effect.
		//
		// A probe being ENABLED out of band is still drift and is still reported:
		// that is the first comparison above, and it is the one that matters.
		return true
	}
	if a.expectedPickup != b.expectedPickup || len(a.endpoints) != len(b.endpoints) {
		return false
	}
	for i := range a.endpoints {
		// ORDER IS SIGNIFICANT: `endpoints` is a List, not a Set, because one
		// certificate fronting several listeners has a meaningful order in the
		// configuration and reordering it is a change the user wrote.
		if a.endpoints[i] != b.endpoints[i] {
			return false
		}
	}
	return true
}

func consumerProbeFacts(ctx context.Context, obj types.Object) (probeFacts, diag.Diagnostics) {
	var diags diag.Diagnostics
	facts := probeFacts{}
	if obj.IsNull() || obj.IsUnknown() {
		return facts, diags
	}
	var vm verificationModel
	diags.Append(obj.As(ctx, &vm, basetypes.ObjectAsOptions{})...)
	if diags.HasError() || vm.ConsumerProbe.IsNull() || vm.ConsumerProbe.IsUnknown() {
		return facts, diags
	}
	var pm consumerProbeModel
	diags.Append(vm.ConsumerProbe.As(ctx, &pm, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return facts, diags
	}
	facts.enabled = !pm.Enabled.IsNull() && !pm.Enabled.IsUnknown() && pm.Enabled.ValueBool()
	if !pm.ExpectedPickup.IsNull() && !pm.ExpectedPickup.IsUnknown() {
		facts.expectedPickup = pm.ExpectedPickup.ValueString()
	}
	if pm.Endpoints.IsNull() || pm.Endpoints.IsUnknown() {
		return facts, diags
	}
	var eps []probeEndpointModel
	diags.Append(pm.Endpoints.ElementsAs(ctx, &eps, false)...)
	if diags.HasError() {
		return facts, diags
	}
	for _, e := range eps {
		ef := probeEndpointFacts{host: e.Host.ValueString(), port: 443}
		if !e.Port.IsNull() && !e.Port.IsUnknown() {
			ef.port = e.Port.ValueInt64()
		}
		if !e.SNI.IsNull() && !e.SNI.IsUnknown() {
			ef.sni = e.SNI.ValueString()
		}
		facts.endpoints = append(facts.endpoints, ef)
	}
	return facts, diags
}

// buildSpecFromPlan projects the Terraform attributes onto the WIRE shape.
//
// The wire keeps `spec.destination` as an OBJECT (service contract §3.5); the
// flat `key_vault_id` / `certificate_name` / `destination_id` attributes are a
// client-side projection, so the catalogue schema and the OpenAPI body are
// unaffected by the flattening.
func buildSpecFromPlan(ctx context.Context, m certificateResourceModel) (contracts.CertificateSpecFields, diag.Diagnostics) {
	var diags diag.Diagnostics
	spec := contracts.CertificateSpecFields{}

	var names []string
	diags.Append(m.DNSNames.ElementsAs(ctx, &names, false)...)
	spec.DNSNames = names

	dest := contracts.DestinationFields{Type: strPtr("azure_key_vault")}
	if !m.KeyVaultID.IsNull() && !m.KeyVaultID.IsUnknown() {
		dest.KeyVaultID = strPtr(m.KeyVaultID.ValueString())
	}
	// The wire always carries the EFFECTIVE certificate name; the "omit it and
	// the object is named after `name`" default is a client-side convenience and
	// the server must not have to reproduce it.
	dest.CertificateName = strPtr(m.effectiveCertificateName())
	if !m.DestinationID.IsNull() && !m.DestinationID.IsUnknown() {
		dest.DestinationID = strPtr(m.DestinationID.ValueString())
	}
	spec.Destination = &dest

	if k, ok := m.keyModel(ctx); ok {
		key := contracts.KeyPolicyWrite{}
		if !k.Algorithm.IsNull() && !k.Algorithm.IsUnknown() {
			key.Algorithm = strPtr(k.Algorithm.ValueString())
		}
		if !k.Size.IsNull() && !k.Size.IsUnknown() {
			key.Size = i64Ptr(k.Size.ValueInt64())
		}
		if !k.Curve.IsNull() && !k.Curve.IsUnknown() {
			key.Curve = strPtr(k.Curve.ValueString())
		}
		if !k.Exportable.IsNull() && !k.Exportable.IsUnknown() {
			key.Exportable = boolPtr(k.Exportable.ValueBool())
		}
		spec.Key = &key
	}

	if !m.ACMEProfile.IsNull() && !m.ACMEProfile.IsUnknown() {
		spec.ACMEProfile = strPtr(m.ACMEProfile.ValueString())
	}
	if !m.ValidationBinding.IsNull() && !m.ValidationBinding.IsUnknown() {
		spec.ValidationBinding = strPtr(m.ValidationBinding.ValueString())
	}
	if !m.ConsumerProfile.IsNull() && !m.ConsumerProfile.IsUnknown() {
		spec.ConsumerProfile = strPtr(m.ConsumerProfile.ValueString())
	}
	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		spec.Description = strPtr(m.Description.ValueString())
	}
	if !m.DeletionPolicy.IsNull() && !m.DeletionPolicy.IsUnknown() {
		dp := contracts.DeletionPolicy(m.DeletionPolicy.ValueString())
		spec.DeletionPolicy = &dp
	}
	if !m.AcknowledgeIrreversibleDelete.IsNull() && !m.AcknowledgeIrreversibleDelete.IsUnknown() {
		spec.AcknowledgeIrreversibleDelete = boolPtr(m.AcknowledgeIrreversibleDelete.ValueBool())
	}
	if !m.Renewal.IsNull() && !m.Renewal.IsUnknown() {
		var rm renewalModel
		diags.Append(m.Renewal.As(ctx, &rm, basetypes.ObjectAsOptions{})...)
		renewal := contracts.RenewalSpec{}
		if !rm.Mode.IsNull() && !rm.Mode.IsUnknown() {
			renewal.Mode = strPtr(rm.Mode.ValueString())
		}
		if !rm.UseARI.IsNull() && !rm.UseARI.IsUnknown() {
			renewal.UseARI = boolPtr(rm.UseARI.ValueBool())
		}
		spec.Renewal = &renewal
	}
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		labels := map[string]string{}
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		spec.Labels = labels
	}
	if !m.CommonName.IsNull() && !m.CommonName.IsUnknown() {
		spec.CommonName = strPtr(m.CommonName.ValueString())
	}
	// The wire ALWAYS carries an EFFECTIVE verification block, even when the
	// configuration has none — the same rule as `certificate_name` above, for a
	// sharper reason.
	//
	// The service applies defaults at CREATE ONLY (G-8): on an update a field the
	// caller OMITTED inherits the value already stored. So a provider that simply
	// leaves `verification` out when the user deletes the block does not turn the
	// probe off — `enabled` comes back `true` from the previous spec, for ever,
	// with nothing in the HCL to explain it. That is the §5.3.1 trap arriving
	// through the server instead of through the schema, and omitting the block is
	// what opens the door to it.
	//
	// `enabled` is therefore always stated. `expected_pickup` and `endpoints`
	// cannot be: the generated wire model marks both `omitempty`, so this build
	// has no way to say "the caller cleared them" — see the provider report's
	// findings. Stating `enabled` is what makes the block revertible, because a
	// disabled probe does nothing whatever its endpoints say.
	probe := contracts.ConsumerProbe{Enabled: boolPtr(false)}
	if !m.Verification.IsNull() && !m.Verification.IsUnknown() {
		var vm verificationModel
		diags.Append(m.Verification.As(ctx, &vm, basetypes.ObjectAsOptions{})...)
		if !vm.ConsumerProbe.IsNull() && !vm.ConsumerProbe.IsUnknown() {
			var pm consumerProbeModel
			diags.Append(vm.ConsumerProbe.As(ctx, &pm, basetypes.ObjectAsOptions{})...)
			if !pm.Enabled.IsNull() && !pm.Enabled.IsUnknown() {
				probe.Enabled = boolPtr(pm.Enabled.ValueBool())
			}
			if !pm.ExpectedPickup.IsNull() && !pm.ExpectedPickup.IsUnknown() {
				probe.ExpectedPickup = strPtr(pm.ExpectedPickup.ValueString())
			}
			if !pm.Endpoints.IsNull() && !pm.Endpoints.IsUnknown() {
				var eps []probeEndpointModel
				diags.Append(pm.Endpoints.ElementsAs(ctx, &eps, false)...)
				for _, e := range eps {
					pe := contracts.ProbeEndpoint{Host: e.Host.ValueString()}
					if !e.Port.IsNull() {
						pe.Port = i64Ptr(e.Port.ValueInt64())
					}
					if !e.SNI.IsNull() {
						pe.SNI = strPtr(e.SNI.ValueString())
					}
					probe.Endpoints = append(probe.Endpoints, pe)
				}
			}
		}
	}
	spec.Verification = &contracts.VerificationSpec{ConsumerProbe: &probe}
	return spec, diags
}

// ------------------------------------------------------------------- helpers

func specKeyAlgorithm(reg *contracts.CertificateRegistration) *string {
	if reg.Spec.Key == nil {
		return nil
	}
	return reg.Spec.Key.Algorithm
}
func specKeySize(reg *contracts.CertificateRegistration) *int64 {
	if reg.Spec.Key == nil {
		return nil
	}
	return reg.Spec.Key.Size
}
func specKeyCurve(reg *contracts.CertificateRegistration) *string {
	if reg.Spec.Key == nil {
		return nil
	}
	return reg.Spec.Key.Curve
}
func specKeyExportable(reg *contracts.CertificateRegistration) *bool {
	if reg.Spec.Key == nil {
		return nil
	}
	return reg.Spec.Key.Exportable
}
func specRenewalMode(reg *contracts.CertificateRegistration) *string {
	if reg.Spec.Renewal == nil {
		return nil
	}
	return reg.Spec.Renewal.Mode
}
func specRenewalUseARI(reg *contracts.CertificateRegistration) *bool {
	if reg.Spec.Renewal == nil {
		return nil
	}
	return reg.Spec.Renewal.UseARI
}

func stringOrNull(v *string) types.String {
	if v == nil {
		return types.StringNull()
	}
	return types.StringValue(*v)
}

func stringOrDefault(v *string, fallback string) types.String {
	if v == nil {
		return types.StringValue(fallback)
	}
	return types.StringValue(*v)
}

func int64OrNull(v *int64) types.Int64 {
	if v == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*v)
}

func int64OrDefault(v *int64, fallback int64) types.Int64 {
	if v == nil {
		return types.Int64Value(fallback)
	}
	return types.Int64Value(*v)
}

func boolOrDefault(v *bool, fallback bool) types.Bool {
	if v == nil {
		return types.BoolValue(fallback)
	}
	return types.BoolValue(*v)
}

func strPtr(s string) *string { return &s }
func i64Ptr(v int64) *int64   { return &v }
func boolPtr(v bool) *bool    { return &v }

// -------------------------------------- the required current_certificate fields

// requiredCurrentCertificateFields are the three fields
// contracts/api/openapi.yaml marks REQUIRED on `CurrentCertificate`, in wire
// spelling. They decode into non-pointer Go strings, so "required" buys no
// decode-time check at all: an omitted or null field is indistinguishable from an
// empty one and arrives as "".
//
// Keep this list in step with the contract. A field added to the contract's
// `required` list and not added here produces the opaque failure this machinery
// exists to prevent.
var requiredCurrentCertificateFields = []string{"thumbprint_sha256", "not_before", "not_after"}

// missingRequiredCertificateFields names the required fields the service did not
// send, in contract order.
func missingRequiredCertificateFields(cc *contracts.CurrentCertificate) []string {
	if cc == nil {
		return nil
	}
	present := map[string]string{
		"thumbprint_sha256": cc.ThumbprintSHA256,
		"not_before":        cc.NotBefore,
		"not_after":         cc.NotAfter,
	}
	var missing []string
	for _, field := range requiredCurrentCertificateFields {
		if strings.TrimSpace(present[field]) == "" {
			missing = append(missing, field)
		}
	}
	return missing
}

// missingCertificateFieldDiagnostics turns a missing required field into an error
// that NAMES THE FIELD, names the registration, says which side is at fault and
// says what to do — one error per field, each against the Terraform attribute it
// corresponds to, so the message lands on the right line.
//
// It is an ERROR and not a warning. The field is required by the wire contract,
// the value is load-bearing (`not_before` is how a consumer knows whether the
// certificate it was handed is yet valid), and the provider will not fabricate
// one. Downgrading it would hide a service defect behind a green apply and put
// incomplete state in front of every consumer reading these attributes.
func missingCertificateFieldDiagnostics(reg *contracts.CertificateRegistration, missing []string) diag.Diagnostics {
	var diags diag.Diagnostics
	for _, field := range missing {
		diags.AddAttributeError(
			path.Root("current_certificate").AtName(field),
			fmt.Sprintf("The service omitted the required field status.current_certificate.%s", field),
			fmt.Sprintf(
				"The certificate for %s/%s is published, but the service's representation of it carries no "+
					"`status.current_certificate.%s`.\n\n"+
					"That field is REQUIRED on `CurrentCertificate` in the API contract, so the provider decodes it as a "+
					"plain string and an omitted or null value is indistinguishable from an empty one. The provider will "+
					"not invent a value for it: %s\n\n"+
					"This is a SERVICE defect, not a configuration mistake, and nothing in your configuration will fix "+
					"it. The certificate itself is unaffected — it exists in the destination vault and the service will "+
					"keep renewing it. `%s` is null in state and the rest of `current_certificate` is populated.\n\n"+
					"Report it to your platform administrator, quoting registration %s and service instance %s. Once the "+
					"service populates the field, the next `terraform apply` completes with no change to your "+
					"configuration.\n\n"+
					"If this apply was a CREATE, Terraform has marked the object tainted; `terraform untaint <address>` "+
					"before re-applying, or the next plan proposes destroying a live certificate.",
				reg.Namespace, reg.Name, field, consequenceOfMissing(field),
				"current_certificate."+field, reg.RegistrationID, reg.ServiceInstanceID))
	}
	return diags
}

// consequenceOfMissing says why the field matters, so the report that reaches the
// platform team carries the consequence and not just the field name.
func consequenceOfMissing(field string) string {
	switch field {
	case "not_before":
		return "a consumer cannot tell whether the certificate it has been handed is yet valid, and a fabricated " +
			"timestamp would make an invalid certificate look in-date."
	case "not_after":
		return "every expiry alert and every renewal decision downstream of this state is computed from it."
	case "thumbprint_sha256":
		return "it is the only identity a consumer can compare against what a listener is actually serving, so " +
			"without it no drift between the vault and the consumer is detectable."
	default:
		return "the contract marks it required."
	}
}

// requiredWireTimestamp maps a required wire timestamp to a value, or to NULL
// when the service sent nothing.
//
// Null rather than `rfc3339.NewValue("")`: "" is a KNOWN value that fails
// rfc3339.ValidateAttribute, which aborts the state write, which in turn makes
// Terraform report a second, misleading "unknown value after apply … always a bug
// in the provider". The absence is already reported by name; state should carry
// the legible form of "absent".
func requiredWireTimestamp(raw string) rfc3339.String {
	if strings.TrimSpace(raw) == "" {
		return rfc3339.NewNull()
	}
	return rfc3339.NewValue(raw)
}

// requiredWireString is requiredWireTimestamp for a plain required string.
func requiredWireString(raw string) types.String {
	if strings.TrimSpace(raw) == "" {
		return types.StringNull()
	}
	return types.StringValue(raw)
}
