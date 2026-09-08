package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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

	m.LastSuccessfulRenewalAt = rfc3339.NewNull()
	if reg.Status.Renewal != nil {
		m.LastSuccessfulRenewalAt = rfc3339.NewValueFromPointer(reg.Status.Renewal.LastSuccessfulRenewalAt)
	}

	// --- current_certificate -------------------------------------------------
	if reg.Status.CurrentCertificate == nil {
		m.CurrentCertificate = types.ObjectNull(currentCertificateAttrTypes())
	} else {
		cc := reg.Status.CurrentCertificate
		obj, d := types.ObjectValueFrom(ctx, currentCertificateAttrTypes(), currentCertificateModel{
			VersionSecretID:      stringOrNull(cc.VersionSecretID),
			VersionCertificateID: stringOrNull(cc.VersionCertificateID),
			ThumbprintSHA256:     types.StringValue(cc.ThumbprintSHA256),
			SerialNumber:         stringOrNull(cc.SerialNumber),
			NotBefore:            rfc3339.NewValue(cc.NotBefore),
			NotAfter:             rfc3339.NewValue(cc.NotAfter),
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
		m.DestinationID = stringOrNull(reg.Spec.Destination.DestinationID)

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

func verificationObjectFrom(ctx context.Context, spec *contracts.VerificationSpec, prior types.Object) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics
	if spec == nil || spec.ConsumerProbe == nil {
		if prior.IsNull() {
			return types.ObjectNull(verificationAttrTypes()), diags
		}
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
	return obj, diags
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
	if !m.Verification.IsNull() && !m.Verification.IsUnknown() {
		var vm verificationModel
		diags.Append(m.Verification.As(ctx, &vm, basetypes.ObjectAsOptions{})...)
		if !vm.ConsumerProbe.IsNull() && !vm.ConsumerProbe.IsUnknown() {
			var pm consumerProbeModel
			diags.Append(vm.ConsumerProbe.As(ctx, &pm, basetypes.ObjectAsOptions{})...)
			probe := contracts.ConsumerProbe{}
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
			spec.Verification = &contracts.VerificationSpec{ConsumerProbe: &probe}
		}
	}
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
