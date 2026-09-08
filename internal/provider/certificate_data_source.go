package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

var (
	_ datasource.DataSource              = (*certificateDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*certificateDataSource)(nil)
)

// NewCertificateDataSource is the CROSS-WORKSPACE CONSUMPTION PATH, and the home
// of every volatile field deliberately kept off the resource (§5.2 "Not on the
// resource").
//
// Those fields change between plans for reasons unrelated to configuration — a
// consumer probe running every 30 minutes can flip `delivery_stage` between two
// plans minutes apart — and every such change would print "Objects have changed
// outside of Terraform". Teams then learn to ignore drift notes, which is how a
// genuine out-of-band spec change goes unnoticed.
//
// It is strictly read-only, never claims ownership, cannot create, and requires
// only `Certificates.Read`.
func NewCertificateDataSource() datasource.DataSource { return &certificateDataSource{} }

type certificateDataSource struct{ data *providerData }

func (d *certificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (d *certificateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = configureDataSource(req, resp)
}

type certificateDataSourceModel struct {
	Namespace  types.String `tfsdk:"namespace"`
	Name       types.String `tfsdk:"name"`
	IncludePEM types.Bool   `tfsdk:"include_pem"`

	ID                types.String `tfsdk:"id"`
	RegistrationID    types.String `tfsdk:"registration_id"`
	ServiceInstanceID types.String `tfsdk:"service_instance_id"`

	DNSNames        types.Set    `tfsdk:"dns_names"`
	KeyVaultID      types.String `tfsdk:"key_vault_id"`
	CertificateName types.String `tfsdk:"certificate_name"`
	Description     types.String `tfsdk:"description"`
	Labels          types.Map    `tfsdk:"labels"`
	SystemLabels    types.Map    `tfsdk:"system_labels"`
	SpecRevision    types.Int64  `tfsdk:"spec_revision"`
	Generation      types.Int64  `tfsdk:"generation"`
	DeletionPolicy  types.String `tfsdk:"deletion_policy"`

	LifecycleState            types.String `tfsdk:"lifecycle_state"`
	Phase                     types.String `tfsdk:"phase"`
	DeliveryStage             types.String `tfsdk:"delivery_stage"`
	FulfilledGeneration       types.Int64  `tfsdk:"fulfilled_generation"`
	PublicationMode           types.String `tfsdk:"publication_mode"`
	ResolvedACMEProfile       types.String `tfsdk:"resolved_acme_profile"`
	ResolvedValidationBinding types.String `tfsdk:"resolved_validation_binding"`
	ResolvedCertificateName   types.String `tfsdk:"resolved_certificate_name"`

	VersionlessSecretID      types.String `tfsdk:"versionless_secret_id"`
	VersionlessCertificateID types.String `tfsdk:"versionless_certificate_id"`
	IssuedDNSNames           types.Set    `tfsdk:"issued_dns_names"`

	CurrentCertificate  types.Object `tfsdk:"current_certificate"`
	PreviousCertificate types.Object `tfsdk:"previous_certificate"`
	Operation           types.Object `tfsdk:"operation"`
	Renewal             types.Object `tfsdk:"renewal"`
	Ownership           types.Object `tfsdk:"ownership"`
	Audit               types.Object `tfsdk:"audit"`
	Consumers           types.List   `tfsdk:"consumers"`
	Conditions          types.List   `tfsdk:"conditions"`

	CertificatePEM types.String `tfsdk:"certificate_pem"`
	ChainPEM       types.String `tfsdk:"chain_pem"`
}

func dsPreviousCertificateTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"not_after": types.StringType, "thumbprint_sha256": types.StringType, "version_secret_id": types.StringType,
	}
}

func dsOperationTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id": types.StringType, "type": types.StringType, "state": types.StringType,
		"phase": types.StringType, "attempt": types.Int64Type, "started_at": types.StringType,
		"last_error_code": types.StringType, "last_error_message": types.StringType,
	}
}

func dsRenewalTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ari_window_start": types.StringType, "ari_window_end": types.StringType,
		"next_check_at": types.StringType, "next_attempt_at": types.StringType,
		"consecutive_failures": types.Int64Type, "last_successful_renewal_at": types.StringType,
		"source": types.StringType,
	}
}

func dsOwnershipTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"owner_principal_id": types.StringType, "owner_principal_type": types.StringType,
		"owner_display_name": types.StringType, "transferable": types.BoolType,
		"claimed_at": types.StringType, "adopted_existing": types.BoolType,
		"destination_claim": types.StringType,
	}
}

func dsAuditTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"created_at": types.StringType, "created_by": types.StringType,
		"updated_at": types.StringType, "updated_by": types.StringType,
	}
}

func dsConsumerTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"host": types.StringType, "port": types.Int64Type, "state": types.StringType,
		"observed_thumbprint_sha256": types.StringType, "last_checked_at": types.StringType,
	}
}

func dsConditionTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type": types.StringType, "status": types.StringType, "reason": types.StringType,
		"message": types.StringType, "policy_revision": types.Int64Type, "last_transition_at": types.StringType,
	}
}

func (d *certificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(desc string) schema.Attribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: desc}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "The full public representation of one certificate registration, INCLUDING the volatile " +
			"status the resource deliberately omits. This is how one workspace consumes a certificate registered by " +
			"another without gaining the ability to change it.\n\n" +
			"It never causes issuance, renewal or an ACME order.",
		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{Required: true},
			"name":      schema.StringAttribute{Required: true},
			"include_pem": schema.BoolAttribute{Optional: true,
				MarkdownDescription: "Include the issued certificate and chain in PEM form. Defaults to `false`. " +
					"**No private key is ever returned, under any flag.**"},

			"id":                  computedString("`{namespace}/{name}`."),
			"registration_id":     computedString(""),
			"service_instance_id": computedString(""),

			"dns_names":        schema.SetAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "The identifiers in the SPECIFICATION."},
			"issued_dns_names": schema.SetAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "The identifiers in the certificate ACTUALLY ISSUED, which may lag the specification."},
			"key_vault_id":     computedString(""),
			"certificate_name": computedString(""),
			"description":      computedString(""),
			"labels":           schema.MapAttribute{Computed: true, ElementType: types.StringType},
			"system_labels":    schema.MapAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Service-owned metadata. Separate from `labels` so the service never writes into the client's."},
			"spec_revision":    schema.Int64Attribute{Computed: true},
			"generation":       schema.Int64Attribute{Computed: true},
			"deletion_policy":  computedString(""),

			"lifecycle_state":             computedString("`active`, `suspended`, `authorization_revoked`, `deleting` or `deleted`."),
			"phase":                       computedString(""),
			"delivery_stage":              computedString("`consumer_unverifiable` is mandatory and must be surfaced: silence must never read as success."),
			"fulfilled_generation":        schema.Int64Attribute{Computed: true},
			"publication_mode":            computedString(""),
			"resolved_acme_profile":       computedString(""),
			"resolved_validation_binding": computedString(""),
			"resolved_certificate_name":   computedString(""),

			"versionless_secret_id":      computedString("The consumption binding point."),
			"versionless_certificate_id": computedString(""),

			"current_certificate": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"version_secret_id": computedString(""), "version_certificate_id": computedString(""),
				"thumbprint_sha256": computedString(""), "serial_number": computedString(""),
				"not_before": computedString(""), "not_after": computedString(""),
				"issued_at": computedString(""), "published_at": computedString(""),
				"issuer": computedString(""), "acme_profile": computedString(""),
			}},
			"previous_certificate": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"not_after": computedString(""), "thumbprint_sha256": computedString(""), "version_secret_id": computedString(""),
			}},
			"operation": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"id": computedString(""), "type": computedString(""), "state": computedString(""),
				"phase": computedString(""), "attempt": schema.Int64Attribute{Computed: true},
				"started_at": computedString(""), "last_error_code": computedString(""), "last_error_message": computedString(""),
			}},
			"renewal": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"ari_window_start": computedString(""), "ari_window_end": computedString(""),
				"next_check_at": computedString(""), "next_attempt_at": computedString(""),
				"consecutive_failures":       schema.Int64Attribute{Computed: true},
				"last_successful_renewal_at": computedString(""), "source": computedString("`ari` or `fallback`."),
			}},
			"ownership": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"owner_principal_id": computedString(""), "owner_principal_type": computedString(""),
				"owner_display_name": computedString("A LABEL ONLY. Never an evaluation input."),
				"transferable":       schema.BoolAttribute{Computed: true},
				"claimed_at":         computedString(""), "adopted_existing": schema.BoolAttribute{Computed: true},
				"destination_claim": computedString(""),
			}},
			"audit": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"created_at": computedString(""), "created_by": computedString(""),
				"updated_at": computedString(""), "updated_by": computedString(""),
			}},
			"consumers": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"host": computedString(""), "port": schema.Int64Attribute{Computed: true},
					"state": computedString(""), "observed_thumbprint_sha256": computedString(""),
					"last_checked_at": computedString(""),
				}}},
			"conditions": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"type": computedString(""), "status": computedString(""), "reason": computedString(""),
					"message": computedString(""), "policy_revision": schema.Int64Attribute{Computed: true},
					"last_transition_at": computedString(""),
				}}},

			"certificate_pem": schema.StringAttribute{Computed: true,
				MarkdownDescription: "The issued leaf in PEM form, only when `include_pem = true`. **Never a private key.**"},
			"chain_pem": schema.StringAttribute{Computed: true,
				MarkdownDescription: "The issuing chain in PEM form, only when `include_pem = true`. **Never a private key.**"},
		},
	}
}

func (d *certificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg certificateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.data == nil || d.data.Client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "The provider produced no API client.")
		return
	}
	ns, name := cfg.Namespace.ValueString(), cfg.Name.ValueString()
	// GET only. A data source must never cause issuance, renewal or an ACME order.
	reg, _, err := d.data.Client.GetRegistration(ctx, ns, name, false)
	if err != nil {
		if apiErr, ok := client.AsAPIError(err); ok {
			resp.Diagnostics.AddError(fmt.Sprintf("Could not read %s/%s (HTTP %d)", ns, name, apiErr.Status),
				fmt.Sprintf("%s\n\n%s\n\nRequest id: %s", apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()))
			return
		}
		resp.Diagnostics.AddError(fmt.Sprintf("Could not read %s/%s", ns, name), err.Error())
		return
	}
	resp.Diagnostics.Append(fillCertificateDataSource(ctx, reg, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !cfg.IncludePEM.ValueBool() {
		cfg.CertificatePEM = types.StringNull()
		cfg.ChainPEM = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

func fillCertificateDataSource(ctx context.Context, reg *contracts.CertificateRegistration, m *certificateDataSourceModel) (diags diag.Diagnostics) {
	m.ID = types.StringValue(reg.Namespace + "/" + reg.Name)
	m.RegistrationID = types.StringValue(reg.RegistrationID)
	m.ServiceInstanceID = types.StringValue(reg.ServiceInstanceID)
	m.SpecRevision = types.Int64Value(reg.Spec.Revision)
	m.Generation = types.Int64Value(reg.Spec.Generation)
	m.Description = stringOrNull(reg.Spec.Description)
	if reg.Spec.DeletionPolicy != nil {
		m.DeletionPolicy = types.StringValue(string(*reg.Spec.DeletionPolicy))
	} else {
		m.DeletionPolicy = types.StringNull()
	}
	names, d := types.SetValueFrom(ctx, types.StringType, reg.Spec.DNSNames)
	diags.Append(d...)
	m.DNSNames = names
	if reg.Spec.Destination != nil {
		m.KeyVaultID = types.StringValue(reg.Spec.Destination.KeyVaultID)
		m.CertificateName = types.StringValue(reg.Spec.Destination.CertificateName)
	}
	labels, d := types.MapValueFrom(ctx, types.StringType, orEmptyMap(reg.Spec.Labels))
	diags.Append(d...)
	m.Labels = labels
	system, d := types.MapValueFrom(ctx, types.StringType, orEmptyMap(reg.SystemLabels))
	diags.Append(d...)
	m.SystemLabels = system

	st := reg.Status
	m.LifecycleState = types.StringValue(st.LifecycleState)
	m.Phase = types.StringValue(st.Phase)
	m.DeliveryStage = types.StringValue(st.DeliveryStage)
	m.FulfilledGeneration = types.Int64Value(st.ObservedGeneration)
	m.PublicationMode = stringOrNull(st.PublicationMode)
	m.ResolvedACMEProfile = stringOrNull(st.ResolvedACMEProfile)
	m.ResolvedValidationBinding = stringOrNull(st.ResolvedValidationBinding)
	m.ResolvedCertificateName = stringOrNull(st.ResolvedCertificateName)

	m.VersionlessSecretID = types.StringNull()
	m.VersionlessCertificateID = types.StringNull()
	m.IssuedDNSNames = types.SetNull(types.StringType)
	if cc := st.CurrentCertificate; cc != nil {
		m.VersionlessSecretID = stringOrNull(cc.VersionlessSecretID)
		m.VersionlessCertificateID = stringOrNull(cc.VersionlessCertificateID)
		issued, d := types.SetValueFrom(ctx, types.StringType, cc.DNSNames)
		diags.Append(d...)
		m.IssuedDNSNames = issued
		obj, d := types.ObjectValue(currentCertificateStringTypes(), map[string]attr.Value{
			"version_secret_id": stringOrNull(cc.VersionSecretID), "version_certificate_id": stringOrNull(cc.VersionCertificateID),
			"thumbprint_sha256": types.StringValue(cc.ThumbprintSHA256), "serial_number": stringOrNull(cc.SerialNumber),
			"not_before": types.StringValue(cc.NotBefore), "not_after": types.StringValue(cc.NotAfter),
			"issued_at": stringOrNull(cc.IssuedAt), "published_at": stringOrNull(cc.PublishedAt),
			"issuer": stringOrNull(cc.Issuer), "acme_profile": stringOrNull(cc.ACMEProfile),
		})
		diags.Append(d...)
		m.CurrentCertificate = obj
	} else {
		m.CurrentCertificate = types.ObjectNull(currentCertificateStringTypes())
	}

	m.PreviousCertificate = types.ObjectNull(dsPreviousCertificateTypes())
	if pc := st.PreviousCertificate; pc != nil {
		obj, d := types.ObjectValue(dsPreviousCertificateTypes(), map[string]attr.Value{
			"not_after": stringOrNull(pc.NotAfter), "thumbprint_sha256": stringOrNull(pc.ThumbprintSHA256),
			"version_secret_id": stringOrNull(pc.VersionSecretID),
		})
		diags.Append(d...)
		m.PreviousCertificate = obj
	}

	m.Operation = types.ObjectNull(dsOperationTypes())
	if op := st.Operation; op != nil {
		phase := types.StringNull()
		if op.Phase != nil {
			phase = types.StringValue(string(*op.Phase))
		}
		opType := types.StringNull()
		if op.Type != nil {
			opType = types.StringValue(string(*op.Type))
		}
		errCode, errMsg := types.StringNull(), types.StringNull()
		if op.LastError != nil {
			errCode = types.StringValue(op.LastError.Code)
			errMsg = types.StringValue(op.LastError.Message)
		}
		obj, d := types.ObjectValue(dsOperationTypes(), map[string]attr.Value{
			"id": stringOrNull(op.ID), "type": opType, "state": types.StringValue(string(op.State)),
			"phase": phase, "attempt": int64OrNull(op.Attempt), "started_at": stringOrNull(op.StartedAt),
			"last_error_code": errCode, "last_error_message": errMsg,
		})
		diags.Append(d...)
		m.Operation = obj
	}

	m.Renewal = types.ObjectNull(dsRenewalTypes())
	if rn := st.Renewal; rn != nil {
		obj, d := types.ObjectValue(dsRenewalTypes(), map[string]attr.Value{
			"ari_window_start": stringOrNull(rn.ARIWindowStart), "ari_window_end": stringOrNull(rn.ARIWindowEnd),
			"next_check_at": stringOrNull(rn.NextCheckAt), "next_attempt_at": stringOrNull(rn.NextAttemptAt),
			"consecutive_failures":       int64OrNull(rn.ConsecutiveFailures),
			"last_successful_renewal_at": stringOrNull(rn.LastSuccessfulRenewalAt), "source": stringOrNull(rn.Source),
		})
		diags.Append(d...)
		m.Renewal = obj
	}

	m.Ownership = types.ObjectNull(dsOwnershipTypes())
	if ow := st.Ownership; ow != nil {
		obj, d := types.ObjectValue(dsOwnershipTypes(), map[string]attr.Value{
			"owner_principal_id": stringOrNull(ow.OwnerPrincipalID), "owner_principal_type": stringOrNull(ow.OwnerPrincipalType),
			"owner_display_name": stringOrNull(ow.OwnerDisplayName), "transferable": boolOrNull(ow.Transferable),
			"claimed_at": stringOrNull(ow.ClaimedAt), "adopted_existing": boolOrNull(ow.AdoptedExisting),
			"destination_claim": stringOrNull(ow.DestinationClaim),
		})
		diags.Append(d...)
		m.Ownership = obj
	}

	m.Audit = types.ObjectNull(dsAuditTypes())
	if au := st.Audit; au != nil {
		obj, d := types.ObjectValue(dsAuditTypes(), map[string]attr.Value{
			"created_at": stringOrNull(au.CreatedAt), "created_by": stringOrNull(au.CreatedBy),
			"updated_at": stringOrNull(au.UpdatedAt), "updated_by": stringOrNull(au.UpdatedBy),
		})
		diags.Append(d...)
		m.Audit = obj
	}

	consumers := make([]attr.Value, 0, len(st.Consumers))
	for _, c := range st.Consumers {
		obj, d := types.ObjectValue(dsConsumerTypes(), map[string]attr.Value{
			"host": types.StringValue(c.Host), "port": int64OrNull(c.Port), "state": types.StringValue(c.State),
			"observed_thumbprint_sha256": stringOrNull(c.ObservedThumbprintSHA256), "last_checked_at": stringOrNull(c.LastCheckedAt),
		})
		diags.Append(d...)
		consumers = append(consumers, obj)
	}
	cl, d := types.ListValue(types.ObjectType{AttrTypes: dsConsumerTypes()}, consumers)
	diags.Append(d...)
	m.Consumers = cl

	conditions := make([]attr.Value, 0, len(st.Conditions))
	for _, c := range st.Conditions {
		obj, d := types.ObjectValue(dsConditionTypes(), map[string]attr.Value{
			"type": types.StringValue(c.Type), "status": types.StringValue(c.Status),
			"reason": stringOrNull(c.Reason), "message": stringOrNull(c.Message),
			"policy_revision": int64OrNull(c.PolicyRevision), "last_transition_at": stringOrNull(c.LastTransitionAt),
		})
		diags.Append(d...)
		conditions = append(conditions, obj)
	}
	condList, d := types.ListValue(types.ObjectType{AttrTypes: dsConditionTypes()}, conditions)
	diags.Append(d...)
	m.Conditions = condList

	m.CertificatePEM = types.StringNull()
	m.ChainPEM = types.StringNull()
	return diags
}

// currentCertificateStringTypes is the data-source shape of current_certificate.
// It uses plain strings rather than the semantic-equality timestamp type: a data
// source has no plan to keep stable.
func currentCertificateStringTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"version_secret_id": types.StringType, "version_certificate_id": types.StringType,
		"thumbprint_sha256": types.StringType, "serial_number": types.StringType,
		"not_before": types.StringType, "not_after": types.StringType,
		"issued_at": types.StringType, "published_at": types.StringType,
		"issuer": types.StringType, "acme_profile": types.StringType,
	}
}

func boolOrNull(v *bool) types.Bool {
	if v == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*v)
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
