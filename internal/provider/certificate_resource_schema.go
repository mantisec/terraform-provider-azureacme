package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/dnsname"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// Defaults named as constants so the schema snapshot test can assert them by
// reference rather than by repeating a literal that would drift with the schema.
const (
	// DefaultCreateTimeout is 60 MINUTES, not 30. The platform review sets the
	// issuance-latency SLO at p99 = 45 minutes; a 30-minute default means the
	// timeout-recovery path is reached ROUTINELY by the design's own numbers
	// (§5.2, A4/FP-3) — and the timeout-recovery path is where certificates get
	// destroyed.
	DefaultCreateTimeout = "60m"
	DefaultReadTimeout   = "2m"
	DefaultUpdateTimeout = "60m"
	DefaultDeleteTimeout = "10m"

	// ACMEProfileSentinel and ValidationBindingSentinel are SENTINELS, not
	// materialised defaults. §5.3.1: an Optional+Computed attribute cannot be
	// reverted by deleting the line, so "track the service default" is expressed
	// as a stored sentinel the service resolves at each issuance.
	ACMEProfileSentinel       = "default"
	ValidationBindingSentinel = "auto"

	// WaitForPublished is the default. `accepted` is the only other permitted
	// value in v1.
	WaitForPublished = "published"
	WaitForAccepted  = "accepted"

	// ConsumerProfileCryptoOnly is the ONE profile for which a non-exportable
	// key is legitimate (§5.6).
	ConsumerProfileCryptoOnly = "keyvault_crypto_only"
)

// labelCharClass is the CORRECTED character class of §5.2.
//
// Reviewer 04 wrote `[A-Za-z0-9 +-./:=_]`, in which `+-.` is the RANGE
// U+002B–U+002E and therefore silently admits `,`. The hyphen goes LAST.
var labelCharClass = regexp.MustCompile(`^[A-Za-z0-9 ._:=/+-]*$`)

// nameRE is the shared namespace/name grammar. It is not redefined here — a
// second definition of a grammar two languages must agree on is a defect
// (internal/primitives is the one definition).
var nameRE = regexp.MustCompile(primitives.NamespacePattern)

func keyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"algorithm":  types.StringType,
		"size":       types.Int64Type,
		"curve":      types.StringType,
		"exportable": types.BoolType,
	}
}

func renewalAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"mode":    types.StringType,
		"use_ari": types.BoolType,
	}
}

func probeEndpointAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"host": types.StringType,
		"port": types.Int64Type,
		"sni":  types.StringType,
	}
}

func consumerProbeAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":         types.BoolType,
		"expected_pickup": types.StringType,
		"endpoints":       types.ListType{ElemType: types.ObjectType{AttrTypes: probeEndpointAttrTypes()}},
	}
}

func verificationAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"consumer_probe": types.ObjectType{AttrTypes: consumerProbeAttrTypes()},
	}
}

func currentCertificateAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"version_secret_id":      types.StringType,
		"version_certificate_id": types.StringType,
		"thumbprint_sha256":      types.StringType,
		"serial_number":          types.StringType,
		"not_before":             rfc3339.StringType{},
		"not_after":              rfc3339.StringType{},
		"issued_at":              rfc3339.StringType{},
		"published_at":           rfc3339.StringType{},
		"issuer":                 types.StringType,
		"acme_profile":           types.StringType,
	}
}

func timeoutsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"create": types.StringType,
		"read":   types.StringType,
		"update": types.StringType,
		"delete": types.StringType,
	}
}

// defaultKeyObject is the STATIC default of §5.2: {algorithm="RSA", size=2048,
// exportable=true}. A static default, not a server round trip — guarantee G-8
// makes defaults apply at CREATE only, so a service upgrade cannot
// re-materialise a different default on an existing registration.
func defaultKeyObject() basetypes.ObjectValue {
	return types.ObjectValueMust(keyAttrTypes(), map[string]attr.Value{
		"algorithm":  types.StringValue("RSA"),
		"size":       types.Int64Value(2048),
		"curve":      types.StringNull(),
		"exportable": types.BoolValue(true),
	})
}

func defaultRenewalObject() basetypes.ObjectValue {
	return types.ObjectValueMust(renewalAttrTypes(), map[string]attr.Value{
		"mode":    types.StringValue("automatic"),
		"use_ari": types.BoolValue(true),
	})
}

func certificateResourceSchema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "A durable certificate registration: **the standing instruction to keep a certificate valid, " +
			"not one signed artefact**. Its identity survives every renewal, and the service keeps fulfilling it whether " +
			"or not Terraform runs.\n\n" +
			"The Terraform-visible primary key is `{namespace}/{name}`, which is also the import id.",
		Attributes: map[string]schema.Attribute{
			// ---------------------------------------------- identity and placement
			"namespace": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The authorisation boundary. Never inferred: a provider-level default would let a " +
					"copy-paste error move a certificate between production and non-production invisibly.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(nameRE, "must match "+primitives.NamespacePattern),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The logical certificate name within the namespace.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(nameRE, "must match "+primitives.NamespacePattern),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "`{namespace}/{name}`. The import id. It carries no version, thumbprint, serial or " +
					"expiry (rule R-1): an id that changed on renewal would make every renewal a replacement.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"registration_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The service's ULID for this registration.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"service_instance_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The service instance this registration was created against. A mismatch on refresh " +
					"is a HARD ERROR and never a removal: one mistyped `endpoint` would otherwise make every `GET` " +
					"legitimately 404 and remove the entire fleet from state.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},

			// ------------------------------------------------------------- names
			"dns_names": schema.SetAttribute{
				Required:    true,
				ElementType: dnsname.StringType{},
				MarkdownDescription: "The identifiers to certify. A `Set`, not a `List`: order carries no meaning, and a " +
					"`List` against a normalising server proposes an update forever — which for this resource means " +
					"reissuing on every apply.",
				Validators: []validator.Set{setvalidator.SizeAtLeast(1)},
			},
			"common_name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "**Reserved and rejected in v1** pending decision D-30. Deriving it from the " +
					"\"first\" DNS name is not available: a `Set` has no first, and deriving it from sort order means " +
					"adding a name silently changes the subject and forces a reissue nobody could predict.",
			},

			// ------------------------------------------------------- destination
			"key_vault_id": schema.StringAttribute{
				Required:   true,
				CustomType: armid.StringType{},
				MarkdownDescription: "The destination Key Vault. **Changing it is a plan-time error, not a replacement** " +
					"— replacing would destroy the registration (and, under `deletion_policy = \"delete\"`, soft-delete " +
					"the live certificate) BEFORE its replacement is issued.",
			},
			"certificate_name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The Key Vault certificate object name. Defaults to `name`. Optional **without** " +
					"`Computed`, so deleting the line genuinely reverts to `name`; the server's resolved value appears in " +
					"`resolved_certificate_name`.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`),
						"must match ^[0-9a-zA-Z-]{1,127}$ (the Key Vault object-name grammar)"),
				},
			},
			"destination_id": schema.StringAttribute{
				Optional: true,
				// PROVISIONAL(D-20): server-resolved destination, `destination_id`
				// reserved. It is accepted and forwarded now and required only by
				// SERVER policy, never by the schema, so the stricter branch stays
				// additive — making a Terraform attribute Required after publication
				// would be breaking.
				MarkdownDescription: "Names a namespace destination policy. Optional in v1; when supplied it must match " +
					"the policy the service resolves, or the request is rejected.",
			},
			"resolved_certificate_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The Key Vault object name the service actually uses.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},

			// -------------------------------------------------------- key policy
			"key": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Default:  objectdefault.StaticValue(defaultKeyObject()),
				MarkdownDescription: "Key policy. **Omit it.** The default — RSA 2048, exportable — is correct for every " +
					"consumer in the v1 matrix, and the registry example deliberately shows no `key` block at all.",
				Attributes: map[string]schema.Attribute{
					"algorithm": schema.StringAttribute{
						Optional: true, Computed: true,
						Default:             stringdefault.StaticString("RSA"),
						MarkdownDescription: "`RSA` or `EC`. EC stays representable so enabling it later is a service policy change, not a schema change.",
						Validators:          []validator.String{stringvalidator.OneOf("RSA", "EC")},
					},
					"size": schema.Int64Attribute{
						Optional: true, Computed: true,
						Default:             int64default.StaticInt64(2048),
						MarkdownDescription: "RSA modulus size. Required when `algorithm = \"RSA\"`.",
						Validators:          []validator.Int64{int64validator.OneOf(2048, 3072, 4096)},
					},
					"curve": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Required when `algorithm = \"EC\"`. Rejected in v1 because the service advertises no curves.",
						Validators:          []validator.String{stringvalidator.OneOf("P-256", "P-384")},
					},
					"exportable": schema.BoolAttribute{
						Optional: true, Computed: true,
						Default: booldefault.StaticBool(true),
						MarkdownDescription: "**Defaults to `true` and `false` is a plan-time ERROR** unless " +
							"`consumer_profile = \"keyvault_crypto_only\"`. Every consumer in the v1 matrix reads the " +
							"PKCS#12 secret, which contains no private key at all when the policy is non-exportable — so " +
							"`false` produces an apply that succeeds, a status page that is entirely green, and an " +
							"Application Gateway listener that will not start, hours later, in a different configuration.",
					},
				},
			},

			// ----------------------------------------------- policy and lifecycle
			"acme_profile": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString(ACMEProfileSentinel),
				MarkdownDescription: "A SENTINEL. `default` keeps tracking the service's current default; the value " +
					"actually used appears in `resolved_acme_profile`.",
			},
			"validation_binding": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString(ValidationBindingSentinel),
				MarkdownDescription: "A SENTINEL. `auto` means server-resolved; the binding actually used appears in " +
					"`resolved_validation_binding`.",
			},
			"consumer_profile": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Validated against `capabilities.consumer_profiles`, never against a provider " +
					"constant — so a consumer outside the v1 matrix is never blocked by a provider release. Omission " +
					"means no consumer-specific validation, never a block.",
			},
			"renewal": schema.SingleNestedAttribute{
				Optional: true, Computed: true,
				Default:             objectdefault.StaticValue(defaultRenewalObject()),
				MarkdownDescription: "Renewal policy only. Changing it never issues.",
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Optional: true, Computed: true,
						Default:             stringdefault.StaticString("automatic"),
						MarkdownDescription: "`suspended` stops renewal without deleting — the declarative escape hatch.",
						Validators:          []validator.String{stringvalidator.OneOf("automatic", "suspended")},
					},
					"use_ari": schema.BoolAttribute{
						Optional: true, Computed: true,
						Default: booldefault.StaticBool(true),
					},
				},
			},
			"deletion_policy": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString("retain"),
				MarkdownDescription: "`retain` or `delete`. The **server's** persisted policy is authoritative for " +
					"destruction and this value may only narrow it. Never implies revocation.",
				Validators: []validator.String{stringvalidator.OneOf("retain", "delete")},
			},
			"acknowledge_irreversible_delete": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default: booldefault.StaticBool(false),
				MarkdownDescription: "Required when `deletion_policy = \"delete\"` and the destination vault has purge " +
					"protection: purge protection makes `delete` conditionally irreversible for up to 90 days.",
			},
			"wait_for": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString(WaitForPublished),
				MarkdownDescription: "`published` (default) or `accepted`. **Client-only**: never sent to the API, never " +
					"overwritten by a refresh. With `accepted`, `versionless_secret_id` is `null` until publication — a " +
					"URI that resolves to nothing is a correctness problem Terraform cannot detect for you.",
			},
			"verification": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Consumer verification. The probe's RESULTS live on the data source, not here.",
				Attributes: map[string]schema.Attribute{
					"consumer_probe": schema.SingleNestedAttribute{
						Optional: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional: true, Computed: true,
								Default: booldefault.StaticBool(false),
								MarkdownDescription: "Defaults to `false`: reachability is constrained by the networking " +
									"mode, and a probe that cannot connect produces a false `consumer_stale`.",
							},
							"expected_pickup": schema.StringAttribute{Optional: true},
							"endpoints": schema.ListNestedAttribute{
								Optional:            true,
								MarkdownDescription: "An array, because one certificate frequently fronts several listeners.",
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"host": schema.StringAttribute{Required: true},
										"port": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(443)},
										"sni":  schema.StringAttribute{Optional: true},
									},
								},
							},
						},
					},
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Stored byte-for-byte; the service never trims it (guarantee G-6).",
				Validators:          []validator.String{stringvalidator.LengthAtMost(1024)},
			},
			"labels": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Client-owned metadata. The server never writes into it — service-owned metadata is " +
					"`system_labels`, which is on the data source. Character class `[A-Za-z0-9 ._:=/+-]`.",
			},

			// ------------------------------------------------- computed outputs
			"versionless_secret_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "**The consumption binding point.** `https://<vault>.<kv-dns-suffix>/secrets/" +
					"<resolved_certificate_name>`. Computed at PLAN time, so a downstream `azurerm_application_gateway` " +
					"sees a known value on the first apply. `null` while `wait_for != \"published\"`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"versionless_certificate_id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"spec_revision": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "Monotonic, **spec-only**. Used as `If-Match`. A renewal never bumps it, so a " +
					"renewal never invalidates a client's precondition.",
			},
			"generation": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Bumps only when the issuance hash changes.",
			},
			"fulfilled_generation": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "The generation actually published. The one deliberate exception to keeping volatile " +
					"status off the resource: it changes a few times a year, so it makes \"is my configuration realised\" " +
					"answerable without a data source and creates no plan noise.",
			},
			"resolved_acme_profile":       schema.StringAttribute{Computed: true},
			"resolved_validation_binding": schema.StringAttribute{Computed: true},
			"publication_mode": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_successful_renewal_at": schema.StringAttribute{
				Computed:   true,
				CustomType: rfc3339.StringType{},
			},
			"current_certificate": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The certificate currently in service. Grouped so the unavoidable post-renewal drift " +
					"note is one compact block a few times a year rather than eight top-level attributes.",
				// UseStateForUnknown is applied CONDITIONALLY in ModifyPlan, not
				// here: it is correct only when the diff touches nothing that could
				// reissue. Marking it unconditionally would make Terraform assert a
				// stale thumbprint that the apply then contradicts.
				PlanModifiers: []planmodifier.Object{},
				Attributes: map[string]schema.Attribute{
					"version_secret_id":      schema.StringAttribute{Computed: true},
					"version_certificate_id": schema.StringAttribute{Computed: true},
					"thumbprint_sha256":      schema.StringAttribute{Computed: true},
					"serial_number":          schema.StringAttribute{Computed: true},
					"not_before":             schema.StringAttribute{Computed: true, CustomType: rfc3339.StringType{}},
					"not_after":              schema.StringAttribute{Computed: true, CustomType: rfc3339.StringType{}},
					"issued_at":              schema.StringAttribute{Computed: true, CustomType: rfc3339.StringType{}},
					"published_at":           schema.StringAttribute{Computed: true, CustomType: rfc3339.StringType{}},
					"issuer":                 schema.StringAttribute{Computed: true},
					"acme_profile":           schema.StringAttribute{Computed: true},
				},
			},
		},
		Blocks: map[string]schema.Block{
			// Legacy block syntax deliberately: it is what every Terraform user
			// knows, and `timeouts` is never sent to the API.
			"timeouts": schema.SingleNestedBlock{
				MarkdownDescription: "Operation timeouts. `create` defaults to **60m**, above the p99 issuance SLO of 45 " +
					"minutes. On a create timeout the provider re-reads the registration and returns SUCCESS if the " +
					"certificate published, because the service keeps working after Terraform gives up.",
				Attributes: map[string]schema.Attribute{
					"create": schema.StringAttribute{Optional: true, MarkdownDescription: "Default `60m`."},
					"read":   schema.StringAttribute{Optional: true, MarkdownDescription: "Default `2m`."},
					"update": schema.StringAttribute{Optional: true, MarkdownDescription: "Default `60m`."},
					"delete": schema.StringAttribute{Optional: true, MarkdownDescription: "Default `10m`."},
				},
				PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// certificateResourceModel mirrors the schema. `tfsdk` tags are the contract
// between the two; a mismatch is caught by ValidateImplementation in the schema
// test.
type certificateResourceModel struct {
	Namespace         types.String `tfsdk:"namespace"`
	Name              types.String `tfsdk:"name"`
	ID                types.String `tfsdk:"id"`
	RegistrationID    types.String `tfsdk:"registration_id"`
	ServiceInstanceID types.String `tfsdk:"service_instance_id"`

	DNSNames   types.Set    `tfsdk:"dns_names"`
	CommonName types.String `tfsdk:"common_name"`

	KeyVaultID              armid.String `tfsdk:"key_vault_id"`
	CertificateName         types.String `tfsdk:"certificate_name"`
	DestinationID           types.String `tfsdk:"destination_id"`
	ResolvedCertificateName types.String `tfsdk:"resolved_certificate_name"`

	Key types.Object `tfsdk:"key"`

	ACMEProfile                   types.String `tfsdk:"acme_profile"`
	ValidationBinding             types.String `tfsdk:"validation_binding"`
	ConsumerProfile               types.String `tfsdk:"consumer_profile"`
	Renewal                       types.Object `tfsdk:"renewal"`
	DeletionPolicy                types.String `tfsdk:"deletion_policy"`
	AcknowledgeIrreversibleDelete types.Bool   `tfsdk:"acknowledge_irreversible_delete"`
	WaitFor                       types.String `tfsdk:"wait_for"`
	Verification                  types.Object `tfsdk:"verification"`
	Description                   types.String `tfsdk:"description"`
	Labels                        types.Map    `tfsdk:"labels"`

	VersionlessSecretID       types.String   `tfsdk:"versionless_secret_id"`
	VersionlessCertificateID  types.String   `tfsdk:"versionless_certificate_id"`
	SpecRevision              types.Int64    `tfsdk:"spec_revision"`
	Generation                types.Int64    `tfsdk:"generation"`
	FulfilledGeneration       types.Int64    `tfsdk:"fulfilled_generation"`
	ResolvedACMEProfile       types.String   `tfsdk:"resolved_acme_profile"`
	ResolvedValidationBinding types.String   `tfsdk:"resolved_validation_binding"`
	PublicationMode           types.String   `tfsdk:"publication_mode"`
	LastSuccessfulRenewalAt   rfc3339.String `tfsdk:"last_successful_renewal_at"`
	CurrentCertificate        types.Object   `tfsdk:"current_certificate"`

	Timeouts types.Object `tfsdk:"timeouts"`
}

type keyModel struct {
	Algorithm  types.String `tfsdk:"algorithm"`
	Size       types.Int64  `tfsdk:"size"`
	Curve      types.String `tfsdk:"curve"`
	Exportable types.Bool   `tfsdk:"exportable"`
}

type renewalModel struct {
	Mode   types.String `tfsdk:"mode"`
	UseARI types.Bool   `tfsdk:"use_ari"`
}

type verificationModel struct {
	ConsumerProbe types.Object `tfsdk:"consumer_probe"`
}

type consumerProbeModel struct {
	Enabled        types.Bool   `tfsdk:"enabled"`
	ExpectedPickup types.String `tfsdk:"expected_pickup"`
	Endpoints      types.List   `tfsdk:"endpoints"`
}

type probeEndpointModel struct {
	Host types.String `tfsdk:"host"`
	Port types.Int64  `tfsdk:"port"`
	SNI  types.String `tfsdk:"sni"`
}

// effectiveCertificateName is `certificate_name` or, when null, `name`.
func (m certificateResourceModel) effectiveCertificateName() string {
	if !m.CertificateName.IsNull() && !m.CertificateName.IsUnknown() && m.CertificateName.ValueString() != "" {
		return m.CertificateName.ValueString()
	}
	return m.Name.ValueString()
}

func (m certificateResourceModel) keyModel(ctx context.Context) (keyModel, bool) {
	var k keyModel
	if m.Key.IsNull() || m.Key.IsUnknown() {
		return k, false
	}
	if diags := m.Key.As(ctx, &k, basetypes.ObjectAsOptions{}); diags.HasError() {
		return k, false
	}
	return k, true
}

// resourceID is the `{namespace}/{name}` primary key. The provider MUST NEVER
// generate a client-side unique key it stores only in memory; this is always
// recomputable from configuration.
func (m certificateResourceModel) resourceID() string {
	return m.Namespace.ValueString() + "/" + m.Name.ValueString()
}

var _ = path.Root
