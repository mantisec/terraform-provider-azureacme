package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// canonicalDNS is the comparison form of a DNS name. It never invents a value:
// an unnormalisable name is compared literally.
func canonicalDNS(s string) string {
	if c, err := primitives.Normalise(s); err == nil {
		return c
	}
	return s
}

// ConfigValidators are the CONFIG-ONLY rules of §5.4. They run before any API
// call at all, which is what makes `exportable = false` fail at validation rather
// than after apply has begun changing other resources.
func (r *certificateResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{certificateConfigValidator{}}
}

type certificateConfigValidator struct{}

func (certificateConfigValidator) Description(context.Context) string {
	return "validates the certificate configuration against the rules that need no service round trip"
}

func (v certificateConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (certificateConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg certificateResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// --- reserved: common_name (D-30) ---------------------------------------
	if !cfg.CommonName.IsNull() && !cfg.CommonName.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("common_name"),
			fmt.Sprintf("`common_name` is reserved and cannot be set in v1: %q", cfg.CommonName.ValueString()),
			"Decision D-30 is unresolved: whether Key Vault accepts a policy subject with no common name, and whether the "+
				"certificate authority accepts such a CSR, are both unverified.\n\n"+
				"It is NOT derived from `dns_names` either — a `Set` has no first element, and deriving it from canonical "+
				"sort order would mean that adding `a.example.com` to a registration whose names all start with `b` silently "+
				"changes the certificate's Common Name and forces a reissue for a reason no user could predict from their "+
				"diff.\n\nRemove the attribute.")
	}

	// --- wait_for ------------------------------------------------------------
	if !cfg.WaitFor.IsNull() && !cfg.WaitFor.IsUnknown() {
		switch cfg.WaitFor.ValueString() {
		case WaitForPublished, WaitForAccepted:
		case "consumer_observed":
			resp.Diagnostics.AddAttributeError(path.Root("wait_for"),
				`"consumer_observed" cannot be waited for`,
				"Waiting for a consumer to observe the certificate would require the consumer to already reference "+
					"`versionless_secret_id` — which it cannot do until this resource has finished applying. That is a "+
					"circular dependency, not a slow wait.\n\n"+
					"Use `wait_for = \"published\"` (the default) and verify consumer pickup with "+
					"`data.azureacme_certificate`, whose `delivery_stage` and `consumers[]` report it.")
		case "best_effort":
			resp.Diagnostics.AddAttributeError(path.Root("wait_for"),
				`"best_effort" is reserved and rejected in v1`,
				"It would return success with a warning while the operation is still healthy. That is the escalation path "+
					"if the v1 timeout contract proves unacceptable, and it is deliberately not enabled yet: the timeout "+
					"contract already returns SUCCESS when the certificate published while Terraform was waiting.\n\n"+
					"Use `\"published\"` or `\"accepted\"`.")
		default:
			resp.Diagnostics.AddAttributeError(path.Root("wait_for"),
				fmt.Sprintf("Invalid `wait_for` value %q", cfg.WaitFor.ValueString()),
				`Expected "published" (the default) or "accepted".`)
		}
	}

	// --- key policy ----------------------------------------------------------
	if k, ok := cfg.keyModel(ctx); ok {
		algorithm := "RSA"
		if !k.Algorithm.IsNull() && !k.Algorithm.IsUnknown() {
			algorithm = k.Algorithm.ValueString()
		}
		sizeSet := !k.Size.IsNull() && !k.Size.IsUnknown()
		curveSet := !k.Curve.IsNull() && !k.Curve.IsUnknown()

		switch algorithm {
		case "RSA":
			if curveSet {
				resp.Diagnostics.AddAttributeError(path.Root("key").AtName("curve"),
					"`key.curve` is meaningless for an RSA key",
					"Set `key.size` instead, or set `key.algorithm = \"EC\"`.\n\n"+
						"A flat `key_algorithm` + `key_size` pair cannot model this at all, which is why the key policy is a "+
						"nested object: with a flat pair users write `algorithm = \"EC\"` with `size = 256` — neither a curve "+
						"nor a valid RSA size — and the provider can only fail at apply.")
			}
		case "EC":
			if sizeSet {
				resp.Diagnostics.AddAttributeError(path.Root("key").AtName("size"),
					"`key.size` is meaningless for an EC key",
					"Set `key.curve` instead.")
			}
			if !curveSet {
				resp.Diagnostics.AddAttributeError(path.Root("key").AtName("curve"),
					"`key.curve` is required when `key.algorithm = \"EC\"`",
					`Expected "P-256" or "P-384".`)
			}
		}

		// --- THE EXPORTABLE RULE (§5.6) -------------------------------------
		//
		// This is the single most dangerous line in the source design and two
		// reviewers specified opposite values. Take `false` and: the apply
		// succeeds; versionless_secret_id is populated; delivery_stage reads
		// published; every status field is green. Then the Application Gateway
		// listener will not start, and the failure surfaces in a DIFFERENT
		// Terraform configuration, as an Azure error about a Key Vault secret,
		// hours later. No error at any layer.
		if !k.Exportable.IsNull() && !k.Exportable.IsUnknown() && !k.Exportable.ValueBool() {
			profile := ""
			if !cfg.ConsumerProfile.IsNull() && !cfg.ConsumerProfile.IsUnknown() {
				profile = cfg.ConsumerProfile.ValueString()
			}
			if profile != ConsumerProfileCryptoOnly {
				resp.Diagnostics.AddAttributeError(path.Root("key").AtName("exportable"),
					"`key.exportable = false` produces a certificate no consumer in the v1 matrix can use",
					"Every consumer in the supported matrix — Application Gateway, Front Door, App Service, API Management, "+
						"Container Apps, the AKS CSI driver and self-managed readers — reads the Key Vault PKCS#12 SECRET, "+
						"which contains NO PRIVATE KEY at all when the certificate policy is non-exportable.\n\n"+
						"With `false` the apply succeeds, `versionless_secret_id` is populated, `delivery_stage` reads "+
						"`published`, and every status field is green — and then the listener will not start, hours later, in "+
						"a different Terraform configuration, as an Azure error about a Key Vault secret.\n\n"+
						"Remove the `key` block entirely (the default is `true`, which is correct for every v1 consumer).\n\n"+
						"If this certificate really is only used for Key Vault cryptographic operations and is never read as "+
						"a secret, set `consumer_profile = \""+ConsumerProfileCryptoOnly+"\"` to say so explicitly.")
			}
		}
	}

	// --- labels --------------------------------------------------------------
	if !cfg.Labels.IsNull() && !cfg.Labels.IsUnknown() {
		labels := map[string]string{}
		resp.Diagnostics.Append(cfg.Labels.ElementsAs(ctx, &labels, false)...)
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			value := labels[k]
			if len(k) > 128 {
				resp.Diagnostics.AddAttributeError(path.Root("labels"),
					fmt.Sprintf("Label key is too long: %q", k),
					fmt.Sprintf("Keys are at most 128 bytes; this one is %d.", len(k)))
			}
			if len(value) > 256 {
				resp.Diagnostics.AddAttributeError(path.Root("labels"),
					fmt.Sprintf("Label value is too long for key %q", k),
					fmt.Sprintf("Values are at most 256 bytes; this one is %d.", len(value)))
			}
			if !labelCharClass.MatchString(k) {
				resp.Diagnostics.AddAttributeError(path.Root("labels"),
					fmt.Sprintf("Invalid character in label key: %q", k),
					"Permitted characters are `[A-Za-z0-9 ._:=/+-]`.")
			}
			if !labelCharClass.MatchString(value) {
				resp.Diagnostics.AddAttributeError(path.Root("labels"),
					fmt.Sprintf("Invalid character in label value: %q", value),
					"Permitted characters are `[A-Za-z0-9 ._:=/+-]`.\n\n"+
						"Note that `,` is NOT permitted: the character class published in the source review was "+
						"`[A-Za-z0-9 +-./:=_]`, in which `+-.` is a RANGE and silently admitted it.")
			}
		}
	}

	// --- deletion_policy = "delete" ------------------------------------------
	if cfg.DeletionPolicy.ValueString() == "delete" &&
		(cfg.AcknowledgeIrreversibleDelete.IsNull() || !cfg.AcknowledgeIrreversibleDelete.ValueBool()) {
		// The purge-protection state of the destination vault is NOT knowable to
		// this provider: it links no Azure control-plane SDK, and no service
		// response carries the flag. The check therefore lands SERVER-SIDE as
		// `400 acknowledgement_required`. This warning exists so the plan says so
		// rather than letting the apply be the first mention of it.
		resp.Diagnostics.AddAttributeWarning(path.Root("deletion_policy"),
			"`deletion_policy = \"delete\"` may be irreversible for up to 90 days",
			"If the destination vault has purge protection enabled, deleting the certificate soft-deletes it and the NAME "+
				"cannot be reused until the retention period expires — 7 to 90 days, configurable only at vault creation.\n\n"+
				"The service rejects this combination with `acknowledgement_required` unless "+
				"`acknowledge_irreversible_delete = true`. Set it deliberately, or use `deletion_policy = \"retain\"`.\n\n"+
				"For non-production destination vaults, create them with `soft_delete_retention_days = 7` and "+
				"`purge_protection_enabled = false`, or a destroy/recreate loop in CI will wedge on the name.")
	}
}

// validateAgainstCapabilities is the half of §5.4 that needs the CACHED
// capabilities document. It runs in ModifyPlan because Terraform calls
// ValidateResourceConfig BEFORE ConfigureProvider, so the cache does not exist
// yet at ValidateConfig time.
func (r *certificateResource) validateAgainstCapabilities(ctx context.Context, plan certificateResourceModel, diags *diag.Diagnostics) {
	if r.data == nil || r.data.Capabilities == nil {
		return
	}
	caps := r.data.Capabilities.Service

	// --- key policy against what the service actually ENABLES ---------------
	if k, ok := plan.keyModel(ctx); ok && !k.Algorithm.IsNull() && !k.Algorithm.IsUnknown() {
		algorithm := k.Algorithm.ValueString()
		if len(caps.KeyPolicies.Algorithms) > 0 && !containsString(caps.KeyPolicies.Algorithms, algorithm) {
			detail := fmt.Sprintf("This service instance enables %s.\n\n", quoteList(caps.KeyPolicies.Algorithms))
			if algorithm == "EC" {
				detail += "EC is REPRESENTABLE in the schema and not PERMITTED in v1: Azure Front Door does not support " +
					"elliptic-curve certificates, so enabling EC is a SERVICE POLICY change (`capabilities.key_policies`), " +
					"not a provider release.\n\n"
			}
			diags.AddAttributeError(path.Root("key").AtName("algorithm"),
				fmt.Sprintf("Key algorithm %q is not enabled on this service", algorithm),
				detail+"Remove the `key` block to take the default (RSA 2048, exportable), which is correct for every "+
					"consumer in the v1 matrix.")
		}
		if algorithm == "RSA" && !k.Size.IsNull() && !k.Size.IsUnknown() && len(caps.KeyPolicies.RSASizes) > 0 {
			if !containsInt64(caps.KeyPolicies.RSASizes, k.Size.ValueInt64()) {
				diags.AddAttributeError(path.Root("key").AtName("size"),
					fmt.Sprintf("RSA key size %d is not enabled on this service", k.Size.ValueInt64()),
					fmt.Sprintf("This service instance enables %v.", caps.KeyPolicies.RSASizes))
			}
		}
		if algorithm == "EC" && !k.Curve.IsNull() && !k.Curve.IsUnknown() && !containsString(caps.KeyPolicies.Curves, k.Curve.ValueString()) {
			diags.AddAttributeError(path.Root("key").AtName("curve"),
				fmt.Sprintf("Curve %q is not enabled on this service", k.Curve.ValueString()),
				"This service instance advertises no curves, so EC is unavailable. Enabling it is a service policy change.")
		}
	}

	// --- acme_profile against the advertised set ----------------------------
	if !plan.ACMEProfile.IsNull() && !plan.ACMEProfile.IsUnknown() {
		profile := plan.ACMEProfile.ValueString()
		if profile != ACMEProfileSentinel {
			names := acmeProfileNames(caps)
			if len(names) > 0 && !containsString(names, profile) {
				diags.AddAttributeError(path.Root("acme_profile"),
					fmt.Sprintf("ACME profile %q is not offered by this service", profile),
					fmt.Sprintf("Available profiles: %s, plus the sentinel %q which tracks the service default (currently %q).",
						quoteList(names), ACMEProfileSentinel, caps.ACME.DefaultProfile))
			}
		}
	}

	// --- consumer_profile against capabilities, NEVER a Go constant ---------
	if !plan.ConsumerProfile.IsNull() && !plan.ConsumerProfile.IsUnknown() {
		name := plan.ConsumerProfile.ValueString()
		known := make([]string, 0, len(caps.ConsumerProfiles))
		for _, p := range caps.ConsumerProfiles {
			known = append(known, p.Name)
		}
		if len(known) > 0 && !containsString(known, name) {
			diags.AddAttributeError(path.Root("consumer_profile"),
				fmt.Sprintf("Consumer profile %q is not known to this service", name),
				fmt.Sprintf("This service instance advertises %s.\n\nThe list comes from `/v1/capabilities`, never from a "+
					"provider constant, so a consumer outside the v1 matrix is never blocked by a provider release.",
					quoteList(known)))
		}
	}

	// --- limits --------------------------------------------------------------
	if caps.Limits.MaxDNSNames != nil && !plan.DNSNames.IsNull() && !plan.DNSNames.IsUnknown() {
		if n := int64(len(plan.DNSNames.Elements())); n > *caps.Limits.MaxDNSNames {
			diags.AddAttributeError(path.Root("dns_names"),
				fmt.Sprintf("Too many DNS names: %d", n),
				fmt.Sprintf("This service instance permits at most %d per registration.", *caps.Limits.MaxDNSNames))
		}
	}
	if caps.Limits.MaxLabels != nil && !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		if n := int64(len(plan.Labels.Elements())); n > *caps.Limits.MaxLabels {
			diags.AddAttributeError(path.Root("labels"),
				fmt.Sprintf("Too many labels: %d", n),
				fmt.Sprintf("This service instance permits at most %d.", *caps.Limits.MaxLabels))
		}
	}

	// --- identifier count against the RESOLVED profile ----------------------
	profileName := plan.ACMEProfile.ValueString()
	if profileName == ACMEProfileSentinel || profileName == "" {
		profileName = caps.ACME.DefaultProfile
	}
	if max, ok := profileMaxIdentifiers(caps, profileName); ok && !plan.DNSNames.IsUnknown() {
		if n := int64(len(plan.DNSNames.Elements())); n > max {
			diags.AddAttributeError(path.Root("dns_names"),
				fmt.Sprintf("Too many DNS names for ACME profile %q: %d", profileName, n),
				fmt.Sprintf("The %q profile permits at most %d identifiers per certificate.", profileName, max))
		}
	}
}

func acmeProfileNames(caps contracts.ServiceCapabilities) []string {
	var out []string
	for _, p := range caps.ACME.Profiles {
		if raw, ok := p["name"]; ok {
			out = append(out, strings.Trim(string(raw), `"`))
		}
	}
	return out
}

func profileMaxIdentifiers(caps contracts.ServiceCapabilities, name string) (int64, bool) {
	for _, p := range caps.ACME.Profiles {
		raw, ok := p["name"]
		if !ok || strings.Trim(string(raw), `"`) != name {
			continue
		}
		if maxRaw, ok := p["max_identifiers"]; ok {
			var n int64
			if _, err := fmt.Sscan(string(maxRaw), &n); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func containsInt64(haystack []int64, needle int64) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func quoteList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ", ")
}
