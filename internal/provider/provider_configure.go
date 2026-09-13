package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// The three embedded version constants of §3.2.
const (
	// apiMajor is the /v1 compatibility boundary.
	apiMajor = 1
	// apiMinorRequired MAY ONLY BE RAISED IN A PROVIDER MAJOR VERSION. Raising it
	// in a patch makes a workspace unplannable after a routine
	// `terraform init -upgrade` — including certificates that use no new feature
	// — until a platform team the consumer does not control deploys a service
	// upgrade. TestAPIMinorRequiredIsZeroInAV0Provider pins it.
	apiMinorRequired = 0
)

// resolvedConfig is the provider configuration after HCL, connection_profile and
// the environment-variable chains have been resolved.
type resolvedConfig struct {
	Endpoint                  string
	Audience                  string
	TenantID                  string
	ClientID                  string
	ExpectedServiceInstanceID string
	Environment               string
	RequestTimeout            time.Duration
	MaxRetries                int
	SkipVersionCheck          bool
	SkipInstanceCheck         bool
	// Credential is the §2.4 rules 1-3 outcome. Zero-valued when resolution
	// failed, in which case `diags` carries the reason.
	Credential credentialSelection
}

// envChain returns the first non-empty value from HCL then each environment
// variable in order. §2.4: MANTISEC_ACME_* always wins, so a workspace can point
// this provider and `azurerm` at different identities.
func envChain(hcl types.String, names ...string) string {
	if !hcl.IsNull() && !hcl.IsUnknown() && hcl.ValueString() != "" {
		return hcl.ValueString()
	}
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func envChainBool(hcl types.Bool, names ...string) (value bool, set bool) {
	if !hcl.IsNull() && !hcl.IsUnknown() {
		return hcl.ValueBool(), true
	}
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			b, err := strconv.ParseBool(v)
			if err == nil {
				return b, true
			}
		}
	}
	return false, false
}

// resolveConfig applies §2.1 (connection_profile), §2.4 (the precedence table)
// and §2.5 step 1 (the unknown-value diagnostic).
func resolveConfig(ctx context.Context, cfg Model, diags *diag.Diagnostics) resolvedConfig {
	out := resolvedConfig{RequestTimeout: 60 * time.Second, MaxRetries: 5, Environment: "public"}

	// --- connection_profile is mutually exclusive with its four constituents --
	profileSet := !cfg.ConnectionProfile.IsNull() && !cfg.ConnectionProfile.IsUnknown()
	if profileSet {
		var conflicts []string
		for name, v := range map[string]types.String{
			"endpoint": cfg.Endpoint, "audience": cfg.Audience, "tenant_id": cfg.TenantID,
			"expected_service_instance_id": cfg.ExpectedServiceInstanceID,
		} {
			if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
				conflicts = append(conflicts, name)
			}
		}
		if len(conflicts) > 0 {
			sortStrings(conflicts)
			diags.AddAttributeError(path.Root("connection_profile"),
				"`connection_profile` conflicts with "+strings.Join(quoteEach(conflicts), ", "),
				fmt.Sprintf("`connection_profile` collapses `endpoint`, `audience`, `tenant_id` and "+
					"`expected_service_instance_id` into one object emitted by the platform module. Setting both it and %s "+
					"is ambiguous.\n\nRemove %s, or stop using `connection_profile`.",
					strings.Join(quoteEach(conflicts), ", "), strings.Join(quoteEach(conflicts), " and ")))
			return out
		}
		attrs := cfg.ConnectionProfile.Attributes()
		out.Endpoint = objectString(attrs, "endpoint")
		out.Audience = objectString(attrs, "audience")
		out.TenantID = objectString(attrs, "tenant_id")
		out.ExpectedServiceInstanceID = objectString(attrs, "expected_service_instance_id")
	}

	// --- the unknown-value diagnostic (§2.5 step 1) --------------------------
	//
	// Terraform Core calls ConfigureProvider DURING PLAN, so an endpoint derived
	// from a resource attribute arrives UNKNOWN. This converts the design's
	// biggest foot-gun into a self-explaining error.
	for name, v := range map[string]types.String{
		"endpoint": cfg.Endpoint, "audience": cfg.Audience, "tenant_id": cfg.TenantID,
	} {
		if v.IsUnknown() {
			addUnknownEndpointDiagnostic(diags, name)
		}
	}
	if cfg.ConnectionProfile.IsUnknown() {
		addUnknownEndpointDiagnostic(diags, "connection_profile")
	}
	if diags.HasError() {
		return out
	}

	if out.Endpoint == "" {
		out.Endpoint = envChain(cfg.Endpoint, chainEndpoint.names...)
	}
	if out.Audience == "" {
		// NEVER derived from an unauthenticated /v1/capabilities call (F-040): a
		// rogue endpoint could otherwise name an audience for which the CI
		// identity already holds a token, turning the provider into a confused
		// deputy.
		out.Audience = envChain(cfg.Audience, chainAudience.names...)
	}
	if out.TenantID == "" {
		out.TenantID = envChain(cfg.TenantID, chainTenantID.names...)
	}
	out.ClientID = envChain(cfg.ClientID, chainClientID.names...)
	if out.ExpectedServiceInstanceID == "" {
		out.ExpectedServiceInstanceID = envChain(cfg.ExpectedServiceInstanceID, chainServiceInstanceID.names...)
	}
	if env := envChain(cfg.Environment, chainEnvironment.names...); env != "" {
		out.Environment = env
	}
	if raw := envChain(cfg.RequestTimeout, "MANTISEC_ACME_REQUEST_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			diags.AddAttributeError(path.Root("request_timeout"), fmt.Sprintf("Invalid duration %q", raw), err.Error())
		} else {
			out.RequestTimeout = d
		}
	}
	if !cfg.MaxRetries.IsNull() && !cfg.MaxRetries.IsUnknown() {
		out.MaxRetries = int(cfg.MaxRetries.ValueInt64())
	}
	out.SkipVersionCheck, _ = envChainBool(cfg.SkipVersionCheck, "MANTISEC_ACME_SKIP_VERSION_CHECK")
	out.SkipInstanceCheck, _ = envChainBool(cfg.SkipInstanceCheck, "MANTISEC_ACME_SKIP_INSTANCE_CHECK")

	if out.Endpoint == "" {
		diags.AddAttributeError(path.Root("endpoint"), "The service endpoint is not configured",
			"Set `endpoint` (or `connection_profile.endpoint`), or the `MANTISEC_ACME_ENDPOINT` environment variable.\n\n"+
				"The endpoint is the base URL of a certificate service deployed by a SEPARATE Terraform configuration. "+
				"This provider never manages that deployment.")
	}
	// `audience` is OPERATOR-CONFIGURED AND REQUIRED (ADR 0019,
	// identity-and-trust-boundaries.md §9.3). It is deliberately never derived
	// from `/v1/capabilities`: that call is answered before the caller has proved
	// anything, so a rogue, misconfigured or DNS-hijacked endpoint naming
	// Microsoft Graph or ARM would harvest a token carrying the caller's full
	// permissions (F-040). An absent audience therefore fails here rather than
	// being discovered from the endpoint it is supposed to constrain.
	if out.Audience == "" {
		diags.AddAttributeError(path.Root("audience"), "The token audience is not configured",
			"Set `audience` (or `connection_profile.audience`), or the `MANTISEC_ACME_AUDIENCE` environment "+
				"variable. The provider requests a token for `{audience}/.default`.\n\n"+
				"The audience is NOT discovered from the service. `/v1/capabilities` may report the audience it "+
				"expects and this provider warns when the two disagree, but it never adopts the reported value: an "+
				"endpoint that could name its own audience could name Microsoft Graph or ARM instead and collect a "+
				"token carrying every permission the caller holds.")
	}
	if diags.HasError() {
		return out
	}
	out.Credential = resolveCredentialSelection(ctx, cfg, out, diags)
	return out
}

func addUnknownEndpointDiagnostic(diags *diag.Diagnostics, attribute string) {
	diags.AddAttributeError(path.Root(attribute),
		fmt.Sprintf("`%s` is not known at plan time (%s)", attribute, DiagEndpointUnknownAtPlan),
		"Terraform Core calls `ConfigureProvider` DURING PLAN, so a provider argument derived from a resource that has "+
			"not been created yet arrives unknown.\n\n"+
			"This provider is a CLIENT of a service deployed by a SEPARATE Terraform configuration. It cannot be "+
			"configured from a resource managed by the same configuration: data sources are read during plan, so any "+
			"`data \"azureacme_…\"` fails on the first apply, refresh works only from the second apply onward (which is "+
			"why the pattern appears to work and then breaks unreproducibly), and destroy fails with \"provider "+
			"configuration not present to destroy\".\n\n"+
			"Use one of the sanctioned patterns:\n"+
			"  • Two root modules, with the endpoint passed as a variable.\n"+
			"  • A platform-owned CUSTOM DOMAIN as the endpoint. Recommended regardless: Azure appends a random token to "+
			"new `*.azurewebsites.net` names, so `default_hostname` is not derivable from module inputs.\n"+
			"  • The `MANTISEC_ACME_ENDPOINT` environment variable, for CI ergonomics.\n\n"+
			"`terraform apply -target=module.platform` is NOT a supported path. `-target` appears to work when the "+
			"platform module and the certificates are in one configuration, which is exactly what a small team will try.")
}

// negotiateCapabilities implements §3.2.
func negotiateCapabilities(ctx context.Context, data *providerData, providerVersion string, resolved resolvedConfig, diags *diag.Diagnostics) {
	caps := data.Capabilities
	if caps == nil {
		return
	}
	service := caps.Service
	expectedInstanceID := resolved.ExpectedServiceInstanceID

	// THE CONFUSED-DEPUTY GUARD, REPORTING HALF (F-040, ADR 0019).
	//
	// `/v1/capabilities` MAY report the audience the service expects. The provider
	// compares it with the operator-configured one and WARNS on a mismatch — and
	// that is the entire extent of it. It never adopts the reported value, because
	// the call that carries it is answered before the caller has proved anything:
	// a rogue, misconfigured or DNS-hijacked endpoint that could name its own
	// audience could name Microsoft Graph or ARM instead and be handed a token
	// carrying every permission the caller holds. A warning tells an operator they
	// have a real misconfiguration; acting on it would BE the misconfiguration.
	if service.Audience != nil && *service.Audience != "" && *service.Audience != resolved.Audience {
		diags.AddWarning("The service reports a different token audience ("+DiagAudienceMismatchReported+")",
			fmt.Sprintf("Configured `audience`: %q.\nThe service at %s reports it expects %q.\n\n"+
				"The provider is CONTINUING WITH THE CONFIGURED AUDIENCE. It never adopts an audience reported by an "+
				"endpoint: `/v1/capabilities` is answered before the caller has proved anything, so an endpoint able "+
				"to name its own audience could name Microsoft Graph or ARM instead and collect a token carrying "+
				"every permission you hold.\n\n"+
				"If the request is rejected with `token_audience_mismatch`, the reported value is probably the "+
				"correct one — change `audience` deliberately, after checking that `endpoint` names the service you "+
				"meant.",
				resolved.Audience, data.Client.Endpoint(), *service.Audience))
	}

	if !data.SkipVersionCheck {
		major, _, _ := parseAPIVersion(service.APIVersion)
		switch classifyAPIVersion(apiMajor, apiMinorRequired, service.APIVersion) {
		case apiVersionUnreadable:
			diags.AddWarning("The service reported an unreadable API version",
				fmt.Sprintf("`api_version` was %q; expected `major.minor`. Proceeding without the version assertions.", service.APIVersion))
		case apiVersionMajorMismatch:
			diags.AddError("The service speaks a different API major version",
				fmt.Sprintf("This provider speaks API major %d; the service at %s reports %s.\n\n"+
					"A major version is the compatibility boundary. Upgrade or downgrade the provider to a release that "+
					"speaks API %d.x.", apiMajor, data.Client.Endpoint(), service.APIVersion, major))
			return
		case apiVersionMinorBelowRequired:
			diags.AddError("The service is older than this provider requires",
				fmt.Sprintf("This provider requires API %d.%d or later; the service reports %s.\n\n"+
					"Ask your platform administrator to upgrade the service.", apiMajor, apiMinorRequired, service.APIVersion))
			return
		case apiVersionAcceptable:
		}

		// FEATURE GATING IS BY NAME, never by version arithmetic, so a HIGHER
		// minor simply proceeds and unknown fields are ignored.
		if service.MinimumClientVersion != "" && semverLess(providerVersion, service.MinimumClientVersion) {
			diags.AddError("This provider version is below the service's minimum",
				fmt.Sprintf("Provider %s; the service at %s requires at least %s.\n\nUpgrade the provider.",
					providerVersion, data.Client.Endpoint(), service.MinimumClientVersion))
			return
		}
		if service.DeprecatedClientVersion != nil && semverLess(providerVersion, *service.DeprecatedClientVersion) {
			deadline := "an unspecified date"
			if service.DeprecatedClientDeadline != nil {
				deadline = *service.DeprecatedClientDeadline
			}
			diags.AddWarning("This provider version is deprecated by the service ("+DiagClientDeprecated+")",
				fmt.Sprintf("Provider %s is below the service's `deprecated_client_version` (%s). Support ends on %s, "+
					"after which plans will fail.\n\nUpgrade the provider before then.",
					providerVersion, *service.DeprecatedClientVersion, deadline))
		}
	}

	if !data.SkipInstanceCheck && expectedInstanceID != "" && expectedInstanceID != service.InstanceID {
		diags.AddError("The endpoint is not the service instance this configuration expects ("+DiagServiceInstanceMismatch+")",
			fmt.Sprintf("`expected_service_instance_id` is %s.\nThe endpoint %s reports instance %s (%q).\n\n"+
				"Refusing to proceed BEFORE any resource is touched. A stale or mistyped `endpoint` would otherwise make "+
				"every registration look absent, and the next apply would reissue the whole fleet against the wrong "+
				"service.\n\nCheck `endpoint`, or update `expected_service_instance_id` if the migration was deliberate.",
				expectedInstanceID, data.Client.Endpoint(), service.InstanceID, service.InstanceName))
	}

	if data.SkipVersionCheck || data.SkipInstanceCheck {
		var skipped []string
		if data.SkipVersionCheck {
			skipped = append(skipped, "`skip_version_check` (version assertions)")
		}
		if data.SkipInstanceCheck {
			skipped = append(skipped, "`skip_instance_check` (service-instance pinning, including the per-resource check in refresh)")
		}
		diags.AddWarning("A capability assertion is disabled ("+DiagCapabilityCheckSkipped+")",
			fmt.Sprintf("Disabled: %s.\n\nThese are two SEPARATE flags on purpose. A single combined flag would mean that "+
				"the documented workaround for a version wedge also disabled service-instance pinning, re-opening the "+
				"mistyped-endpoint failure in which every certificate is removed from state and reissued against the "+
				"wrong service.\n\nThe `/v1/capabilities` call itself still happens; only the assertions are skipped.",
				strings.Join(skipped, " and ")))
	}
	tflog.Info(ctx, "negotiated service capabilities", map[string]any{
		"instance_id": service.InstanceID, "instance_name": service.InstanceName,
		"api_version": service.APIVersion, "features": service.Features,
	})
}

// apiVersionVerdict is the declared outcome of ONE (provider, service) API
// version pairing — the rule table of release-engineering.md §9.3.
//
// It is a named type rather than a bare bool pair so the version-negotiation
// matrix (version_matrix_test.go, CI-VERSION-MATRIX-SECRET-SURFACE) can enumerate
// every outcome the provider is capable of reaching and fail when a pairing
// reaches one nobody declared. A silent fourth outcome is exactly the compatibility
// bug the matrix exists to catch.
type apiVersionVerdict int

const (
	// apiVersionUnreadable is a version string that is not `major.minor`. It is a
	// WARNING, not an error: a service that cannot spell its version is a service
	// bug, and refusing to plan over it would make a provider release the only
	// escape from someone else's typo.
	apiVersionUnreadable apiVersionVerdict = iota
	// apiVersionMajorMismatch is fatal in BOTH directions. The major version is
	// the compatibility boundary, so a service one major ahead is as unusable as
	// one major behind.
	apiVersionMajorMismatch
	// apiVersionMinorBelowRequired is fatal: the provider needs a feature set the
	// service predates.
	apiVersionMinorBelowRequired
	// apiVersionAcceptable covers the equal minor AND every HIGHER one. A higher
	// minor proceeds — feature gating is by NAME, never by version arithmetic
	// (F-065), so a newer service simply works and its unknown fields, features,
	// enum values and error codes are ignored.
	apiVersionAcceptable
)

// classifyAPIVersion is the version half of §3.2, separated from the diagnostics
// so the rule table can be asserted for a provider requirement OTHER than the one
// this build ships. `apiMinorRequired` is 0 today, which makes
// `apiVersionMinorBelowRequired` unreachable through the fake service harness —
// every minor below the required one is also a different major. Keeping the rule
// exercised through this function is what stops it rotting until the day the
// constant rises.
func classifyAPIVersion(providerMajor, providerMinorRequired int, serviceAPIVersion string) apiVersionVerdict {
	major, minor, ok := parseAPIVersion(serviceAPIVersion)
	switch {
	case !ok:
		return apiVersionUnreadable
	case major != providerMajor:
		return apiVersionMajorMismatch
	case minor < providerMinorRequired:
		return apiVersionMinorBelowRequired
	default:
		return apiVersionAcceptable
	}
}

func parseAPIVersion(v string) (major, minor int, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(parts[0])
	b, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

// semverLess compares two dotted versions numerically. A version this function
// cannot parse — "dev", a release-candidate suffix — is treated as NOT LESS, so
// a development build is never blocked by a minimum-version check it cannot
// meaningfully answer.
func semverLess(a, b string) bool {
	av, aok := parseSemver(a)
	bv, bok := parseSemver(b)
	if !aok || !bok {
		return false
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			return av[i] < bv[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// objectString reads one string attribute out of the connection_profile object.
func objectString(attrs map[string]attr.Value, name string) string {
	v, ok := attrs[name]
	if !ok {
		return ""
	}
	s, ok := v.(basetypes.StringValue)
	if !ok || s.IsNull() || s.IsUnknown() {
		return ""
	}
	return s.ValueString()
}

func quoteEach(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, "`"+v+"`")
	}
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
