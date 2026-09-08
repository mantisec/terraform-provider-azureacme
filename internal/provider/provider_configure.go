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

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
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
	ExpectedServiceInstanceID string
	Environment               string
	RequestTimeout            time.Duration
	MaxRetries                int
	SkipVersionCheck          bool
	SkipInstanceCheck         bool
	CredentialMethod          string
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
		out.Endpoint = envChain(cfg.Endpoint, "MANTISEC_ACME_ENDPOINT")
	}
	if out.Audience == "" {
		// NEVER derived from an unauthenticated /v1/capabilities call (F-040): a
		// rogue endpoint could otherwise name an audience for which the CI
		// identity already holds a token, turning the provider into a confused
		// deputy.
		out.Audience = envChain(cfg.Audience, "MANTISEC_ACME_AUDIENCE")
	}
	if out.TenantID == "" {
		out.TenantID = envChain(cfg.TenantID, "MANTISEC_ACME_TENANT_ID", "ARM_TENANT_ID", "AZURE_TENANT_ID")
	}
	if out.ExpectedServiceInstanceID == "" {
		out.ExpectedServiceInstanceID = envChain(cfg.ExpectedServiceInstanceID, "MANTISEC_ACME_SERVICE_INSTANCE_ID")
	}
	if env := envChain(cfg.Environment, "MANTISEC_ACME_ENVIRONMENT", "ARM_ENVIRONMENT", "AZURE_ENVIRONMENT"); env != "" {
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
	out.CredentialMethod = resolveCredentialMethod(ctx, cfg, diags)
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

// resolveCredentialMethod implements §2.4 rules 1 and 2: MORE THAN ONE explicit
// method is an ERROR; exactly one is used alone.
//
// NEVER DefaultAzureCredential. It falls through silently to a developer
// identity, which in CI means a job that should have failed authenticates as
// whoever last ran `az login` on a self-hosted runner. The failure mode is a
// WRONG-IDENTITY SUCCESS, not an error.
func resolveCredentialMethod(_ context.Context, cfg Model, diags *diag.Diagnostics) string {
	type method struct {
		name string
		set  bool
	}
	useOIDC, oidcSet := envChainBool(cfg.UseOIDC, "MANTISEC_ACME_USE_OIDC", "ARM_USE_OIDC")
	useMSI, msiSet := envChainBool(cfg.UseMSI, "MANTISEC_ACME_USE_MSI", "ARM_USE_MSI")
	certPath := envChain(cfg.ClientCertificatePath, "MANTISEC_ACME_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE_PATH")

	explicit := []method{
		{"use_oidc", oidcSet && useOIDC},
		{"use_msi", msiSet && useMSI},
		{"client_certificate_path", certPath != ""},
	}
	var chosen []string
	for _, m := range explicit {
		if m.set {
			chosen = append(chosen, m.name)
		}
	}
	if len(chosen) > 1 {
		diags.AddError("More than one credential method is configured: "+strings.Join(quoteEach(chosen), ", "),
			"Determinism beats convenience. Configure exactly one explicit credential method, or leave them all unset "+
				"and let the ordered ambient chain apply.\n\n"+
				"`DefaultAzureCredential` is deliberately NOT used anywhere in this provider: it falls through silently to "+
				"a developer identity, so a CI job that should have failed authenticates as whoever last ran `az login` on "+
				"the runner. That failure mode is a wrong-identity SUCCESS, not an error.")
		return ""
	}
	if len(chosen) == 1 {
		return chosen[0]
	}

	// The ordered ambient chain, each step gated on its OWN environment
	// precondition.
	switch {
	case os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" && os.Getenv("AZURE_CLIENT_ID") != "":
		return "workload_identity"
	case os.Getenv("IDENTITY_ENDPOINT") != "" || os.Getenv("MSI_ENDPOINT") != "":
		return "managed_identity"
	default:
		return "azure_cli"
	}
}

// buildTokenSource turns the resolved method into a TokenSource.
//
// SCOPE NOTE. Entra token ACQUISITION is owned by AUTH-PROVIDER-CREDENTIAL-CHAIN
// and needs `azidentity`, which this build does not link. What lives here is the
// SELECTION logic of §2.4 (rules 1-3), which is what the provider contract owns,
// plus two sources that need no SDK:
//
//   - MANTISEC_ACME_TOKEN: a pre-acquired bearer token. This is how CI and the
//     acceptance suite authenticate against a fake or a proxied service.
//   - the OIDC token file, when `use_oidc` names one.
//
// Any other method returns a source that fails with a diagnostic naming the
// missing piece, rather than silently sending no Authorization header to a
// production endpoint.
func buildTokenSource(method, audience string) client.TokenSource {
	if raw := os.Getenv("MANTISEC_ACME_TOKEN"); raw != "" {
		return client.StaticTokenSource{Value: raw, MethodName: "static_token_from_environment"}
	}
	return &deferredTokenSource{method: method, audience: audience}
}

type deferredTokenSource struct {
	method   string
	audience string
}

func (d *deferredTokenSource) Method() string { return d.method }

func (d *deferredTokenSource) Token(context.Context) (string, error) {
	if file := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"); d.method == "workload_identity" && file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading the federated token file %q: %w", file, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf(
		"this provider build cannot acquire an Entra token with the %q method: the credential chain "+
			"(AUTH-PROVIDER-CREDENTIAL-CHAIN) is not linked into this build. "+
			"Supply a pre-acquired bearer token for audience %q in MANTISEC_ACME_TOKEN, or use a build that links it",
		d.method, d.audience)
}

// negotiateCapabilities implements §3.2.
func negotiateCapabilities(ctx context.Context, data *providerData, providerVersion string, expectedInstanceID string, diags *diag.Diagnostics) {
	caps := data.Capabilities
	if caps == nil {
		return
	}
	service := caps.Service

	if !data.SkipVersionCheck {
		major, minor, ok := parseAPIVersion(service.APIVersion)
		switch {
		case !ok:
			diags.AddWarning("The service reported an unreadable API version",
				fmt.Sprintf("`api_version` was %q; expected `major.minor`. Proceeding without the version assertions.", service.APIVersion))
		case major != apiMajor:
			diags.AddError("The service speaks a different API major version",
				fmt.Sprintf("This provider speaks API major %d; the service at %s reports %s.\n\n"+
					"A major version is the compatibility boundary. Upgrade or downgrade the provider to a release that "+
					"speaks API %d.x.", apiMajor, data.Client.Endpoint(), service.APIVersion, major))
			return
		case minor < apiMinorRequired:
			diags.AddError("The service is older than this provider requires",
				fmt.Sprintf("This provider requires API %d.%d or later; the service reports %s.\n\n"+
					"Ask your platform administrator to upgrade the service.", apiMajor, apiMinorRequired, service.APIVersion))
			return
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
