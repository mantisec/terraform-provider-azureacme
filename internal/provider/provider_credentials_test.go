package provider

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// credentialEnvVars is every environment variable that can influence §2.4
// resolution. The tables below clear ALL of them for every case and then set
// only what the case names, so a contributor's own exported `ARM_*` cannot make
// a case pass or fail for reasons the case does not state.
//
// It is DERIVED from `credentialEnvChains` rather than typed out, because a
// hand-maintained copy goes stale the moment a row is added to §2.4's table —
// and a variable that is not cleared is one the CI runner may have exported,
// which turns a deterministic test into one that passes on a laptop.
var credentialEnvVars = func() []string {
	// The rule-3 preconditions and the pre-acquired-token method are not rows of
	// the precedence table, so they are named here.
	names := []string{envStaticToken, "IDENTITY_ENDPOINT", "MSI_ENDPOINT"}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	for _, chain := range credentialEnvChains {
		for _, n := range chain.names {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names
}()

// withCredentialEnv clears every credential variable and applies env.
func withCredentialEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range credentialEnvVars {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// resolveCredentialsFor runs the whole of §2.4 for one case.
func resolveCredentialsFor(t *testing.T, m Model) (resolvedConfig, diag.Diagnostics) {
	t.Helper()
	var diags diag.Diagnostics
	resolved := resolveConfig(context.Background(), m, &diags)
	return resolved, diags
}

// baseCredentialModel is a model whose non-credential arguments are complete, so
// a case's diagnostics are only ever about credentials.
func baseCredentialModel(t *testing.T) Model {
	t.Helper()
	m := nullProviderModel(t)
	m.Endpoint = types.StringValue("https://certs.example.com")
	m.Audience = types.StringValue("api://mantisec-acme")
	m.TenantID = types.StringValue("00000000-0000-0000-0000-000000000000")
	return m
}

func diagnosticsText(d diag.Diagnostics) string {
	var b strings.Builder
	for _, one := range d {
		b.WriteString(one.Summary())
		b.WriteString(" ")
		b.WriteString(one.Detail())
		b.WriteString("\n")
	}
	return b.String()
}

// TestCredentialResolution is terraform-provider-contract.md §2.4 rules 1, 2 and
// 3, end to end and in one table.
//
// The three properties it exists to hold, in the item's own words:
//
//   - configuring TWO explicit methods returns a configuration error naming both;
//   - exactly one configured method is used, with NO fallback, even when the
//     ambient chain's preconditions are all satisfied around it;
//   - the unconfigured case walks the rule-3 chain only as far as each step's own
//     environment precondition allows, and fails loudly when no step qualifies.
//
// Every one of them protects against the same failure: a WRONG-IDENTITY SUCCESS,
// where the run authenticates as a principal nobody chose, the service answers
// `404` because that principal owns nothing, and `Read` is one bad `if` away from
// calling that "the registration is gone".
func TestCredentialResolution(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "client.pfx")
	if err := os.WriteFile(certPath, []byte("not a real certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		env    map[string]string
		mutate func(*Model)

		wantMethod string
		wantRule   int
		// wantErrorContains is every substring the error must carry. A non-empty
		// value also asserts that resolution produced NO method at all.
		wantErrorContains []string
	}{
		// ------------------------------------------------------------- rule 1
		{
			name:              "rule 1: use_oidc and use_msi together is an error naming both",
			mutate:            func(m *Model) { m.UseOIDC = types.BoolValue(true); m.UseMSI = types.BoolValue(true) },
			wantErrorContains: []string{DiagMultipleCredentialMethods, "use_oidc", "use_msi", "EXACTLY ONE"},
		},
		{
			name: "rule 1: use_oidc and client_certificate_path together is an error naming both",
			mutate: func(m *Model) {
				m.UseOIDC = types.BoolValue(true)
				m.ClientCertificatePath = types.StringValue(certPath)
			},
			wantErrorContains: []string{DiagMultipleCredentialMethods, "use_oidc", "client_certificate_path"},
		},
		{
			name:              "rule 1: a pre-acquired token alongside use_msi is an error naming both",
			env:               map[string]string{"MANTISEC_ACME_TOKEN": "pre-acquired", "ARM_CLIENT_ID": "client"},
			mutate:            func(m *Model) { m.UseMSI = types.BoolValue(true) },
			wantErrorContains: []string{DiagMultipleCredentialMethods, "MANTISEC_ACME_TOKEN", "use_msi"},
		},
		{
			name: "rule 1: three configured methods names all three",
			env:  map[string]string{"ARM_USE_OIDC": "true"},
			mutate: func(m *Model) {
				m.UseMSI = types.BoolValue(true)
				m.ClientCertificatePath = types.StringValue(certPath)
			},
			wantErrorContains: []string{"use_oidc", "use_msi", "client_certificate_path"},
		},
		{
			name:       "rule 1 does NOT fire on use_cli, which is the rule-3 gate rather than a method",
			mutate:     func(m *Model) { m.UseOIDC = types.BoolValue(true); m.UseCLI = types.BoolValue(true) },
			wantMethod: methodWorkloadIdentity,
			wantRule:   2,
		},
		{
			name:       "rule 1 does NOT fire on use_oidc = false",
			mutate:     func(m *Model) { m.UseOIDC = types.BoolValue(false); m.UseMSI = types.BoolValue(true) },
			env:        map[string]string{"ARM_CLIENT_ID": "client"},
			wantMethod: methodManagedIdentity,
			wantRule:   2,
		},

		// ------------------------------------------------------------- rule 2
		{
			name:       "rule 2: use_oidc alone",
			mutate:     func(m *Model) { m.UseOIDC = types.BoolValue(true) },
			wantMethod: methodWorkloadIdentity,
			wantRule:   2,
		},
		{
			name: "rule 2: the ONE configured method wins even though every ambient precondition is satisfied",
			env: map[string]string{
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
				"AZURE_CLIENT_ID":            "federated-client",
				"IDENTITY_ENDPOINT":          "http://169.254.169.254/metadata/identity/oauth2/token",
			},
			mutate:     func(m *Model) { m.ClientCertificatePath = types.StringValue(certPath) },
			wantMethod: methodClientCertificate,
			wantRule:   2,
		},
		{
			name:       "rule 2: a pre-acquired token is an explicit method",
			env:        map[string]string{"MANTISEC_ACME_TOKEN": "pre-acquired"},
			wantMethod: methodStaticToken,
			wantRule:   2,
		},
		{
			name:       "rule 2: use_msi with client_id",
			env:        map[string]string{"ARM_CLIENT_ID": "user-assigned-client-id"},
			mutate:     func(m *Model) { m.UseMSI = types.BoolValue(true) },
			wantMethod: methodManagedIdentity,
			wantRule:   2,
		},
		{
			name:   "rule 2: use_msi WITHOUT client_id is an error, because IMDS answers an ambiguous request",
			mutate: func(m *Model) { m.UseMSI = types.BoolValue(true) },
			wantErrorContains: []string{
				DiagManagedIdentityClientIDRequired, "client_id", "AMBIGUOUS", "AZURE_CLIENT_ID",
			},
		},

		// ------------------------------------------------------------- rule 3
		{
			name: "rule 3 step 1: both federated preconditions present",
			env: map[string]string{
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token",
				"AZURE_CLIENT_ID":            "federated-client",
			},
			wantMethod: methodWorkloadIdentity,
			wantRule:   3,
		},
		{
			name:       "rule 3 step 1 is SKIPPED when only the token file is present",
			env:        map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token"},
			wantMethod: methodAzureCLI,
			wantRule:   3,
		},
		{
			name:       "rule 3 step 1 is SKIPPED when only the client id is present",
			env:        map[string]string{"AZURE_CLIENT_ID": "federated-client"},
			wantMethod: methodAzureCLI,
			wantRule:   3,
		},
		{
			name: "rule 3 step 1 is tried BEFORE step 2 when both preconditions hold",
			env: map[string]string{
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
				"AZURE_CLIENT_ID":            "federated-client",
				"IDENTITY_ENDPOINT":          "http://169.254.169.254/metadata/identity/oauth2/token",
			},
			wantMethod: methodWorkloadIdentity,
			wantRule:   3,
		},
		{
			name: "rule 3 step 2: IDENTITY_ENDPOINT with a client id",
			env: map[string]string{
				"IDENTITY_ENDPOINT": "http://169.254.169.254/metadata/identity/oauth2/token",
				"ARM_CLIENT_ID":     "user-assigned-client-id",
			},
			wantMethod: methodManagedIdentity,
			wantRule:   3,
		},
		{
			name: "rule 3 step 2: MSI_ENDPOINT is the same precondition",
			env: map[string]string{
				"MSI_ENDPOINT":            "http://127.0.0.1:41337/msi/token",
				"MANTISEC_ACME_CLIENT_ID": "user-assigned-client-id",
			},
			wantMethod: methodManagedIdentity,
			wantRule:   3,
		},
		{
			name: "rule 3 step 2 errors rather than falling through to the CLI when client_id is absent",
			env: map[string]string{
				"IDENTITY_ENDPOINT": "http://169.254.169.254/metadata/identity/oauth2/token",
			},
			wantErrorContains: []string{DiagManagedIdentityClientIDRequired},
		},
		{
			name:       "rule 3 step 3: nothing configured and nothing in the environment",
			wantMethod: methodAzureCLI,
			wantRule:   3,
		},
		{
			name:   "rule 3 step 3 is gated on use_cli, so use_cli = false leaves NO step qualifying",
			mutate: func(m *Model) { m.UseCLI = types.BoolValue(false) },
			wantErrorContains: []string{
				DiagNoCredentialMethod, "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_ENDPOINT", "use_cli",
			},
		},
		{
			name:              "rule 3 step 3 is gated by ARM_USE_CLI too",
			env:               map[string]string{"ARM_USE_CLI": "false"},
			wantErrorContains: []string{DiagNoCredentialMethod},
		},
		{
			name:       "MANTISEC_ACME_USE_CLI beats ARM_USE_CLI",
			env:        map[string]string{"MANTISEC_ACME_USE_CLI": "true", "ARM_USE_CLI": "false"},
			wantMethod: methodAzureCLI,
			wantRule:   3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCredentialEnv(t, tc.env)
			m := baseCredentialModel(t)
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			resolved, diags := resolveCredentialsFor(t, m)
			text := diagnosticsText(diags)

			if len(tc.wantErrorContains) > 0 {
				if !diags.HasError() {
					t.Fatalf("expected a configuration error; got method %q and diagnostics:\n%s",
						resolved.Credential.Method, text)
				}
				if resolved.Credential.Method != "" {
					t.Errorf("a failed resolution must select NO method; got %q", resolved.Credential.Method)
				}
				for _, want := range tc.wantErrorContains {
					if !strings.Contains(text, want) {
						t.Errorf("the error must name %q; got:\n%s", want, text)
					}
				}
				return
			}

			if diags.HasError() {
				t.Fatalf("unexpected error:\n%s", text)
			}
			if resolved.Credential.Method != tc.wantMethod {
				t.Errorf("method = %q, want %q (diagnostics: %s)", resolved.Credential.Method, tc.wantMethod, text)
			}
			if resolved.Credential.Rule != tc.wantRule {
				t.Errorf("chosen by rule %d, want rule %d", resolved.Credential.Rule, tc.wantRule)
			}
		})
	}
}

// TestCredentialResolution_NoSilentFallbackWhenTheChosenMethodFails is the other
// half of §2.4 rule 2: "exactly one configured method is used with NO FALLBACK
// when it fails".
//
// The configured method here cannot produce a token in this build. The provider
// must then FAIL, naming the method it was told to use — never quietly try the
// next one, and never send an unauthenticated request to a production endpoint.
func TestCredentialResolution_NoSilentFallbackWhenTheChosenMethodFails(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("a.federated.assertion"), 0o600); err != nil {
		t.Fatal(err)
	}
	withCredentialEnv(t, map[string]string{
		// Both remaining chain steps are available. Neither may be reached.
		"AZURE_FEDERATED_TOKEN_FILE": tokenFile,
		"AZURE_CLIENT_ID":            "federated-client",
	})

	m := baseCredentialModel(t)
	m.ClientCertificatePath = types.StringValue(filepath.Join(t.TempDir(), "client.pfx"))

	resolved, diags := resolveCredentialsFor(t, m)
	if diags.HasError() {
		t.Fatalf("resolveConfig: %s", diagnosticsText(diags))
	}
	if resolved.Credential.Method != methodClientCertificate {
		t.Fatalf("method = %q, want %q", resolved.Credential.Method, methodClientCertificate)
	}

	src := buildTokenSource(resolved.Credential)
	if src.Method() != methodClientCertificate {
		t.Errorf("the token source must report the method actually used (it is what the 401 diagnostic names); got %q",
			src.Method())
	}
	token, err := src.Token(context.Background())
	if err == nil {
		t.Fatalf("the client-certificate method cannot produce a token in this build, so it must FAIL rather than "+
			"fall back; got a token of %d bytes", len(token))
	}
	if token != "" {
		t.Fatal("a failing token source must return no token at all")
	}
	if !strings.Contains(err.Error(), methodClientCertificate) {
		t.Errorf("the failure must name the method that was configured; got %q", err)
	}
	for _, mustNotFallBack := range []string{methodAzureCLI, methodWorkloadIdentity, methodManagedIdentity} {
		if strings.Contains(err.Error(), "using "+mustNotFallBack) {
			t.Errorf("the error suggests a fallback to %q was attempted: %q", mustNotFallBack, err)
		}
	}
}

// TestFederatedAssertionIsNeverSentAsABearerToken.
//
// `AZURE_FEDERATED_TOKEN_FILE` holds the CI system's OIDC client ASSERTION, whose
// audience is `api://AzureADTokenExchange`. Presenting it to the service as a
// bearer token would authenticate nothing and would hand the endpoint a credential
// it can replay to Entra to obtain an access token as the caller — the confused
// deputy of F-015 with the roles reversed.
func TestFederatedAssertionIsNeverSentAsABearerToken(t *testing.T) {
	const assertion = "eyJhbGciOiJSUzI1NiJ9.THE-CI-ASSERTION-MUST-NEVER-BE-SENT.sig"
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte(assertion), 0o600); err != nil {
		t.Fatal(err)
	}
	withCredentialEnv(t, map[string]string{
		"AZURE_FEDERATED_TOKEN_FILE": tokenFile,
		"AZURE_CLIENT_ID":            "federated-client",
	})

	resolved, diags := resolveCredentialsFor(t, baseCredentialModel(t))
	if diags.HasError() {
		t.Fatalf("resolveConfig: %s", diagnosticsText(diags))
	}
	if resolved.Credential.Method != methodWorkloadIdentity {
		t.Fatalf("method = %q, want %q", resolved.Credential.Method, methodWorkloadIdentity)
	}

	got, err := buildTokenSource(resolved.Credential).Token(context.Background())
	if err == nil {
		t.Fatal("the workload-identity source must fail rather than produce a token in this build")
	}
	if got == assertion {
		t.Fatal("the CI assertion was returned as a bearer token: it would be replayable against Entra by whatever " +
			"the endpoint turns out to be")
	}
	if strings.Contains(err.Error(), assertion) {
		t.Fatalf("the assertion leaked into the error text: %q", err)
	}
}

// TestConfigure_ReportedAudienceMismatchWarnsAndChangesNothing is the F-040
// confused-deputy guard, reporting half.
//
// `/v1/capabilities` MAY report the audience the service expects. The provider
// warns when it disagrees with the configured one, and that is all: adopting a
// value from an endpoint that has not authenticated anything is how a rogue,
// misconfigured or DNS-hijacked host names Microsoft Graph or ARM and is handed a
// token carrying every permission the caller holds.
func TestConfigure_ReportedAudienceMismatchWarnsAndChangesNothing(t *testing.T) {
	const configured = "api://mantisec-acme"
	const reported = "https://graph.microsoft.com"

	srv := fakeservice.New(t, func(o *fakeservice.Options) { o.ReportedAudience = reported })
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), configured, "tenant", "")
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})

	if resp.Diagnostics.HasError() {
		t.Fatalf("a reported-audience mismatch is a WARNING, never an error: %v", resp.Diagnostics)
	}
	var detail string
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), DiagAudienceMismatchReported) {
			detail = d.Detail()
		}
	}
	if detail == "" {
		t.Fatalf("expected the %s warning; got %v", DiagAudienceMismatchReported, resp.Diagnostics)
	}
	for _, want := range []string{configured, reported, "CONTINUING WITH THE CONFIGURED AUDIENCE"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the warning must contain %q; got:\n%s", want, detail)
		}
	}

	data, ok := resp.ResourceData.(*providerData)
	if !ok {
		t.Fatalf("ResourceData = %T, want *providerData", resp.ResourceData)
	}
	if got := data.Client.Audience(); got != configured {
		t.Fatalf("the client requests tokens for %q; it must still use the CONFIGURED audience %q", got, configured)
	}
}

// TestConfigure_MatchingReportedAudienceIsSilent: the warning must fire on a
// genuine disagreement and nothing else, or operators learn to ignore it.
func TestConfigure_MatchingReportedAudienceIsSilent(t *testing.T) {
	const configured = "api://mantisec-acme"
	for _, tc := range []struct {
		name     string
		reported string
	}{
		{"the service agrees", configured},
		{"the service reports nothing at all", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeservice.New(t, func(o *fakeservice.Options) { o.ReportedAudience = tc.reported })
			m := nullProviderModel(t)
			m.ConnectionProfile = connectionProfileObject(t, srv.URL(), configured, "tenant", "")
			resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
			if resp.Diagnostics.HasError() {
				t.Fatalf("Configure: %v", resp.Diagnostics)
			}
			for _, d := range resp.Diagnostics.Warnings() {
				if strings.Contains(d.Summary(), DiagAudienceMismatchReported) {
					t.Fatalf("unexpected audience warning: %s", d.Detail())
				}
			}
		})
	}
}

// TestConfigure_AudienceIsRequired. The audience is operator-configured and
// required (ADR 0019); it is never discovered from the endpoint it exists to
// constrain.
func TestConfigure_AudienceIsRequired(t *testing.T) {
	withCredentialEnv(t, map[string]string{"MANTISEC_ACME_ENDPOINT": "https://certs.example.com"})
	_, diags := resolveCredentialsFor(t, nullProviderModel(t))
	if !diags.HasError() {
		t.Fatal("an unset audience must be a configuration error")
	}
	text := diagnosticsText(diags)
	for _, want := range []string{"audience", "MANTISEC_ACME_AUDIENCE", "never adopts"} {
		if !strings.Contains(text, want) {
			t.Errorf("the error must mention %q; got:\n%s", want, text)
		}
	}
}

// ---------------------------------------------------------------------------
// §2.4's ENVIRONMENT-VARIABLE PRECEDENCE TABLE
//
// PROV-UNIT-TEST-SUITE asks the credential-precedence test to cover EVERY ROW of
// terraform-provider-contract.md §2.4's table, so what follows walks the table
// row by row and, inside each row, level by level: HCL, then each environment
// variable in the order the spec prints them.
//
// The failure being guarded against is quiet and expensive. Every row exists so
// that `MANTISEC_ACME_*` can point this provider at a different identity from
// the `azurerm` provider sharing the same workspace. Get one chain's order
// wrong and the run authenticates as the `azurerm` identity instead; the service
// answers `404` because that principal owns nothing in the namespace; and `Read`
// is one bad `if` away from calling that "the registration is gone". Nothing in
// that sequence looks like a bug until certificates start reissuing.

// specEnvChain is one argument of §2.4's table, TRANSCRIBED FROM THE SPEC.
//
// It is deliberately a second copy of the chain the provider declares, and the
// only copy in this file that is not read back out of the provider. Without it
// the precedence cases below would be self-fulfilling: they drive
// `credentialEnvChains`, so reordering a chain in the provider would silently
// reorder their expectations too and the suite would stay green while the
// provider stopped matching the spec.
type specEnvChain struct {
	// row is the row of §2.4's table the argument appears in. Two rows carry two
	// arguments each, so rows and arguments are not one-to-one.
	row string
	// argument is the table's left column entry.
	argument string
	// names is the chain the SPEC prints below the HCL value, in the spec's order.
	names []string
}

// specCredentialEnvTable is §2.4's environment-variable precedence table:
// thirteen rows, fifteen arguments, in the order the spec prints them.
var specCredentialEnvTable = []specEnvChain{
	{"endpoint", "endpoint", []string{"MANTISEC_ACME_ENDPOINT"}},
	{"audience", "audience", []string{"MANTISEC_ACME_AUDIENCE"}},
	{"tenant_id", "tenant_id", []string{"MANTISEC_ACME_TENANT_ID", "ARM_TENANT_ID", "AZURE_TENANT_ID"}},
	{"client_id", "client_id", []string{"MANTISEC_ACME_CLIENT_ID", "ARM_CLIENT_ID", "AZURE_CLIENT_ID"}},
	{"use_oidc", "use_oidc", []string{"MANTISEC_ACME_USE_OIDC", "ARM_USE_OIDC"}},
	{"oidc_token", "oidc_token", []string{"MANTISEC_ACME_OIDC_TOKEN", "ARM_OIDC_TOKEN"}},
	{"oidc_token_file_path", "oidc_token_file_path", []string{
		"MANTISEC_ACME_OIDC_TOKEN_FILE_PATH", "ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"}},
	{"oidc_request_url / _token", "oidc_request_url", []string{
		"ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"}},
	{"oidc_request_url / _token", "oidc_request_token", []string{
		"ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}},
	{"use_msi", "use_msi", []string{"MANTISEC_ACME_USE_MSI", "ARM_USE_MSI"}},
	{"client_certificate_path / _password", "client_certificate_path", []string{
		"MANTISEC_ACME_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE_PATH"}},
	{"client_certificate_path / _password", "client_certificate_password", []string{
		"MANTISEC_ACME_CLIENT_CERTIFICATE_PASSWORD", "ARM_CLIENT_CERTIFICATE_PASSWORD"}},
	{"use_cli", "use_cli", []string{"MANTISEC_ACME_USE_CLI", "ARM_USE_CLI"}},
	{"environment", "environment", []string{"MANTISEC_ACME_ENVIRONMENT", "ARM_ENVIRONMENT", "AZURE_ENVIRONMENT"}},
	{"expected_service_instance_id", "expected_service_instance_id", []string{"MANTISEC_ACME_SERVICE_INSTANCE_ID"}},
}

// specCredentialEnvRows is the left column of the table above, deduplicated and
// still in the spec's order.
func specCredentialEnvRows() []string {
	var rows []string
	for _, entry := range specCredentialEnvTable {
		if len(rows) == 0 || rows[len(rows)-1] != entry.row {
			rows = append(rows, entry.row)
		}
	}
	return rows
}

// precedenceCase is one ARGUMENT of §2.4's table plus everything needed to
// resolve it at each level of its chain and observe which level won.
type precedenceCase struct {
	// chain is the PRODUCTION declaration, not a copy of it. Taking the variable
	// names from `credentialEnvChains` is what makes this an assertion about the
	// provider rather than about a second transcription of the table.
	chain envChainRow
	// specRow is the row of §2.4's table this argument belongs to.
	specRow string

	// setHCL writes the highest-precedence level.
	setHCL func(m *Model, v string)
	// prepare supplies whatever else the case needs for resolution to get as far
	// as the argument under test: the two REQUIRED arguments, and `client_id` on
	// the managed-identity path (ADR 0019).
	prepare func(m *Model)

	// winning is written at the level under test, losing at every
	// lower-precedence level. Every HIGHER level is cleared, so `observe`
	// reporting `wantWinning` proves the level under test was both reached and
	// preferred over everything below it.
	winning string
	losing  string
	// wantWinning is what `observe` must report when the level under test wins,
	// and wantUnset what it reports with nothing set anywhere. For a string
	// argument the winner is the value itself; a BOOLEAN argument's only
	// observable is the credential method the flag selects, so it is a method
	// name.
	wantWinning string
	wantUnset   string
	// unsetIsAnError marks `endpoint` and `audience`, which are required: with
	// nothing set anywhere they fail rather than resolving to a default.
	unsetIsAnError bool

	// observe reports what the provider actually resolved for this argument.
	observe func(resolvedConfig) string
}

// precedenceCases is one case per argument of §2.4's table.
func precedenceCases() []precedenceCase {
	endpoint := func(m *Model) { m.Endpoint = types.StringValue("https://certs.example.com") }
	audience := func(m *Model) { m.Audience = types.StringValue("api://mantisec-acme") }
	connected := func(m *Model) { endpoint(m); audience(m) }

	return []precedenceCase{
		{
			chain: chainEndpoint, specRow: "endpoint",
			setHCL:  func(m *Model, v string) { m.Endpoint = types.StringValue(v) },
			prepare: audience,
			winning: "https://winning.example.com", losing: "https://losing.example.com",
			wantWinning: "https://winning.example.com", unsetIsAnError: true,
			observe: func(c resolvedConfig) string { return c.Endpoint },
		},
		{
			chain: chainAudience, specRow: "audience",
			setHCL:  func(m *Model, v string) { m.Audience = types.StringValue(v) },
			prepare: endpoint,
			winning: "api://winning", losing: "api://losing",
			wantWinning: "api://winning", unsetIsAnError: true,
			observe: func(c resolvedConfig) string { return c.Audience },
		},
		{
			chain: chainTenantID, specRow: "tenant_id",
			setHCL:  func(m *Model, v string) { m.TenantID = types.StringValue(v) },
			prepare: connected,
			winning: "tenant-winning", losing: "tenant-losing",
			wantWinning: "tenant-winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.TenantID },
		},
		{
			chain: chainClientID, specRow: "client_id",
			setHCL:  func(m *Model, v string) { m.ClientID = types.StringValue(v) },
			prepare: connected,
			winning: "client-winning", losing: "client-losing",
			wantWinning: "client-winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.ClientID },
		},
		{
			// A boolean row: the flag has no resolved value of its own, so what is
			// observed is the METHOD it selects. A lower level winning would set
			// the flag false and the selection would fall through to the CLI, so
			// the two outcomes are distinguishable.
			chain: chainUseOIDC, specRow: "use_oidc",
			setHCL:  func(m *Model, v string) { m.UseOIDC = types.BoolValue(v == "true") },
			prepare: connected,
			winning: "true", losing: "false",
			wantWinning: methodWorkloadIdentity, wantUnset: methodAzureCLI,
			observe: func(c resolvedConfig) string { return c.Credential.Method },
		},
		{
			chain: chainOIDCToken, specRow: "oidc_token",
			setHCL:  func(m *Model, v string) { m.OIDCToken = types.StringValue(v) },
			prepare: connected,
			winning: "assertion-winning", losing: "assertion-losing",
			wantWinning: "assertion-winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.OIDCToken },
		},
		{
			chain: chainOIDCTokenFilePath, specRow: "oidc_token_file_path",
			setHCL:  func(m *Model, v string) { m.OIDCTokenFilePath = types.StringValue(v) },
			prepare: connected,
			winning: "/run/secrets/winning", losing: "/run/secrets/losing",
			wantWinning: "/run/secrets/winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.OIDCTokenFilePath },
		},
		{
			chain: chainOIDCRequestURL, specRow: "oidc_request_url / _token",
			setHCL:  func(m *Model, v string) { m.OIDCRequestURL = types.StringValue(v) },
			prepare: connected,
			winning: "https://actions.example/winning", losing: "https://actions.example/losing",
			wantWinning: "https://actions.example/winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.OIDCRequestURL },
		},
		{
			chain: chainOIDCRequestToken, specRow: "oidc_request_url / _token",
			setHCL:  func(m *Model, v string) { m.OIDCRequestToken = types.StringValue(v) },
			prepare: connected,
			winning: "request-token-winning", losing: "request-token-losing",
			wantWinning: "request-token-winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.OIDCRequestToken },
		},
		{
			chain: chainUseMSI, specRow: "use_msi",
			setHCL: func(m *Model, v string) { m.UseMSI = types.BoolValue(v == "true") },
			// The managed-identity path requires `client_id` unconditionally
			// (ADR 0019), so supply it here rather than let this row fail for a
			// reason that has nothing to do with precedence.
			prepare: func(m *Model) { connected(m); m.ClientID = types.StringValue("user-assigned-client-id") },
			winning: "true", losing: "false",
			wantWinning: methodManagedIdentity, wantUnset: methodAzureCLI,
			observe: func(c resolvedConfig) string { return c.Credential.Method },
		},
		{
			chain: chainClientCertificatePath, specRow: "client_certificate_path / _password",
			setHCL:  func(m *Model, v string) { m.ClientCertificatePath = types.StringValue(v) },
			prepare: connected,
			winning: "/etc/pki/winning.pfx", losing: "/etc/pki/losing.pfx",
			wantWinning: "/etc/pki/winning.pfx", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.ClientCertificatePath },
		},
		{
			chain: chainClientCertificatePassword, specRow: "client_certificate_path / _password",
			setHCL:  func(m *Model, v string) { m.ClientCertificatePassword = types.StringValue(v) },
			prepare: connected,
			// Markers, not credentials: nothing here unlocks anything.
			winning: "not-a-password-winning", losing: "not-a-password-losing",
			wantWinning: "not-a-password-winning", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.Credential.ClientCertificatePassword },
		},
		{
			// `use_cli` defaults to TRUE and gates the chain's last step, so the
			// observable is again the method: a lower level winning sets it false
			// and no step of the ambient chain qualifies, which resolves to no
			// method at all.
			chain: chainUseCLI, specRow: "use_cli",
			setHCL:  func(m *Model, v string) { m.UseCLI = types.BoolValue(v == "true") },
			prepare: connected,
			winning: "true", losing: "false",
			wantWinning: methodAzureCLI, wantUnset: methodAzureCLI,
			observe: func(c resolvedConfig) string { return c.Credential.Method },
		},
		{
			chain: chainEnvironment, specRow: "environment",
			setHCL:  func(m *Model, v string) { m.Environment = types.StringValue(v) },
			prepare: connected,
			winning: "usgovernment", losing: "china",
			// §2.2: `environment` defaults to `public`, which drives the authority
			// host and the Key Vault DNS suffix.
			wantWinning: "usgovernment", wantUnset: "public",
			observe: func(c resolvedConfig) string { return c.Environment },
		},
		{
			chain: chainServiceInstanceID, specRow: "expected_service_instance_id",
			setHCL:  func(m *Model, v string) { m.ExpectedServiceInstanceID = types.StringValue(v) },
			prepare: connected,
			winning: "01WINNING0000000000000000AB", losing: "01LOSING00000000000000000AB",
			wantWinning: "01WINNING0000000000000000AB", wantUnset: "",
			observe: func(c resolvedConfig) string { return c.ExpectedServiceInstanceID },
		},
	}
}

// TestCredentialPrecedenceTable walks every row of §2.4's environment-variable
// precedence table, at every level of every chain.
//
// For each level it writes the winning marker at that level, the losing marker
// at every LOWER-precedence level, and nothing at all above — so an assertion
// that the winning marker came out proves both that the level is consulted and
// that it beats everything the spec says it outranks.
func TestCredentialPrecedenceTable(t *testing.T) {
	for _, tc := range precedenceCases() {
		t.Run(tc.chain.argument, func(t *testing.T) {
			for level := 0; level <= len(tc.chain.names); level++ {
				name := "HCL beats every environment variable"
				if level > 0 {
					name = tc.chain.names[level-1] + " wins"
				}
				t.Run(name, func(t *testing.T) {
					m := nullProviderModel(t)
					if tc.prepare != nil {
						tc.prepare(&m)
					}
					env := map[string]string{}
					if level == 0 {
						tc.setHCL(&m, tc.winning)
					} else {
						env[tc.chain.names[level-1]] = tc.winning
					}
					for _, lower := range tc.chain.names[level:] {
						env[lower] = tc.losing
					}
					withCredentialEnv(t, env)

					resolved, diags := resolveCredentialsFor(t, m)
					if diags.HasError() {
						t.Fatalf("resolveConfig: %s", diagnosticsText(diags))
					}
					if got := tc.observe(resolved); got != tc.wantWinning {
						t.Errorf("%s resolved to %q, want %q — the chain of §2.4 is `HCL → %s`",
							tc.chain.argument, got, tc.wantWinning, strings.Join(tc.chain.names, " → "))
					}
				})
			}

			t.Run("nothing set anywhere", func(t *testing.T) {
				withCredentialEnv(t, nil)
				m := nullProviderModel(t)
				if tc.prepare != nil {
					tc.prepare(&m)
				}
				resolved, diags := resolveCredentialsFor(t, m)
				if tc.unsetIsAnError {
					if !diags.HasError() {
						t.Fatalf("%s is REQUIRED: with nothing set anywhere resolution must fail, not default",
							tc.chain.argument)
					}
					return
				}
				if diags.HasError() {
					t.Fatalf("resolveConfig: %s", diagnosticsText(diags))
				}
				if got := tc.observe(resolved); got != tc.wantUnset {
					t.Errorf("%s with nothing set resolved to %q, want %q", tc.chain.argument, got, tc.wantUnset)
				}
			})
		})
	}
}

// TestCredentialPrecedenceCoversEveryRowOfSection24 is the completeness half of
// the criterion: it fails when §2.4's table grows a row, or the provider grows a
// chain, that no case above exercises.
//
// It checks the two directions separately, because they catch different
// mistakes: an argument the provider resolves but nobody tests is an untested
// chain, and a row of the spec nobody claims is a chain the provider may not
// resolve at all.
func TestCredentialPrecedenceCoversEveryRowOfSection24(t *testing.T) {
	cases := precedenceCases()

	// --- every chain the provider declares is exercised exactly once ---------
	declared := map[string]bool{}
	for _, chain := range credentialEnvChains {
		if declared[chain.argument] {
			t.Errorf("credentialEnvChains declares %q twice", chain.argument)
		}
		declared[chain.argument] = true
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		if !declared[tc.chain.argument] {
			t.Errorf("a precedence case exercises %q, which credentialEnvChains does not declare", tc.chain.argument)
			continue
		}
		if covered[tc.chain.argument] {
			t.Errorf("%q has more than one precedence case", tc.chain.argument)
		}
		covered[tc.chain.argument] = true
	}
	for _, chain := range credentialEnvChains {
		if !covered[chain.argument] {
			t.Errorf("the provider resolves %q from `HCL → %s`, and no precedence case covers it",
				chain.argument, strings.Join(chain.names, " → "))
		}
	}

	// --- every row of the spec table is claimed --------------------------
	rows := specCredentialEnvRows()
	claimed := map[string]bool{}
	for _, row := range rows {
		claimed[row] = false
	}
	for _, tc := range cases {
		if _, ok := claimed[tc.specRow]; !ok {
			t.Errorf("case %q names spec row %q, which is not a row of §2.4's table", tc.chain.argument, tc.specRow)
			continue
		}
		claimed[tc.specRow] = true
	}
	for _, row := range rows {
		if !claimed[row] {
			t.Errorf("row %q of §2.4's table has no precedence case", row)
		}
	}
	if len(rows) != 13 {
		t.Errorf("§2.4's table has 13 rows; specCredentialEnvTable transcribes %d", len(rows))
	}

	// --- no environment variable feeds two arguments -------------------------
	//
	// A name in two chains is an ambiguity: exporting it would move two arguments
	// at once, and the operator debugging the second one has no reason to suspect
	// the first.
	owner := map[string]string{}
	for _, chain := range credentialEnvChains {
		if len(chain.names) == 0 {
			t.Errorf("%q declares an empty chain", chain.argument)
		}
		for _, n := range chain.names {
			if prev, ok := owner[n]; ok {
				t.Errorf("%s feeds both %q and %q", n, prev, chain.argument)
			}
			owner[n] = chain.argument
		}
	}
}

// TestCredentialEnvChainsMatchTheSpecTable compares the chains the provider
// DECLARES with §2.4's table as transcribed above, argument by argument and name
// by name, including order.
//
// It is the assertion `TestCredentialPrecedenceTable` cannot make about itself.
// That test drives `credentialEnvChains`, so it proves the provider honours the
// order it declares; only this one proves the declared order is the SPEC's. Swap
// `MANTISEC_ACME_TENANT_ID` and `ARM_TENANT_ID` in the provider and every
// precedence case still passes — a workspace that set both would then silently
// authenticate as the `azurerm` identity — and this test is what fails.
func TestCredentialEnvChainsMatchTheSpecTable(t *testing.T) {
	if len(credentialEnvChains) != len(specCredentialEnvTable) {
		t.Fatalf("the provider declares %d chains; §2.4's table has %d arguments",
			len(credentialEnvChains), len(specCredentialEnvTable))
	}
	for i, want := range specCredentialEnvTable {
		got := credentialEnvChains[i]
		if got.argument != want.argument {
			t.Errorf("chain %d is %q; §2.4's table has %q in that position", i, got.argument, want.argument)
			continue
		}
		if !slices.Equal(got.names, want.names) {
			t.Errorf("the provider resolves %q from `HCL → %s`; §2.4 says `HCL → %s`",
				want.argument, strings.Join(got.names, " → "), strings.Join(want.names, " → "))
		}
	}
}
