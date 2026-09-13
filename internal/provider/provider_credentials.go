package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
)

// Credential SELECTION — terraform-provider-contract.md §2.4, which is the
// authority on credential resolution, using the method list of
// identity-and-trust-boundaries.md §9.3 and ADR 0019.
//
// NEVER `DefaultAzureCredential`, anywhere, for any reason. Its silent fallback
// order picks up an unintended identity — most commonly a developer's `az login`
// inside a CI container — and the failure mode is a WRONG-IDENTITY SUCCESS, not
// an error. A run that authenticates to the wrong tenant then gets a `404`, and
// `Read` is one bad `if` away from reading a `404` as "the resource is gone".
// `TestDefaultAzureCredentialIsNeverReferenced` fails the build if the
// identifier is ever written into this module's code.
//
// The three rules, verbatim from §2.4:
//
//  1. MORE THAN ONE explicit method configured → ERROR. Determinism beats
//     convenience; silently preferring one is the wrong-identity success above.
//  2. Exactly one configured → use ONLY it. No fallback when it fails.
//  3. None configured → an ordered chain, EACH STEP GATED ON ITS OWN ENVIRONMENT
//     PRECONDITION: workload identity → managed identity → Azure CLI.

// The stable credential-method identifiers. They are what
// `client.Client.CredentialMethod()` returns, so they appear in the §7.2.2 `401`
// diagnostic and must not be reworded casually.
const (
	methodStaticToken       = "static_token"
	methodWorkloadIdentity  = "workload_identity"
	methodManagedIdentity   = "managed_identity"
	methodClientCertificate = "client_certificate"
	methodAzureCLI          = "azure_cli"
)

// envStaticToken carries a PRE-ACQUIRED bearer token for `{audience}/.default`.
//
// It is an EXPLICIT credential method, not a shortcut around the chain: an
// operator who exports it has configured a credential just as deliberately as one
// who sets `use_msi`, so it takes part in rule 1 and collides loudly with any
// other explicit method rather than silently pre-empting it.
const envStaticToken = "MANTISEC_ACME_TOKEN" //nolint:gosec // an environment variable NAME, not a credential

// ---------------------------------------------------------------------------
// §2.4's ENVIRONMENT-VARIABLE PRECEDENCE TABLE, transcribed once.
//
// Every row reads "HCL first, then these names in order". `MANTISEC_ACME_*`
// always wins so a workspace can point this provider and `azurerm` at different
// identities; the `ARM_*` / `AZURE_*` tail exists because the same CI identity
// normally serves both and forcing duplicate variables invites drift.
//
// The chains are DECLARED here rather than written inline at their call sites
// for two reasons. Two files consume them — `resolveConfig` resolves the
// connection and environment rows, this file the credential rows — and a chain
// written out twice is a chain that drifts. And `TestCredentialPrecedenceTable`
// walks `credentialEnvChains`, so a row of the spec table that is transcribed
// here but never read, or read in the wrong order, fails a test rather than
// surfacing months later as a CI job that authenticated as the wrong identity.

// envChainRow is one row of that table.
type envChainRow struct {
	// argument is the table's left column.
	argument string
	// names is the chain BELOW the HCL value, highest precedence first.
	names []string
}

var (
	chainEndpoint          = envChainRow{"endpoint", []string{"MANTISEC_ACME_ENDPOINT"}}
	chainAudience          = envChainRow{"audience", []string{"MANTISEC_ACME_AUDIENCE"}}
	chainTenantID          = envChainRow{"tenant_id", []string{"MANTISEC_ACME_TENANT_ID", "ARM_TENANT_ID", "AZURE_TENANT_ID"}}
	chainClientID          = envChainRow{"client_id", []string{"MANTISEC_ACME_CLIENT_ID", "ARM_CLIENT_ID", "AZURE_CLIENT_ID"}}
	chainUseOIDC           = envChainRow{"use_oidc", []string{"MANTISEC_ACME_USE_OIDC", "ARM_USE_OIDC"}}
	chainOIDCToken         = envChainRow{"oidc_token", []string{"MANTISEC_ACME_OIDC_TOKEN", "ARM_OIDC_TOKEN"}}
	chainOIDCTokenFilePath = envChainRow{"oidc_token_file_path", []string{
		"MANTISEC_ACME_OIDC_TOKEN_FILE_PATH", "ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"}}
	chainOIDCRequestURL   = envChainRow{"oidc_request_url", []string{"ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"}}
	chainOIDCRequestToken = envChainRow{"oidc_request_token", []string{"ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}}
	chainUseMSI           = envChainRow{"use_msi", []string{"MANTISEC_ACME_USE_MSI", "ARM_USE_MSI"}}

	chainClientCertificatePath = envChainRow{"client_certificate_path", []string{
		"MANTISEC_ACME_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE_PATH"}}
	chainClientCertificatePassword = envChainRow{"client_certificate_password", []string{
		"MANTISEC_ACME_CLIENT_CERTIFICATE_PASSWORD", "ARM_CLIENT_CERTIFICATE_PASSWORD"}}

	chainUseCLI            = envChainRow{"use_cli", []string{"MANTISEC_ACME_USE_CLI", "ARM_USE_CLI"}}
	chainEnvironment       = envChainRow{"environment", []string{"MANTISEC_ACME_ENVIRONMENT", "ARM_ENVIRONMENT", "AZURE_ENVIRONMENT"}}
	chainServiceInstanceID = envChainRow{"expected_service_instance_id", []string{"MANTISEC_ACME_SERVICE_INSTANCE_ID"}}
)

// credentialEnvChains is every row above, in the spec table's own order. The
// precedence test iterates it, so the list is the one place a new row is added.
var credentialEnvChains = []envChainRow{
	chainEndpoint, chainAudience, chainTenantID, chainClientID,
	chainUseOIDC, chainOIDCToken, chainOIDCTokenFilePath,
	chainOIDCRequestURL, chainOIDCRequestToken,
	chainUseMSI, chainClientCertificatePath, chainClientCertificatePassword,
	chainUseCLI, chainEnvironment, chainServiceInstanceID,
}

// credentialSelection is the outcome of §2.4 rules 1-3: exactly one method, plus
// the inputs that method needs. Rule 1 produces an error and no selection.
type credentialSelection struct {
	// Method is one of the method* constants above; empty when resolution failed.
	Method string
	// Rule records which rule of §2.4 chose the method: 2 for an explicitly
	// configured one, 3 for a step of the ambient chain. It exists so a
	// diagnostic can say WHY a credential was chosen, which is the question an
	// operator debugging a wrong-identity failure actually has.
	Rule int
	// ConfiguredBy names the attribute or environment variable that configured an
	// explicit method (rule 2), or the environment precondition that admitted a
	// chain step (rule 3).
	ConfiguredBy string

	Audience string
	TenantID string
	ClientID string

	// The federation and client-certificate inputs of §2.4's table. They are
	// resolved here, next to the rules that choose between the methods, so the
	// precedence the spec states is applied in exactly one place.
	//
	// NONE of them is a bearer token for the service and none may ever be sent as
	// one. `OIDCToken` and the two `OIDCRequest*` values are the CI system's OIDC
	// client ASSERTION and the credentials used to fetch it, whose audience is
	// `api://AzureADTokenExchange`; see the comment on `deferredTokenSource.Token`
	// for what presenting one to the service endpoint would actually hand over.
	OIDCToken                 string
	OIDCTokenFilePath         string
	OIDCRequestURL            string
	OIDCRequestToken          string
	ClientCertificatePath     string
	ClientCertificatePassword string
}

// explicitMethod is one candidate for §2.4 rules 1 and 2.
type explicitMethod struct {
	// attribute is what the operator set, named VERBATIM in the rule-1 error so
	// the message points at something greppable in their configuration.
	attribute string
	method    string
	set       bool
}

// resolveCredentialSelection applies §2.4 rules 1-3 and the managed-identity
// `client_id` rule of ADR 0019.
//
// It reads only already-resolved values plus the environment preconditions the
// spec names literally, so the whole of §2.4 is decided in one place and can be
// asserted by a table-driven test without a network, a credential or a clock.
func resolveCredentialSelection(_ context.Context, cfg Model, out resolvedConfig, diags *diag.Diagnostics) credentialSelection {
	useOIDC, oidcSet := envChainBool(cfg.UseOIDC, chainUseOIDC.names...)
	useMSI, msiSet := envChainBool(cfg.UseMSI, chainUseMSI.names...)
	useCLI, cliSet := envChainBool(cfg.UseCLI, chainUseCLI.names...)
	if !cliSet {
		// §2.2: `use_cli` defaults to true and is tried LAST.
		useCLI = true
	}

	sel := credentialSelection{
		Audience:                  out.Audience,
		TenantID:                  out.TenantID,
		ClientID:                  out.ClientID,
		OIDCToken:                 envChain(cfg.OIDCToken, chainOIDCToken.names...),
		OIDCTokenFilePath:         envChain(cfg.OIDCTokenFilePath, chainOIDCTokenFilePath.names...),
		OIDCRequestURL:            envChain(cfg.OIDCRequestURL, chainOIDCRequestURL.names...),
		OIDCRequestToken:          envChain(cfg.OIDCRequestToken, chainOIDCRequestToken.names...),
		ClientCertificatePath:     envChain(cfg.ClientCertificatePath, chainClientCertificatePath.names...),
		ClientCertificatePassword: envChain(cfg.ClientCertificatePassword, chainClientCertificatePassword.names...),
	}

	// ------------------------------------------------------------- rules 1 & 2
	//
	// `use_cli` is deliberately NOT in this list. §2.4 rule 3 makes it the GATE on
	// the chain's last step ("only when `use_cli`, default `true`"), not a fourth
	// explicit method — and because it defaults to true, treating it as one would
	// make every ordinary workspace that also sets `use_oidc` a rule-1 error.
	explicit := []explicitMethod{
		{attribute: "use_oidc", method: methodWorkloadIdentity, set: oidcSet && useOIDC},
		{attribute: "use_msi", method: methodManagedIdentity, set: msiSet && useMSI},
		{attribute: "client_certificate_path", method: methodClientCertificate, set: sel.ClientCertificatePath != ""},
		{attribute: envStaticToken, method: methodStaticToken, set: os.Getenv(envStaticToken) != ""},
	}
	var chosen []explicitMethod
	for _, m := range explicit {
		if m.set {
			chosen = append(chosen, m)
		}
	}

	if len(chosen) > 1 {
		names := make([]string, 0, len(chosen))
		for _, m := range chosen {
			names = append(names, m.attribute)
		}
		diags.AddError(
			"More than one credential method is configured: "+strings.Join(quoteEach(names), ", ")+
				" ("+DiagMultipleCredentialMethods+")",
			fmt.Sprintf("Configured: %s.\n\n"+
				"Determinism beats convenience. Configure EXACTLY ONE explicit credential method, or leave them all "+
				"unset and let the ordered ambient chain apply.\n\n"+
				"Choosing one for you is how a run authenticates to the wrong tenant and then sees a `404` that this "+
				"provider's `Read` must not mistake for \"the registration is gone\".\n\n"+
				"`DefaultAzureCredential` is deliberately NOT used anywhere in this provider for the same reason: it "+
				"falls through silently to a developer identity, so a CI job that should have failed authenticates as "+
				"whoever last ran `az login` on the runner. That failure mode is a wrong-identity SUCCESS, not an error.",
				strings.Join(quoteEach(names), ", ")))
		return credentialSelection{}
	}

	if len(chosen) == 1 {
		sel.Method = chosen[0].method
		sel.Rule = 2
		sel.ConfiguredBy = chosen[0].attribute
		return requireManagedIdentityClientID(sel, diags)
	}

	// ------------------------------------------------------------------ rule 3
	//
	// The ordered chain, each step gated on its OWN environment precondition. A
	// step whose precondition is absent is SKIPPED, never attempted and never
	// substituted for — and if no step qualifies the provider fails loudly rather
	// than sending an unauthenticated request to a production endpoint.
	federatedTokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	azureClientID := os.Getenv("AZURE_CLIENT_ID")
	identityEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	msiEndpoint := os.Getenv("MSI_ENDPOINT")

	switch {
	case federatedTokenFile != "" && azureClientID != "":
		sel.Method = methodWorkloadIdentity
		sel.Rule = 3
		sel.ConfiguredBy = "AZURE_FEDERATED_TOKEN_FILE + AZURE_CLIENT_ID"
		if sel.OIDCTokenFilePath == "" {
			sel.OIDCTokenFilePath = federatedTokenFile
		}
		if sel.ClientID == "" {
			sel.ClientID = azureClientID
		}
	case identityEndpoint != "" || msiEndpoint != "":
		sel.Method = methodManagedIdentity
		sel.Rule = 3
		sel.ConfiguredBy = "IDENTITY_ENDPOINT/MSI_ENDPOINT"
	case useCLI:
		sel.Method = methodAzureCLI
		sel.Rule = 3
		sel.ConfiguredBy = "use_cli"
	default:
		diags.AddError("No credential method could be resolved ("+DiagNoCredentialMethod+")",
			"No explicit credential method is configured, and no step of the ambient chain of "+
				"`terraform-provider-contract.md` §2.4 rule 3 met its environment precondition:\n\n"+
				"  1. workload identity — needs `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_CLIENT_ID`; neither pair is set.\n"+
				"  2. managed identity — needs `IDENTITY_ENDPOINT` or `MSI_ENDPOINT`; neither is set.\n"+
				"  3. Azure CLI — disabled, because `use_cli` (or `ARM_USE_CLI`) is set to false.\n\n"+
				"Configure one method explicitly (`use_oidc`, `use_msi` with `client_id`, or "+
				"`client_certificate_path`), export a pre-acquired bearer token in `"+envStaticToken+"`, or "+
				"re-enable `use_cli`.\n\n"+
				"The provider fails here rather than falling back, because a fallback is how a run authenticates as an "+
				"identity nobody chose.")
		return credentialSelection{}
	}

	return requireManagedIdentityClientID(sel, diags)
}

// requireManagedIdentityClientID enforces ADR 0019: on the managed-identity path
// `client_id` is MANDATORY.
//
// The provider cannot see how many user-assigned identities are attached to the
// host, so it cannot rule out the ambiguous case — and in the ambiguous case IMDS
// silently returns SOME identity's token rather than failing. An ambiguity that
// resolves silently to the wrong principal is exactly the failure class this whole
// section exists to prevent, so the requirement is unconditional. A host carrying
// only a system-assigned identity sets `client_id` to that identity's client id.
func requireManagedIdentityClientID(sel credentialSelection, diags *diag.Diagnostics) credentialSelection {
	if sel.Method != methodManagedIdentity || sel.ClientID != "" {
		return sel
	}
	diags.AddError("`client_id` is required on the managed-identity path ("+DiagManagedIdentityClientIDRequired+")",
		"The managed-identity credential was selected (by "+sel.ConfiguredBy+") but no `client_id` is configured.\n\n"+
			"When more than one user-assigned identity is attached to the host the IMDS request is AMBIGUOUS, and IMDS "+
			"answers it by returning some identity's token rather than by failing — so an unqualified request can "+
			"silently authenticate as the wrong principal. The provider cannot see how many identities are attached, "+
			"so it requires the id rather than gambling.\n\n"+
			"Set `client_id`, or `MANTISEC_ACME_CLIENT_ID` / `ARM_CLIENT_ID` / `AZURE_CLIENT_ID`. On a host carrying "+
			"only a system-assigned identity, use that identity's client id.")
	return credentialSelection{}
}

// buildTokenSource turns the resolved selection into a client.TokenSource.
//
// SCOPE NOTE, stated plainly because the gap is deliberate. Selecting the
// credential is what `terraform-provider-contract.md` §2.4 specifies and is what
// this file implements in full. ACQUIRING an Entra token for
// `{audience}/.default` needs `azidentity`, which this build does not link, so
// every method other than the pre-acquired token returns a source that FAILS with
// a diagnostic naming the method — never one that silently sends no
// `Authorization` header to a production endpoint, and never one that substitutes
// a different credential.
func buildTokenSource(sel credentialSelection) client.TokenSource {
	if sel.Method == methodStaticToken {
		return client.StaticTokenSource{Value: os.Getenv(envStaticToken), MethodName: methodStaticToken}
	}
	return &deferredTokenSource{selection: sel}
}

// deferredTokenSource fails loudly for a method this build cannot acquire.
type deferredTokenSource struct {
	selection credentialSelection
}

func (d *deferredTokenSource) Method() string {
	if d.selection.Method == "" {
		return "none"
	}
	return d.selection.Method
}

// Token never returns a credential.
//
// IT MUST NOT READ `AZURE_FEDERATED_TOKEN_FILE` AND SEND THE CONTENTS. That file
// holds the CI system's OIDC client ASSERTION, whose audience is
// `api://AzureADTokenExchange` — Entra's token-exchange endpoint, not this
// service. Presenting it as a bearer token would not authenticate anything; it
// would hand the endpoint a credential it can replay to Entra to obtain an access
// token as the caller's identity. That is the confused deputy of F-015 with the
// roles reversed, and it is why the assertion is treated as key material
// everywhere in this provider.
func (d *deferredTokenSource) Token(context.Context) (string, error) {
	return "", fmt.Errorf(
		"this provider build cannot acquire an Entra token with the %q credential method (selected by %s): "+
			"the Entra credential implementation of AUTH-PROVIDER-CREDENTIAL-CHAIN is not linked into this build. "+
			"Export a pre-acquired bearer token for audience %q in %s, or use a build that links it",
		d.Method(), d.selection.ConfiguredBy, d.selection.Audience, envStaticToken)
}
