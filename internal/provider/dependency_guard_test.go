package provider

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenDataPlanePackages is the deny-list for terraform-provider-contract.md
// §9.2 rule 1.
//
// WHY THIS EXISTS, stated here so nobody deletes it as hygiene: for a Key Vault
// certificate, the sibling secret object's value is the PKCS#12 bundle INCLUDING
// THE PRIVATE KEY. A well-meaning "just fetch the secret so users can see the
// chain" convenience feature would therefore write private keys into every
// consumer's state file and every archived plan. The provider never calls Key
// Vault; it only constructs and echoes URIs.
//
// `azidentity` is deliberately absent from this list — the credential chain of
// §2.4 needs it, and it is not a data-plane SDK.
var forbiddenDataPlanePackages = []string{
	// The two named explicitly by §9.2.
	"azsecrets",
	"azcertificates",
	// The rest of the Azure data plane, because the rule is "links no Azure
	// data-plane SDK at all", not "links neither of two packages".
	"azkeys",
	"azblob",
	"azqueue",
	"aztables",
	"azure-sdk-for-go/sdk/security/keyvault",
	"azure-sdk-for-go/sdk/storage",
}

// TestNoAzureDataPlaneSDKIsLinked runs the §9.2 check inside the ordinary test
// suite so `go test ./...` is the CI gate and no separate job can be dropped.
func TestNoAzureDataPlaneSDKIsLinked(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = repoRelative(t, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./... failed: %v\n%s", err, out)
	}
	deps := string(out)
	if !strings.Contains(deps, "github.com/hashicorp/terraform-plugin-framework") {
		t.Fatalf("go list -deps produced no plugin-framework dependency — the guard is not actually looking at this module:\n%s", firstLines(deps, 10))
	}
	for _, offence := range dataPlaneOffences(deps) {
		t.Errorf("FORBIDDEN: %s.\n"+
			"terraform-provider-contract.md §9.2: a Key Vault certificate's sibling secret value is the PFX INCLUDING THE PRIVATE KEY. "+
			"The provider constructs and echoes URIs; it never calls Key Vault.", offence)
	}
}

// dataPlaneOffences is the matcher, separated from the `go list` invocation so
// TestNoAzureDataPlaneSDKIsLinked_GuardFiresOnAForbiddenImport can feed it a
// dependency list that DOES contain a data-plane package
// (CI-VERSION-MATRIX-SECRET-SURFACE).
func dataPlaneOffences(deps string) []string {
	var offences []string
	for _, forbidden := range forbiddenDataPlanePackages {
		for _, line := range strings.Split(deps, "\n") {
			if strings.Contains(line, forbidden) {
				offences = append(offences, fmt.Sprintf("the provider links %q via %q", forbidden, line))
			}
		}
	}
	return offences
}

// TestNoAzureDataPlaneSDKIsLinked_GuardFiresOnAForbiddenImport proves the guard
// is capable of failing.
//
// The real check has only ever been observed PASSING, and a matcher that always
// returned "no offences" would look exactly the same in the log. So each package
// on the deny-list is fed to the matcher inside a plausible `go list -deps` line
// — the shape an actual import would produce — and must be reported.
func TestNoAzureDataPlaneSDKIsLinked_GuardFiresOnAForbiddenImport(t *testing.T) {
	// The two the specification names, spelled as `go list -deps` would print
	// them after somebody added the import.
	for _, imported := range []string{
		"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets",
		"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates",
	} {
		deps := strings.Join([]string{
			"github.com/hashicorp/terraform-plugin-framework/diag",
			imported,
			"github.com/mantisec/terraform-provider-azureacme/internal/provider",
		}, "\n")
		offences := dataPlaneOffences(deps)
		if len(offences) == 0 {
			t.Errorf("GUARD IS VACUOUS: %q passed the data-plane matcher. Adding that import to the provider "+
				"would put the PKCS#12 secret — the private key — one convenience feature away from every "+
				"consumer's state file, and CI would say nothing.", imported)
		}
	}

	// And every other entry on the deny-list, so no branch of the list quietly
	// stops matching.
	for _, forbidden := range forbiddenDataPlanePackages {
		if len(dataPlaneOffences("github.com/Azure/azure-sdk-for-go/sdk/"+forbidden)) == 0 {
			t.Errorf("GUARD IS VACUOUS for deny-list entry %q", forbidden)
		}
	}

	// The converse: an ordinary dependency list must produce nothing, or the
	// guard fails every build for the wrong reason. `azidentity` is the case that
	// matters — the credential chain of §2.4 needs it and it is NOT a data-plane
	// SDK.
	clean := strings.Join([]string{
		"github.com/hashicorp/terraform-plugin-framework/diag",
		"github.com/Azure/azure-sdk-for-go/sdk/azidentity",
		"github.com/mantisec/terraform-provider-azureacme/internal/client",
	}, "\n")
	if offences := dataPlaneOffences(clean); len(offences) > 0 {
		t.Errorf("the matcher reported %v on a clean dependency list; azidentity is the credential chain, not a "+
			"data-plane SDK", offences)
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// forbiddenCredentialIdentifiers are the azidentity symbols that must never be
// REFERENCED by this module's code — AUTH-PROVIDER-CREDENTIAL-CHAIN, ADR 0019,
// terraform-provider-contract.md §2.4.
//
// WHY THIS EXISTS, stated here so nobody deletes it as hygiene:
// `DefaultAzureCredential` has a silent fallback order that picks up an
// unintended identity — most commonly a developer's `az login` inside a CI
// container. The failure mode is a WRONG-IDENTITY SUCCESS, not an error: the run
// authenticates to the wrong tenant, every registration legitimately answers
// `404`, and this provider's `Read` is one bad `if` away from reading that as
// "the certificate is gone" and reissuing the fleet against the wrong service.
// Reviewers 01 and 04 converged on forbidding it independently.
var forbiddenCredentialIdentifiers = []string{
	"DefaultAzureCredential",
	"NewDefaultAzureCredential",
}

// TestDefaultAzureCredentialIsNeverReferenced is the §2.4 guard, run inside the
// ordinary test suite so `go test ./...` is the gate and no separate job can be
// dropped. `provider-ci.yml` also runs it as a named step, for the same reason
// the data-plane guard is duplicated there: a control that exists only inside a
// test suite disappears the day someone adds a build tag.
//
// It is an AST check, not a grep, and that distinction is the whole design. The
// identifier legitimately appears in this module as PROSE — in the comment above,
// in the code comments of provider_credentials.go, and inside the diagnostic
// string that tells an operator why the provider does not use it. A grep would
// therefore have to be either vacuous or permanently suppressed. Parsing without
// comments and inspecting only identifier nodes leaves prose alone and still
// fails on a single real reference, including one hidden inside a build-tagged
// file, because the parser reads every file on disk rather than every file the
// current build selects.
func TestDefaultAzureCredentialIsNeverReferenced(t *testing.T) {
	root := repoRelative(t, ".")

	var parsed int
	var sentinelSeen bool
	var offences []string

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The module's own tree only. `docs/` and `examples/` carry no Go.
			if d.Name() == ".git" || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, readErr := os.ReadFile(p) //nolint:gosec // a path produced by walking this module
		if readErr != nil {
			return readErr
		}
		// The vacuity sentinel: at least one file must contain the identifier as
		// PROSE. If none does, the walker is not reaching the code that explains
		// the rule, and a scan that finds nothing proves nothing.
		if bytes.Contains(src, []byte("DefaultAzureCredential")) {
			sentinelSeen = true
		}

		// parser.SkipObjectResolution keeps this fast; comments are dropped
		// because the default mode does not retain them.
		file, parseErr := parser.ParseFile(token.NewFileSet(), p, src, parser.SkipObjectResolution)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", p, parseErr)
		}
		parsed++

		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, forbidden := range forbiddenCredentialIdentifiers {
				if ident.Name == forbidden {
					rel, relErr := filepath.Rel(root, p)
					if relErr != nil {
						rel = p
					}
					offences = append(offences, fmt.Sprintf("%s: identifier %q", rel, ident.Name))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if parsed < 20 {
		t.Fatalf("GUARD IS VACUOUS: only %d Go files were parsed under %s, so this check is not looking at the module", parsed, root)
	}
	if !sentinelSeen {
		t.Fatalf("GUARD IS VACUOUS: no file under %s mentions DefaultAzureCredential even in prose, so the walker is "+
			"not reaching the credential code that explains why it is forbidden", root)
	}
	for _, o := range offences {
		t.Errorf("FORBIDDEN: %s.\n"+
			"terraform-provider-contract.md §2.4 and ADR 0019: `DefaultAzureCredential` falls through silently to a "+
			"developer identity, so a CI job that should have failed authenticates as whoever last ran `az login` on "+
			"the runner. Build the chain explicitly — internal/provider/provider_credentials.go.", o)
	}
}
