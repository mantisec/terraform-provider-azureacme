package provider

import (
	"os/exec"
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
	for _, forbidden := range forbiddenDataPlanePackages {
		for _, line := range strings.Split(deps, "\n") {
			if strings.Contains(line, forbidden) {
				t.Errorf("FORBIDDEN: the provider links %q via %q.\n"+
					"terraform-provider-contract.md §9.2: a Key Vault certificate's sibling secret value is the PFX INCLUDING THE PRIVATE KEY. "+
					"The provider constructs and echoes URIs; it never calls Key Vault.", forbidden, line)
			}
		}
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
