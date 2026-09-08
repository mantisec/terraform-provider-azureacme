package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExamplesDoNotUseTerraformRemoteState.
//
// Every `terraform_remote_state` example is deleted from this provider's
// documentation on purpose. The only worked example anywhere in the source
// reviews obtained the publishing identity that way, which grants every
// certificate-consuming workspace read access to the platform's storage account
// keys and its full resource graph — "a privilege escalation dressed as
// convenience". The secure path is `data.azureacme_service.this.publisher_principal_id`,
// and this test keeps the insecure one from creeping back.
func TestExamplesDoNotUseTerraformRemoteState(t *testing.T) {
	roots := []string{repoRelative(t, "examples"), repoRelative(t, "templates")}
	checked := 0
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			checked++
			// Comments are checked as PROSE, not as configuration: the examples
			// explain WHY the insecure pattern is banned, and naming it is the
			// point of that explanation.
			if strings.Contains(withoutComments(string(b)), "terraform_remote_state") {
				t.Errorf("%s uses terraform_remote_state. Use data.azureacme_service.this.publisher_principal_id: "+
					"reading the platform's state to find one principal id grants this workspace its storage account "+
					"keys and its entire resource graph.", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if checked == 0 {
		t.Fatal("no example or template files were checked, so this test proves nothing")
	}
	t.Logf("checked %d example and template files", checked)
}

// TestRegistryExampleShowsNoKeyBlock is §5.6 point 4.
//
// The registry example is what people copy. `key.exportable = false` produces a
// certificate that looks entirely healthy and that Application Gateway cannot
// use, so the example must not show a `key` block at all — the default is
// correct for every consumer in the v1 matrix.
func TestRegistryExampleShowsNoKeyBlock(t *testing.T) {
	path := repoRelative(t, filepath.Join("examples", "resources", "azureacme_certificate", "resource.tf"))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the registry example is missing: %v", err)
	}
	body := withoutComments(string(b))
	for _, forbidden := range []string{"key =", "key  =", "exportable", "algorithm ="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the registry example contains %q. §5.6: it must show NO `key` block at all.", forbidden)
		}
	}
	// And it must show the six concepts.
	body = string(b)
	for _, want := range []string{"namespace", "name", "dns_names", "key_vault_id",
		"publisher_principal_id", "connection_profile", "versionless_secret_id"} {
		if !strings.Contains(body, want) {
			t.Errorf("the registry example is missing %q; §5.1 targets exactly six concepts", want)
		}
	}
}

// withoutComments strips `#` and `//` comment lines from HCL so a rule about
// CONFIGURATION is not tripped by prose explaining that rule.
func withoutComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
