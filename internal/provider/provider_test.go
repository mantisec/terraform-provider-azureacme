package provider

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	fwresource "github.com/hashicorp/terraform-plugin-framework/provider"
)

// TestModulePathIsMirrorRepository is the check demanded by
// release-engineering.md §2 and SCAFFOLD-PROVIDER-MODULE: the Go module path is
// the MIRROR repository path from day one, not a monorepo path. Setting it late
// means rewriting every import at the worst possible moment.
func TestModulePathIsMirrorRepository(t *testing.T) {
	root := repoRelative(t, "go.mod")
	b, err := os.ReadFile(root)
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	re := regexp.MustCompile(`(?m)^module\s+(\S+)$`)
	m := re.FindSubmatch(b)
	if m == nil {
		t.Fatal("go.mod has no module directive")
	}
	if got := string(m[1]); got != ModulePath {
		t.Fatalf("go.mod module path = %q, want the mirror repository path %q", got, ModulePath)
	}
	if got := string(m[1]); got == "mantisec-acmebot" || filepath.Base(got) != "terraform-provider-azureacme" {
		t.Fatalf("module path %q does not end in the mirror repository name", got)
	}
}

// TestProviderTypeNameIsOneWayDoor pins the provider address's second segment,
// which is the resource type prefix. terraform-provider-contract.md §1.1: there
// is no `moved` across provider addresses.
func TestProviderTypeNameIsOneWayDoor(t *testing.T) {
	var resp provider.MetadataResponse
	New("test")().Metadata(context.Background(), provider.MetadataRequest{}, &resp)
	if resp.TypeName != "azureacme" {
		t.Fatalf("provider type name = %q, want %q — this is a one-way door (D-37, F-115)", resp.TypeName, "azureacme")
	}
}

// TestProviderSchemaIsValid proves the plugin-framework toolchain works end to
// end: the schema compiles, validates and carries the configuration surface of
// terraform-provider-contract.md §2.2.
func TestProviderSchemaIsValid(t *testing.T) {
	ctx := context.Background()
	var resp fwresource.SchemaResponse
	New("test")().Schema(ctx, fwresource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %+v", resp.Diagnostics)
	}
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema implementation invalid: %+v", diags)
	}

	// The four values that must be settable both individually and through
	// `connection_profile`, plus the two safety flags that must stay separate
	// (terraform-provider-contract.md §2.2 — one flag must never disable both).
	for _, name := range []string{
		"connection_profile", "endpoint", "audience", "tenant_id",
		"expected_service_instance_id", "skip_version_check", "skip_instance_check",
	} {
		if _, ok := resp.Schema.Attributes[name]; !ok {
			t.Errorf("provider schema is missing %q", name)
		}
	}
	// Deliberately absent (§2.3).
	for _, name := range []string{"client_secret", "insecure_skip_tls_verify", "default_namespace", "deletion_policy"} {
		if _, ok := resp.Schema.Attributes[name]; ok {
			t.Errorf("provider schema declares %q, which §2.3 says must not exist", name)
		}
	}
}

// TestNoResourcesOrDataSourcesYet documents that this item deliberately ships
// none, so a later diff adding one is visible.
func TestNoResourcesOrDataSourcesYet(t *testing.T) {
	p := New("test")()
	if got := len(p.Resources(context.Background())); got != 0 {
		t.Fatalf("Resources() = %d, want 0 in SCAFFOLD-PROVIDER-MODULE", got)
	}
	if got := len(p.DataSources(context.Background())); got != 0 {
		t.Fatalf("DataSources() = %d, want 0 in SCAFFOLD-PROVIDER-MODULE", got)
	}
}

// repoRelative resolves a path relative to the Go module root from a test running
// in a package directory.
func repoRelative(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Join(dir, rel)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not find the module root from %s", rel)
	return ""
}
