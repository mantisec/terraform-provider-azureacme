package provider

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	fwresource "github.com/hashicorp/terraform-plugin-framework/provider"
	fwres "github.com/hashicorp/terraform-plugin-framework/resource"
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

// TestResourceAndDataSourceInventory pins the v1 inventory of
// terraform-provider-contract.md §1.2: ONE resource and SIX data sources.
func TestResourceAndDataSourceInventory(t *testing.T) {
	ctx := context.Background()
	p := New("test")()

	var resourceNames []string
	for _, ctor := range p.Resources(ctx) {
		var meta fwres.MetadataResponse
		ctor().Metadata(ctx, fwres.MetadataRequest{ProviderTypeName: ProviderTypeName}, &meta)
		resourceNames = append(resourceNames, meta.TypeName)
	}
	sort.Strings(resourceNames)
	if want := []string{"azureacme_certificate"}; !equalStrings(resourceNames, want) {
		t.Errorf("resources = %v, want %v — `azureacme_certificate` is the ONLY resource in v1", resourceNames, want)
	}

	var dataSourceNames []string
	for _, ctor := range p.DataSources(ctx) {
		var meta datasource.MetadataResponse
		ctor().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: ProviderTypeName}, &meta)
		dataSourceNames = append(dataSourceNames, meta.TypeName)
	}
	sort.Strings(dataSourceNames)
	want := []string{
		"azureacme_certificate", "azureacme_certificates", "azureacme_namespace",
		"azureacme_service", "azureacme_validation_binding", "azureacme_validation_bindings",
	}
	if !equalStrings(dataSourceNames, want) {
		t.Errorf("data sources = %v, want %v", dataSourceNames, want)
	}
}

// TestReservedResourceTypeNamesAreNotRegistered discharges the §1.3 reservation.
//
// PROVISIONAL(D-19): the decision was taken as branch (a) — policy is authored
// only by the platform Terraform pipeline and the API has no policy write path —
// so `azureacme_namespace`, `azureacme_dns_binding`, `azureacme_destination_policy`
// and `azureacme_role_binding` are NEVER BUILT as resources. The names are
// reserved so that reopening D-19 as (b) or (c) stays ADDITIVE.
//
// Terraform keeps resource and data-source type names in separate namespaces, so
// the `azureacme_namespace` DATA SOURCE below is not a collision.
func TestReservedResourceTypeNamesAreNotRegistered(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	registered := map[string]bool{}
	for _, ctor := range p.Resources(ctx) {
		var meta fwres.MetadataResponse
		ctor().Metadata(ctx, fwres.MetadataRequest{ProviderTypeName: ProviderTypeName}, &meta)
		registered[meta.TypeName] = true
	}
	for _, reserved := range ReservedResourceTypeNames {
		if registered[reserved] {
			t.Errorf("resource type %q is registered, but it is RESERVED pending decision D-19. "+
				"Under the provisional branch (a) these four resources are never built.", reserved)
		}
	}
	if len(ReservedResourceTypeNames) != 4 {
		t.Errorf("the reservation covers %d names, want the 4 of §1.3", len(ReservedResourceTypeNames))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
