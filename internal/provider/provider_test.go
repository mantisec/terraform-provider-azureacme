package provider

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

// TestDeveloperToolsArePinnedInGoSum is SCAFFOLD-PROVIDER-MODULE's pinning
// check: `go.sum` pins tfplugindocs, and every generator this module shells out
// to is pinned the same way — by a blank import in `tools/tools.go`.
//
// contracts-and-codegen.md §4.3: "Generator versions are pinned — Go via
// `tools/tools.go` and `go.sum`, Python via `requirements-dev.txt` with hashes.
// An unpinned generator turns a dependency update into a silent contract
// change." A `go run <tool>@latest` resolves to a different generator on a
// different day, and the drift check then reports a contract change nobody made.
//
// THE CONTRACT GENERATORS ARE PYTHON. `contracts/tools/generate.py` emits this
// module's `internal/contracts/` package, so the Go-side set of contract
// generators is empty today and `tools/tools.go` pins tfplugindocs alone. That
// is a reason to assert the emptiness, not to skip the check: the second half
// below fails on any `go:generate` directive in this module that runs a package
// `tools/tools.go` does not pin, so the day a Go generator arrives unpinned,
// this test is what says so.
func TestDeveloperToolsArePinnedInGoSum(t *testing.T) {
	tools := readRepoFile(t, filepath.Join("tools", "tools.go"))

	// The build tag is what keeps a documentation generator out of `go build`,
	// `go vet` and the Azure data-plane guard's `go list -deps` view.
	if !strings.Contains(tools, "//go:build tools") {
		t.Error("tools/tools.go has no `//go:build tools` constraint, so its imports enter the " +
			"shipped dependency graph and dependency_guard_test.go starts judging a " +
			"documentation generator's transitive dependencies")
	}

	blankImport := regexp.MustCompile(`(?m)^\s*_\s+"([^"]+)"`)
	var pinned []string
	for _, m := range blankImport.FindAllStringSubmatch(tools, -1) {
		pinned = append(pinned, m[1])
	}
	if len(pinned) == 0 {
		t.Fatal("tools/tools.go blank-imports nothing, so it pins nothing and this check is vacuous")
	}

	const tfplugindocs = "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
	if !containsString(pinned, tfplugindocs) {
		t.Errorf("tools/tools.go does not blank-import %q. `make provider-docs` runs it, and an "+
			"unpinned tfplugindocs emits different bytes for different contributors, which turns "+
			"the docs drift check in provider-ci.yml into a coin toss.", tfplugindocs)
	}

	requires := moduleRequirements(t)
	sum := readRepoFile(t, "go.sum")
	for _, importPath := range pinned {
		module, version := owningModule(requires, importPath)
		if module == "" {
			t.Errorf("tools/tools.go imports %q but go.mod requires no module providing it, "+
				"so nothing pins its version", importPath)
			continue
		}
		// Both lines matter: the `h1:` hash pins the module's content, the
		// `/go.mod h1:` hash pins the graph it drags in.
		for _, want := range []string{
			module + " " + version + " h1:",
			module + " " + version + "/go.mod h1:",
		} {
			if !strings.Contains(sum, want) {
				t.Errorf("go.sum carries no %q line, so %s is required but not pinned by hash",
					want, importPath)
			}
		}
	}

	// No generate directive may run a generator `tools/tools.go` does not pin.
	// The module declares none today; this walk is what keeps that a fact rather
	// than an assumption.
	//
	// The needle is ASSEMBLED, so this file — which has to name the directive in
	// order to report it — is not itself a match. Same discipline, and the same
	// reason, as .github/scripts/check_workflow_hygiene.py: a check that has to
	// exempt itself has started to stop covering itself.
	const generateDirective = "//go:" + "generate"
	root := filepath.Dir(repoRelative(t, "go.mod"))
	directive := regexp.MustCompile(regexp.QuoteMeta(generateDirective) + `\s+(.*)`)
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// `dist/` is GoReleaser output and is git-ignored; the rest hold no Go.
			switch d.Name() {
			case ".git", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, m := range directive.FindAllStringSubmatch(string(b), -1) {
			cmd := strings.TrimSpace(m[1])
			if !runsAPinnedTool(cmd, pinned) {
				t.Errorf("%s carries `%s %s`, which does not run a package pinned in "+
					"tools/tools.go. An unpinned generator resolves differently on a different "+
					"day and the contract drift check then reports a change nobody made "+
					"(contracts-and-codegen.md §4.3).", rel, generateDirective, cmd)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module for go:generate directives: %v", err)
	}
	if scanned < 10 {
		t.Fatalf("only %d .go file(s) were scanned for go:generate directives, so the walk is "+
			"not looking at this module", scanned)
	}
}

// runsAPinnedTool reports whether a generate-directive command line invokes a
// package that tools/tools.go pins. `go run <pkg>@<version>` is deliberately NOT
// pinned: that form bypasses go.mod entirely, so go.sum never sees the tool.
func runsAPinnedTool(cmd string, pinned []string) bool {
	fields := strings.Fields(cmd)
	if len(fields) < 3 || fields[0] != "go" || fields[1] != "run" {
		return false
	}
	pkg := fields[2]
	if strings.Contains(pkg, "@") {
		return false
	}
	return containsString(pinned, pkg)
}

// moduleRequirements returns go.mod's `require` graph as module path → version,
// covering both the block form and the single-line form.
func moduleRequirements(t *testing.T) map[string]string {
	t.Helper()
	reqs := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(readRepoFile(t, "go.mod"), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		fields := strings.Fields(line)
		if inBlock {
			if len(fields) == 2 && strings.HasPrefix(fields[1], "v") {
				reqs[fields[0]] = fields[1]
			}
			continue
		}
		if len(fields) == 3 && fields[0] == "require" && strings.HasPrefix(fields[2], "v") {
			reqs[fields[1]] = fields[2]
		}
	}
	if len(reqs) == 0 {
		t.Fatal("go.mod declares no requirements, so the pinning check would pass vacuously")
	}
	return reqs
}

// owningModule finds the longest required module path that is a prefix of an
// import path — `.../terraform-plugin-docs/cmd/tfplugindocs` is provided by the
// module `.../terraform-plugin-docs`.
func owningModule(requires map[string]string, importPath string) (string, string) {
	best := ""
	for module := range requires {
		if importPath == module || strings.HasPrefix(importPath, module+"/") {
			if len(module) > len(best) {
				best = module
			}
		}
	}
	if best == "" {
		return "", ""
	}
	return best, requires[best]
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
