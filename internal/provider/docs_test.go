package provider

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwres "github.com/hashicorp/terraform-plugin-framework/resource"
)

// The registry documentation is GENERATED — `make provider-docs` runs
// tfplugindocs over the schema descriptions, `examples/` and `templates/`, and
// `.github/workflows/provider-ci.yml` regenerates and diffs it so a stale page
// fails the pull request. This file asserts the properties a diff cannot: that
// the pages the contract requires exist, that they say the load-bearing things,
// and that the index actually reaches them.
//
// It lives here rather than in a package of its own for the same reason
// examples_test.go does: `internal/provider/` is where the schema those pages
// are generated FROM is defined, so a schema change and the assertion about its
// rendered page move together.

// requiredGuides is terraform-provider-contract.md §12, in its order. The key is
// the guide's file stem — `templates/guides/<stem>.md.tmpl` renders to
// `docs/guides/<stem>.md` — and the value is a phrase the page must contain, so
// that a guide cannot satisfy this test by existing while saying nothing.
//
// Item 7, the error reference, is in this list like any other guide but is the
// one that is GENERATED, from contracts/errors/error-codes.yaml. See
// TestGeneratedErrorReferencePageCarriesEveryErrorCode.
var requiredGuides = []struct {
	stem      string
	specItem  string
	mustState string
}{
	{"quickstart", "§12.1 quickstart", "publisher_principal_id"},
	{"two-stage-bootstrap", "§12.2 two-stage bootstrap", "cannot issue its own first certificate"},
	{"waiting-timeouts-and-recovery", "§12.3 waiting, timeouts and recovery", "terraform untaint"},
	{"consumer-integration", "§12.4 consumer integration", "consumer_stale"},
	{"destroy-and-decommission", "§12.5 destroy and decommission", "soft_delete_retention_days"},
	{"destination-change-migration", "§12.6 destination-change migration", "cannot move between Key Vaults"},
	{"error-reference", "§12.7 error reference (generated)", "Next action"},
	{"version-compatibility", "§12.8 version compatibility and upgrade policy", "90 days"},
	{"destination-vault-security", "§12.9 destination vault owner security note", "Key Vault Certificates Officer"},
	{"saved-plan-hygiene", "§12.10 saved-plan secret hygiene", "credential-bearing"},
	{"what-this-product-does-not-do", "§12.11 what this product does not do", "Certificate Transparency"},
}

// TestEveryRequiredGuideIsRenderedAndLinkedFromTheIndex.
//
// §12 opens with "the following are NOT optional — several of the failure modes
// above are really the absence of one of them". A guide that exists but is not
// linked from the provider index page is, for a registry reader, absent: the
// registry's own navigation lists guides by `page_title`, and the index page is
// the only place this provider controls the order and the "read this when".
func TestEveryRequiredGuideIsRenderedAndLinkedFromTheIndex(t *testing.T) {
	index := readDocsFile(t, filepath.Join("docs", "index.md"))

	for _, guide := range requiredGuides {
		t.Run(guide.stem, func(t *testing.T) {
			// The rendered page. tfplugindocs renders a guide template with no
			// template action byte-for-byte, so the template IS the page — but
			// this asserts the PAGE, because that is what ships.
			page := readDocsFile(t, filepath.Join("docs", "guides", guide.stem+".md"))

			if !strings.Contains(page, "page_title:") {
				t.Errorf("docs/guides/%s.md has no `page_title:` front matter; "+
					"the registry cannot title it (%s)", guide.stem, guide.specItem)
			}
			if !strings.Contains(page, guide.mustState) {
				t.Errorf("docs/guides/%s.md does not mention %q, which is the point of "+
					"%s", guide.stem, guide.mustState, guide.specItem)
			}

			// The source template must exist too: a page in docs/ with no
			// template behind it is a hand-written file in a generated tree,
			// and the next `make provider-docs` deletes it.
			tmpl := filepath.Join("templates", "guides", guide.stem+".md.tmpl")
			if _, err := os.Stat(repoRelative(t, tmpl)); err != nil {
				t.Errorf("%s is missing, so docs/guides/%s.md is an orphan that the next "+
					"regeneration removes: %v", tmpl, guide.stem, err)
			}

			link := "guides/" + guide.stem
			if !strings.Contains(index, link) {
				t.Errorf("docs/index.md does not link %q, so %s is unreachable from the "+
					"provider's front page", link, guide.specItem)
			}
		})
	}
}

// TestGeneratedCertificatePageShowsTheSixConceptConfiguration is §5.6 point 4,
// asserted where it actually matters — on the GENERATED page rather than on the
// example file examples_test.go already covers.
//
// The registry page is what people copy. `key.exportable = false` produces an
// apply that succeeds, a `versionless_secret_id` that is populated, a
// `delivery_stage` of `published`, every status field green — and an Application
// Gateway listener that will not start, failing hours later in a different
// Terraform configuration as an Azure error about a Key Vault secret. No error
// at any layer. The page must therefore show NO `key` block at all.
func TestGeneratedCertificatePageShowsTheSixConceptConfiguration(t *testing.T) {
	page := readDocsFile(t, filepath.Join("docs", "resources", "certificate.md"))

	usage := usageSection(t, page)

	// The six concepts of §5.1: namespace, name, DNS names, destination vault,
	// the publisher role assignment, and one connection profile — plus the
	// versionless output that is the consumption binding point.
	for _, want := range []string{
		"namespace", "name", "dns_names", "key_vault_id",
		"publisher_principal_id", "connection_profile", "versionless_secret_id",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("the generated usage section is missing %q; §5.1 targets exactly six concepts", want)
		}
	}

	// And no `key` block. Comments are stripped first: the snippet EXPLAINS why
	// the block is absent, and naming it is the point of that explanation.
	config := withoutComments(usage)
	for _, forbidden := range []string{"key =", "key  =", "exportable", "algorithm ="} {
		if strings.Contains(config, forbidden) {
			t.Errorf("the generated usage section contains %q. §5.6 point 4: the registry "+
				"example must show NO `key` block at all — the default is correct for every "+
				"consumer in the v1 matrix and the example is what people copy.", forbidden)
		}
	}

	// The insecure remote-state pattern must not reach the registry through the
	// generated page either. examples_test.go guards the source; this guards the
	// artefact, in the one place a reader copies from.
	if strings.Contains(config, "remote_state") {
		t.Error("the generated usage section reads another workspace's state to obtain the " +
			"publishing identity (A4/FP-13): that grants this workspace the platform's storage " +
			"account keys and its entire resource graph. Use " +
			"data.azureacme_service.this.publisher_principal_id.")
	}
}

// TestGeneratedErrorReferencePageCarriesEveryErrorCode.
//
// terraform-provider-contract.md §12 item 7 asks for the error reference
// "generated from contracts/errors/error-codes.yaml so it cannot drift, one row
// per code with actor, next_action, attribute and retryability". A
// hand-transcribed table of ninety-odd codes is a second source of truth that
// goes stale silently, and a reader who trusts a stale `actor` column escalates
// to the wrong team.
//
// The comparison is against `internal/contracts/errorcodes.gen.go` rather than
// against the taxonomy YAML, and that is deliberate on three counts:
//
//   - The two artefacts are emitted by ONE run of contracts/tools/generate.py
//     from that YAML, and contracts/tools/check_drift.py asserts both against
//     it. Comparing them to each other therefore asserts §12 item 7 through the
//     repository's own drift mechanism, and localises the remaining failure —
//     one output regenerated without the other, or either hand-edited — in the
//     suite that owns the page.
//   - It reads nothing outside this Go module, so it does not skip in the
//     release mirror, where contracts/ is absent.
//   - The constants are the codes the PROVIDER can actually branch on. A code
//     the provider knows and the registry does not document is precisely the
//     user-facing gap this page exists to close.
//
// The set equality runs both ways. The reverse direction is what keeps a
// WITHDRAWN code off the page: a retired code is deliberately not materialised
// as a constant (service-api-contract.md §9.5), because a withdrawn name on a
// public page teaches the wrong code to the next reader as effectively as a
// constant would.
func TestGeneratedErrorReferencePageCarriesEveryErrorCode(t *testing.T) {
	page := readDocsFile(t, filepath.Join("docs", "guides", "error-reference.md"))

	// The columns §12 item 7 names. Without `Actor` a reader cannot tell whether
	// the fix is in their configuration; without `Next action` the page is a
	// glossary rather than the entry point to a remediation.
	for _, column := range []string{"| Code |", " Actor ", " Attribute ", " Retryable ", " Next action |"} {
		if !strings.Contains(page, column) {
			t.Errorf("the error reference has no %q column; §12 item 7 requires actor, "+
				"next_action, attribute and retryability", strings.TrimSpace(column))
		}
	}

	declared := goErrorCodeConstants(t)
	documented := errorReferenceRows(page)

	if len(declared) == 0 {
		t.Fatal("no Code constants were parsed out of internal/contracts/errorcodes.gen.go, " +
			"so this test proves nothing")
	}
	if len(documented) == 0 {
		t.Fatal("no code rows were parsed out of the error reference, so this test proves nothing")
	}

	var missing, extra []string
	for code := range declared {
		if !documented[code] {
			missing = append(missing, code)
		}
	}
	for code := range documented {
		if !declared[code] {
			extra = append(extra, code)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("the error reference has no row for %d of %d error codes the provider declares: "+
			"%v. Both artefacts come from contracts/errors/error-codes.yaml — run "+
			"`make contracts-generate && make provider-docs`.", len(missing), len(declared), missing)
	}
	if len(extra) > 0 {
		t.Errorf("the error reference documents %v, which the provider does not declare. Either "+
			"the page is ahead of the generated constants, or it names a WITHDRAWN code — a "+
			"retired name is never printed, because it teaches the wrong code to the next reader "+
			"(service-api-contract.md §9.5).", extra)
	}
	t.Logf("checked %d declared error codes against %d documented rows", len(declared), len(documented))
}

// TestErrorReferencePageIsTheDriftCheckedTemplate.
//
// tfplugindocs renders `templates/guides/<name>.md.tmpl` byte-for-byte when the
// template carries no template action, which is what lets one generator own the
// error reference. If that ever stops being true — a tfplugindocs change, or a
// template action creeping into the generated output — the rendered page becomes
// a second artefact with no drift check behind it, and the DO NOT EDIT marker on
// the template stops protecting the thing the registry actually serves.
func TestErrorReferencePageIsTheDriftCheckedTemplate(t *testing.T) {
	page := readDocsFile(t, filepath.Join("docs", "guides", "error-reference.md"))
	tmpl := readDocsFile(t, filepath.Join("templates", "guides", "error-reference.md.tmpl"))

	if page != tmpl {
		t.Error("docs/guides/error-reference.md is not byte-identical to " +
			"templates/guides/error-reference.md.tmpl. The template is the drift-checked " +
			"artefact (contracts/tools/check_drift.py); if the rendering is no longer " +
			"byte-for-byte, the page the registry serves is unprotected.")
	}
	if !strings.Contains(page, "DO NOT EDIT") {
		t.Error("the error reference carries no DO NOT EDIT marker, so nothing tells a reader " +
			"who opens it that a hand edit is reverted by `make contracts-verify`")
	}
	if !strings.Contains(page, "contracts/errors/error-codes.yaml") {
		t.Error("the error reference does not name its own source file, so a reader who wants " +
			"to change a row cannot find where to change it")
	}
}

// TestGeneratedPagesExistForEveryTypeTheProviderRegisters.
//
// FILE_MAP §4: "A new resource or data source is a three-part change: the Go
// file, the `examples/` snippet, and regenerated `docs/`." The CI diff catches a
// stale page; it does not catch a page nobody ever generated because the type
// was added and `make provider-docs` was never run on a branch that also touched
// a file the workflow's `paths:` filter watches.
func TestGeneratedPagesExistForEveryTypeTheProviderRegisters(t *testing.T) {
	ctx := context.Background()
	p := New("test")()

	registered := map[string][]string{"resources": nil, "data-sources": nil}
	for _, ctor := range p.Resources(ctx) {
		var meta fwres.MetadataResponse
		ctor().Metadata(ctx, fwres.MetadataRequest{ProviderTypeName: ProviderTypeName}, &meta)
		registered["resources"] = append(registered["resources"], meta.TypeName)
	}
	for _, ctor := range p.DataSources(ctx) {
		var meta datasource.MetadataResponse
		ctor().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: ProviderTypeName}, &meta)
		registered["data-sources"] = append(registered["data-sources"], meta.TypeName)
	}

	checked := 0
	for dir, typeNames := range registered {
		if len(typeNames) == 0 {
			t.Fatalf("the provider registers no %s, so this test proves nothing", dir)
		}
		for _, typeName := range typeNames {
			stem := strings.TrimPrefix(typeName, ProviderTypeName+"_")
			page := filepath.Join("docs", dir, stem+".md")
			body := readDocsFile(t, page)
			if !strings.Contains(body, "## Schema") {
				t.Errorf("%s has no schema section, so tfplugindocs did not see %s", page, typeName)
			}
			checked++
		}
	}
	t.Logf("checked %d generated type pages", checked)
}

// --------------------------------------------------------------------- helpers

func readDocsFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(repoRelative(t, rel))
	if err != nil {
		t.Fatalf("%s is missing. It is generated: run `make provider-docs`. (%v)", rel, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", rel)
	}
	return string(b)
}

// readRepoFile is readDocsFile for a HAND-WRITTEN file, so the failure does not
// tell a reader to regenerate something no generator owns.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(repoRelative(t, rel))
	if err != nil {
		t.Fatalf("%s is missing: %v", rel, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", rel)
	}
	return string(b)
}

// usageSection returns the fenced `terraform` block of a generated page's
// "## Example Usage" section — the part a reader copies.
func usageSection(t *testing.T, page string) string {
	t.Helper()
	const marker = "## Example Usage"
	idx := strings.Index(page, marker)
	if idx < 0 {
		t.Fatal("the generated page has no `## Example Usage` section, so the examples/ snippet " +
			"did not reach it. Check the path: tfplugindocs reads " +
			"examples/resources/azureacme_<type>/resource.tf and nothing else.")
	}
	rest := page[idx+len(marker):]
	open := strings.Index(rest, "```terraform")
	if open < 0 {
		t.Fatal("the `## Example Usage` section contains no ```terraform block")
	}
	rest = rest[open+len("```terraform"):]
	closeAt := strings.Index(rest, "```")
	if closeAt < 0 {
		t.Fatal("the usage section's ```terraform block is never closed")
	}
	return rest[:closeAt]
}

var (
	goCodeConstant    = regexp.MustCompile("(?m)^\\tCode[A-Za-z0-9]+ Code = \"([a-z0-9_]+)\"$")
	errorReferenceRow = regexp.MustCompile("^\\| `([a-z0-9_]+)` \\|")
)

// goErrorCodeConstants is the set of wire codes `internal/contracts/errorcodes.gen.go`
// declares. Scanned rather than reflected over, because the package exports the
// constants individually and Go has no way to enumerate a package's constants at
// run time.
func goErrorCodeConstants(t *testing.T) map[string]bool {
	t.Helper()
	raw := readDocsFile(t, filepath.Join("internal", "contracts", "errorcodes.gen.go"))
	codes := map[string]bool{}
	for _, m := range goCodeConstant.FindAllStringSubmatch(raw, -1) {
		codes[m[1]] = true
	}
	return codes
}

// errorReferenceRows is the set of codes the generated page carries a CODE table
// row for.
//
// Two things on the page look like a code row and are not: the `actor` legend
// under "Who can act", whose first cell is a backticked actor id, and any
// backticked code in prose. The eight-column shape is what separates them — a
// code row is `Code | HTTP | Surface | Retryable | Actor | Attribute | Meaning |
// Next action`, so it carries at least nine pipes even before a cell's escaped
// `\|` is counted, while a legend row carries three.
const errorReferenceRowPipes = 9

func errorReferenceRows(page string) map[string]bool {
	codes := map[string]bool{}
	for _, line := range strings.Split(page, "\n") {
		m := errorReferenceRow.FindStringSubmatch(line)
		if m == nil || strings.Count(line, "|") < errorReferenceRowPipes {
			continue
		}
		codes[m[1]] = true
	}
	return codes
}

// TestGoreleaserMatchesRegistryPublishingRequirements.
//
// release-engineering.md §4.4 carries a `[VERIFY]` note: the Terraform
// Registry's GPG and packaging requirements have changed more than once, and a
// pre-2026 GoReleaser template must not be trusted. The requirements were
// re-verified on 2026-09-13 (recorded in
// docs/agent-context/changelogs/2026-09-13-prov-docs-and-examples.md and inline
// in .goreleaser.yml); this test is what keeps the configuration on them.
//
// It matters because every one of these failures is discovered AFTER the tag is
// public and immutable: the release builds, the signature verifies, and the
// registry refuses to ingest it.
func TestGoreleaserMatchesRegistryPublishingRequirements(t *testing.T) {
	const manifest = "terraform-registry-manifest.json"
	raw := readRepoFile(t, ".goreleaser.yml")

	// The manifest must be BOTH attached to the release AND checksummed. The
	// registry verifies it against SHA256SUMS, so `release.extra_files` alone
	// publishes a manifest the registry then rejects. Two stanzas, both
	// required, and that is exactly the kind of duplication a tidy-up deletes.
	for _, stanza := range []string{"checksum:", "release:"} {
		block := yamlBlock(t, raw, stanza)
		if !strings.Contains(block, manifest) {
			t.Errorf("`%s` does not carry `extra_files` naming %s. The registry both reads the "+
				"manifest as a release asset AND verifies its checksum against SHA256SUMS; "+
				"omitting either fails ingestion after the tag is already public.", stanza, manifest)
		}
	}

	// The required asset names, all derived from `.ProjectName`, which in the
	// mirror repository is `terraform-provider-azureacme`.
	for _, want := range []string{
		"{{ .ProjectName }}_v{{ .Version }}",                      // binary
		"{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}", // archive
		"{{ .ProjectName }}_{{ .Version }}_SHA256SUMS",            // checksums
		"{{ .ProjectName }}_{{ .Version }}_manifest.json",         // manifest asset
	} {
		if !strings.Contains(raw, want) {
			t.Errorf(".goreleaser.yml does not produce %q; the registry matches asset names "+
				"literally against the terraform-provider-{NAME} pattern", want)
		}
	}

	// The signature is over the checksums file, detached, and BINARY. `--armor`
	// produces an ASCII-armoured .sig the registry will not accept, and it is a
	// one-word change somebody makes while debugging a signing problem.
	signs := yamlBlock(t, raw, "signs:")
	for _, want := range []string{"artifacts: checksum", "--detach-sign", "GPG_FINGERPRINT"} {
		if !strings.Contains(signs, want) {
			t.Errorf("the `signs:` stanza does not contain %q", want)
		}
	}
	if strings.Contains(signs, "--armor") || strings.Contains(signs, "--armour") {
		t.Error("the `signs:` stanza asks GPG to ASCII-armour the signature. The registry expects " +
			"a BINARY detached signature in `..._SHA256SUMS.sig`.")
	}

	// The platform matrix release-engineering.md §4.4 requires: linux, darwin and
	// windows × amd64 and arm64, six binaries. `goreleaser build --snapshot` is
	// what proves they actually build; this is what stops one quietly leaving the
	// list, which nobody notices until a consumer on that platform cannot install
	// the provider at all.
	builds := yamlBlock(t, raw, "builds:")
	for _, want := range []string{"linux", "darwin", "windows"} {
		if !strings.Contains(builds, "- "+want) {
			t.Errorf("the `builds:` stanza does not cross-compile for %s; §4.4 requires "+
				"linux/darwin/windows × amd64/arm64", want)
		}
	}
	for _, want := range []string{"amd64", "arm64"} {
		if !strings.Contains(builds, "- "+want) {
			t.Errorf("the `builds:` stanza does not cross-compile for %s; §4.4 requires "+
				"linux/darwin/windows × amd64/arm64", want)
		}
	}

	// zip, and only zip. The registry does not accept tar.gz.
	archives := yamlBlock(t, raw, "archives:")
	if !strings.Contains(archives, "zip") {
		t.Error("the `archives:` stanza does not produce zip archives")
	}
	if strings.Contains(archives, "tar.gz") {
		t.Error("the `archives:` stanza produces tar.gz; the registry accepts zip only")
	}

	// terraform-registry-manifest.json itself: protocol version 6, because this
	// is a Plugin Framework provider. The GoReleaser default of ["5.0"] would
	// publish a provider Terraform then talks to over the wrong protocol.
	m := readRepoFile(t, manifest)
	for _, want := range []string{`"version": 1`, `"protocol_versions"`, `"6.0"`} {
		if !strings.Contains(m, want) {
			t.Errorf("%s does not contain %s", manifest, want)
		}
	}
}

// yamlBlock returns the top-level YAML block introduced by `key` — the key's own
// line plus every following line that is indented or blank. Enough to tell one
// stanza from another without adding a YAML parser to this module for one test.
func yamlBlock(t *testing.T, raw, key string) string {
	t.Helper()
	lines := strings.Split(raw, "\n")
	start := -1
	for i, line := range lines {
		if line == key {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf(".goreleaser.yml has no top-level `%s` stanza", key)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(lines[i], " ") || strings.HasPrefix(lines[i], "\t") {
			continue
		}
		end = i
		break
	}
	return strings.Join(lines[start:end], "\n")
}
