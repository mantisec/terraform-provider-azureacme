package provider

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// diagnosticConstantsFromSource reads diagnostics.go and returns every `Diag*`
// constant's Go name and string value.
//
// It parses the SOURCE rather than reading AllProviderDiagnosticIDs, and that is
// the whole point: the slice is hand-maintained, so a check that trusted it could
// be silenced by leaving a new constant out — which had already happened to three
// of them. The compiler cannot help here (a string constant nobody references
// still compiles), so the parser stands in for it.
func diagnosticConstantsFromSource(t *testing.T) map[string]string {
	t.Helper()

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "diagnostics.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing diagnostics.go: %v", err)
	}

	found := map[string]string{}
	for _, decl := range parsed.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if len(name.Name) < 4 || name.Name[:4] != "Diag" || i >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s is not a plain string constant; this test cannot read it", name.Name)
				}
				unquoted, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				found[name.Name] = unquoted
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("no Diag* constants were parsed out of diagnostics.go, so this test is not looking at it any more")
	}
	return found
}

// TestNoProviderDiagnosticIDCollidesWithAPublishedWireCode is the test
// diagnostics.go names, and the one the taxonomy's reserved-name carve-out rests
// on.
//
// contracts/errors/error-codes.yaml holds `service_instance_mismatch` as a
// rejected alias with a null `canonical` — a name reserved OUT of the wire
// taxonomy — and contracts/tools/check_contracts.py exempts exactly that class of
// name from its repository-wide grep when it appears outside the wire surface,
// i.e. here. The exemption is sound only while the provider's diagnostic
// namespace and the wire taxonomy are disjoint sets. If they ever overlap, a
// support answer stops being decidable: `ownership_transfer_required` in a
// transcript would name either the service's 409 or a refusal the provider
// reached on its own without making a request, and the reader cannot tell which.
func TestNoProviderDiagnosticIDCollidesWithAPublishedWireCode(t *testing.T) {
	published := map[string]bool{}
	for _, code := range contracts.AllCodes() {
		published[string(code)] = true
	}
	if len(published) == 0 {
		t.Fatal("the generated contracts package reports no published codes")
	}

	for name, value := range diagnosticConstantsFromSource(t) {
		if published[value] {
			t.Errorf(
				"%s = %q collides with a published wire error code. A provider diagnostic and a "+
					"service error code must never share a name: rename the diagnostic (the wire "+
					"code is immutable) and say in a comment which event it describes.",
				name, value,
			)
		}
	}
}

// TestAllProviderDiagnosticIDsListsEveryDiagnosticConstant closes the omission
// route. Without it, the collision test above could be satisfied by deleting the
// offending entry from the slice rather than by renaming the constant.
func TestAllProviderDiagnosticIDsListsEveryDiagnosticConstant(t *testing.T) {
	declared := diagnosticConstantsFromSource(t)

	want := make([]string, 0, len(declared))
	for _, value := range declared {
		want = append(want, value)
	}
	got := append([]string(nil), AllProviderDiagnosticIDs...)
	sort.Strings(want)
	sort.Strings(got)

	if len(want) != len(got) {
		t.Fatalf("AllProviderDiagnosticIDs has %d entries; diagnostics.go declares %d Diag* constants\n  slice: %v\n  const: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("AllProviderDiagnosticIDs does not match the Diag* constants\n  slice: %v\n  const: %v", got, want)
		}
	}
}

// TestProviderDiagnosticIDsAreUnique catches the copy-paste that would make two
// diagnostics indistinguishable in a support transcript.
func TestProviderDiagnosticIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for name, value := range diagnosticConstantsFromSource(t) {
		if first, ok := seen[value]; ok {
			t.Errorf("%s and %s both use the identifier %q", first, name, value)
			continue
		}
		seen[value] = name
	}
}
