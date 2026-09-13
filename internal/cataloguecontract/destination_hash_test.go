package cataloguecontract

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/contractschema"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// destinationHash in the golden catalogue documents — catalogue-and-concurrency.md
// R-2.5.2, STATE-CATALOGUE-STORE-PRIMITIVES.
//
// This is the one property of the corpus a schema cannot check. `Sha256Hex` says
// sixty-four lowercase hex characters and every value in the corpus satisfies it,
// including a value nobody can compute — which is what the fixtures carried: one
// placeholder constant reused as a certificate thumbprint AND as a destination
// hash. Both conformance suites were green over it, and "both implementations
// agree on the golden examples" was vacuously true because neither had been
// asked.
//
// So the check is a DERIVATION, not a comparison against a literal: the hash a
// document records must be the hash `internal/primitives` computes from the vault
// resource id and certificate name sitting beside it in that same document. The
// Python half asserts the same thing over the same files in
// functionapp-azureacme/tests/catalogue/test_golden_examples_agreement.py, and
// the two can only both pass if the two implementations agree.

// The two spellings of the destination triple. Catalogue documents are camelCase
// and the wire is snake_case; both are read, so a document moved between the two
// planes is still checked rather than silently skipped.
var (
	hashKeys  = []string{"destinationHash", "destination_hash"}
	vaultKeys = []string{"keyVaultResourceId", "key_vault_id"}
	nameKeys  = []string{"certificateName", "certificate_name"}
)

// TestEveryRecordedDestinationHashIsTheOneThisProviderComputes walks the whole
// manifest, reject fixtures included: each of those is refused for a declared
// reason that is never the hash, so a wrong hash inside one would sit unexamined
// for ever.
func TestEveryRecordedDestinationHashIsTheOneThisProviderComputes(t *testing.T) {
	dir, manifest := loadManifest(t)
	checked := 0

	for _, entry := range manifest.Examples {
		document := decodeJSON(t, filepath.Join(dir, entry.File))
		for _, destination := range destinationsIn(document) {
			vault := firstString(destination, vaultKeys)
			certificate := firstString(destination, nameKeys)
			recorded := firstString(destination, hashKeys)
			checked++
			if want := primitives.DestinationHash(vault, certificate); recorded != want {
				t.Errorf("%s: destinationHash %s, want %s — the hash is derived from the vault "+
					"id and certificate name beside it (R-2.5.2), never chosen",
					entry.File, recorded, want)
			}
		}
	}

	// Without this, the loop above is loudest when it inspects nothing at all.
	if checked < 5 {
		t.Errorf("only %d destination triples in the corpus; the derivation is barely exercised",
			checked)
	}
}

// TestCaseVariantsOfTheGoldenDestinationCollapseOntoOneHash is F-092 asserted on
// the destination the shared fixtures actually name, rather than only on the
// vector corpus. Computed over un-normalised inputs the If-None-Match ownership
// guard never fires, and the second registration silently claims a destination
// the first owns.
func TestCaseVariantsOfTheGoldenDestinationCollapseOntoOneHash(t *testing.T) {
	dir, _ := loadManifest(t)
	document := decodeJSON(t, filepath.Join(dir, "destination-ownership-claimed-v1.json"))
	destinations := destinationsIn(document)
	if len(destinations) == 0 {
		t.Fatal("the claimed-ownership golden document carries no destination triple")
	}
	vault := firstString(destinations[0], vaultKeys)
	certificate := firstString(destinations[0], nameKeys)
	recorded := firstString(destinations[0], hashKeys)

	for _, variant := range [][2]string{
		{strings.ToUpper(vault), certificate},
		{vault, strings.ToUpper(certificate)},
		{strings.ToUpper(vault), strings.ToUpper(certificate)},
	} {
		if got := primitives.DestinationHash(variant[0], variant[1]); got != recorded {
			t.Errorf("%s / %s hashes to %s, want %s: two spellings of one destination must "+
				"collide, or the ownership guard never fires",
				variant[0], variant[1], got, recorded)
		}
	}

	// The other half of the property: the hash still tells destinations apart.
	if primitives.DestinationHash(vault, certificate+"-2") == recorded {
		t.Error("a different certificate name collides with the golden destination")
	}
	if primitives.DestinationHash(vault+"2", certificate) == recorded {
		t.Error("a different vault collides with the golden destination")
	}
}

// destinationsIn returns every object in the document carrying the WHOLE
// destination triple. Only the whole triple: an object holding a
// `destinationHash` alone — a status document's publication intent, say —
// records a hash whose inputs live in another blob, and recomputing it here
// would be checking an invented pair.
func destinationsIn(node any) []map[string]any {
	var out []map[string]any
	switch typed := node.(type) {
	case map[string]any:
		if firstString(typed, hashKeys) != "" &&
			firstString(typed, vaultKeys) != "" &&
			firstString(typed, nameKeys) != "" {
			out = append(out, typed)
		}
		for _, key := range contractschema.SortedKeys(typed) {
			out = append(out, destinationsIn(typed[key])...)
		}
	case []any:
		for _, value := range typed {
			out = append(out, destinationsIn(value)...)
		}
	}
	return out
}

func firstString(object map[string]any, keys []string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok {
			return value
		}
	}
	return ""
}
