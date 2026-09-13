package policycontract

import (
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/contractschema"
)

// THE READER ITSELF LIVES IN internal/contractschema.
//
// It used to live here, in full. `contracts/policy/` and `contracts/catalogue/`
// are both cross-referencing sets of `*.schema.json` files, so their two
// conformance suites need the same reader — and a `_test.go` file cannot be
// imported, so the second suite would have had to copy it. A copied validator
// drifts, which is the exact failure the cross-language harness exists to
// prevent. What is left here is the policy-specific half: where the documents
// are, and the names the rest of this package already calls them by.

const schemaBase = "https://mantisec.dev/acme/contracts/policy/"

// policyDirEnv points the suite at contracts/policy/ when the walk up from the
// test's working directory cannot find it.
const policyDirEnv = "ACME_POLICY_CONTRACTS"

type (
	schemaSet = contractschema.Set
	verr      = contractschema.Err
)

var (
	pointerOf          = contractschema.PointerOf
	sortedKeys         = contractschema.SortedKeys
	canonical          = contractschema.Canonical
	containsValue      = contractschema.ContainsValue
	everySubschema     = contractschema.EverySubschema
	annotationKeywords = contractschema.AnnotationKeywords
	supportedKeywords  = contractschema.SupportedKeywords
)

// policyDir locates contracts/policy/, which lives OUTSIDE this Go module. It is
// read at test time, never embedded and never shipped, so the "no build-time
// cross-deliverable file reference" rule of root FILE_MAP.md §6 is not engaged.
func policyDir(t *testing.T) string {
	t.Helper()
	if dir := contractschema.FindDir(policyDirEnv, "policy"); dir != "" {
		return dir
	}
	t.Skipf("contracts/policy/ not found from the test working directory; set %s", policyDirEnv)
	return ""
}

func decodeJSON(t *testing.T, path string) any {
	t.Helper()
	value, err := contractschema.DecodeJSON(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return value
}

func loadSchemaSet(t *testing.T) *schemaSet {
	t.Helper()
	set, err := contractschema.Load(policyDir(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return set
}
