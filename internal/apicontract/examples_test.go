package apicontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The API golden examples — contracts/api/examples/, validated against the
// schemas in contracts/api/openapi.yaml.
//
// BOTH language suites validate the SAME files: this is the Go half, and
// functionapp-azureacme/tests/api/test_error_details_and_examples.py is the
// Python half. A per-language fixture set would defeat the entire point,
// because the defect being defended against is two conforming implementations
// reading one document differently.
//
// The manifest is a committed list, not a glob — a glob silently passes when a
// fixture is deleted — and every reject entry declares the JSON pointer and the
// schema keyword that MUST do the rejecting, so a negative fixture cannot pass
// by being refused for the wrong reason. A large minority of the entries are
// reject cases: an uppercase thumbprint, a fractional-seconds timestamp, a
// namespace carrying a path traversal, a `PUT` body carrying `spec.revision`.
// Those are the shapes the two implementations are most likely to disagree
// about, and a harness that checked only the happy path would see none of them.

type manifestEntry struct {
	File          string `json:"file"`
	SchemaRef     string `json:"schema_ref"`
	Outcome       string `json:"outcome"`
	Description   string `json:"description"`
	RejectPath    string `json:"reject_path"`
	RejectKeyword string `json:"reject_keyword"`
}

type exampleManifest struct {
	Area     string          `json:"area"`
	Examples []manifestEntry `json:"examples"`
}

func examplesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(apiDir(t), "examples")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("%s not found — the golden API documents have not landed", dir)
	}
	return dir
}

func loadManifest(t *testing.T) (string, exampleManifest) {
	t.Helper()
	dir := examplesDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("reading the example manifest: %v", err)
	}
	var manifest exampleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decoding the example manifest: %v", err)
	}
	if len(manifest.Examples) == 0 {
		t.Fatal("the example manifest lists no examples")
	}
	return dir, manifest
}

func decodeJSON(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out any
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return out
}

// TestTheSchemasUseOnlyKeywordsThisReaderImplements is the guard that keeps the
// small reader in openapi_test.go honest. A schema that grows
// `patternProperties` or `if`/`then` fails HERE, loudly, rather than being
// silently ignored on the Go side while the Python side enforces it.
func TestTheSchemasUseOnlyKeywordsThisReaderImplements(t *testing.T) {
	doc := loadOpenAPI(t)
	schemas, _ := componentSchemas(doc.root)
	for _, name := range sortedKeys(schemas) {
		schema, ok := schemas[name].(map[string]any)
		if !ok {
			t.Errorf("components.schemas.%s is not a schema object", name)
			continue
		}
		for _, node := range everySubschema(schema) {
			for _, keyword := range sortedKeys(node) {
				if annotationKeywords[keyword] || supportedKeywords[keyword] {
					continue
				}
				t.Errorf("components.schemas.%s uses the JSON Schema keyword %q, which this "+
					"reader does not implement; implement it rather than letting the Go side "+
					"under-validate", name, keyword)
			}
		}
	}
}

func TestTheManifestAndTheExampleDirectoryAgree(t *testing.T) {
	dir, manifest := loadManifest(t)
	listed := map[string]bool{}
	for _, entry := range manifest.Examples {
		listed[entry.File] = true
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, path := range matches {
		if base := filepath.Base(path); base != "index.json" {
			onDisk[base] = true
		}
	}
	for name := range listed {
		if !onDisk[name] {
			t.Errorf("the manifest lists %s, which is not on disk", name)
		}
	}
	for name := range onDisk {
		if !listed[name] {
			t.Errorf("%s is on disk and unlisted; the manifest is a list, not a glob", name)
		}
	}
}

// TestEveryManifestEntryNamesASchemaAndAnOutcome fails on a manifest that
// cannot be checked, rather than letting an unresolvable `schema_ref` or a
// reject entry with no declared reason pass silently.
func TestEveryManifestEntryNamesASchemaAndAnOutcome(t *testing.T) {
	doc := loadOpenAPI(t)
	_, manifest := loadManifest(t)
	for _, entry := range manifest.Examples {
		if _, err := doc.resolve(entry.SchemaRef); err != nil {
			t.Errorf("%s names schema_ref %q: %v", entry.File, entry.SchemaRef, err)
		}
		switch entry.Outcome {
		case "accept":
		case "reject":
			if entry.RejectKeyword == "" {
				t.Errorf("%s is a reject entry that declares no reject_keyword; a negative "+
					"fixture that does not say WHY can pass by being rejected for the wrong "+
					"reason", entry.File)
			}
		default:
			t.Errorf("%s declares outcome %q, which is neither accept nor reject",
				entry.File, entry.Outcome)
		}
	}
}

func TestGoldenExamplesValidateExactlyAsTheManifestDeclares(t *testing.T) {
	doc := loadOpenAPI(t)
	dir, manifest := loadManifest(t)

	for _, entry := range manifest.Examples {
		t.Run(entry.File, func(t *testing.T) {
			schema, err := doc.resolve(entry.SchemaRef)
			if err != nil {
				t.Fatalf("the manifest names %s: %v", entry.SchemaRef, err)
			}
			document := decodeJSON(t, filepath.Join(dir, entry.File))
			errors := doc.validate(schema, document, "")

			if entry.Outcome == "accept" {
				for _, e := range errors {
					t.Errorf("must validate, but %s", e)
				}
				return
			}

			if len(errors) == 0 {
				t.Fatal("must be REJECTED but validated cleanly")
			}
			wantPointer := pointerOf(entry.RejectPath)
			for _, e := range errors {
				if e.pointer == wantPointer && e.keyword == entry.RejectKeyword {
					return
				}
			}
			got := make([]string, 0, len(errors))
			for _, e := range errors {
				got = append(got, e.pointer+" "+e.keyword)
			}
			sort.Strings(got)
			t.Errorf("rejected, but not for its declared reason (%s %s); got %v. A negative "+
				"fixture that passes for the wrong reason asserts nothing",
				wantPointer, entry.RejectKeyword, got)
		})
	}
}

// TestBothOutcomesAreExercised. A manifest that had lost its reject entries
// would still pass every test above, and the harness would then be asserting
// only that valid documents are valid — which is the half that never catches
// anything.
func TestBothOutcomesAreExercised(t *testing.T) {
	_, manifest := loadManifest(t)
	counts := map[string]int{}
	for _, entry := range manifest.Examples {
		counts[entry.Outcome]++
	}
	if counts["accept"] == 0 {
		t.Error("no accept examples")
	}
	if counts["reject"] == 0 {
		t.Error("no reject examples; the failure shapes are what the two implementations are " +
			"most likely to disagree about")
	}
	t.Logf("checked %d accept and %d reject examples against contracts/api/openapi.yaml",
		counts["accept"], counts["reject"])
}

// TestThePutPreconditionRuleIsDocumented. §3.3: a `PUT` carrying neither
// `If-None-Match` nor `If-Match` is `428 precondition_required`, and there is a
// golden problem document for it. The rule is what makes lost updates
// structurally impossible rather than merely discouraged; the fake service's
// half of the same assertion is TestPreconditionRequired in
// internal/fakeservice.
func TestThePutPreconditionRuleIsDocumented(t *testing.T) {
	doc := loadOpenAPI(t)
	paths, ok := doc.root["paths"].(map[string]any)
	if !ok {
		t.Fatal("the OpenAPI document carries no paths")
	}
	item, ok := paths["/namespaces/{namespace}/certificates/{name}"].(map[string]any)
	if !ok {
		t.Fatal("the registration path is absent from the OpenAPI document")
	}
	put, ok := item["put"].(map[string]any)
	if !ok {
		t.Fatal("the registration path declares no PUT")
	}
	responses, ok := put["responses"].(map[string]any)
	if !ok {
		t.Fatal("the PUT declares no responses")
	}
	for _, status := range []string{"200", "201", "202", "428"} {
		if _, present := responses[status]; !present {
			t.Errorf("the PUT does not document a %s response", status)
		}
	}

	_, manifest := loadManifest(t)
	found := false
	for _, entry := range manifest.Examples {
		if entry.File == "problem-precondition_required.json" {
			found = true
		}
	}
	if !found {
		t.Error("no golden problem document for precondition_required; the 428 rule is " +
			"documented in prose but has no example either implementation can be held to")
	}
}
