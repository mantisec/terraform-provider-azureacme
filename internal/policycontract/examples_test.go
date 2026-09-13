package policycontract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The policy document contract — contracts/policy/ and its golden examples.
//
// authorisation-model.md §3.1 names five document types plus the index. Their
// schemas are in contracts/policy/, the golden documents are in
// contracts/policy/examples/, and BOTH language suites validate the same files:
// this is the Go half, and
// functionapp-azureacme/tests/authz/test_policy_document_schemas.py is the
// Python half. A per-language fixture set would defeat the point, because the
// defect being defended against is two conforming implementations reading one
// document differently.
//
// The manifest is a committed list, not a glob, and every reject entry declares
// the JSON pointer and the schema keyword that MUST do the rejecting — so a
// negative fixture cannot pass by being refused for the wrong reason.

// documentTypeSchemas is authorisation-model.md §3.1's list: the index plus the
// five document types. common.schema.json is the shared $defs and is not a
// document type.
var documentTypeSchemas = []string{
	"policy-index.schema.json",
	"principal-binding.schema.json",
	"namespace.schema.json",
	"domain-authorisation.schema.json",
	"validation-binding.schema.json",
	"destination-policy.schema.json",
}

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
	dir := filepath.Join(policyDir(t), "examples")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("%s not found — the golden policy documents have not landed", dir)
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

// ---------------------------------------------------------------- §3.1

func TestTheIndexAndTheFiveDocumentTypesEachHaveASchema(t *testing.T) {
	set := loadSchemaSet(t)
	for _, name := range documentTypeSchemas {
		if _, ok := set.Docs[name]; !ok {
			t.Errorf("no schema for the %s document type", strings.TrimSuffix(name, ".schema.json"))
		}
	}
	if _, ok := set.Docs["common.schema.json"]; !ok {
		t.Error("the shared $defs document is missing")
	}
	for _, name := range set.Names() {
		id, _ := set.Docs[name]["$id"].(string)
		if !strings.HasPrefix(id, schemaBase) {
			t.Errorf("%s carries $id %q, outside the policy namespace", name, id)
		}
	}
}

// TestTheSchemaSetUsesOnlyKeywordsThisReaderImplements is the guard that keeps
// the small reader in schemaset_test.go honest. A schema that grows
// `patternProperties` or `if`/`then` fails HERE, loudly, rather than being
// silently ignored on the Go side while the Python side enforces it.
func TestTheSchemaSetUsesOnlyKeywordsThisReaderImplements(t *testing.T) {
	set := loadSchemaSet(t)
	for _, name := range set.Names() {
		for _, node := range everySubschema(set.Docs[name]) {
			for _, keyword := range sortedKeys(node) {
				if annotationKeywords[keyword] || supportedKeywords[keyword] {
					continue
				}
				t.Errorf("%s uses the JSON Schema keyword %q, which this reader does not "+
					"implement; implement it rather than letting the Go side under-validate",
					name, keyword)
			}
		}
	}
}

// ---------------------------------------------------------------- goldens

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

func TestGoldenExamplesValidateExactlyAsTheManifestDeclares(t *testing.T) {
	set := loadSchemaSet(t)
	dir, manifest := loadManifest(t)

	for _, entry := range manifest.Examples {
		t.Run(entry.File, func(t *testing.T) {
			schema, ok := set.Docs[entry.SchemaRef]
			if !ok {
				t.Fatalf("the manifest names %s, which is not in the schema set", entry.SchemaRef)
			}
			document := decodeJSON(t, filepath.Join(dir, entry.File))
			errors := set.Validate(schema, document, "", entry.SchemaRef)

			if entry.Outcome == "accept" {
				for _, e := range errors {
					t.Errorf("must validate, but %s", e)
				}
				return
			}

			if len(errors) == 0 {
				t.Fatal("must be REJECTED but validated cleanly")
			}
			want := verr{Pointer: pointerOf(entry.RejectPath), Keyword: entry.RejectKeyword}
			for _, e := range errors {
				if e.Pointer == want.Pointer && e.Keyword == want.Keyword {
					return
				}
			}
			got := make([]string, 0, len(errors))
			for _, e := range errors {
				got = append(got, e.Pointer+" "+e.Keyword)
			}
			sort.Strings(got)
			t.Errorf("rejected, but not for its declared reason (%s %s); got %v. A negative "+
				"fixture that passes for the wrong reason asserts nothing",
				want.Pointer, want.Keyword, got)
		})
	}
}

// ---------------------------------------------------------------- §5.1

func TestThereAreExactlyThreeMatchKinds(t *testing.T) {
	set := loadSchemaSet(t)
	kind := defOf(t, set, "MatchKind")
	values, _ := kind["enum"].([]any)
	got := make([]string, 0, len(values))
	for _, value := range values {
		text, _ := value.(string)
		got = append(got, text)
	}
	if strings.Join(got, ",") != "exact,subtree,wildcard" {
		t.Errorf("match kinds are %v; the model has exactly three and no fourth is inferable", got)
	}
}

// TestAMatchRuleIsClosed — `additionalProperties: false` is what makes the three
// kinds the WHOLE vocabulary. Without it a rule could carry a `pattern` beside a
// legal kind: ignored by one evaluator, honoured by the next.
func TestAMatchRuleIsClosed(t *testing.T) {
	set := loadSchemaSet(t)
	rule := defOf(t, set, "MatchRule")
	if open, _ := rule["additionalProperties"].(bool); open {
		t.Error("a match rule accepts additional properties")
	} else if _, present := rule["additionalProperties"]; !present {
		t.Error("a match rule does not declare additionalProperties: false")
	}
	properties, _ := rule["properties"].(map[string]any)
	kind, _ := properties["kind"].(map[string]any)
	if ref, _ := kind["$ref"].(string); !strings.HasSuffix(ref, "/MatchKind") {
		t.Errorf("a match rule's kind is %v rather than the three-value enum", kind)
	}
}

var (
	regexNamedField   = regexp.MustCompile(`(?i)regex|regexp|expression`)
	patternNamedField = regexp.MustCompile(`(?i)pattern`)
)

// TestNoFieldAcceptsARegularExpressionForAnIdentifier — a regex in a hostname
// matcher is a recurring source of authorisation bypass (unanchored patterns,
// `.` matching any character, catastrophic backtracking), so the schema set
// offers nowhere to put one.
//
// Two things are checked. No field is NAMED for a pattern language; and any
// field whose name mentions "pattern" is an array of match rules rather than a
// string, which is the one place the word legitimately appears
// (validation-binding.permittedNamePatterns).
func TestNoFieldAcceptsARegularExpressionForAnIdentifier(t *testing.T) {
	set := loadSchemaSet(t)
	walked := 0
	for _, name := range set.Names() {
		for _, node := range everySubschema(set.Docs[name]) {
			properties, _ := node["properties"].(map[string]any)
			for _, field := range sortedKeys(properties) {
				walked++
				where := fmt.Sprintf("%s:%s", name, field)
				if regexNamedField.MatchString(field) {
					t.Errorf("%s is named for a pattern language", where)
				}
				if !patternNamedField.MatchString(field) {
					continue
				}
				subschema, _ := properties[field].(map[string]any)
				if kind, _ := subschema["type"].(string); kind != "array" {
					t.Errorf("%s mentions 'pattern' and is not an array of match rules", where)
					continue
				}
				items, _ := subschema["items"].(map[string]any)
				if ref, _ := items["$ref"].(string); !strings.HasSuffix(ref, "/MatchRule") {
					t.Errorf("%s mentions 'pattern' and its items are not match rules", where)
				}
			}
		}
	}
	if walked == 0 {
		t.Fatal("no properties were walked — the walker is broken, not the schemas")
	}
}

// ---------------------------------------------------------------- §5.5 A10

// TestADestinationPolicyHasNoPrefixForm — a prefix policy has no vault list, so
// §5.6's one declaration would have to emit a resource-group-scoped
// `Key Vault Certificates Officer` assignment, and every vault the caller
// creates inside that group becomes a valid delivery target.
func TestADestinationPolicyHasNoPrefixForm(t *testing.T) {
	set := loadSchemaSet(t)
	_, manifest := loadManifest(t)

	var prefixes []string
	for _, entry := range manifest.Examples {
		if entry.SchemaRef == "destination-policy.schema.json" &&
			entry.Outcome == "reject" && entry.RejectPath == "/keyVaultResourceId" {
			prefixes = append(prefixes, entry.File)
		}
	}
	if len(prefixes) < 2 {
		t.Errorf("both the subscription and the resource-group prefix need a negative fixture; "+
			"found %v", prefixes)
	}

	schema := set.Docs["destination-policy.schema.json"]
	required, _ := schema["required"].([]any)
	if !containsValue(required, "keyVaultResourceId") {
		t.Error("keyVaultResourceId is not required — a destination with no vault would validate")
	}
	if strings.Contains(strings.ToLower(canonical(schema["properties"])), "prefix") {
		t.Error("a destination-policy property documenting a prefix form has appeared")
	}
}

// ---------------------------------------------------------------- helpers

func defOf(t *testing.T, set *schemaSet, name string) map[string]any {
	t.Helper()
	common, ok := set.Docs["common.schema.json"]
	if !ok {
		t.Fatal("common.schema.json is missing")
	}
	defs, _ := common["$defs"].(map[string]any)
	node, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("common.schema.json has no $defs/%s", name)
	}
	return node
}
