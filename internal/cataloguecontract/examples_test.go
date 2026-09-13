package cataloguecontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/contractschema"
)

// The catalogue golden examples — contracts/catalogue/examples/, validated
// against contracts/catalogue/*.schema.json.
//
// BOTH language suites load the SAME manifest and validate the SAME files: this
// is the Go half, and
// functionapp-azureacme/tests/catalogue/test_golden_examples.py is the Python
// half. A per-language fixture set would defeat the entire point, because the
// defect being defended against is two conforming implementations reading one
// document differently.
//
// The manifest is a committed list, not a glob — a glob silently passes when a
// fixture is deleted — and every reject entry declares the JSON pointer and the
// schema keyword that MUST do the rejecting, so a negative fixture cannot pass
// by being refused for the wrong reason. TestARejectFixtureRejectedForTheWrongReasonIsNotAccepted
// is the proof of that, rather than the claim of it.

// catalogueDirEnv points the suite at contracts/catalogue/ when the walk up from
// the test's working directory cannot find it.
const catalogueDirEnv = "ACME_CATALOGUE_CONTRACTS"

const schemaBase = "https://mantisec.dev/acme/contracts/catalogue/"

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

func catalogueDir(t *testing.T) string {
	t.Helper()
	if dir := contractschema.FindDir(catalogueDirEnv, "catalogue"); dir != "" {
		return dir
	}
	t.Skipf("contracts/catalogue/ not found from the test working directory; set %s",
		catalogueDirEnv)
	return ""
}

func loadSchemaSet(t *testing.T) *contractschema.Set {
	t.Helper()
	set, err := contractschema.Load(catalogueDir(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return set
}

func examplesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(catalogueDir(t), "examples")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("%s not found — the golden catalogue documents have not landed", dir)
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
	value, err := contractschema.DecodeJSON(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return value
}

// declaredReasonMatched is the predicate the reject half of the harness turns
// on: an example must be refused at the pointer and by the keyword its manifest
// entry names. It is a named function rather than an inline loop so that
// TestARejectFixtureRejectedForTheWrongReasonIsNotAccepted can put a wrong
// declaration through the very same code the real check uses.
func declaredReasonMatched(errors []contractschema.Err, entry manifestEntry) bool {
	want := contractschema.PointerOf(entry.RejectPath)
	for _, e := range errors {
		if e.Pointer == want && e.Keyword == entry.RejectKeyword {
			return true
		}
	}
	return false
}

func summarise(errors []contractschema.Err) []string {
	got := make([]string, 0, len(errors))
	for _, e := range errors {
		got = append(got, e.Pointer+" "+e.Keyword)
	}
	sort.Strings(got)
	return got
}

// ---------------------------------------------------------------- the schemas

func TestEveryCatalogueSchemaCarriesAnIDInItsOwnNamespace(t *testing.T) {
	set := loadSchemaSet(t)
	for _, name := range set.Names() {
		id, _ := set.Docs[name]["$id"].(string)
		if !strings.HasPrefix(id, schemaBase) {
			t.Errorf("%s carries $id %q, outside the catalogue namespace", name, id)
		}
	}
}

// TestTheSchemaSetUsesOnlyKeywordsThisReaderImplements is the guard that keeps
// the small reader in internal/contractschema honest. A schema that grows
// `patternProperties` or `dependentRequired` fails HERE, loudly, rather than
// being silently ignored on the Go side while the Python side enforces it.
func TestTheSchemaSetUsesOnlyKeywordsThisReaderImplements(t *testing.T) {
	set := loadSchemaSet(t)
	for _, name := range set.Names() {
		for _, node := range contractschema.EverySubschema(set.Docs[name]) {
			for _, keyword := range contractschema.SortedKeys(node) {
				if contractschema.AnnotationKeywords[keyword] ||
					contractschema.SupportedKeywords[keyword] {
					continue
				}
				t.Errorf("%s uses the JSON Schema keyword %q, which this reader does not "+
					"implement; implement it rather than letting the Go side under-validate",
					name, keyword)
			}
		}
	}
}

// ---------------------------------------------------------------- the manifest

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

// TestEveryManifestEntryNamesASchemaAndAnOutcome fails on a manifest that cannot
// be checked, rather than letting an unresolvable `schema_ref` or a reject entry
// with no declared reason pass silently.
func TestEveryManifestEntryNamesASchemaAndAnOutcome(t *testing.T) {
	set := loadSchemaSet(t)
	_, manifest := loadManifest(t)
	for _, entry := range manifest.Examples {
		if _, ok := set.Docs[entry.SchemaRef]; !ok {
			t.Errorf("%s names schema_ref %q, which is not in the schema set",
				entry.File, entry.SchemaRef)
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
			if !declaredReasonMatched(errors, entry) {
				t.Errorf("rejected, but not for its declared reason (%s %s); got %v. A negative "+
					"fixture that passes for the wrong reason asserts nothing",
					contractschema.PointerOf(entry.RejectPath), entry.RejectKeyword,
					summarise(errors))
			}
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
	t.Logf("checked %d accept and %d reject examples against contracts/catalogue/",
		counts["accept"], counts["reject"])
}

// TestARejectFixtureRejectedForTheWrongReasonIsNotAccepted is the harness's own
// negative control.
//
// Every other test here can pass while the reject half checks nothing but "some
// error occurred" — and a reject fixture that is refused for an unrelated reason
// asserts nothing at all, because the shape it was written to pin is no longer
// the shape being refused. So this test takes a real reject entry, mis-declares
// its reason two ways, and puts each through the SAME predicate the real check
// calls. If the predicate ever degrades into an outcome-only check, this goes
// red first.
func TestARejectFixtureRejectedForTheWrongReasonIsNotAccepted(t *testing.T) {
	set := loadSchemaSet(t)
	dir, manifest := loadManifest(t)

	checked := 0
	for _, entry := range manifest.Examples {
		if entry.Outcome != "reject" {
			continue
		}
		schema, ok := set.Docs[entry.SchemaRef]
		if !ok {
			continue
		}
		document := decodeJSON(t, filepath.Join(dir, entry.File))
		errors := set.Validate(schema, document, "", entry.SchemaRef)
		if len(errors) == 0 {
			continue // TestGoldenExamplesValidateExactlyAsTheManifestDeclares owns that failure.
		}
		checked++

		if !declaredReasonMatched(errors, entry) {
			t.Errorf("%s: the control needs the declared reason to match first", entry.File)
			continue
		}
		wrongKeyword := entry
		wrongKeyword.RejectKeyword = "maxLength"
		if declaredReasonMatched(errors, wrongKeyword) {
			t.Errorf("%s: the harness accepted the WRONG keyword; it is checking the outcome "+
				"and not the reason", entry.File)
		}
		wrongPointer := entry
		wrongPointer.RejectPath = "/aPointerNothingInThisDocumentUses"
		if declaredReasonMatched(errors, wrongPointer) {
			t.Errorf("%s: the harness accepted the WRONG pointer; it is checking the outcome "+
				"and not the reason", entry.File)
		}
	}
	if checked == 0 {
		t.Fatal("no reject fixture reached the control — the control is watching nothing")
	}
	t.Logf("the declared-reason check was proved to discriminate on %d reject fixtures", checked)
}

// ---------------------------------------------------------------- round trip

// TestEveryAcceptExampleRoundTripsThroughTheGeneratedEnvelope.
//
// contracts-and-codegen.md §8.5: a generated model must preserve fields it does
// not know about on a round trip. Every accept fixture goes through
// contracts.Document — which names three members and has never heard of the rest
// — and must come back out byte-for-byte equal as a document. A model that
// dropped what it does not know would fail here on every fixture, and would fail
// in production as a rolling deployment silently stripping a newer writer's
// fields across the fleet.
func TestEveryAcceptExampleRoundTripsThroughTheGeneratedEnvelope(t *testing.T) {
	dir, manifest := loadManifest(t)
	for _, entry := range manifest.Examples {
		if entry.Outcome != "accept" {
			continue
		}
		t.Run(entry.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, entry.File))
			if err != nil {
				t.Fatal(err)
			}
			var document contracts.Document
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("the generated envelope cannot read the document: %v", err)
			}
			out, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("the generated envelope cannot write the document back: %v", err)
			}
			if before, after := normalise(t, raw), normalise(t, out); !reflect.DeepEqual(before, after) {
				t.Errorf("the round trip did not preserve the document.\nlost: %v\nadded: %v",
					missingKeys(before, after), missingKeys(after, before))
			}
		})
	}
}

// TestAFieldTheGeneratedModelDoesNotKnowSurvivesSerialisation is the same
// property stated on the one fixture that exists to witness it, so the reason
// the round trip matters is legible without reading the whole manifest.
//
// `unknownTopLevelField` and `issuance.futureFieldFromANewerWriter` are what a
// NEWER writer put in a document this build's model does not describe. Both must
// survive, and `kind` must still be readable beside them: that pair of
// properties — parse what you know, keep what you do not — is exactly what makes
// the two-phase expand/migrate/contract change of §8.3 safe.
func TestAFieldTheGeneratedModelDoesNotKnowSurvivesSerialisation(t *testing.T) {
	dir, manifest := loadManifest(t)
	const witness = "spec-v1-unknown-fields.json"
	listed := false
	for _, entry := range manifest.Examples {
		if entry.File == witness {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("%s is not in the manifest; the unknown-field property has no witness", witness)
	}

	raw, err := os.ReadFile(filepath.Join(dir, witness))
	if err != nil {
		t.Fatal(err)
	}
	var document contracts.Document
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Kind != contracts.KindCertificateRegistrationSpec {
		t.Errorf("the envelope read kind %q", document.Kind)
	}
	if _, held := document.Extra["unknownTopLevelField"]; !held {
		t.Error("the model did not keep the top-level member it does not know")
	}

	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	after := normalise(t, out)
	if got := after["unknownTopLevelField"]; got != "written by a newer service version" {
		t.Errorf("the unknown top-level member did not survive: %v", got)
	}
	issuance, ok := after["issuance"].(map[string]any)
	if !ok {
		t.Fatal("issuance did not survive the round trip")
	}
	if _, held := issuance["futureFieldFromANewerWriter"]; !held {
		t.Error("the unknown NESTED member did not survive; a bag that keeps only top-level " +
			"members still strips what a newer writer adds inside a block")
	}
}

func normalise(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return out
}

func missingKeys(from, in map[string]any) []string {
	var out []string
	for key, value := range from {
		other, present := in[key]
		if !present || !reflect.DeepEqual(value, other) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}
