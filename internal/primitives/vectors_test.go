package primitives

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The vectors are the contract; this implementation and its Python twin are
// conveniences (contracts-and-codegen.md §7.3). Both languages run THE SAME
// files — a per-language copy would defeat the entire point, because the defect
// class being defended against is silent cross-language divergence.
//
// Location: contracts/primitives/vectors/, outside this Go module. That is fine
// and deliberate: the files are read at TEST time, never embedded and never
// shipped, so the "no build-time cross-deliverable file reference" rule of root
// FILE_MAP.md §6 is not engaged.

const vectorsEnv = "ACME_PRIMITIVES_VECTORS"

func vectorsDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv(vectorsEnv); v != "" {
		return v
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", "primitives", "vectors")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func loadVectors(t *testing.T, name string) []byte {
	t.Helper()
	dir := vectorsDir(t)
	if dir == "" {
		t.Skipf("contracts/primitives/vectors/ not found — the shared vector corpus has not landed yet. "+
			"Set %s to point at it. This suite lights up the moment it exists.", vectorsEnv)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Skipf("%s not found in %s — this test lights up when the vector file lands: %v", name, dir, err)
	}
	return b
}

type normVector struct {
	Input     string `json:"input"`
	Expect    string `json:"expect"` // "ok" | "reject"
	Canonical string `json:"canonical"`
	Reason    string `json:"reason"`
	Category  string `json:"category"`
}

// TestNormalisationVectors runs the conformance corpus of
// authorisation-model.md §4.6 — at least 300 cases across twelve categories.
func TestNormalisationVectors(t *testing.T) {
	raw := loadVectors(t, "normalisation-vectors.json")

	var vectors []normVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		// Some corpora wrap the array in an object with metadata.
		var wrapper struct {
			Vectors []normVector `json:"vectors"`
			Cases   []normVector `json:"cases"`
		}
		if err2 := json.Unmarshal(raw, &wrapper); err2 != nil {
			t.Fatalf("normalisation-vectors.json is neither an array nor {vectors|cases: [...]}: %v / %v", err, err2)
		}
		vectors = wrapper.Vectors
		if len(vectors) == 0 {
			vectors = wrapper.Cases
		}
	}
	if len(vectors) == 0 {
		t.Fatal("normalisation-vectors.json decoded to zero cases")
	}

	var failures int
	for i, v := range vectors {
		name := fmt.Sprintf("%03d/%s", i, v.Category)
		got, err := Normalise(v.Input)
		switch v.Expect {
		case "ok":
			if err != nil {
				t.Errorf("%s: Normalise(%q) rejected (%v), vector expects ok → %q", name, v.Input, err, v.Canonical)
				failures++
				continue
			}
			if v.Canonical != "" && got != v.Canonical {
				t.Errorf("%s: Normalise(%q) = %q, vector expects %q", name, v.Input, got, v.Canonical)
				failures++
			}
		case "reject":
			if err == nil {
				t.Errorf("%s: Normalise(%q) = %q, vector expects rejection (%s)", name, v.Input, got, v.Reason)
				failures++
			}
		default:
			t.Errorf("%s: vector has unknown expect value %q", name, v.Expect)
			failures++
		}
	}
	t.Logf("ran %d normalisation vectors, %d failures", len(vectors), failures)
}

// TestNamespaceVectors runs the shared namespace grammar corpus.
func TestNamespaceVectors(t *testing.T) {
	raw := loadVectors(t, "namespace-vectors.json")
	var doc struct {
		Regex   string `json:"regex"`
		Vectors []struct {
			ID     string `json:"id"`
			Value  string `json:"value"`
			Expect string `json:"expect"` // "accept" | "reject"
			Note   string `json:"note"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("namespace-vectors.json does not decode: %v", err)
	}
	if doc.Regex != NamespacePattern {
		t.Fatalf("the corpus regex %q and the implementation %q disagree", doc.Regex, NamespacePattern)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("namespace-vectors.json decoded to zero cases")
	}
	for _, v := range doc.Vectors {
		err := ValidateNamespace(v.Value)
		if v.Expect == "accept" && err != nil {
			t.Errorf("%s: ValidateNamespace(%q) rejected (%v), corpus expects accept", v.ID, v.Value, err)
		}
		if v.Expect == "reject" && err == nil {
			t.Errorf("%s: ValidateNamespace(%q) accepted, corpus expects rejection (%s)", v.ID, v.Value, v.Note)
		}
	}
	t.Logf("ran %d namespace vectors", len(doc.Vectors))
}

// TestDestinationHashVectors runs the shared destinationHash corpus, including
// the F-092 groups whose entries MUST collide.
func TestDestinationHashVectors(t *testing.T) {
	raw := loadVectors(t, "destination-hash-vectors.json")
	var doc struct {
		Vectors []struct {
			ID                  string `json:"id"`
			MustHashIdentically *bool  `json:"must_hash_identically"`
			Entries             []struct {
				VaultResourceID string `json:"vault_resource_id"`
				CertificateName string `json:"certificate_name"`
				DestinationHash string `json:"destination_hash"`
			} `json:"entries"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("destination-hash-vectors.json does not decode: %v", err)
	}
	checked := 0
	for _, g := range doc.Vectors {
		distinct := map[string]struct{}{}
		for _, e := range g.Entries {
			got := DestinationHash(e.VaultResourceID, e.CertificateName)
			if e.DestinationHash != "" && got != e.DestinationHash {
				t.Errorf("%s: DestinationHash(%q, %q) = %s, corpus expects %s", g.ID, e.VaultResourceID, e.CertificateName, got, e.DestinationHash)
			}
			distinct[got] = struct{}{}
			checked++
		}
		if g.MustHashIdentically != nil {
			if *g.MustHashIdentically && len(distinct) != 1 {
				t.Errorf("%s: entries hashed to %d distinct values, expected 1 — the If-None-Match ownership guard would never fire (F-092)", g.ID, len(distinct))
			}
			if !*g.MustHashIdentically && len(distinct) != len(g.Entries) {
				t.Errorf("%s: entries collided but must not", g.ID)
			}
		}
	}
	if checked == 0 {
		t.Fatal("destination-hash-vectors.json produced no comparable case")
	}
	t.Logf("ran %d destinationHash vectors", checked)
}

// TestWireFormatVectors runs the shared wire-format corpus.
//
// The corpus asserts the SHAPE rules and says so: "the regex is a shape check;
// calendar validity is a separate parse step". 2026-02-29 is shape-valid and
// calendar-invalid, and the corpus expects the shape check to accept it.
func TestWireFormatVectors(t *testing.T) {
	raw := loadVectors(t, "wire-format-vectors.json")
	var doc struct {
		Patterns map[string]string `json:"patterns"`
		Vectors  []struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Value  string `json:"value"`
			Expect string `json:"expect"`
			Note   string `json:"note"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("wire-format-vectors.json does not decode: %v", err)
	}
	if got := doc.Patterns["timestamp"]; got != TimestampPattern {
		t.Fatalf("the corpus timestamp shape %q and the implementation %q disagree", got, TimestampPattern)
	}
	if got := doc.Patterns["hex"]; got != HexPattern {
		t.Fatalf("the corpus hex shape %q and the implementation %q disagree", got, HexPattern)
	}
	shapes := map[string]*regexp.Regexp{
		"timestamp":  regexp.MustCompile(TimestampPattern),
		"hex":        regexp.MustCompile(HexPattern),
		"sha256_hex": regexp.MustCompile(`^[0-9a-f]{64}$`),
	}
	checked := 0
	for _, v := range doc.Vectors {
		shape, ok := shapes[v.Kind]
		if !ok {
			continue // kinds owned by the generated contract package
		}
		checked++
		matched := shape.MatchString(v.Value)
		if matched && v.Expect == "reject" {
			t.Errorf("%s: %q matched %s, corpus expects rejection (%s)", v.ID, v.Value, v.Kind, v.Note)
		}
		if !matched && v.Expect == "accept" {
			t.Errorf("%s: %q did not match %s, corpus expects accept", v.ID, v.Value, v.Kind)
		}
	}
	if checked == 0 {
		t.Fatal("wire-format-vectors.json produced no comparable case")
	}
	t.Logf("ran %d wire-format vectors", checked)
}

// TestParseTimestampIsStricterThanTheShape — both languages must agree that a
// shape-valid non-day is still rejected by the parser.
func TestParseTimestampIsStricterThanTheShape(t *testing.T) {
	if _, err := ParseTimestamp("2026-02-29T00:00:00Z"); err == nil {
		t.Error("2026-02-29 accepted; 2026 is not a leap year")
	}
	if _, err := ParseTimestamp("2028-02-29T00:00:00Z"); err != nil {
		t.Errorf("2028-02-29 rejected; 2028 is a leap year: %v", err)
	}
}

// TestNormalisationCorpusIsComplete asserts the corpus SIZE, which is
// contracts/'s acceptance criterion rather than this package's. It is separate
// from correctness so that a corpus still being written fails on completeness
// alone and never masks a real implementation divergence.
func TestNormalisationCorpusIsComplete(t *testing.T) {
	raw := loadVectors(t, "normalisation-vectors.json")
	var vectors []normVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		var wrapper struct {
			Vectors []normVector `json:"vectors"`
			Cases   []normVector `json:"cases"`
		}
		if err2 := json.Unmarshal(raw, &wrapper); err2 != nil {
			t.Fatalf("normalisation-vectors.json does not decode: %v / %v", err, err2)
		}
		vectors = wrapper.Vectors
		if len(vectors) == 0 {
			vectors = wrapper.Cases
		}
	}
	categories := map[string]struct{}{}
	for _, v := range vectors {
		if v.Category != "" {
			categories[v.Category] = struct{}{}
		}
	}
	if len(vectors) < 300 {
		t.Errorf("corpus has %d cases across %d categories; authorisation-model.md §4.6 requires at least 300 across twelve", len(vectors), len(categories))
	}
	if len(categories) < 12 {
		t.Errorf("corpus covers %d categories; §4.6 requires twelve", len(categories))
	}
}
