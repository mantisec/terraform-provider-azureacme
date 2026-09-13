package primitives

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The correction table's own proof (SCAFFOLD-IDNA-DIFFERENTIAL-SWEEP).
//
// A correction table is a list of assertions about a dependency's behaviour, and a dependency's
// behaviour changes. Two failure modes follow, and the tests below are one each:
//
//   - an entry is DELETED, or never had a case behind it, and nothing notices. The corpus is the
//     only thing standing between this package and its Python twin, so an entry the corpus does
//     not witness is an entry that can be removed in a refactor with a green suite.
//   - an entry becomes REDUNDANT because golang.org/x/net/idna caught up with the Unicode version
//     Python's idna carries. Then the correction is dead code that reads like a live control, and
//     the honest move is to delete it — which is only safe to do when something says so.
//
// TestEveryCorrectionIsWitnessedByAVector covers both: it removes each entry in turn and requires
// the shared corpus to notice. A newly redundant entry fails it, and the failure message says so.

// withCorrections swaps the compiled replacer for one built from `table`, runs `body`, and puts
// the original back. Normalise reads the package-level replacer, which is what makes a mutation
// test possible at all; nothing here runs in parallel, so the swap is safe.
func withCorrections(t *testing.T, table []uts46Correction, body func()) {
	t.Helper()
	original := uts46MappingCorrections
	uts46MappingCorrections = newUTS46Replacer(table)
	defer func() { uts46MappingCorrections = original }()
	body()
}

// corpusDisagreements runs the whole shared corpus and returns the cases the current normaliser
// gets wrong. Zero is the only acceptable answer for the unmutated table, and it is asserted by
// TestNormalisationVectors; here the count is the instrument.
func corpusDisagreements(t *testing.T, vectors []normVector) []string {
	t.Helper()
	var wrong []string
	for _, v := range vectors {
		got, err := Normalise(v.Input)
		switch v.Expect {
		case "ok":
			if err != nil {
				wrong = append(wrong, fmt.Sprintf("%q: rejected, corpus expects %q", v.Input, v.Canonical))
			} else if v.Canonical != "" && got != v.Canonical {
				wrong = append(wrong, fmt.Sprintf("%q: %q, corpus expects %q", v.Input, got, v.Canonical))
			}
		case "reject":
			if err == nil {
				wrong = append(wrong, fmt.Sprintf("%q: %q, corpus expects rejection", v.Input, got))
			}
		}
	}
	return wrong
}

func corpusVectors(t *testing.T) []normVector {
	t.Helper()
	raw := loadVectors(t, "normalisation-vectors.json")
	var wrapper struct {
		Vectors []normVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("normalisation-vectors.json does not decode: %v", err)
	}
	if len(wrapper.Vectors) == 0 {
		t.Fatal("normalisation-vectors.json decoded to zero cases")
	}
	return wrapper.Vectors
}

// TestEveryCorrectionIsWitnessedByAVector is the deliberate mutation.
//
// For each entry: rebuild the replacer without it, run the whole corpus, and require at least one
// case to fail. If none does, the entry is either unnecessary or unwitnessed, and both are worth
// a red suite.
func TestEveryCorrectionIsWitnessedByAVector(t *testing.T) {
	vectors := corpusVectors(t)

	if wrong := corpusDisagreements(t, vectors); len(wrong) != 0 {
		t.Fatalf("the corpus already disagrees with the UNMUTATED normaliser in %d place(s); "+
			"the mutation below would prove nothing. First: %s", len(wrong), wrong[0])
	}

	for i, correction := range uts46MappingCorrectionTable {
		mutated := make([]uts46Correction, 0, len(uts46MappingCorrectionTable)-1)
		mutated = append(mutated, uts46MappingCorrectionTable[:i]...)
		mutated = append(mutated, uts46MappingCorrectionTable[i+1:]...)

		withCorrections(t, mutated, func() {
			if len(corpusDisagreements(t, vectors)) == 0 {
				t.Errorf("removing correction %d (%s) breaks no corpus case.\n"+
					"Either the corpus has no vector for it — add one to "+
					"contracts/tools/build_normalisation_vectors.py and regenerate — or "+
					"golang.org/x/net/idna has caught up with the Unicode version Python's idna "+
					"carries and the entry is now dead code that should be deleted.",
					i, correction.Why)
			}
		})
	}

	t.Logf("%d correction(s), every one witnessed by at least one corpus case",
		len(uts46MappingCorrectionTable))
}

// TestCorrectionTableIsWellFormed keeps the table itself honest: no duplicate source, no entry
// that corrects a character to itself, and every entry carrying its one-line reason.
func TestCorrectionTableIsWellFormed(t *testing.T) {
	seen := map[string]int{}
	for i, correction := range uts46MappingCorrectionTable {
		if correction.From == "" {
			t.Errorf("correction %d has an empty From, which would make the replacer nonsense", i)
		}
		if correction.From == correction.To {
			t.Errorf("correction %d (%s) maps a character to itself", i, correction.Why)
		}
		if correction.Why == "" {
			t.Errorf("correction %d has no reason; the next reader cannot tell whether to keep it", i)
		}
		if first, dup := seen[correction.From]; dup {
			t.Errorf("correction %d repeats the source of correction %d; strings.Replacer takes "+
				"the first, so the second is silently dead", i, first)
		}
		seen[correction.From] = i
	}
	if len(uts46MappingCorrectionTable) == 0 {
		t.Fatal("the correction table is empty; the U+1E9E divergence alone requires one entry")
	}
}
