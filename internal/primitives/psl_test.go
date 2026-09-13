package primitives

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

type pslVector struct {
	ID                string  `json:"id"`
	Identifier        string  `json:"identifier"`
	PublicSuffix      string  `json:"public_suffix"`
	RegisteredDomain  *string `json:"registered_domain"`
	TwoLabelHeuristic string  `json:"two_label_heuristic"`
	Note              string  `json:"note"`
}

type pslCorpus struct {
	Counts struct {
		Vectors                  int `json:"vectors"`
		TwoLabelHeuristicDiverge int `json:"two_label_heuristic_diverges"`
		MultiLabelPublicSuffix   int `json:"multi_label_public_suffix"`
	} `json:"counts"`
	Vectors []pslVector `json:"vectors"`
}

// TestPSLVectors runs the shared registered-domain corpus — THE SAME FILE the
// Python suite runs.
//
// rate-limits-and-admission.md §2: "registered domain" is eTLD+1 from the pinned
// Public Suffix List, never "the last two labels". Three components need the
// answer, and if this half and the Python half disagree, a policy that permits a
// wildcard and a ledger that counts it are charging different budgets. The
// heuristic recorded beside each case is what a plausible-looking wrong
// implementation would have said; it UNDER-COUNTS, so nothing observable goes
// wrong until issuance fails with the budget already spent.
func TestPSLVectors(t *testing.T) {
	raw := loadVectors(t, "psl-vectors.json")
	var corpus pslCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("psl-vectors.json does not decode: %v", err)
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("psl-vectors.json decoded to zero cases")
	}

	list, err := LoadPublicSuffixList("")
	if err != nil {
		t.Fatalf("the pinned snapshot did not load: %v", err)
	}

	diverged, multiLabel := 0, 0
	for _, v := range corpus.Vectors {
		want := ""
		if v.RegisteredDomain != nil {
			want = *v.RegisteredDomain
		}
		got, err := RegisteredDomain(v.Identifier)
		if err != nil {
			t.Fatalf("%s: RegisteredDomain(%q): %v", v.ID, v.Identifier, err)
		}
		if got != want {
			t.Errorf("%s: RegisteredDomain(%q) = %q, corpus expects %q (%s)", v.ID, v.Identifier, got, want, v.Note)
		}
		if suffix := list.PublicSuffix(pslIdentifier(v.Identifier)); suffix != v.PublicSuffix {
			t.Errorf("%s: PublicSuffix(%q) = %q, corpus expects %q", v.ID, v.Identifier, suffix, v.PublicSuffix)
		}
		if v.TwoLabelHeuristic != want {
			diverged++
		}
		if strings.Count(v.PublicSuffix, ".") >= 2 {
			multiLabel++
		}
	}

	if len(corpus.Vectors) != corpus.Counts.Vectors {
		t.Errorf("corpus declares %d vectors, carries %d", corpus.Counts.Vectors, len(corpus.Vectors))
	}
	if diverged != corpus.Counts.TwoLabelHeuristicDiverge {
		t.Errorf("%d vectors diverge from the two-label heuristic, corpus declares %d", diverged, corpus.Counts.TwoLabelHeuristicDiverge)
	}
	if multiLabel != corpus.Counts.MultiLabelPublicSuffix || multiLabel < 1 {
		t.Errorf("corpus must carry a multi-label public suffix and declare how many: found %d, declared %d. "+
			"An implementation that stops looking after two rule labels is wrong ONLY for those, and only silently",
			multiLabel, corpus.Counts.MultiLabelPublicSuffix)
	}
	t.Logf("ran %d PSL vectors, %d of which the two-label heuristic gets wrong", len(corpus.Vectors), diverged)
}

// TestAMissingSnapshotIsAnErrorNotAHeuristic — degrading here is §2's silent
// under-count, which is the worst failure shape available: nothing observable
// goes wrong until issuance fails with the budget already spent.
func TestAMissingSnapshotIsAnErrorNotAHeuristic(t *testing.T) {
	t.Setenv(PSLPathEnv, filepath.Join(t.TempDir(), "absent", "public_suffix_list.dat"))

	if _, err := LoadPublicSuffixList(""); !errors.Is(err, ErrPSLSnapshotMissing) {
		t.Fatalf("a missing snapshot returned %v, want ErrPSLSnapshotMissing", err)
	}
	if _, err := RegisteredDomain("foo.co.uk"); !errors.Is(err, ErrPSLSnapshot) {
		t.Fatalf("RegisteredDomain with no snapshot returned %v, want an ErrPSLSnapshot", err)
	}
}

// TestASnapshotThatIsNotThePinnedOneIsRefused — a different list gives different
// registered domains, so the ledger would partition its budget differently from
// the policy validator that admitted the request, and nothing would say so until
// a certificate was refused.
func TestASnapshotThatIsNotThePinnedOneIsRefused(t *testing.T) {
	impostor := filepath.Join(t.TempDir(), "public_suffix_list.dat")
	if err := os.WriteFile(impostor, []byte("// not the pinned list\ncom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PSLPathEnv, impostor)

	_, err := LoadPublicSuffixList("")
	if !errors.Is(err, ErrPSLSnapshotMismatch) {
		t.Fatalf("an impostor snapshot returned %v, want ErrPSLSnapshotMismatch", err)
	}
	if !strings.Contains(err.Error(), contracts.PublicSuffixListSHA256) {
		t.Errorf("the error must name the pinned digest so the fix is obvious: %v", err)
	}
}

// TestThePinnedSnapshotLoadsAndCarriesBothSections — the refusals above are only
// worth having if the real file passes, and both sections must be in it. The CA
// computes its registered_domain limit over the full list, so ICANN-only parsing
// pools every GitHub Pages site in the fleet into one budget.
func TestThePinnedSnapshotLoadsAndCarriesBothSections(t *testing.T) {
	list, err := LoadPublicSuffixList("")
	if err != nil {
		t.Fatalf("the pinned snapshot did not load: %v", err)
	}
	if _, ok := list.rules["com"]; !ok {
		t.Error("the ICANN section did not parse")
	}
	if _, ok := list.rules["github.io"]; !ok {
		t.Error("the PRIVATE section did not parse; ICANN-only pools every Pages site into one budget")
	}
	if _, ok := list.exceptions["www.ck"]; !ok {
		t.Error("exception rules did not parse")
	}
}
