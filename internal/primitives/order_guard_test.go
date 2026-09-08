package primitives

import (
	"os"
	"strings"
	"testing"
)

// TestNormaliserUsesNoUnicodeAwareLowercase is a SOURCE-level guard on the
// N5 -> N6 -> N7 order, and it exists because the output-level guard is not
// equally load-bearing in both languages.
//
// Mutating this implementation to lowercase before ToASCII produces five vector
// failures here, because Go's strings.ToLower applies SIMPLE case mapping and
// turns U+0130 into a bare "i". The same mutation in Python produces NO vector
// failure, because Python's str.lower() applies FULL case mapping and happens to
// agree with UTS-46 on exactly the characters the corpus covers. So in Python
// the corpus cannot see the inversion — only a source-level rule can.
//
// The rule: the only lowercase in this package is asciiLower, which runs after
// ToASCII on octets that are already ASCII.
func TestNormaliserUsesNoUnicodeAwareLowercase(t *testing.T) {
	for _, file := range []string{"normalise.go", "namespace.go", "destination.go", "wireformat.go"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		src := string(b)
		for _, forbidden := range []string{"strings.ToLower", "unicode.ToLower", "cases.Lower"} {
			if strings.Contains(src, forbidden) {
				t.Errorf("%s uses %s. Unicode-aware lowercasing disagrees between Go and Python "+
					"(U+0130 is the worked example) and must never touch an identifier. "+
					"Use asciiLower, and only after UTS-46 ToASCII (authorisation-model.md §4.3 N7).", file, forbidden)
			}
		}
	}
}

// TestNormalisationSubstepsAppearInOrder pins the substep order in the source,
// so an edit that reorders N5/N6/N7 is visible in review even before a vector
// fails.
func TestNormalisationSubstepsAppearInOrder(t *testing.T) {
	b, err := os.ReadFile("normalise.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	markers := []string{"--- N1 ", "--- N2 ", "--- N3 ", "--- N4 ", "--- N5 ", "--- N6 ", "--- N7 ", "--- N8 ", "--- N10 "}
	previous := -1
	for _, m := range markers {
		at := strings.Index(src, m)
		if at < 0 {
			t.Fatalf("normalise.go has no %q marker", m)
		}
		if at < previous {
			t.Fatalf("substep %q appears out of order — the order is NOT commutative (A1/S11)", m)
		}
		previous = at
	}
}
