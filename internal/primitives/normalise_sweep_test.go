package primitives

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

// The Go half of the code-point differential sweep
// (SCAFFOLD-IDNA-DIFFERENTIAL-SWEEP).
//
// WHY A HARNESS AND NOT A TEST. The sweep's whole purpose is to compare THIS
// normaliser against the Python one in functionapp-azureacme, and a Go test
// cannot see the Python one. So the comparison lives in the driver,
// contracts/tools/sweep_normalisation.py, and this file is the part of it that
// has to be inside the provider's Go module to reach an internal package. The
// driver hands over a plan, this harness expands it, normalises every probe and
// writes the outcomes back; the driver does the same in Python and compares.
//
// WHY IT IS SKIPPED BY DEFAULT. The sweep is a scheduled job, not a pull-request
// gate (contracts-idna-sweep.yml) — it takes tens of seconds and needs a Python
// interpreter that `go test` has no business requiring. Every divergence it finds
// is turned into a correction-table entry or a corpus vector, and THOSE run on
// every pull request in TestNormalisationVectors. This harness is discovery; the
// vectors are the regression.
//
// It is gated on two environment variables rather than a build tag so that the
// file is compiled — and therefore kept honest by `go vet` and by every
// refactor — on every ordinary run.

const (
	sweepPlanEnv    = "ACME_NORMALISE_SWEEP_PLAN"
	sweepOutcomeEnv = "ACME_NORMALISE_SWEEP_OUTCOMES"
)

// sweepPlan is the wire format the driver writes. Probe construction is stated
// once, here and in the driver, in a form both languages expand identically:
// replace the sole "{}" in each template with the single character, once per
// template per code point, templates fastest.
//
// The two sides expanding the plan differently would silently compare unrelated
// answers, so the outcome file's header carries a digest of the probe stream and
// the driver refuses to compare unless its own digest matches.
type sweepPlan struct {
	Version         int      `json:"version"`
	Templates       []string `json:"templates"`
	CodePointRanges [][2]int `json:"code_point_ranges"`
}

// TestNormaliseSweepHarness normalises every probe in the plan and writes one
// outcome line per probe, in plan order.
//
// The outcome vocabulary is deliberately narrow: "ok\t<canonical>" or
// "reject\t<substep>". Canonical forms are ASCII [a-z0-9.*-] after N7 and
// substeps are "N1".."N11", so neither can contain a tab or a newline and the
// format needs no escaping.
func TestNormaliseSweepHarness(t *testing.T) {
	planPath := os.Getenv(sweepPlanEnv)
	outcomePath := os.Getenv(sweepOutcomeEnv)
	if planPath == "" || outcomePath == "" {
		t.Skipf("differential sweep harness: set %s and %s to run it. "+
			"It is driven by contracts/tools/sweep_normalisation.py on a schedule, "+
			"not on every pull request; the divergences it finds are carried by the "+
			"vector corpus, which does run on every pull request.",
			sweepPlanEnv, sweepOutcomeEnv)
	}

	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("reading the sweep plan: %v", err)
	}
	var plan sweepPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decoding the sweep plan: %v", err)
	}
	if plan.Version != 1 {
		t.Fatalf("sweep plan version %d is not supported by this harness (expected 1)", plan.Version)
	}
	if len(plan.Templates) == 0 || len(plan.CodePointRanges) == 0 {
		t.Fatal("sweep plan has no templates or no code-point ranges — it would prove nothing")
	}
	for _, template := range plan.Templates {
		if countPlaceholders(template) != 1 {
			t.Fatalf("sweep template %q must contain exactly one \"{}\" placeholder", template)
		}
	}

	handle, err := os.Create(outcomePath)
	if err != nil {
		t.Fatalf("creating the outcome file: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing the outcome file: %v", cerr)
		}
	}()

	// Outcomes stream out as they are computed and the count-and-digest line is
	// the FOOTER, not the header: a sweep over the whole code-point range is
	// millions of probes, and buffering them all to learn the count first would
	// cost hundreds of megabytes for nothing.
	writer := bufio.NewWriterSize(handle, 1<<20)
	digest := sha256.New()
	count := 0
	for _, span := range plan.CodePointRanges {
		lo, hi := span[0], span[1]
		if lo > hi {
			t.Fatalf("sweep plan range [%d, %d] is inverted", lo, hi)
		}
		for cp := lo; cp <= hi; cp++ {
			if cp < 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
				// Surrogates have no UTF-8 encoding, so no probe carrying one
				// survives the trip between the two languages. The driver
				// excludes them from the plan; this is the belt and braces.
				t.Fatalf("sweep plan range [%d, %d] includes U+%04X, which has no UTF-8 encoding", lo, hi, cp)
			}
			for _, template := range plan.Templates {
				probe := expandTemplate(template, rune(cp))
				digest.Write([]byte(probe))
				digest.Write([]byte{0})
				if _, err := writer.WriteString(sweepOutcome(probe)); err != nil {
					t.Fatalf("writing an outcome: %v", err)
				}
				if err := writer.WriteByte('\n'); err != nil {
					t.Fatalf("writing an outcome: %v", err)
				}
				count++
			}
		}
	}
	if _, err := fmt.Fprintf(writer, "sweep\t%d\t%s\n", count, hex.EncodeToString(digest.Sum(nil))); err != nil {
		t.Fatalf("writing the outcome footer: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flushing the outcome file: %v", err)
	}
	t.Logf("sweep harness: %d probes over %d code-point range(s), outcomes in %s",
		count, len(plan.CodePointRanges), outcomePath)
}

// sweepOutcome renders one Normalise call as the driver's comparison key.
func sweepOutcome(probe string) string {
	canonical, err := Normalise(probe)
	if err == nil {
		return "ok\t" + canonical
	}
	var rejection *RejectionError
	if errors.As(err, &rejection) {
		return "reject\t" + rejection.Step
	}
	return "reject\t?"
}

func expandTemplate(template string, r rune) string {
	for i := 0; i+1 < len(template); i++ {
		if template[i] == '{' && template[i+1] == '}' {
			return template[:i] + string(r) + template[i+2:]
		}
	}
	return template
}

func countPlaceholders(template string) int {
	n := 0
	for i := 0; i+1 < len(template); i++ {
		if template[i] == '{' && template[i+1] == '}' {
			n++
		}
	}
	return n
}
