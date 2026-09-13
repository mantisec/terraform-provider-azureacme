package primitives

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// The pinned Public Suffix List — the Go half of the shared primitive.
//
// contracts-and-codegen.md §7.2: ONE pinned snapshot, three consumers — the
// policy validator, the rate-limit ledger and the wildcard-base validator. A
// policy that permits a wildcard and a ledger that counts it must not disagree
// about what the registered domain is (E-07).
//
// "Registered domain" means eTLD+1 computed from the list, never "the last two
// labels". `foo.co.uk` and `foo.github.io` are counted separately by the CA, and
// a two-label heuristic UNDER-COUNTS silently: nothing observable goes wrong
// until issuance fails with the budget already spent. So a missing or
// hash-mismatched snapshot is an ERROR here, never a fallback — see
// ErrPSLSnapshotMissing and ErrPSLSnapshotMismatch.
//
// Both the ICANN and the PRIVATE sections are used, deliberately: the CA
// computes its registered_domain limit over the full list, so `foo.github.io` is
// its own registered domain and is not pooled with every other `github.io` user.
//
// The answers are pinned by contracts/primitives/vectors/psl-vectors.json, which
// the Python half runs too.

// PSLPathEnv overrides where the snapshot is read from. A packaged provider sets
// it; a repository checkout does not need to.
const PSLPathEnv = "ACME_PSL_SNAPSHOT"

// ErrPSLSnapshot is the sentinel both snapshot failures wrap, so a caller that
// only wants to say "the list is unusable" does not have to name both.
var ErrPSLSnapshot = errors.New("psl_snapshot")

// ErrPSLSnapshotMissing is returned when the pinned snapshot is not on disk. It
// is deliberately not a silent fall back to a two-label heuristic.
var ErrPSLSnapshotMissing = fmt.Errorf("%w: not found", ErrPSLSnapshot)

// ErrPSLSnapshotMismatch is returned when the file on disk is not the one the
// contract pins. A different list gives different registered domains, so the
// ledger would partition its budget differently from the policy validator that
// admitted the request — and the divergence would be invisible until a
// certificate was refused.
var ErrPSLSnapshotMismatch = fmt.Errorf("%w: sha256 mismatch", ErrPSLSnapshot)

// PublicSuffixList is a parsed snapshot. Build it with LoadPublicSuffixList.
type PublicSuffixList struct {
	// Keys are the rule's labels joined by ".", lower-cased, "*" included
	// verbatim as a wildcard label.
	rules      map[string]struct{}
	exceptions map[string]struct{}
	// Source is the path the rules were read from.
	Source string
}

type pslResult struct {
	list *PublicSuffixList
	err  error
}

var pslCache sync.Map // path -> pslResult

// LoadPublicSuffixList reads, verifies and caches the pinned snapshot at path.
// An empty path resolves the snapshot from PSLPathEnv, then by walking up from
// the working directory to the repository's single pinned copy.
func LoadPublicSuffixList(path string) (*PublicSuffixList, error) {
	if path == "" {
		resolved, err := snapshotPath()
		if err != nil {
			return nil, err
		}
		path = resolved
	}
	if cached, ok := pslCache.Load(path); ok {
		result := cached.(pslResult)
		return result.list, result.err
	}
	list, err := parsePSL(path)
	pslCache.Store(path, pslResult{list: list, err: err})
	return list, err
}

func snapshotPath() (string, error) {
	if override := os.Getenv(PSLPathEnv); override != "" {
		if info, err := os.Stat(override); err != nil || info.IsDir() {
			return "", fmt.Errorf("%w: %s=%s is not a file", ErrPSLSnapshotMissing, PSLPathEnv, override)
		}
		return override, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPSLSnapshotMissing, err)
	}
	// Exactly one snapshot exists in the repository (SNAPSHOT.json pin rule), so
	// there is one relative location to look for and no second candidate to
	// prefer. Shipping a copy inside this module is CI-PACKAGE-RUNTIME-DATA-FILES.
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", "primitives", "psl", "public_suffix_list.dat")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf(
		"%w: no contracts/primitives/psl/public_suffix_list.dat above the working directory; set %s. "+
			"It is never fetched at run time (SNAPSHOT.json pin rule)",
		ErrPSLSnapshotMissing, PSLPathEnv)
}

func parsePSL(path string) (*PublicSuffixList, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrPSLSnapshotMissing, path, err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if digest != contracts.PublicSuffixListSHA256 {
		return nil, fmt.Errorf(
			"%w: %s hashes to %s, but contracts/primitives/primitives.yaml pins %s. A snapshot the "+
				"contract does not pin gives registered domains the Python half does not agree with",
			ErrPSLSnapshotMismatch, path, digest, contracts.PublicSuffixListSHA256)
	}

	list := &PublicSuffixList{
		rules:      make(map[string]struct{}, 16384),
		exceptions: make(map[string]struct{}, 64),
		Source:     path,
	}
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// The file carries U-labels for some entries. Identifiers reaching this
		// package are already A-labels (Normalise), so the rule is folded the same
		// way rather than normalising the identifier a second time — two
		// normalisers is the A1/S11 deny-rule bypass.
		rule := strings.Fields(line)[0]
		if after, found := strings.CutPrefix(rule, "!"); found {
			list.exceptions[pslFold(after)] = struct{}{}
			continue
		}
		list.rules[pslFold(rule)] = struct{}{}
	}
	return list, nil
}

// pslFold lower-cases a rule and converts any U-label in it to its A-label. This
// is a rule-side conversion of a pinned data file, not identifier
// normalisation, so it is not a second normaliser.
func pslFold(rule string) string {
	if isASCII(rule) {
		return asciiLower(rule)
	}
	labels := strings.Split(rule, ".")
	for i, label := range labels {
		if isASCII(label) {
			labels[i] = asciiLower(label)
			continue
		}
		encoded, err := uts46.ToASCII(label)
		if err != nil {
			// A malformed pinned snapshot. Keep the label rather than dropping the
			// rule: a dropped rule silently widens what counts as a registered
			// domain, which is the failure this whole module exists to prevent.
			labels[i] = strings.ToLower(label)
			continue
		}
		labels[i] = encoded
	}
	return strings.Join(labels, ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// PublicSuffix returns the public suffix of name, or "" when an exception rule
// leaves none. The algorithm is the one at https://publicsuffix.org/list/ —
// an exception rule prevails, then the longest matching rule, then the implicit
// "*" rule that makes an unknown TLD its own public suffix.
func (l *PublicSuffixList) PublicSuffix(name string) string {
	labels := strings.Split(name, ".")

	for start := range labels {
		candidate := strings.Join(labels[start:], ".")
		if _, ok := l.exceptions[candidate]; ok {
			if start+1 >= len(labels) {
				return ""
			}
			return strings.Join(labels[start+1:], ".")
		}
	}

	best := ""
	bestLabels := 0
	for start := range labels {
		candidate := strings.Join(labels[start:], ".")
		candidateLabels := len(labels) - start
		if _, ok := l.rules[candidate]; ok {
			if candidateLabels > bestLabels {
				best, bestLabels = candidate, candidateLabels
			}
			continue
		}
		wildcard := strings.Join(append([]string{"*"}, labels[start+1:]...), ".")
		if _, ok := l.rules[wildcard]; ok && candidateLabels > bestLabels {
			best, bestLabels = candidate, candidateLabels
		}
	}
	if bestLabels == 0 {
		// The implicit "*" rule: an unknown TLD is itself a public suffix.
		return labels[len(labels)-1]
	}
	return best
}

// RegisteredDomain returns the eTLD+1 of name, or "" when name has no label
// below its public suffix — a bare `co.uk` is nobody's registered domain and
// must not be charged as one.
func (l *PublicSuffixList) RegisteredDomain(name string) string {
	suffix := l.PublicSuffix(name)
	if suffix == "" {
		return name
	}
	if name == suffix {
		return ""
	}
	suffixLabels := strings.Count(suffix, ".") + 1
	labels := strings.Split(name, ".")
	if len(labels) <= suffixLabels {
		return ""
	}
	return strings.Join(labels[len(labels)-suffixLabels-1:], ".")
}

// RegisteredDomain is the package-level convenience over the pinned snapshot:
// the eTLD+1 of an already-normalised ACME identifier.
//
// A leading "*." is stripped first. `*.example.com` and `example.com` are two
// distinct identifiers for the identifier_set hash but share ONE registered
// domain, so they share one budget.
//
// The empty string means "no registered domain" — the identifier is itself a
// public suffix. An error means the snapshot is unusable, which is never
// downgraded to a guess.
func RegisteredDomain(identifier string) (string, error) {
	list, err := LoadPublicSuffixList("")
	if err != nil {
		return "", err
	}
	return list.RegisteredDomain(pslIdentifier(identifier)), nil
}

func pslIdentifier(identifier string) string {
	name := strings.TrimPrefix(identifier, "*.")
	return strings.TrimRight(name, ".")
}
