// Package primitives is the Go half of the shared cross-language primitives.
//
// SINGLE DEFINITION. contracts-and-codegen.md §7.4: no other package in this
// module may define a namespace regex, a normalisation function, a
// destinationHash, a PSL lookup or a timestamp format. This package is the one
// definition; everything else consumes it. A CI grep enforces that.
//
// The normative definitions live in the specifications, not here:
//   - identifier normalisation ....... authorisation-model.md §4.3, substeps N1-N13
//   - namespace / name grammar ....... authorisation-model.md §8.2
//   - destinationHash ................ contracts-and-codegen.md §7.2
//   - wire formats ................... contracts-and-codegen.md §7.2
//
// The vectors in contracts/primitives/vectors/ are the contract; this
// implementation and its Python twin are conveniences (§7.3).
package primitives

import "errors"

// ErrInvalidIdentifier is the sentinel every normalisation rejection wraps. It
// maps to the `invalid_identifier` condition of authorisation-model.md §10.2.
var ErrInvalidIdentifier = errors.New("invalid_identifier")

// RejectionError names the substep that rejected, so a failing vector points at
// a rule rather than at a stack frame.
type RejectionError struct {
	Step   string // "N1".."N11", "NS" for the namespace grammar
	Reason string
}

func (e *RejectionError) Error() string { return e.Step + ": " + e.Reason }
func (e *RejectionError) Unwrap() error { return ErrInvalidIdentifier }

func reject(step, reason string) error { return &RejectionError{Step: step, Reason: reason} }

// asciiLower lowercases ASCII bytes and nothing else.
//
// It is deliberately NOT strings.ToLower: that is Unicode-aware and Go's and
// Python's Unicode lowercasing disagree on characters such as U+0130, which is
// exactly the class of silent cross-language divergence this package exists to
// remove. After UTS-46 ToASCII every octet is ASCII, so a byte operation is both
// correct and locale-independent (authorisation-model.md §4.3 N7).
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
