package primitives

import (
	"net"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// uts46 is the pinned UTS-46 profile of authorisation-model.md §4.3 N6.
//
// Every one of the six flags is stated explicitly and non-negotiably. An
// unpinned mode is the "two implementations of IDNA-2008 to A-label" that
// produced the A1/S11 deny-rule bypass; see §4.4 for why non-transitional is
// not to be re-litigated.
var uts46 = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),    // NON-transitional. Pinned.
	idna.StrictDomainName(true), // UseSTD3ASCIIRules = true
	idna.ValidateLabels(true),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.BidiRule(), // CheckBidi = true
	idna.VerifyDNSLength(true),
)

// uts46MappingCorrections repairs characters where golang.org/x/net/idna's
// generated mapping table disagrees with the UTS-46 IdnaMappingTable, and
// therefore with Python's `idna` package.
//
// THIS IS THE A1/S11 DEFECT CLASS CAUGHT IN THE ACT. UTS-46 maps U+1E9E (LATIN
// CAPITAL LETTER SHARP S) to U+00DF; under non-transitional processing U+00DF is
// then preserved and punycoded, giving "xn--zca". x/net/idna instead maps U+1E9E
// straight to "ss" in BOTH transitional and non-transitional modes — the
// IDNA2003 answer — so Go produced "ss.example.com" where Python produced
// "xn--zca.example.com". Two implementations of "IDNA-2008 to A-label", one
// deny rule, one bypass.
//
// The correction is applied between N5 and N6, because it IS part of the UTS-46
// mapping stage; it does not disturb the N5 -> N6 -> N7 order. The shared vector
// corpus is what proves it: contracts/primitives/vectors/normalisation-vectors.json
// is the arbiter, not either library.
var uts46MappingCorrections = strings.NewReplacer(
	"\u1e9e", "\u00df", // LATIN CAPITAL LETTER SHARP S -> LATIN SMALL LETTER SHARP S
)

// Normalise applies authorisation-model.md §4.3 substeps N1-N13 in order and
// returns the canonical form (N13) — the value that is stored, hashed, indexed,
// compared and logged. Nothing is ever compared before it has passed this.
//
// The order is NOT commutative. NFC (N5) then UTS-46 ToASCII (N6) then
// ASCII-lowercase (N7). Lowercasing before ToASCII is the A1/S11 bypass.
func Normalise(input string) (string, error) {
	// --- N1 -----------------------------------------------------------------
	if input == "" {
		return "", reject("N1", "empty identifier")
	}
	if len(input) > 255 {
		return "", reject("N1", "longer than 255 octets before processing")
	}
	for _, r := range input {
		switch {
		case r == 0:
			return "", reject("N1", "NUL")
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return "", reject("N1", "C0/C1 control character")
		case unicode.IsSpace(r):
			return "", reject("N1", "Unicode whitespace")
		case r == '%':
			return "", reject("N1", "percent sign or percent-encoded byte")
		}
	}

	// --- N2 -----------------------------------------------------------------
	// Runs before any split on '.', so no implementation's splitting behaviour
	// can matter.
	for _, r := range input {
		if r == '。' || r == '．' || r == '｡' {
			return "", reject("N2", "ideographic/fullwidth/halfwidth full stop")
		}
	}

	// --- N3 -----------------------------------------------------------------
	s := input
	if strings.HasSuffix(s, ".") {
		if strings.HasSuffix(s, "..") {
			return "", reject("N3", "two or more trailing dots")
		}
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", reject("N3", "identifier is a lone dot")
	}
	if strings.HasPrefix(s, ".") {
		return "", reject("N3", "leading dot")
	}
	if strings.Contains(s, "..") {
		return "", reject("N3", "empty label")
	}

	// --- N4 -----------------------------------------------------------------
	wildcard := false
	if strings.HasPrefix(s, "*.") {
		wildcard = true
		s = s[2:]
	}
	if strings.Contains(s, "*") {
		return "", reject("N4", "'*' outside a leading '*.' label")
	}
	if s == "" {
		return "", reject("N4", "bare wildcard")
	}

	// --- N11 (literals) -----------------------------------------------------
	// Checked here as well as after ToASCII: an IPv6 literal contains ':' which
	// UseSTD3ASCIIRules rejects with a less useful reason.
	if ip := net.ParseIP(s); ip != nil {
		return "", reject("N11", "IP literal")
	}

	// --- N5 -----------------------------------------------------------------
	s = norm.NFC.String(s)

	// --- N9, on the INPUT labels ---------------------------------------------
	// A second x/net/idna divergence. Given "xn--9-", Go's ToASCII decodes the
	// A-label to "9" and hands back a perfectly valid "9.example.com", silently
	// REWRITING an identifier that must be refused: "xn--9-" ends in a hyphen
	// (N8) and does not round-trip (N9). Python's idna rejects it. Checking the
	// input labels closes the gap, because after ToASCII there is no xn-- label
	// left to check.
	for _, l := range strings.Split(s, ".") {
		if !strings.HasPrefix(asciiLower(l), "xn--") {
			continue
		}
		if err := checkPunycodeLabel(asciiLower(l)); err != nil {
			return "", err
		}
	}

	// --- N6 -----------------------------------------------------------------
	s = uts46MappingCorrections.Replace(s)
	ascii, err := uts46.ToASCII(s)
	if err != nil {
		return "", reject("N6", "UTS-46 ToASCII: "+err.Error())
	}

	// --- N7 -----------------------------------------------------------------
	// After ToASCII every octet is ASCII, so this is a byte operation.
	ascii = asciiLower(ascii)

	// --- N8 -----------------------------------------------------------------
	labels := strings.Split(ascii, ".")
	for _, l := range labels {
		if l == "" {
			return "", reject("N8", "empty label")
		}
		if len(l) > 63 {
			return "", reject("N8", "label longer than 63 octets")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", reject("N8", "label begins or ends with '-'")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return "", reject("N8", "character outside [a-z0-9-]")
			}
		}
	}

	// --- N9, on the OUTPUT labels --------------------------------------------
	for _, l := range labels {
		if !strings.HasPrefix(l, "xn--") {
			continue
		}
		if err := checkPunycodeLabel(l); err != nil {
			return "", err
		}
	}

	// --- N10 ----------------------------------------------------------------
	if len(ascii) > 253 {
		return "", reject("N10", "total length greater than 253 octets")
	}

	// --- N11 ----------------------------------------------------------------
	if len(labels) < 2 {
		return "", reject("N11", "fewer than two labels")
	}
	last := labels[len(labels)-1]
	allNumeric := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allNumeric = false
			break
		}
	}
	if allNumeric {
		return "", reject("N11", "all-numeric rightmost label")
	}

	// --- N12 / N13 ----------------------------------------------------------
	if wildcard {
		return "*." + ascii, nil
	}
	return ascii, nil
}

// checkPunycodeLabel enforces N8's hyphen rule and N9's round-trip rule on one
// lowercase A-label. Rejecting is always correct here: an identifier that does
// not round-trip has two spellings, and two spellings of one name is how a deny
// rule is bypassed.
func checkPunycodeLabel(label string) error {
	if strings.HasSuffix(label, "-") {
		return reject("N8", "xn-- label ends with '-'")
	}
	payload := strings.TrimPrefix(label, "xn--")
	if payload == "" {
		return reject("N9", "xn-- label with an empty payload")
	}
	u, err := idna.Punycode.ToUnicode(label)
	if err != nil {
		return reject("N9", "xn-- label does not decode as punycode")
	}
	back, err := idna.Punycode.ToASCII(u)
	if err != nil || asciiLower(back) != label {
		return reject("N9", "xn-- label does not round-trip")
	}
	return nil
}
