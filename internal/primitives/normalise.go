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

// uts46Correction is one repair to the UTS-46 mapping stage: a code point whose
// mapping in golang.org/x/net/idna's generated table differs from the mapping in
// the table Python's `idna` package carries, and therefore from the answer the
// shared vector corpus pins.
//
// It is a slice and not a bare strings.Replacer so that the table can be
// ENUMERATED — normalise_corrections_test.go removes each entry in turn and
// requires the corpus to notice. A correction nothing witnesses is a correction
// nobody will ever discover has stopped being needed.
type uts46Correction struct {
	From string // the code point x/net/idna maps differently
	To   string // what UTS-46 maps it to; "" means the code point is ignored
	Why  string // one line, for the reader of a failing mutation
}

// uts46MappingCorrectionTable repairs characters where golang.org/x/net/idna's
// generated mapping table disagrees with the UTS-46 IdnaMappingTable, and
// therefore with Python's `idna` package.
//
// THE FIRST ENTRY IS THE A1/S11 DEFECT CLASS CAUGHT IN THE ACT. UTS-46 maps
// U+1E9E (LATIN CAPITAL LETTER SHARP S) to U+00DF; under non-transitional
// processing U+00DF is then preserved and punycoded, giving "xn--zca".
// x/net/idna instead maps U+1E9E straight to "ss" in BOTH transitional and
// non-transitional modes — the IDNA2003 answer — so Go produced
// "ss.example.com" where Python produced "xn--zca.example.com". Two
// implementations of "IDNA-2008 to A-label", one deny rule, one bypass.
//
// THE REST WERE FOUND BY THE CODE-POINT SWEEP (SCAFFOLD-IDNA-DIFFERENTIAL-SWEEP,
// contracts/tools/sweep_normalisation.py), which asks both normalisers about
// every assigned code point instead of about the cases an author thought of.
// Their common cause is a Unicode VERSION skew, not a library bug:
// x/net/idna v0.50.0 carries the Unicode 15.0.0 IdnaMappingTable and Python's
// idna 3.19 carries Unicode 17.0.0, and UTS-46 changed these code points in
// between. Forty-one of them Go still disallows where UTS-46 now maps them to a
// lowercase form; twenty-four Go disallows where UTS-46 now ignores them;
// forty-one are Unicode 16.0 additions Go has never heard of, several of which
// map straight to plain ASCII; and four both languages map identically but
// disagree about, because Go decides whether the Bidi rule applies BEFORE
// mapping and Python decides AFTER.
// Every one is two verdicts for one identifier, which is why they are repaired
// here rather than left for the deny rule to miss.
//
// WHEN x/net/idna CATCHES UP, an entry becomes a no-op and its mutation test
// starts failing — which is the signal to delete it, and the reason the mutation
// test exists in that form.
//
// The correction is applied between N5 and N6, because it IS part of the UTS-46
// mapping stage; it does not disturb the N5 -> N6 -> N7 order. The shared vector
// corpus is what proves it: contracts/primitives/vectors/normalisation-vectors.json
// is the arbiter, not either library.
var uts46MappingCorrectionTable = []uts46Correction{
	{From: "ẞ", To: "ß", Why: "U+1E9E LATIN CAPITAL LETTER SHARP S -> U+00DF, not \"ss\""},

	// --- x/net/idna disallows; UTS-46 17.0.0 maps to a lowercase form -------
	{From: "\u04c0", To: "\u04cf", Why: "U+04C0 CYRILLIC LETTER PALOCHKA -> U+04CF"},
	{From: "\u10a0", To: "\u2d00", Why: "U+10A0 GEORGIAN CAPITAL LETTER AN -> U+2D00"},
	{From: "\u10a1", To: "\u2d01", Why: "U+10A1 GEORGIAN CAPITAL LETTER BAN -> U+2D01"},
	{From: "\u10a2", To: "\u2d02", Why: "U+10A2 GEORGIAN CAPITAL LETTER GAN -> U+2D02"},
	{From: "\u10a3", To: "\u2d03", Why: "U+10A3 GEORGIAN CAPITAL LETTER DON -> U+2D03"},
	{From: "\u10a4", To: "\u2d04", Why: "U+10A4 GEORGIAN CAPITAL LETTER EN -> U+2D04"},
	{From: "\u10a5", To: "\u2d05", Why: "U+10A5 GEORGIAN CAPITAL LETTER VIN -> U+2D05"},
	{From: "\u10a6", To: "\u2d06", Why: "U+10A6 GEORGIAN CAPITAL LETTER ZEN -> U+2D06"},
	{From: "\u10a7", To: "\u2d07", Why: "U+10A7 GEORGIAN CAPITAL LETTER TAN -> U+2D07"},
	{From: "\u10a8", To: "\u2d08", Why: "U+10A8 GEORGIAN CAPITAL LETTER IN -> U+2D08"},
	{From: "\u10a9", To: "\u2d09", Why: "U+10A9 GEORGIAN CAPITAL LETTER KAN -> U+2D09"},
	{From: "\u10aa", To: "\u2d0a", Why: "U+10AA GEORGIAN CAPITAL LETTER LAS -> U+2D0A"},
	{From: "\u10ab", To: "\u2d0b", Why: "U+10AB GEORGIAN CAPITAL LETTER MAN -> U+2D0B"},
	{From: "\u10ac", To: "\u2d0c", Why: "U+10AC GEORGIAN CAPITAL LETTER NAR -> U+2D0C"},
	{From: "\u10ad", To: "\u2d0d", Why: "U+10AD GEORGIAN CAPITAL LETTER ON -> U+2D0D"},
	{From: "\u10ae", To: "\u2d0e", Why: "U+10AE GEORGIAN CAPITAL LETTER PAR -> U+2D0E"},
	{From: "\u10af", To: "\u2d0f", Why: "U+10AF GEORGIAN CAPITAL LETTER ZHAR -> U+2D0F"},
	{From: "\u10b0", To: "\u2d10", Why: "U+10B0 GEORGIAN CAPITAL LETTER RAE -> U+2D10"},
	{From: "\u10b1", To: "\u2d11", Why: "U+10B1 GEORGIAN CAPITAL LETTER SAN -> U+2D11"},
	{From: "\u10b2", To: "\u2d12", Why: "U+10B2 GEORGIAN CAPITAL LETTER TAR -> U+2D12"},
	{From: "\u10b3", To: "\u2d13", Why: "U+10B3 GEORGIAN CAPITAL LETTER UN -> U+2D13"},
	{From: "\u10b4", To: "\u2d14", Why: "U+10B4 GEORGIAN CAPITAL LETTER PHAR -> U+2D14"},
	{From: "\u10b5", To: "\u2d15", Why: "U+10B5 GEORGIAN CAPITAL LETTER KHAR -> U+2D15"},
	{From: "\u10b6", To: "\u2d16", Why: "U+10B6 GEORGIAN CAPITAL LETTER GHAN -> U+2D16"},
	{From: "\u10b7", To: "\u2d17", Why: "U+10B7 GEORGIAN CAPITAL LETTER QAR -> U+2D17"},
	{From: "\u10b8", To: "\u2d18", Why: "U+10B8 GEORGIAN CAPITAL LETTER SHIN -> U+2D18"},
	{From: "\u10b9", To: "\u2d19", Why: "U+10B9 GEORGIAN CAPITAL LETTER CHIN -> U+2D19"},
	{From: "\u10ba", To: "\u2d1a", Why: "U+10BA GEORGIAN CAPITAL LETTER CAN -> U+2D1A"},
	{From: "\u10bb", To: "\u2d1b", Why: "U+10BB GEORGIAN CAPITAL LETTER JIL -> U+2D1B"},
	{From: "\u10bc", To: "\u2d1c", Why: "U+10BC GEORGIAN CAPITAL LETTER CIL -> U+2D1C"},
	{From: "\u10bd", To: "\u2d1d", Why: "U+10BD GEORGIAN CAPITAL LETTER CHAR -> U+2D1D"},
	{From: "\u10be", To: "\u2d1e", Why: "U+10BE GEORGIAN CAPITAL LETTER XAN -> U+2D1E"},
	{From: "\u10bf", To: "\u2d1f", Why: "U+10BF GEORGIAN CAPITAL LETTER JHAN -> U+2D1F"},
	{From: "\u10c0", To: "\u2d20", Why: "U+10C0 GEORGIAN CAPITAL LETTER HAE -> U+2D20"},
	{From: "\u10c1", To: "\u2d21", Why: "U+10C1 GEORGIAN CAPITAL LETTER HE -> U+2D21"},
	{From: "\u10c2", To: "\u2d22", Why: "U+10C2 GEORGIAN CAPITAL LETTER HIE -> U+2D22"},
	{From: "\u10c3", To: "\u2d23", Why: "U+10C3 GEORGIAN CAPITAL LETTER WE -> U+2D23"},
	{From: "\u10c4", To: "\u2d24", Why: "U+10C4 GEORGIAN CAPITAL LETTER HAR -> U+2D24"},
	{From: "\u10c5", To: "\u2d25", Why: "U+10C5 GEORGIAN CAPITAL LETTER HOE -> U+2D25"},
	{From: "\u2132", To: "\u214e", Why: "U+2132 TURNED CAPITAL F -> U+214E"},
	{From: "\u2183", To: "\u2184", Why: "U+2183 ROMAN NUMERAL REVERSED ONE HUNDRED -> U+2184"},

	// --- both map these the same way, but Go decides whether the Bidi rule
	// applies BEFORE mapping and Python decides AFTER. Mapping them here puts
	// Go's decision on the mapped form, which is Python's order: "aℵb" becomes
	// "aאb", the label is then a right-to-left one inside a left-to-right label,
	// and both refuse it. Without this Go issues for a name Python refuses. -----
	{From: "\u2135", To: "\u05d0", Why: "U+2135 ALEF SYMBOL -> U+05D0, which is Bidi class R"},
	{From: "\u2136", To: "\u05d1", Why: "U+2136 BET SYMBOL -> U+05D1, which is Bidi class R"},
	{From: "\u2137", To: "\u05d2", Why: "U+2137 GIMEL SYMBOL -> U+05D2, which is Bidi class R"},
	{From: "\u2138", To: "\u05d3", Why: "U+2138 DALET SYMBOL -> U+05D3, which is Bidi class R"},

	// --- code points Unicode 16.0 ADDED, so x/net/idna's 15.0.0 table has never
	// heard of them and disallows them while UTS-46 17.0.0 maps them to plain
	// ASCII. These are the sharpest of the lot: U+1CCD6 maps to "a", so without
	// the correction one identifier has an ASCII spelling Python accepts and a
	// spelling Go refuses. Found by the --scope all sweep, which CPython's own
	// unicodedata calls unassigned and the assigned-only sweep therefore misses. --
	{From: "\ua7cb", To: "\u0264", Why: "U+A7CB (Unicode 16.0) -> U+0264"},
	{From: "\ua7d2", To: "\ua7d3", Why: "U+A7D2 (Unicode 16.0) -> U+A7D3"},
	{From: "\ua7d4", To: "\ua7d5", Why: "U+A7D4 (Unicode 16.0) -> U+A7D5"},
	{From: "\ua7dc", To: "\u019b", Why: "U+A7DC (Unicode 16.0) -> U+019B"},
	{From: "\ua7f1", To: "\u0073", Why: "U+A7F1 (Unicode 16.0) -> U+0073"},
	{From: "\U0001ccd6", To: "\u0061", Why: "U+1CCD6 (Unicode 16.0) -> U+0061"},
	{From: "\U0001ccd7", To: "\u0062", Why: "U+1CCD7 (Unicode 16.0) -> U+0062"},
	{From: "\U0001ccd8", To: "\u0063", Why: "U+1CCD8 (Unicode 16.0) -> U+0063"},
	{From: "\U0001ccd9", To: "\u0064", Why: "U+1CCD9 (Unicode 16.0) -> U+0064"},
	{From: "\U0001ccda", To: "\u0065", Why: "U+1CCDA (Unicode 16.0) -> U+0065"},
	{From: "\U0001ccdb", To: "\u0066", Why: "U+1CCDB (Unicode 16.0) -> U+0066"},
	{From: "\U0001ccdc", To: "\u0067", Why: "U+1CCDC (Unicode 16.0) -> U+0067"},
	{From: "\U0001ccdd", To: "\u0068", Why: "U+1CCDD (Unicode 16.0) -> U+0068"},
	{From: "\U0001ccde", To: "\u0069", Why: "U+1CCDE (Unicode 16.0) -> U+0069"},
	{From: "\U0001ccdf", To: "\u006a", Why: "U+1CCDF (Unicode 16.0) -> U+006A"},
	{From: "\U0001cce0", To: "\u006b", Why: "U+1CCE0 (Unicode 16.0) -> U+006B"},
	{From: "\U0001cce1", To: "\u006c", Why: "U+1CCE1 (Unicode 16.0) -> U+006C"},
	{From: "\U0001cce2", To: "\u006d", Why: "U+1CCE2 (Unicode 16.0) -> U+006D"},
	{From: "\U0001cce3", To: "\u006e", Why: "U+1CCE3 (Unicode 16.0) -> U+006E"},
	{From: "\U0001cce4", To: "\u006f", Why: "U+1CCE4 (Unicode 16.0) -> U+006F"},
	{From: "\U0001cce5", To: "\u0070", Why: "U+1CCE5 (Unicode 16.0) -> U+0070"},
	{From: "\U0001cce6", To: "\u0071", Why: "U+1CCE6 (Unicode 16.0) -> U+0071"},
	{From: "\U0001cce7", To: "\u0072", Why: "U+1CCE7 (Unicode 16.0) -> U+0072"},
	{From: "\U0001cce8", To: "\u0073", Why: "U+1CCE8 (Unicode 16.0) -> U+0073"},
	{From: "\U0001cce9", To: "\u0074", Why: "U+1CCE9 (Unicode 16.0) -> U+0074"},
	{From: "\U0001ccea", To: "\u0075", Why: "U+1CCEA (Unicode 16.0) -> U+0075"},
	{From: "\U0001cceb", To: "\u0076", Why: "U+1CCEB (Unicode 16.0) -> U+0076"},
	{From: "\U0001ccec", To: "\u0077", Why: "U+1CCEC (Unicode 16.0) -> U+0077"},
	{From: "\U0001cced", To: "\u0078", Why: "U+1CCED (Unicode 16.0) -> U+0078"},
	{From: "\U0001ccee", To: "\u0079", Why: "U+1CCEE (Unicode 16.0) -> U+0079"},
	{From: "\U0001ccef", To: "\u007a", Why: "U+1CCEF (Unicode 16.0) -> U+007A"},
	{From: "\U0001ccf0", To: "\u0030", Why: "U+1CCF0 (Unicode 16.0) -> U+0030"},
	{From: "\U0001ccf1", To: "\u0031", Why: "U+1CCF1 (Unicode 16.0) -> U+0031"},
	{From: "\U0001ccf2", To: "\u0032", Why: "U+1CCF2 (Unicode 16.0) -> U+0032"},
	{From: "\U0001ccf3", To: "\u0033", Why: "U+1CCF3 (Unicode 16.0) -> U+0033"},
	{From: "\U0001ccf4", To: "\u0034", Why: "U+1CCF4 (Unicode 16.0) -> U+0034"},
	{From: "\U0001ccf5", To: "\u0035", Why: "U+1CCF5 (Unicode 16.0) -> U+0035"},
	{From: "\U0001ccf6", To: "\u0036", Why: "U+1CCF6 (Unicode 16.0) -> U+0036"},
	{From: "\U0001ccf7", To: "\u0037", Why: "U+1CCF7 (Unicode 16.0) -> U+0037"},
	{From: "\U0001ccf8", To: "\u0038", Why: "U+1CCF8 (Unicode 16.0) -> U+0038"},
	{From: "\U0001ccf9", To: "\u0039", Why: "U+1CCF9 (Unicode 16.0) -> U+0039"},

	// --- x/net/idna disallows; UTS-46 17.0.0 ignores ------------------------
	{From: "\u115f", To: "", Why: "U+115F HANGUL CHOSEONG FILLER is ignored"},
	{From: "\u1160", To: "", Why: "U+1160 HANGUL JUNGSEONG FILLER is ignored"},
	{From: "\u17b4", To: "", Why: "U+17B4 KHMER VOWEL INHERENT AQ is ignored"},
	{From: "\u17b5", To: "", Why: "U+17B5 KHMER VOWEL INHERENT AA is ignored"},
	{From: "\u180e", To: "", Why: "U+180E MONGOLIAN VOWEL SEPARATOR is ignored"},
	{From: "\u2061", To: "", Why: "U+2061 FUNCTION APPLICATION is ignored"},
	{From: "\u2062", To: "", Why: "U+2062 INVISIBLE TIMES is ignored"},
	{From: "\u2063", To: "", Why: "U+2063 INVISIBLE SEPARATOR is ignored"},
	{From: "\u206a", To: "", Why: "U+206A INHIBIT SYMMETRIC SWAPPING is ignored"},
	{From: "\u206b", To: "", Why: "U+206B ACTIVATE SYMMETRIC SWAPPING is ignored"},
	{From: "\u206c", To: "", Why: "U+206C INHIBIT ARABIC FORM SHAPING is ignored"},
	{From: "\u206d", To: "", Why: "U+206D ACTIVATE ARABIC FORM SHAPING is ignored"},
	{From: "\u206e", To: "", Why: "U+206E NATIONAL DIGIT SHAPES is ignored"},
	{From: "\u206f", To: "", Why: "U+206F NOMINAL DIGIT SHAPES is ignored"},
	{From: "\u3164", To: "", Why: "U+3164 HANGUL FILLER is ignored"},
	{From: "\uffa0", To: "", Why: "U+FFA0 HALFWIDTH HANGUL FILLER is ignored"},
	{From: "\U0001d173", To: "", Why: "U+1D173 MUSICAL SYMBOL BEGIN BEAM is ignored"},
	{From: "\U0001d174", To: "", Why: "U+1D174 MUSICAL SYMBOL END BEAM is ignored"},
	{From: "\U0001d175", To: "", Why: "U+1D175 MUSICAL SYMBOL BEGIN TIE is ignored"},
	{From: "\U0001d176", To: "", Why: "U+1D176 MUSICAL SYMBOL END TIE is ignored"},
	{From: "\U0001d177", To: "", Why: "U+1D177 MUSICAL SYMBOL BEGIN SLUR is ignored"},
	{From: "\U0001d178", To: "", Why: "U+1D178 MUSICAL SYMBOL END SLUR is ignored"},
	{From: "\U0001d179", To: "", Why: "U+1D179 MUSICAL SYMBOL BEGIN PHRASE is ignored"},
	{From: "\U0001d17a", To: "", Why: "U+1D17A MUSICAL SYMBOL END PHRASE is ignored"},
}

// uts46MappingCorrections is the table above, compiled once.
var uts46MappingCorrections = newUTS46Replacer(uts46MappingCorrectionTable)

func newUTS46Replacer(table []uts46Correction) *strings.Replacer {
	pairs := make([]string, 0, 2*len(table))
	for _, correction := range table {
		pairs = append(pairs, correction.From, correction.To)
	}
	return strings.NewReplacer(pairs...)
}

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
