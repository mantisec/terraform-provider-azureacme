package primitives

import "testing"

// TestNormalisationOrderIsNotCommutative is the A1/S11 guard. U+0130 (LATIN
// CAPITAL LETTER I WITH DOT ABOVE) is the worked example: UTS-46 maps it to
// "i" + U+0307, so the canonical form is a punycode label. An implementation
// that lowercases BEFORE ToASCII produces plain "i" and silently widens
// authority. authorisation-model.md §4.3 N5-N7.
func TestNormalisationOrderIsNotCommutative(t *testing.T) {
	got, err := Normalise("İstanbul.example.com")
	if err != nil {
		t.Fatalf("U+0130 identifier rejected: %v", err)
	}
	if got == "istanbul.example.com" {
		t.Fatal("U+0130 normalised to plain 'istanbul' — lowercase ran before ToASCII (the A1/S11 bypass)")
	}
	// Verified byte-identical against the Python implementation.
	if got != "xn--istanbul-o0e.example.com" {
		t.Fatalf("U+0130 canonical form = %q, want xn--istanbul-o0e.example.com (the Python twin agrees)", got)
	}
	// The Turkish dotless I is a plain ASCII-safe mapping and must not become a
	// punycode label.
	if got, err := Normalise("ıstanbul.example.com"); err != nil {
		t.Fatalf("dotless i rejected: %v", err)
	} else if got == "istanbul.example.com" {
		t.Fatal("dotless i folded onto ASCII 'i'")
	}
}

// TestNonTransitionalDeviations pins the UTS-46 mode. Transitional processing
// maps eszett to "ss"; non-transitional punycodes it. authorisation-model.md §4.4.
func TestNonTransitionalDeviations(t *testing.T) {
	got, err := Normalise("straße.example.com")
	if err != nil {
		t.Fatalf("eszett rejected: %v", err)
	}
	if got == "strasse.example.com" {
		t.Fatal("eszett mapped to 'ss' — the profile is configured TRANSITIONAL, which is the A1/S11 defect")
	}
	if got != "xn--strae-oqa.example.com" {
		t.Fatalf("eszett canonical form = %q, want xn--strae-oqa.example.com", got)
	}
}

func TestNormaliseRejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"fullwidth stop":     "a．example.com",
		"ideographic stop":   "a。example.com",
		"halfwidth stop":     "a｡example.com",
		"two trailing dots":  "example.com..",
		"leading dot":        ".example.com",
		"empty label":        "a..example.com",
		"percent":            "a%2eexample.com",
		"NUL":                "a\x00.example.com",
		"whitespace":         "a b.example.com",
		"control":            "a\x01.example.com",
		"bare wildcard":      "*",
		"double wildcard":    "**.example.com",
		"mid-label wildcard": "a*.example.com",
		"second-label star":  "*.*.example.com",
		"single label":       "example",
		"numeric TLD":        "example.123",
		"ipv4 literal":       "192.168.0.1",
		"ipv6 literal":       "::1",
		"leading hyphen":     "-a.example.com",
		"trailing hyphen":    "a-.example.com",
		"bad punycode":       "xn--.example.com",
	}
	for name, in := range cases {
		if got, err := Normalise(in); err == nil {
			t.Errorf("%s: Normalise(%q) = %q, want rejection", name, in, got)
		}
	}
}

func TestNormaliseAccepts(t *testing.T) {
	cases := map[string]string{
		"EXAMPLE.COM":       "example.com",
		"example.com.":      "example.com",
		"*.Example.COM":     "*.example.com",
		"xn--strae-oqa.com": "xn--strae-oqa.com",
		"a.example.com":     "a.example.com",
	}
	for in, want := range cases {
		got, err := Normalise(in)
		if err != nil {
			t.Errorf("Normalise(%q) rejected: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNFCEquivalence — NFD and NFC inputs must produce one canonical form (N5).
func TestNFCEquivalence(t *testing.T) {
	nfc, err1 := Normalise("café.example.com")  // é
	nfd, err2 := Normalise("café.example.com") // e + combining acute
	if err1 != nil || err2 != nil {
		t.Fatalf("café rejected: %v / %v", err1, err2)
	}
	if nfc != nfd {
		t.Fatalf("NFC %q and NFD %q produced different canonical forms", nfc, nfd)
	}
}

// TestNamespaceGrammar — the `?` in the optional group is the whole point (E-01):
// a one-character namespace is accepted, and both languages must agree.
func TestNamespaceGrammar(t *testing.T) {
	if NamespacePattern != `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` {
		t.Fatalf("namespace pattern drifted: %q", NamespacePattern)
	}
	accept := []string{"a", "1", "ab", "payments-prod", str('a', 63)}
	for _, s := range accept {
		if err := ValidateNamespace(s); err != nil {
			t.Errorf("ValidateNamespace(%q) rejected: %v", s, err)
		}
	}
	rejectCases := []string{"", "A", "-a", "a-", "a_b", "a.b", "a/b", "a\\b", "a%b",
		"..", ".", "_a", "admin", "system", "platform", "policy", "internal", str('a', 64)}
	for _, s := range rejectCases {
		if err := ValidateNamespace(s); err == nil {
			t.Errorf("ValidateNamespace(%q) accepted, want rejection", s)
		}
	}
}

// TestDestinationHashIsCaseInsensitive is F-092: if these two differ, the
// If-None-Match ownership guard never fires and the second claim on the same
// destination succeeds.
func TestDestinationHashIsCaseInsensitive(t *testing.T) {
	a := DestinationHash("/subscriptions/S/resourceGroups/Payments-Prod/providers/Microsoft.KeyVault/vaults/KV", "API")
	b := DestinationHash("/subscriptions/s/resourcegroups/payments-prod/providers/microsoft.keyvault/vaults/kv", "api")
	if a != b {
		t.Fatalf("destinationHash differs by case: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("destinationHash length = %d, want 64 lowercase hex characters", len(a))
	}
	if ValidateHex(a, 64) != nil {
		t.Fatalf("destinationHash %q is not lowercase hex with no separators", a)
	}
	if DestinationHash("a", "b") == DestinationHash("ab", "") {
		t.Fatal("the '|' separator is not doing its job")
	}
}

func TestWireFormats(t *testing.T) {
	if _, err := ParseTimestamp("2026-09-09T01:02:03.456Z"); err == nil {
		t.Error("fractional seconds accepted on the wire")
	}
	if _, err := ParseTimestamp("2026-09-09T01:02:03+10:00"); err == nil {
		t.Error("non-Z offset accepted on the wire")
	}
	if _, err := ParseTimestamp("2026-09-09T01:02:03Z"); err != nil {
		t.Errorf("valid timestamp rejected: %v", err)
	}
	if ValidateHex("ABCDEF", 6) == nil {
		t.Error("uppercase thumbprint accepted")
	}
	if ValidateHex("ab:cd", 5) == nil {
		t.Error("separator in thumbprint accepted")
	}
}

func str(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
