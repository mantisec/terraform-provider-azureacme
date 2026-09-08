// Package customtypes_test holds the equivalence-class suite for the three
// semantic-equality types of terraform-provider-contract.md §4.
//
// It lives in one external test package so that a single table can state, for
// each type, the equivalence classes §4 and PROV-SEMANTIC-EQUALITY-TYPES demand:
// identical, case-varied, trailing-dot, punycode/unicode pair, and genuinely
// different.
package customtypes_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/dnsname"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/rfc3339"
)

func semanticEquals(t *testing.T, a, b basetypes.StringValuableWithSemanticEquals) bool {
	t.Helper()
	got, diags := a.StringSemanticEquals(context.Background(), b.(basetypes.StringValuable))
	if diags.HasError() {
		t.Fatalf("semantic equality diagnostics: %+v", diags)
	}
	return got
}

func TestDNSNameSemanticEquality(t *testing.T) {
	cases := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"identical", "api.example.com", "api.example.com", true},
		{"case varied", "API.Example.COM", "api.example.com", true},
		{"trailing dot", "api.example.com.", "api.example.com", true},
		{"trailing dot and case", "API.EXAMPLE.COM.", "api.example.com", true},
		{"unicode and a-label", "münchen.example.com", "xn--mnchen-3ya.example.com", true},
		{"wildcard case varied", "*.API.example.com", "*.api.example.com", true},
		{"genuinely different", "api.example.com", "www.example.com", false},
		{"wildcard versus base", "*.example.com", "example.com", false},
		{"different tld", "api.example.com", "api.example.net", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := semanticEquals(t, dnsname.NewValue(tc.a), dnsname.NewValue(tc.b)); got != tc.equal {
				t.Fatalf("semanticEquals(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.equal)
			}
		})
	}
}

// TestDNSNameRejectsConfusables is the §4 rule that the fullwidth and
// ideographic full stops are REJECTED, not silently normalised. Silently mapping
// them makes the client's idea of a name differ from the policy engine's.
func TestDNSNameRejectsConfusables(t *testing.T) {
	for _, bad := range []string{
		"api．example.com", // FULLWIDTH FULL STOP
		"api。example.com", // IDEOGRAPHIC FULL STOP
		"api｡example.com", // HALFWIDTH IDEOGRAPHIC FULL STOP
	} {
		var resp xattr.ValidateAttributeResponse
		dnsname.NewValue(bad).ValidateAttribute(context.Background(),
			xattr.ValidateAttributeRequest{Path: path.Root("dns_names")}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Fatalf("%q was accepted; §4 requires rejection, not silent normalisation", bad)
		}
	}
	var ok xattr.ValidateAttributeResponse
	dnsname.NewValue("api.example.com").ValidateAttribute(context.Background(),
		xattr.ValidateAttributeRequest{Path: path.Root("dns_names")}, &ok)
	if ok.Diagnostics.HasError() {
		t.Fatalf("a valid name was rejected: %+v", ok.Diagnostics)
	}
}

// TestDNSNameMatchesSharedVectors loads the cross-language corpus rather than
// restating it. PROV-SEMANTIC-EQUALITY-TYPES: "a test loads the shared vectors
// rather than restating them". The provider must agree with the service about
// what a name is, or a permitted name and a normalised name diverge.
func TestDNSNameMatchesSharedVectors(t *testing.T) {
	vectorPath := vectorsFile(t, "normalisation-vectors.json")
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("shared vector corpus not readable (%v); internal/primitives owns the primary vector test", err)
	}
	var doc struct {
		Vectors []struct {
			Input     string `json:"input"`
			Expect    string `json:"expect"`
			Canonical string `json:"canonical"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("shared vector corpus does not parse: %v", err)
	}
	checked := 0
	for _, v := range doc.Vectors {
		if v.Expect != "ok" || v.Canonical == "" {
			continue
		}
		// The canonical form must be semantically equal to its own input: that
		// is precisely the round trip the server performs when it echoes the
		// stored name back at the next Read.
		if !semanticEquals(t, dnsname.NewValue(v.Input), dnsname.NewValue(v.Canonical)) {
			t.Errorf("input %q and its canonical form %q are not semantically equal — a plan would diff forever", v.Input, v.Canonical)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no accepted vectors found in the corpus")
	}
	t.Logf("checked %d accepted vectors from the shared corpus", checked)
}

func TestARMIDSemanticEquality(t *testing.T) {
	const base = "/subscriptions/8B1E6A2C-4F3D-4A5B-9C7E-1D2F3A4B5C6D/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-payments"
	cases := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"identical", base, base, true},
		{"segment name casing", base,
			"/subscriptions/8B1E6A2C-4F3D-4A5B-9C7E-1D2F3A4B5C6D/resourcegroups/rg-payments/providers/microsoft.keyvault/vaults/kv-payments", true},
		{"subscription guid casing", base,
			"/subscriptions/8b1e6a2c-4f3d-4a5b-9c7e-1d2f3a4b5c6d/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-payments", true},
		{"vault name casing is a real difference", base,
			"/subscriptions/8B1E6A2C-4F3D-4A5B-9C7E-1D2F3A4B5C6D/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/KV-Payments", false},
		{"different vault", base,
			"/subscriptions/8B1E6A2C-4F3D-4A5B-9C7E-1D2F3A4B5C6D/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-other", false},
		{"different resource group", base,
			"/subscriptions/8B1E6A2C-4F3D-4A5B-9C7E-1D2F3A4B5C6D/resourceGroups/rg-other/providers/Microsoft.KeyVault/vaults/kv-payments", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := semanticEquals(t, armid.NewValue(tc.a), armid.NewValue(tc.b)); got != tc.equal {
				t.Fatalf("semanticEquals = %v, want %v\n a = %s\n b = %s", got, tc.equal, tc.a, tc.b)
			}
		})
	}
}

func TestARMIDValidation(t *testing.T) {
	for _, bad := range []string{
		"kv-payments",
		"/subscriptions/abc/resourceGroups/rg",
		"subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
		"/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults",
	} {
		var resp xattr.ValidateAttributeResponse
		armid.NewValue(bad).ValidateAttribute(context.Background(),
			xattr.ValidateAttributeRequest{Path: path.Root("key_vault_id")}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("%q was accepted as an ARM resource id", bad)
		}
	}
}

func TestRFC3339SemanticEquality(t *testing.T) {
	cases := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"identical", "2026-11-28T04:11:01Z", "2026-11-28T04:11:01Z", true},
		{"fractional zero", "2026-11-28T04:11:01Z", "2026-11-28T04:11:01.000Z", true},
		{"offset form", "2026-11-28T04:11:01Z", "2026-11-28T05:11:01+01:00", true},
		{"one second apart", "2026-11-28T04:11:01Z", "2026-11-28T04:11:02Z", false},
		{"different day", "2026-11-28T04:11:01Z", "2026-11-29T04:11:01Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := semanticEquals(t, rfc3339.NewValue(tc.a), rfc3339.NewValue(tc.b)); got != tc.equal {
				t.Fatalf("semanticEquals(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.equal)
			}
		})
	}
}

// TestNullAndUnknownAreNotCollapsed guards the case every semantic-equality
// implementation gets wrong once: a null and a known value must not be equal
// just because neither normalises.
func TestNullAndUnknownAreNotCollapsed(t *testing.T) {
	if semanticEquals(t, dnsname.NewNull(), dnsname.NewValue("api.example.com")) {
		t.Error("dnsname: null == known")
	}
	if semanticEquals(t, armid.NewUnknown(), armid.NewValue("/subscriptions/a/resourceGroups/b/providers/Microsoft.KeyVault/vaults/c")) {
		t.Error("armid: unknown == known")
	}
	if !semanticEquals(t, rfc3339.NewNull(), rfc3339.NewNull()) {
		t.Error("rfc3339: null != null")
	}
}

// vectorsFile locates the SHARED corpus, which lives outside this Go module at
// contracts/primitives/vectors/. It is read at test time and never embedded:
// an embedded copy is a second definition, and two definitions of a
// normalisation rule is the silent cross-language divergence this whole
// mechanism exists to prevent.
func vectorsFile(t *testing.T, name string) string {
	t.Helper()
	if v := os.Getenv("ACME_PRIMITIVES_VECTORS"); v != "" {
		return filepath.Join(v, name)
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", "primitives", "vectors")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return filepath.Join(candidate, name)
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("contracts/primitives/vectors/ not found from the test working directory")
	return ""
}
