package fakeservice_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// The fake's destinationHash must be the production one, computed by the shared
// primitive, and it must agree with the corpus both languages run.
//
// contracts-and-codegen.md §7.2/§7.4: `destinationHash` is
// sha256(lower(vaultResourceId) + "|" + lower(certificateName)) and has exactly
// one home per language. A fake that hashes differently from production cannot
// catch an ownership-guard bug: the guard is an If-None-Match on this value, so
// a fake computing its own version makes every ownership test assert against a
// server that cannot violate the property being tested. That is the same class
// of defect as the echoing fake normalise.go was written to end.
//
// The corpus is contracts/primitives/vectors/destination-hash-vectors.json —
// THE SAME FILE the Python suite runs.

const destinationVectorsEnv = "ACME_PRIMITIVES_VECTORS"

func destinationHashVectors(t *testing.T) []byte {
	t.Helper()
	dir := os.Getenv(destinationVectorsEnv)
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			candidate := filepath.Join(wd, "contracts", "primitives", "vectors")
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				dir = candidate
				break
			}
			parent := filepath.Dir(wd)
			if parent == wd {
				break
			}
			wd = parent
		}
	}
	if dir == "" {
		t.Skipf("contracts/primitives/vectors/ not found; set %s to point at it", destinationVectorsEnv)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "destination-hash-vectors.json"))
	if err != nil {
		t.Skipf("destination-hash-vectors.json not found in %s: %v", dir, err)
	}
	return raw
}

// TestTheFakeHashesDestinationsTheWayProductionDoes drives the fake with every
// entry of the shared corpus and asserts three values are one value: what the
// fake stored, what the shared Go primitive computes, and what the corpus pins.
func TestTheFakeHashesDestinationsTheWayProductionDoes(t *testing.T) {
	var doc struct {
		Vectors []struct {
			ID                  string `json:"id"`
			MustHashIdentically bool   `json:"must_hash_identically"`
			Entries             []struct {
				VaultResourceID string `json:"vault_resource_id"`
				CertificateName string `json:"certificate_name"`
				DestinationHash string `json:"destination_hash"`
			} `json:"entries"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(destinationHashVectors(t), &doc); err != nil {
		t.Fatalf("destination-hash-vectors.json does not decode: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("destination-hash-vectors.json decoded to zero groups")
	}

	srv := fakeservice.New(t)
	checked := 0
	for groupIndex, group := range doc.Vectors {
		observed := map[string]struct{}{}
		for entryIndex, entry := range group.Entries {
			// A distinct namespace per entry: the corpus deliberately contains
			// entries that MUST collide, and the point here is what the fake
			// computes, not whether its ownership guard fires on the second claim.
			namespace := fmt.Sprintf("dh%d-%d", groupIndex, entryIndex)
			reg := srv.SeedRegistration(fakeservice.RegistrationSeed{
				Namespace:       namespace,
				Name:            "cert",
				KeyVaultID:      entry.VaultResourceID,
				CertificateName: entry.CertificateName,
			})
			if reg.Spec.Destination == nil || reg.Spec.Destination.DestinationHash == nil {
				t.Fatalf("%s entry %d: the fake stored no destinationHash", group.ID, entryIndex)
			}
			got := *reg.Spec.Destination.DestinationHash

			want := primitives.DestinationHash(entry.VaultResourceID, entry.CertificateName)
			if got != want {
				t.Errorf("%s entry %d: the fake stored %s, the shared primitive computes %s — "+
					"a fake that hashes differently from production cannot catch an ownership-guard bug",
					group.ID, entryIndex, got, want)
			}
			if entry.DestinationHash != "" && got != entry.DestinationHash {
				t.Errorf("%s entry %d: the fake stored %s, the shared corpus pins %s",
					group.ID, entryIndex, got, entry.DestinationHash)
			}
			observed[got] = struct{}{}
			checked++
		}

		// The corpus' own invariant, re-asserted through the fake: if the fake
		// collapsed or split a group the guard would fire on the wrong requests.
		if group.MustHashIdentically && len(observed) != 1 {
			t.Errorf("%s: the fake produced %d distinct hashes where the corpus requires 1 — "+
				"the If-None-Match ownership guard would never fire (F-092)", group.ID, len(observed))
		}
		if !group.MustHashIdentically && len(observed) != len(group.Entries) {
			t.Errorf("%s: the fake collided %d entries onto %d hashes; two distinct destinations "+
				"sharing one ownership hash blocks one team's claim with another's",
				group.ID, len(group.Entries), len(observed))
		}
	}
	if checked == 0 {
		t.Fatal("the corpus produced no comparable entry")
	}
	t.Logf("drove %d destinationHash vectors through the fake", checked)
}
