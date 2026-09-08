package primitives

import (
	"crypto/sha256"
	"encoding/hex"
)

// DestinationHash is the ownership-claim key.
//
// contracts-and-codegen.md §7.2: sha256(lower(vaultResourceId) + "|" +
// lower(certificateName)), lowercase hex, no separators.
//
// The lowercase is ASCII-only and deliberately so — see asciiLower. Computing it
// over un-normalised inputs makes `Payments-Prod/api` and `payments-prod/api`
// hash differently, so the If-None-Match ownership guard never fires: that is
// F-092, the exact failure the ownership record exists to prevent.
func DestinationHash(vaultResourceID, certificateName string) string {
	sum := sha256.Sum256([]byte(asciiLower(vaultResourceID) + "|" + asciiLower(certificateName)))
	return hex.EncodeToString(sum[:])
}
