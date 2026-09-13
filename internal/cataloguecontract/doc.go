// Package cataloguecontract is the Go half of the catalogue-document contract
// conformance.
//
// It ships nothing. The package exists so that the Go toolchain has a home for
// the assertions that `contracts/catalogue/*.schema.json` and the golden
// documents in `contracts/catalogue/examples/` still say what the catalogue
// specification says they say — the same assertions the Python suite makes in
// `functionapp-azureacme/tests/catalogue/test_golden_examples.py`, over the same
// files and the same manifest.
//
// WHY BOTH LANGUAGES, for documents only the service ever writes. The provider
// does not read a catalogue document, and that is beside the point: the defect
// this guards against is not a document that is wrong, it is a document that two
// conforming implementations read differently
// (`contracts-and-codegen.md` §6.1). The catalogue is where a schemaVersion
// migration happens, so it is the contract where a silent divergence costs the
// most — and the second reader is what makes a divergence visible at all.
//
// `destination_hash_test.go` carries the one assertion that is about a VALUE
// rather than a shape: `destinationHash` is derived
// (`catalogue-and-concurrency.md` R-2.5.2), so a golden document records a hash
// this module must be able to recompute from the vault id and certificate name
// beside it. A schema validator cannot see that — 64 hex characters is 64 hex
// characters — which is how the corpus carried a hand-picked placeholder that
// neither implementation agreed with.
//
// The reader itself is `internal/contractschema`, shared with
// `internal/policycontract` because both contracts are cross-referencing sets of
// `*.schema.json` files. Everything here lives in _test.go files, so nothing is
// linked into the provider binary, and the contract files are read at test time,
// never embedded and never shipped.
package cataloguecontract
