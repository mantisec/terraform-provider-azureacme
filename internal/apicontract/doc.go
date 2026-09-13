// Package apicontract is the Go half of the API golden-example conformance.
//
// It ships nothing. The package exists so that the Go toolchain has a home for
// the assertions that the golden documents in `contracts/api/examples/` still
// validate against the schemas in `contracts/api/openapi.yaml` — the same
// assertions the Python suite makes in
// `functionapp-azureacme/tests/api/test_error_details_and_examples.py`, over the
// same files.
//
// Why both languages and not one. The wire contract is written by one side and
// read by the other, and the failure this guards against is not a document that
// is wrong — it is a document that two conforming implementations read
// differently. A large minority of the example set is deliberately failure
// cases, because the failure shapes are exactly what the two implementations are
// most likely to disagree about.
//
// This is the API sibling of `internal/policycontract/`, which does the same job
// for `contracts/policy/`. The two readers are separate on purpose: the policy
// plane is a set of JSON Schema documents that `$ref` each other across files,
// while the API schemas are one YAML document whose `$ref`s are all
// document-local, and the reader that resolves one is not the reader that
// resolves the other.
//
// Everything else lives in _test.go files, so nothing here is linked into the
// provider binary.
package apicontract
