// Package policycontract is the Go half of the policy-document contract
// conformance.
//
// It ships nothing. The package exists so that the Go toolchain has a home for
// the assertions that `contracts/policy/*.schema.json` and the golden documents
// in `contracts/policy/examples/` still say what the authorisation model says
// they say — the same assertions the Python suite makes in
// `functionapp-azureacme/tests/authz/test_policy_document_schemas.py`, over the
// same files.
//
// Why both languages and not one. The policy plane is authored on one side of
// the wire and evaluated on the other, and the failure this guards against is
// not a document that is wrong — it is a document that two conforming
// implementations read differently. A single-language check cannot see that
// class of defect at all.
//
// Everything lives in _test.go files, so nothing here is linked into the
// provider binary.
package policycontract
