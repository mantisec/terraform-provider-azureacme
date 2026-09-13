package fakeservice

// The two guards the generated route table pays for, watched going RED.
//
// A check that has never been seen to fail is not a check, and both of these
// are silent by design in every other test in this package. They are exercised
// from INSIDE the package because the only way to watch a guard fail without
// failing the test that watches it is to substitute what it reports through.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheStatusGuardGoesRedOnAnUndeclaredStatus.
//
// The guard's whole value is that a fake cannot teach the client to handle a
// response the real service will never send. If it were quietly broken, every
// test in this package would still pass — which is exactly why it is asserted
// here rather than assumed from the green suite.
func TestTheStatusGuardGoesRedOnAnUndeclaredStatus(t *testing.T) {
	route, _, ok := MatchRoute(http.MethodGet, "/v1/namespaces/payments-prod/certificates/api")
	if !ok {
		t.Fatal("GET on a registration does not resolve to a contract operation")
	}

	var reported []string
	record := func(format string, args ...any) {
		reported = append(reported, fmt.Sprintf(format, args...))
	}

	declared := &conformantWriter{ResponseWriter: httptest.NewRecorder(), fail: record, route: route}
	declared.WriteHeader(http.StatusNotFound)
	if len(reported) != 0 {
		t.Errorf("404 is declared for getCertificate and the guard still complained: %v", reported)
	}

	undeclared := &conformantWriter{ResponseWriter: httptest.NewRecorder(), fail: record, route: route}
	undeclared.WriteHeader(http.StatusTeapot)
	if len(reported) != 1 {
		t.Fatalf("418 is not declared for getCertificate and the guard said nothing: %v", reported)
	}
	for _, want := range []string{"418", "getCertificate", "contracts/api/openapi.yaml"} {
		if !strings.Contains(reported[0], want) {
			t.Errorf("the guard's message does not name %q, so a reader cannot act on it: %s",
				want, reported[0])
		}
	}

	// One report per response, not one per Write. A guard that shouts on every
	// byte is a guard people turn off.
	undeclared.WriteHeader(http.StatusTeapot)
	if len(reported) != 1 {
		t.Errorf("the guard reported the same response twice: %v", reported)
	}
}

// TestADocumentedOperationTheFakeDoesNotModelFailsLoudly.
//
// The alternative — answering a plausible 404 at an address the real service
// serves — is how a test comes to prove nothing at all, so this path must fail
// rather than respond.
func TestADocumentedOperationTheFakeDoesNotModelFailsLoudly(t *testing.T) {
	srv := New(t)
	var reported []string
	srv.setFail(func(format string, args ...any) {
		reported = append(reported, fmt.Sprintf(format, args...))
	})

	// A documented operation with no handler in this package today.
	resp, err := http.Get(srv.URL() + "/v1/admin/retained")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("an unmodelled documented operation answered %d; 501 is the honest answer, and "+
			"404 would be indistinguishable from the contract not having the endpoint",
			resp.StatusCode)
	}
	if len(reported) != 1 {
		t.Fatalf("an unmodelled documented operation did not fail the test: %v", reported)
	}
	if !strings.Contains(reported[0], "listRetained") {
		t.Errorf("the message does not name the operation: %s", reported[0])
	}
}
