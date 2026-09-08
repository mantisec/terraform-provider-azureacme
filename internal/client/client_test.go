package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Endpoint:  srv.URL,
		Audience:  "api://mantisec-acme",
		Tokens:    StaticTokenSource{Value: "test-bearer-token", MethodName: "workload_identity"},
		UserAgent: "terraform-provider-azureacme/1.2.3 (+terraform/1.12.2) Go/1.24",
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

// TestRedirectIsNotFollowed is the Easy Auth trap. Its default for an
// unauthenticated request is a 302 to an interactive sign-in page, and Go's
// http.Client follows redirects by DEFAULT — turning an authentication failure
// into an HTML 200. The test asserts both halves: the redirect is an error, and
// the bearer token never reaches the redirect target.
func TestRedirectIsNotFollowed(t *testing.T) {
	var signInHits int
	var tokenSeenAtSignIn string
	signIn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signInHits++
		tokenSeenAtSignIn = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>sign in</html>"))
	}))
	t.Cleanup(signIn.Close)

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", signIn.URL+"/.auth/login/aad")
		w.WriteHeader(http.StatusFound)
	})

	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"})
	tErr, ok := AsTransportError(err)
	if !ok {
		t.Fatalf("expected a transport error, got %T: %v", err, err)
	}
	if tErr.Reason != ReasonRedirect {
		t.Fatalf("reason = %q, want %q", tErr.Reason, ReasonRedirect)
	}
	if signInHits != 0 {
		t.Fatalf("the redirect was followed %d times; CheckRedirect must return http.ErrUseLastResponse", signInHits)
	}
	if tokenSeenAtSignIn != "" {
		t.Fatalf("a bearer token reached the redirect target: %q", tokenSeenAtSignIn)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the diagnostic must say the service should return 401 rather than redirect; got %q", err.Error())
	}
}

// TestHTMLContentTypeIsATransportError: an HTML 200 is an authentication portal,
// never a decoded response and never an absence.
func TestHTMLContentTypeIsATransportError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Sign in</body></html>"))
	})
	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"})
	tErr, ok := AsTransportError(err)
	if !ok {
		t.Fatalf("expected a transport error, got %T: %v", err, err)
	}
	if tErr.Reason != ReasonContentType {
		t.Fatalf("reason = %q, want %q", tErr.Reason, ReasonContentType)
	}
	if !strings.Contains(err.Error(), "text/html") {
		t.Errorf("the diagnostic must name the content type received; got %q", err.Error())
	}
}

// TestUnknownErrorCodeRendersServerText. A code added by a newer service is not
// an error condition: next_action, title, detail and request_id must survive
// verbatim, or forward compatibility costs actionability.
func TestUnknownErrorCodeRendersServerText(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{
		  "code": "destination_quantum_entangled",
		  "status": 409,
		  "title": "The destination is entangled",
		  "detail": "A future failure mode this build has never heard of.",
		  "next_action": "Ask the platform team to disentangle vault kv-payments.",
		  "request_id": "01JABCDEFGHJKMNPQRSTVWXYZ0",
		  "retryable": false,
		  "actor": "platform_admin"
		}`))
	})
	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"})
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected an API error, got %T: %v", err, err)
	}
	if apiErr.Known {
		t.Fatal("a fabricated future code must not be found in the compiled taxonomy")
	}
	if got := apiErr.NextAction(); got != "Ask the platform team to disentangle vault kv-payments." {
		t.Errorf("next_action = %q, want the server's text verbatim", got)
	}
	if got := apiErr.RequestID(); got != "01JABCDEFGHJKMNPQRSTVWXYZ0" {
		t.Errorf("request_id = %q, want the server's value verbatim", got)
	}
	if got := apiErr.Title(); got != "The destination is entangled" {
		t.Errorf("title = %q", got)
	}
	if got := apiErr.Actor(); got != "platform_admin" {
		t.Errorf("actor = %q, want the server's classification", got)
	}
	if retry, _ := RetryDecision(err); retry {
		t.Error("an unknown code with retryable=false must not be retried")
	}
}

// TestRetryClassifier is the table PROV-API-CLIENT asks for: 409-with-Retry-After,
// 409-without, every fallback status, and a body-supplied `retryable` overriding
// the status.
func TestRetryClassifier(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		retryAfter  string
		wantRetry   bool
	}{
		{"409 with Retry-After is retried", 409, "application/problem+json",
			`{"code":"destination_access_denied","status":409,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "5", true},
		{"409 without Retry-After is not retried", 409, "application/problem+json",
			`{"code":"registration_exists","status":409,"retryable":false,"request_id":"r","title":"t","next_action":"n"}`, "", false},
		{"409 claiming retryable but with no Retry-After is still not retried", 409, "application/problem+json",
			`{"code":"operation_in_flight","status":409,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "", false},
		{"408 is retried", 408, "application/problem+json",
			`{"code":"service_unavailable","status":408,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "", true},
		{"429 is retried", 429, "application/problem+json",
			`{"code":"rate_limited","status":429,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "2", true},
		{"500 is retried", 500, "application/problem+json",
			`{"code":"internal_error","status":500,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "", true},
		{"503 is retried", 503, "application/problem+json",
			`{"code":"service_unavailable","status":503,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`, "1", true},
		{"the body overrides a retryable-looking status", 503, "application/problem+json",
			`{"code":"catalogue_schema_too_new","status":503,"retryable":false,"request_id":"r","title":"t","next_action":"n"}`, "", false},
		{"403 is never retried", 403, "application/problem+json",
			`{"code":"authorisation_denied","status":403,"retryable":false,"request_id":"r","title":"t","next_action":"n"}`, "", false},
		{"a malformed 503 falls back to the status", 503, "application/problem+json", `not json`, "", true},
		{"a malformed 400 falls back to the status", 400, "application/problem+json", `not json`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"})
			if err == nil {
				t.Fatal("expected an error")
			}
			if retry, _ := RetryDecision(err); retry != tc.wantRetry {
				t.Fatalf("RetryDecision = %v, want %v (err: %v)", retry, tc.wantRetry, err)
			}
		})
	}
}

// TestRetryLoopHonoursRetryAfterAndStops proves DoRetrying actually retries and
// actually stops.
func TestRetryLoopHonoursRetryAfterAndStops(t *testing.T) {
	var calls int
	var slept []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"service_unavailable","status":503,"retryable":true,"request_id":"r","title":"t","next_action":"n"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Endpoint: srv.URL, MaxRetries: 5,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DoRetrying(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"}); err != nil {
		t.Fatalf("DoRetrying: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	for _, d := range slept {
		if d != 7*time.Second {
			t.Fatalf("slept %v; the client must never poll faster than Retry-After", d)
		}
	}
}

// TestEveryRequestCarriesADistinctRequestIDAndUserAgent.
func TestEveryRequestCarriesADistinctRequestIDAndUserAgent(t *testing.T) {
	seen := map[string]bool{}
	var userAgents []string
	var accepts []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen[r.Header.Get("X-Request-Id")] = true
		userAgents = append(userAgents, r.Header.Get("User-Agent"))
		accepts = append(accepts, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	for i := 0; i < 5; i++ {
		if _, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/capabilities"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("saw %d distinct X-Request-Id values across 5 requests, want 5", len(seen))
	}
	for id := range seen {
		if len(id) != 26 {
			t.Fatalf("X-Request-Id %q is not a 26-character ULID", id)
		}
	}
	for _, ua := range userAgents {
		if !strings.HasPrefix(ua, "terraform-provider-azureacme/") || !strings.Contains(ua, "+terraform/") || !strings.Contains(ua, "Go/") {
			t.Fatalf("User-Agent %q does not match terraform-provider-azureacme/<ver> (+terraform/<ver>) Go/<ver>", ua)
		}
	}
	for _, a := range accepts {
		if !strings.Contains(a, "application/json") {
			t.Fatalf("Accept = %q, want application/json", a)
		}
	}
}

// TestPutRefusesToOmitAPrecondition. A PUT with neither If-None-Match nor
// If-Match is 428 at the service; the client must fail in its own suite instead.
func TestPutRefusesToOmitAPrecondition(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the client issued a PUT with no precondition; the request must never leave the process")
		w.WriteHeader(http.StatusOK)
	})
	_, err := c.PutRegistration(context.Background(), "ns", "n", contracts.CertificateSpecFields{}, PutOptions{})
	if err == nil {
		t.Fatal("expected an error when neither precondition is set")
	}
	_, err = c.PutRegistration(context.Background(), "ns", "n", contracts.CertificateSpecFields{},
		PutOptions{IfNoneMatchAny: true, IfMatchRevision: ptrInt64(3)})
	if err == nil {
		t.Fatal("expected an error when both preconditions are set")
	}
}

// TestPutSendsExactlyOnePreconditionAndAnIdempotencyKey.
func TestPutSendsExactlyOnePreconditionAndAnIdempotencyKey(t *testing.T) {
	var ifNoneMatch, ifMatch, idempotency string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		ifNoneMatch = r.Header.Get("If-None-Match")
		ifMatch = r.Header.Get("If-Match")
		idempotency = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"namespace":"ns","name":"n"}`))
	})
	if _, err := c.PutRegistration(context.Background(), "ns", "n", contracts.CertificateSpecFields{},
		PutOptions{IfNoneMatchAny: true}); err != nil {
		t.Fatal(err)
	}
	if ifNoneMatch != "*" || ifMatch != "" {
		t.Fatalf("create PUT sent If-None-Match=%q If-Match=%q", ifNoneMatch, ifMatch)
	}
	if len(idempotency) != 26 {
		t.Fatalf("Idempotency-Key %q is not a ULID", idempotency)
	}
	if _, err := c.PutRegistration(context.Background(), "ns", "n", contracts.CertificateSpecFields{},
		PutOptions{IfMatchRevision: ptrInt64(4)}); err != nil {
		t.Fatal(err)
	}
	if ifMatch != `W/"4"` || ifNoneMatch != "" {
		t.Fatalf("update PUT sent If-Match=%q If-None-Match=%q", ifMatch, ifNoneMatch)
	}
}

// TestErrorsIsWorksAgainstTheTaxonomySentinels.
func TestErrorsIsWorksAgainstTheTaxonomySentinels(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"registration_not_found","status":404,"retryable":false,"request_id":"r","title":"t","next_action":"n"}`))
	})
	_, _, err := c.GetRegistration(context.Background(), "ns", "n", false)
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected an API error, got %T", err)
	}
	if apiErr.Code() != contracts.CodeRegistrationNotFound {
		t.Fatalf("code = %q", apiErr.Code())
	}
	if !apiErr.Is(contracts.ErrRegistrationNotFound) {
		t.Fatal("errors.Is against the published sentinel failed")
	}
}

func ptrInt64(v int64) *int64 { return &v }
