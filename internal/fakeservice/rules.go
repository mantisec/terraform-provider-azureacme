package fakeservice

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// Match selects requests a Rule applies to. A zero Match matches everything.
type Match struct {
	Method     string
	Path       string // exact, including the /v1 prefix
	PathSuffix string
	QueryHas   string // a raw query substring, e.g. "intent=manage"
}

func (m Match) matches(r *http.Request) bool {
	if m.Method != "" && !strings.EqualFold(m.Method, r.Method) {
		return false
	}
	if m.Path != "" && r.URL.Path != m.Path {
		return false
	}
	if m.PathSuffix != "" && !strings.HasSuffix(r.URL.Path, m.PathSuffix) {
		return false
	}
	if m.QueryHas != "" && !strings.Contains(r.URL.RawQuery, m.QueryHas) {
		return false
	}
	return true
}

// Rule overrides the fake's ordinary behaviour for matching requests.
//
// Rules are the scenario DSL: they are how a test asks for the responses no real
// service will produce on demand — a redirect to a sign-in page, an HTML error
// page, an untyped 404, a 404 from a DIFFERENT service instance.
type Rule struct {
	Match Match
	// Times bounds how many requests the rule serves. 0 means unlimited.
	Times   int
	Handler http.HandlerFunc

	used int
}

// AddRule installs a rule. Rules are consulted in insertion order, before the
// fake's own routing.
func (s *Server) AddRule(r Rule) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	rule := r
	s.rules = append(s.rules, &rule)
	return s
}

// ClearRules removes every installed rule.
func (s *Server) ClearRules() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = nil
}

// takeRule returns the first applicable rule, consuming one use.
func (s *Server) takeRule(r *http.Request) http.HandlerFunc {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rule := range s.rules {
		if rule.Times > 0 && rule.used >= rule.Times {
			continue
		}
		if rule.Match.matches(r) {
			rule.used++
			return rule.Handler
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Canned responses. Each of these exists because §7.2.2 has a row for it and
// PROV-READ requires every row to be tested.
// ---------------------------------------------------------------------------

// RespondRaw writes an arbitrary status, content type and body.
func RespondRaw(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// RespondRedirect is the Easy Auth trap: its DEFAULT for an unauthenticated
// request is a redirect to an interactive sign-in page. A client that follows it
// sees an HTML 200.
func RespondRedirect(status int, location string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	}
}

// RespondHTML is the page a caller actually receives when the endpoint is an
// authentication portal rather than the API.
func RespondHTML(status int) http.HandlerFunc {
	return RespondRaw(status, "text/html; charset=utf-8",
		"<!doctype html><html><head><title>Sign in</title></head><body>Redirecting to sign in…</body></html>")
}

// RespondEmptyBody is a status with a JSON content type and NO body — the
// "untyped 404" of §7.2.2, which must never remove a resource from state.
func RespondEmptyBody(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
	}
}

// RespondMalformedJSON is a JSON content type whose body does not parse.
func RespondMalformedJSON(status int) http.HandlerFunc {
	return RespondRaw(status, "application/problem+json", `{"code": "registration_not_found"`)
}

// ProblemOption mutates a problem document before it is written.
type ProblemOption func(*contracts.Problem)

// WithServiceInstanceID stamps the id. Condition 4 of the removal conjunction
// compares it against the id pinned at create.
func WithServiceInstanceID(id string) ProblemOption {
	return func(p *contracts.Problem) { p.ServiceInstanceID = &id }
}

// WithoutServiceInstanceID removes the stamp. On a 404 or 410 that is a service
// contract violation, and the client must treat it as "not proven to match" —
// never as "matches".
func WithoutServiceInstanceID() ProblemOption {
	return func(p *contracts.Problem) { p.ServiceInstanceID = nil }
}

// WithRetryAfterSeconds adds the retry signal that makes a 409 retryable.
func WithRetryAfterSeconds(secs int64) ProblemOption {
	return func(p *contracts.Problem) { p.RetryAfter = &secs; p.Retryable = true }
}

// WithDetail sets the detail line.
func WithDetail(detail string) ProblemOption {
	return func(p *contracts.Problem) { p.Detail = &detail }
}

// WithNextAction overrides next_action, so a test can prove the SERVER's text
// reaches the diagnostic verbatim.
func WithNextAction(next string) ProblemOption {
	return func(p *contracts.Problem) { p.NextAction = next }
}

// WithFieldErrors attaches per-field subproblems, so a rejection can be asserted
// to land on the right line of HCL through the §5.5 wire-path map rather than as
// a resource-level error.
func WithFieldErrors(errs ...contracts.ProblemFieldError) ProblemOption {
	return func(p *contracts.Problem) { p.Errors = append(p.Errors, errs...) }
}

// WithRawCode sets a code string that need not exist in the taxonomy — used to
// prove an UNKNOWN code still renders next_action and request_id verbatim.
func WithRawCode(code string) ProblemOption {
	return func(p *contracts.Problem) { p.Code = code; p.Type = "https://mantisec.dev/acme/errors/" + code }
}

// BuildProblem renders a problem document from the taxonomy.
func BuildProblem(status int, code contracts.Code, instanceID string, opts ...ProblemOption) contracts.Problem {
	meta, known := contracts.Lookup(code)
	p := contracts.Problem{
		Code:       string(code),
		Status:     int64(status),
		Type:       "https://mantisec.dev/acme/errors/" + string(code),
		RequestID:  "01J0000000000000000000FAKE"[:26],
		Title:      "Error",
		NextAction: "Contact your platform administrator.",
	}
	if known {
		p.Title = meta.Title
		p.NextAction = meta.NextAction
		p.Actor = string(meta.Actor)
		p.Retryable = meta.Retryable
	}
	if instanceID != "" {
		p.ServiceInstanceID = &instanceID
	}
	for _, o := range opts {
		o(&p)
	}
	return p
}

// RespondProblem writes a taxonomy-backed problem+json response.
func RespondProblem(status int, code contracts.Code, instanceID string, opts ...ProblemOption) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		p := BuildProblem(status, code, instanceID, opts...)
		if p.RetryAfter != nil {
			w.Header().Set("Retry-After", strconv.FormatInt(*p.RetryAfter, 10))
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Service-Instance-Id", instanceID)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(p)
	}
}

// RespondProblemNoRetryAfter is the 409 the client must NOT retry.
func RespondProblemNoRetryAfter(status int, code contracts.Code, instanceID string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		p := BuildProblem(status, code, instanceID)
		p.Retryable = false
		p.RetryAfter = nil
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Service-Instance-Id", instanceID)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(p)
	}
}
