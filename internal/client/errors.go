package client

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// TransportReason classifies a failure that never produced a typed error body.
//
// The distinction matters because of ONE rule: `Read` may remove a resource from
// state only when it received a TYPED, JSON, matching-instance 404 or 410
// (terraform-provider-contract.md §7.2.1). Every TransportError is, by
// construction, not that — so keeping these separate from *APIError is what makes
// the removal conjunction checkable rather than hopeful.
type TransportReason string

const (
	// ReasonNetwork covers dial failures, TLS failures, timeouts and context
	// deadlines.
	ReasonNetwork TransportReason = "network"
	// ReasonRedirect is any 3xx. Easy Auth's DEFAULT is a redirect to an
	// interactive sign-in page, and Go's http.Client follows redirects by
	// default — which turns an authentication failure into an HTML 200. The
	// client sets CheckRedirect so the redirect is never followed and the bearer
	// token never reaches the redirect target.
	ReasonRedirect TransportReason = "redirect"
	// ReasonContentType is a response whose Content-Type is neither
	// application/json nor application/problem+json. An HTML body is an
	// authentication portal, not the API — and never a 404-equivalent.
	ReasonContentType TransportReason = "content_type"
	// ReasonMalformedBody is a JSON content type whose body does not parse.
	ReasonMalformedBody TransportReason = "malformed_body"
)

// TransportError is a failure that produced no typed error body.
type TransportError struct {
	Reason      TransportReason
	Method      string
	URL         string
	Status      int // 0 when there was no response at all
	ContentType string
	Location    string // for ReasonRedirect
	RequestID   string
	BodySnippet string
	Err         error
}

func (e *TransportError) Error() string {
	switch e.Reason {
	case ReasonRedirect:
		return fmt.Sprintf("%s %s: the endpoint returned a redirect (%d to %q); the service must be configured to return 401 rather than redirect to a sign-in page",
			e.Method, e.URL, e.Status, e.Location)
	case ReasonContentType:
		return fmt.Sprintf("%s %s: expected JSON, received %s — the endpoint is probably an authentication portal, not the API",
			e.Method, e.URL, displayContentType(e.ContentType))
	case ReasonMalformedBody:
		return fmt.Sprintf("%s %s: HTTP %d carried a JSON content type but a body that does not parse", e.Method, e.URL, e.Status)
	default:
		return fmt.Sprintf("%s %s: %v", e.Method, e.URL, e.Err)
	}
}

func (e *TransportError) Unwrap() error { return e.Err }

func displayContentType(ct string) string {
	if ct == "" {
		return "a response with no Content-Type"
	}
	return ct
}

// APIError is a typed problem+json response. It exists ONLY when the response
// carried a JSON content type and the body parsed — which is conditions 2 of the
// four-part removal conjunction, discharged by construction.
type APIError struct {
	Status     int
	Problem    contracts.Problem
	Method     string
	URL        string
	RetryAfter time.Duration
	// HasRetryAfter records whether a Retry-After signal was present at all,
	// which is the difference between a 409 the client retries and one it does
	// not.
	HasRetryAfter bool
	// Meta is the taxonomy entry for the code. Known is false for a code added by
	// a newer service, which is NOT an error: next_action, title, detail and the
	// request id are still rendered verbatim.
	Meta  contracts.Metadata
	Known bool
}

func (e *APIError) Code() contracts.Code { return contracts.Code(e.Problem.Code) }

// ServiceInstanceID is condition 4 of the removal conjunction. It is nil when the
// service did not stamp one, which for a 404 or 410 is a contract violation and
// must NOT be read as "matches".
func (e *APIError) ServiceInstanceID() *string { return e.Problem.ServiceInstanceID }

// Actor is the taxonomy's actor classification — who can act. It is what turns a
// service error into a diagnostic a user can act on, rather than a message
// passed through verbatim.
func (e *APIError) Actor() string {
	if e.Problem.Actor != "" {
		return e.Problem.Actor
	}
	if e.Known {
		return string(e.Meta.Actor)
	}
	return ""
}

// NextAction prefers the SERVER's next_action, because a newer service knows more
// about its own failure than this build's compiled-in taxonomy does.
func (e *APIError) NextAction() string {
	if e.Problem.NextAction != "" {
		return e.Problem.NextAction
	}
	if e.Known {
		return e.Meta.NextAction
	}
	return ""
}

func (e *APIError) Title() string {
	if e.Problem.Title != "" {
		return e.Problem.Title
	}
	if e.Known {
		return e.Meta.Title
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

func (e *APIError) Detail() string {
	if e.Problem.Detail != nil {
		return *e.Problem.Detail
	}
	return ""
}

func (e *APIError) RequestID() string { return e.Problem.RequestID }

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d %s (%s)", e.Method, e.URL, e.Status, e.Problem.Code, e.Title())
}

// Is lets callers write errors.Is(err, contracts.ErrRegistrationNotFound).
func (e *APIError) Is(target error) bool {
	if sentinel := contracts.Sentinel(e.Code()); sentinel != nil {
		return errors.Is(sentinel, target)
	}
	return false
}

// AsAPIError is the narrowing every caller needs before it may reason about a
// code at all.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// AsTransportError narrows to the untyped half.
func AsTransportError(err error) (*TransportError, bool) {
	var tErr *TransportError
	if errors.As(err, &tErr) {
		return tErr, true
	}
	return nil, false
}

// retryableStatuses is the STATUS FALLBACK of PROV-API-CLIENT, used only when the
// body did not parse into a Problem.
var retryableStatuses = map[int]bool{
	http.StatusRequestTimeout:      true, // 408
	http.StatusTooManyRequests:     true, // 429
	http.StatusInternalServerError: true, // 500
	http.StatusBadGateway:          true, // 502
	http.StatusServiceUnavailable:  true, // 503
	http.StatusGatewayTimeout:      true, // 504
}

// RetryDecision classifies an error for the retry loop.
//
// Rules, in order (PROV-API-CLIENT; service contract §9.2):
//
//  1. A parsed body's `retryable` is AUTHORITATIVE.
//  2. A `409` additionally requires a `Retry-After` signal. The service's own
//     contract makes `Retry-After` mandatory on any `409` it classifies as
//     retryable, so this only ever refuses to retry a conflict the service did
//     not tell us to retry — the safe direction, and the acceptance criterion
//     ("a 409 carrying Retry-After is retried and a 409 without it is not").
//  3. When the body did NOT parse, fall back to the status: 408, 429, 5xx and any
//     transport error.
//  4. An UNKNOWN code is NOT a reason to stop trusting `retryable`; it is a
//     reason not to branch on the code. Forward compatibility costs nothing here.
func RetryDecision(err error) (retry bool, after time.Duration) {
	if err == nil {
		return false, 0
	}
	if apiErr, ok := AsAPIError(err); ok {
		if apiErr.Status == http.StatusConflict && !apiErr.HasRetryAfter {
			return false, 0
		}
		return apiErr.Problem.Retryable, apiErr.RetryAfter
	}
	if tErr, ok := AsTransportError(err); ok {
		switch tErr.Reason {
		case ReasonRedirect, ReasonContentType:
			// An authentication portal does not become the API by being asked
			// again, and retrying hides the real cause behind a timeout.
			return false, 0
		case ReasonMalformedBody:
			if tErr.Status == http.StatusConflict {
				return false, 0
			}
			return retryableStatuses[tErr.Status] || tErr.Status >= 500, 0
		default:
			return true, 0
		}
	}
	return false, 0
}

// parseRetryAfter reads the header. Only the delta-seconds form is used: the
// HTTP-date form is legal but the service contract specifies seconds, and
// guessing at a date form invites a clock-skew bug in the one place a client is
// least able to notice one.
func parseRetryAfter(h http.Header) (time.Duration, bool) {
	raw := h.Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}
