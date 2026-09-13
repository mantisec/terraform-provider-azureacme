// Package client is the hand-written HTTP transport for the service API, written
// against the GENERATED models in internal/contracts.
//
// It implements terraform-provider-contract.md §2.5 and §9.2. Two transport rules
// carry most of the safety:
//
//   - REDIRECTS ARE NEVER FOLLOWED. Easy Auth's default for an unauthenticated
//     request is a 302 to an interactive sign-in page, and Go's http.Client
//     follows redirects by default. Following one turns an authentication failure
//     into an HTML 200 — and, in the Read path, an HTML 200 or an untyped 404 is
//     one bad `if` away from removing a live certificate from state.
//   - A NON-JSON CONTENT TYPE IS A TRANSPORT ERROR, never an absence. The same
//     reason.
//
// The client links NO Azure data-plane SDK (§9.2 rule 1) and is guarded by
// internal/provider/dependency_guard_test.go.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// APIPathPrefix is the single path-versioned prefix. `/v1` is the compatibility
// boundary (contracts/api/openapi.yaml `servers`).
const APIPathPrefix = "/v1"

// maxBodyBytes bounds what is read from a response. A hostile or misconfigured
// endpoint returning a multi-gigabyte HTML page must not exhaust the provider.
const maxBodyBytes = 8 << 20

// TokenSource yields a bearer token for the configured audience.
//
// INTERFACE I DEPEND ON, NOT ONE I IMPLEMENT. The credential chain of §2.4 —
// which explicitly forbids DefaultAzureCredential — is owned by
// AUTH-PROVIDER-CREDENTIAL-CHAIN. This package needs exactly two things from it:
// a token, and the NAME of the method that produced it, because the §7.2.2
// diagnostic for a 401 must name "the credential method actually used".
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Method is a stable identifier such as "workload_identity", "managed_identity"
	// or "azure_cli".
	Method() string
}

// StaticTokenSource is for tests and for an explicitly supplied token.
type StaticTokenSource struct {
	Value      string
	MethodName string
}

func (s StaticTokenSource) Token(context.Context) (string, error) { return s.Value, nil }
func (s StaticTokenSource) Method() string {
	if s.MethodName == "" {
		return "static"
	}
	return s.MethodName
}

// Config configures a Client.
type Config struct {
	// Endpoint is the base URL WITHOUT the /v1 prefix.
	Endpoint string
	Audience string
	Tokens   TokenSource
	// UserAgent must carry the provider version and the Terraform version; the
	// service's minimum_client_version enforcement and its client.version_observed
	// telemetry key on it (§2.5).
	UserAgent      string
	RequestTimeout time.Duration
	MaxRetries     int
	// HTTPClient overrides the constructed client. Tests use it; production does
	// not, because the constructed one carries the redirect rule.
	HTTPClient *http.Client
	// NewRequestID is overridable so tests can assert distinct ids without
	// depending on entropy.
	NewRequestID func() string
	// Sleep is overridable so retry tests do not take real seconds.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client is the service API client. It is safe for concurrent use.
type Client struct {
	cfg     Config
	http    *http.Client
	baseURL *url.URL

	// requests counts every HTTP request actually issued. Several acceptance
	// criteria are stated as "asserted by counting requests at the fake service";
	// counting here as well makes the same assertion available to a unit test.
	requests int64
}

// New builds a Client. It fails rather than guessing when the endpoint is not a
// usable absolute URL.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	base, err := url.Parse(strings.TrimSuffix(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("endpoint %q is not a URL: %w", cfg.Endpoint, err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("endpoint %q must be an absolute URL such as https://certs.example.com", cfg.Endpoint)
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.NewRequestID == nil {
		cfg.NewRequestID = NewULID
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepContext
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	// Applied even to a caller-supplied client: the rule is not negotiable, and a
	// test that supplied a redirect-following client would be testing something
	// the provider never does.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	httpClient.Timeout = cfg.RequestTimeout
	return &Client{cfg: cfg, http: httpClient, baseURL: base}, nil
}

// Endpoint returns the configured base URL, for diagnostics that must name it.
func (c *Client) Endpoint() string { return c.baseURL.String() }

// Audience returns the OPERATOR-CONFIGURED token audience this client requests
// tokens for. It is fixed at construction and is never influenced by anything the
// endpoint says: `/v1/capabilities` may report an audience and the provider may
// warn that the two disagree, but the value here does not move (F-040, ADR 0019).
func (c *Client) Audience() string { return c.cfg.Audience }

// CredentialMethod names the credential method in use, for the 401 diagnostic.
func (c *Client) CredentialMethod() string {
	if c.cfg.Tokens == nil {
		return "none"
	}
	return c.cfg.Tokens.Method()
}

// RequestCount is the number of HTTP requests this client has issued.
func (c *Client) RequestCount() int64 { return c.requests }

// Request describes one call.
type Request struct {
	Method string
	// Path is relative to the /v1 prefix, e.g. "/namespaces/x/certificates/y".
	Path string
	// RawPath bypasses the /v1 prefix (only /healthz needs this).
	RawPath string
	Query   url.Values
	Headers http.Header
	Body    any
}

// Response is a successful (2xx) response with its body still undecoded.
type Response struct {
	Status    int
	Header    http.Header
	Body      []byte
	RequestID string
	// ETag is `W/"{spec.revision}"` on registration responses.
	ETag string
	// ServiceInstanceID is the X-Service-Instance-Id header, when present.
	ServiceInstanceID string
	RetryAfter        time.Duration
	HasRetryAfter     bool
	OperationLocation string
}

// Decode unmarshals the body into out.
func (r *Response) Decode(out any) error {
	if len(r.Body) == 0 {
		return nil
	}
	return json.Unmarshal(r.Body, out)
}

// Do issues one request with no retries. Callers that want the retry policy call
// DoRetrying.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	u := *c.baseURL
	if req.RawPath != "" {
		u.Path = strings.TrimSuffix(u.Path, "/") + req.RawPath
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/") + APIPathPrefix + req.Path
	}
	if len(req.Query) > 0 {
		u.RawQuery = req.Query.Encode()
	}

	var bodyReader io.Reader
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, u.String(), bodyReader)
	if err != nil {
		return nil, &TransportError{Reason: ReasonNetwork, Method: req.Method, URL: u.String(), Err: err}
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	httpReq.Header.Set("Accept", "application/json, application/problem+json")
	if bodyBytes != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.cfg.UserAgent)
	}
	requestID := c.cfg.NewRequestID()
	httpReq.Header.Set("X-Request-Id", requestID)

	if c.cfg.Tokens != nil {
		token, err := c.cfg.Tokens.Token(ctx)
		if err != nil {
			return nil, &TransportError{
				Reason: ReasonNetwork, Method: req.Method, URL: u.String(), RequestID: requestID,
				Err: fmt.Errorf("acquiring a token with the %s credential: %w", c.cfg.Tokens.Method(), err),
			}
		}
		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}
	}

	c.requests++
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, &TransportError{Reason: ReasonNetwork, Method: req.Method, URL: u.String(), RequestID: requestID, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if readErr != nil {
		return nil, &TransportError{Reason: ReasonNetwork, Method: req.Method, URL: u.String(), Status: resp.StatusCode, RequestID: requestID, Err: readErr}
	}

	// --- rule 1: any 3xx is an error, and the token never reached the target ---
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, &TransportError{
			Reason: ReasonRedirect, Method: req.Method, URL: u.String(),
			Status: resp.StatusCode, Location: resp.Header.Get("Location"),
			RequestID: headerOr(resp.Header, "X-Request-Id", requestID),
		}
	}

	contentType := ""
	if raw := resp.Header.Get("Content-Type"); raw != "" {
		if mt, _, err := mime.ParseMediaType(raw); err == nil {
			contentType = mt
		} else {
			contentType = raw
		}
	}

	// A 204 legitimately carries no body and no content type.
	bodyless := resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(body)) == 0

	// --- rule 2: a non-JSON content type is a transport error, never an absence ---
	if !bodyless && contentType != "application/json" && contentType != "application/problem+json" {
		return nil, &TransportError{
			Reason: ReasonContentType, Method: req.Method, URL: u.String(),
			Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
			RequestID:   headerOr(resp.Header, "X-Request-Id", requestID),
			BodySnippet: snippet(body),
		}
	}

	retryAfter, hasRetryAfter := parseRetryAfter(resp.Header)

	if resp.StatusCode >= 400 {
		var problem contracts.Problem
		if bodyless {
			return nil, &TransportError{
				Reason: ReasonMalformedBody, Method: req.Method, URL: u.String(),
				Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
				RequestID: headerOr(resp.Header, "X-Request-Id", requestID),
			}
		}
		if err := json.Unmarshal(body, &problem); err != nil {
			return nil, &TransportError{
				Reason: ReasonMalformedBody, Method: req.Method, URL: u.String(),
				Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
				RequestID: headerOr(resp.Header, "X-Request-Id", requestID), BodySnippet: snippet(body), Err: err,
			}
		}
		if problem.RequestID == "" {
			problem.RequestID = headerOr(resp.Header, "X-Request-Id", requestID)
		}
		// A body-supplied retry_after is honoured when the header is absent, so a
		// service that puts it in only one place still gets the retry it asked for.
		if !hasRetryAfter && problem.RetryAfter != nil && *problem.RetryAfter >= 0 {
			retryAfter = time.Duration(*problem.RetryAfter) * time.Second
			hasRetryAfter = true
		}
		meta, known := contracts.Lookup(contracts.Code(problem.Code))
		return nil, &APIError{
			Status: resp.StatusCode, Problem: problem, Method: req.Method, URL: u.String(),
			RetryAfter: retryAfter, HasRetryAfter: hasRetryAfter, Meta: meta, Known: known,
		}
	}

	return &Response{
		Status:            resp.StatusCode,
		Header:            resp.Header,
		Body:              body,
		RequestID:         headerOr(resp.Header, "X-Request-Id", requestID),
		ETag:              resp.Header.Get("ETag"),
		ServiceInstanceID: resp.Header.Get("X-Service-Instance-Id"),
		RetryAfter:        retryAfter,
		HasRetryAfter:     hasRetryAfter,
		OperationLocation: resp.Header.Get("Operation-Location"),
	}, nil
}

// DoRetrying applies the retry policy of PROV-API-CLIENT, bounded by MaxRetries
// and by ctx.
//
// It never retries faster than a supplied Retry-After: rate-limiting the
// provider's own client is cheaper than a 429 (§7.1.3 rule 4).
func (c *Client) DoRetrying(ctx context.Context, req Request) (*Response, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		resp, err := c.Do(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		retry, after := RetryDecision(err)
		if !retry || attempt >= c.cfg.MaxRetries {
			return nil, lastErr
		}
		if after <= 0 {
			after = backoffFor(attempt)
		}
		tflog.Debug(ctx, "retrying a service request", map[string]any{
			"attempt": attempt + 1, "after_seconds": after.Seconds(), "reason": err.Error(),
		})
		if sleepErr := c.cfg.Sleep(ctx, after); sleepErr != nil {
			return nil, lastErr
		}
	}
}

// backoffFor is the 2s -> 5s -> 10s -> 30s cap of §7.1.3, without jitter for the
// short transport retry ladder; the operation poller adds jitter.
func backoffFor(attempt int) time.Duration {
	switch attempt {
	case 0:
		return 2 * time.Second
	case 1:
		return 5 * time.Second
	case 2:
		return 10 * time.Second
	default:
		return 30 * time.Second
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func headerOr(h http.Header, key, fallback string) string {
	if v := h.Get(key); v != "" {
		return v
	}
	return fallback
}

func snippet(b []byte) string {
	const limit = 200
	s := strings.TrimSpace(string(b))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
