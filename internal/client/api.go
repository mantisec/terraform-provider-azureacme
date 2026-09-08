package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// GetCapabilities calls GET /v1/capabilities. Called ONCE per provider instance
// and cached for its lifetime (§3.1), so plan-time validation costs no API calls.
func (c *Client) GetCapabilities(ctx context.Context) (*contracts.Capabilities, *Response, error) {
	resp, err := c.DoRetrying(ctx, Request{Method: http.MethodGet, Path: "/capabilities"})
	if err != nil {
		return nil, nil, err
	}
	var caps contracts.Capabilities
	if err := resp.Decode(&caps); err != nil {
		return nil, resp, &TransportError{
			Reason: ReasonMalformedBody, Method: http.MethodGet, URL: c.Endpoint() + "/v1/capabilities",
			Status: resp.Status, RequestID: resp.RequestID, Err: err,
		}
	}
	return &caps, resp, nil
}

// GetRegistration calls GET /v1/namespaces/{ns}/certificates/{name}.
//
// intentManage sends `?intent=manage`, which the service authorises against
// `Certificates.Manage` rather than `Certificates.Read`. terraform import MUST
// send it: without it any principal holding only Read could import a registration
// into their own state and manage it — a silent ownership transfer (§7.5, F-064).
func (c *Client) GetRegistration(ctx context.Context, namespace, name string, intentManage bool) (*contracts.CertificateRegistration, *Response, error) {
	req := Request{Method: http.MethodGet, Path: registrationPath(namespace, name)}
	if intentManage {
		req.Query = url.Values{"intent": []string{"manage"}}
	}
	resp, err := c.DoRetrying(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	var reg contracts.CertificateRegistration
	if err := resp.Decode(&reg); err != nil {
		return nil, resp, &TransportError{
			Reason: ReasonMalformedBody, Method: http.MethodGet, URL: c.Endpoint() + "/v1" + registrationPath(namespace, name),
			Status: resp.Status, RequestID: resp.RequestID, Err: err,
		}
	}
	return &reg, resp, nil
}

// PutResult is the outcome of a create or update PUT. All three success statuses
// carry the full representation and an ETag; 202 additionally carries the
// operation.
type PutResult struct {
	Status int
	// Registration is populated for 200, 201 and — through OperationAccepted's
	// embedded registration — for 202.
	Registration *contracts.CertificateRegistration
	Accepted     *contracts.OperationAccepted
	Response     *Response
}

// PutOptions carries the conditional-request headers. EXACTLY ONE of
// IfNoneMatchAny and IfMatchRevision must be set: a PUT with neither is `428
// precondition_required`, which is the rule that makes lost updates structurally
// impossible instead of merely discouraged (F-015).
type PutOptions struct {
	IfNoneMatchAny  bool
	IfMatchRevision *int64
	IdempotencyKey  string
}

// ETagFor renders the weak ETag form the service expects.
func ETagFor(revision int64) string { return `W/"` + strconv.FormatInt(revision, 10) + `"` }

// PutRegistration calls PUT /v1/namespaces/{ns}/certificates/{name}.
func (c *Client) PutRegistration(ctx context.Context, namespace, name string, spec contracts.CertificateSpecFields, opts PutOptions) (*PutResult, error) {
	if opts.IfNoneMatchAny == (opts.IfMatchRevision != nil) {
		// Caught here rather than by the service, because a provider that sends
		// neither (or both) is a defect its own test suite should fail on.
		return nil, fmt.Errorf("exactly one of If-None-Match and If-Match must be set (service contract: a PUT with neither is 428 precondition_required)")
	}
	headers := http.Header{}
	if opts.IfNoneMatchAny {
		headers.Set("If-None-Match", "*")
	}
	if opts.IfMatchRevision != nil {
		headers.Set("If-Match", ETagFor(*opts.IfMatchRevision))
	}
	if opts.IdempotencyKey == "" {
		opts.IdempotencyKey = NewULID()
	}
	headers.Set("Idempotency-Key", opts.IdempotencyKey)

	resp, err := c.DoRetrying(ctx, Request{
		Method:  http.MethodPut,
		Path:    registrationPath(namespace, name),
		Headers: headers,
		Body:    contracts.CertificateSpecEnvelope{Spec: spec},
	})
	if err != nil {
		return nil, err
	}
	out := &PutResult{Status: resp.Status, Response: resp}
	switch resp.Status {
	case http.StatusAccepted:
		var accepted contracts.OperationAccepted
		if err := resp.Decode(&accepted); err != nil {
			return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodPut, Status: resp.Status, RequestID: resp.RequestID, Err: err}
		}
		out.Accepted = &accepted
		out.Registration = accepted.Registration
	default:
		var reg contracts.CertificateRegistration
		if err := resp.Decode(&reg); err != nil {
			return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodPut, Status: resp.Status, RequestID: resp.RequestID, Err: err}
		}
		out.Registration = &reg
	}
	return out, nil
}

// DeleteOptions carries the delete policy and the optional precondition.
//
// If-Match is OPTIONAL on DELETE and is omitted rather than failing a destroy on
// a stale revision (§7.4).
type DeleteOptions struct {
	Policy          string
	IfMatchRevision *int64
}

// DeleteRegistration calls DELETE /v1/namespaces/{ns}/certificates/{name}.
func (c *Client) DeleteRegistration(ctx context.Context, namespace, name string, opts DeleteOptions) (*Response, *contracts.OperationAccepted, error) {
	req := Request{Method: http.MethodDelete, Path: registrationPath(namespace, name), Headers: http.Header{}}
	if opts.Policy != "" {
		req.Query = url.Values{"policy": []string{opts.Policy}}
	}
	if opts.IfMatchRevision != nil {
		req.Headers.Set("If-Match", ETagFor(*opts.IfMatchRevision))
	}
	resp, err := c.DoRetrying(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	if resp.Status == http.StatusAccepted {
		var accepted contracts.OperationAccepted
		if err := resp.Decode(&accepted); err != nil {
			return resp, nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodDelete, Status: resp.Status, RequestID: resp.RequestID, Err: err}
		}
		return resp, &accepted, nil
	}
	return resp, nil, nil
}

// GetOperation calls GET /v1/operations/{operationId}.
//
// On 404 operation_not_found or 410 operation_expired the CALLER falls back to
// the registration (§7.1.3 rule 3). That fallback is the single most valuable
// robustness property of the polling design: an apply survives losing the
// operation record entirely.
func (c *Client) GetOperation(ctx context.Context, operationID string) (*contracts.Operation, *Response, error) {
	resp, err := c.DoRetrying(ctx, Request{Method: http.MethodGet, Path: "/operations/" + url.PathEscape(operationID)})
	if err != nil {
		return nil, nil, err
	}
	var op contracts.Operation
	if err := resp.Decode(&op); err != nil {
		return nil, resp, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodGet, Status: resp.Status, RequestID: resp.RequestID, Err: err}
	}
	return &op, resp, nil
}

// ListRegistrations calls GET /v1/namespaces/{ns}/certificates, one page.
func (c *Client) ListRegistrations(ctx context.Context, namespace string, query url.Values) (*contracts.RegistrationCollection, error) {
	resp, err := c.DoRetrying(ctx, Request{
		Method: http.MethodGet,
		Path:   "/namespaces/" + url.PathEscape(namespace) + "/certificates",
		Query:  query,
	})
	if err != nil {
		return nil, err
	}
	var out contracts.RegistrationCollection
	if err := resp.Decode(&out); err != nil {
		return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodGet, Status: resp.Status, RequestID: resp.RequestID, Err: err}
	}
	return &out, nil
}

// GetNamespace calls GET /v1/namespaces/{ns}.
func (c *Client) GetNamespace(ctx context.Context, namespace string) (*contracts.NamespaceDetail, error) {
	resp, err := c.DoRetrying(ctx, Request{Method: http.MethodGet, Path: "/namespaces/" + url.PathEscape(namespace)})
	if err != nil {
		return nil, err
	}
	var out contracts.NamespaceDetail
	if err := resp.Decode(&out); err != nil {
		return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodGet, Status: resp.Status, RequestID: resp.RequestID, Err: err}
	}
	return &out, nil
}

// GetValidationBinding calls GET /v1/validation-bindings/{id}.
func (c *Client) GetValidationBinding(ctx context.Context, id string) (*contracts.ValidationBinding, error) {
	resp, err := c.DoRetrying(ctx, Request{Method: http.MethodGet, Path: "/validation-bindings/" + url.PathEscape(id)})
	if err != nil {
		return nil, err
	}
	var out contracts.ValidationBinding
	if err := resp.Decode(&out); err != nil {
		return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodGet, Status: resp.Status, RequestID: resp.RequestID, Err: err}
	}
	return &out, nil
}

// ListValidationBindings calls GET /v1/validation-bindings, one page.
func (c *Client) ListValidationBindings(ctx context.Context, query url.Values) (*contracts.ValidationBindingCollection, error) {
	resp, err := c.DoRetrying(ctx, Request{Method: http.MethodGet, Path: "/validation-bindings", Query: query})
	if err != nil {
		return nil, err
	}
	var out contracts.ValidationBindingCollection
	if err := resp.Decode(&out); err != nil {
		return nil, &TransportError{Reason: ReasonMalformedBody, Method: http.MethodGet, Status: resp.Status, RequestID: resp.RequestID, Err: err}
	}
	return &out, nil
}

func registrationPath(namespace, name string) string {
	return "/namespaces/" + url.PathEscape(namespace) + "/certificates/" + url.PathEscape(name)
}
