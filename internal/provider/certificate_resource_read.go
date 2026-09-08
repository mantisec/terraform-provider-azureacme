package provider

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// ReadAction is the decision of terraform-provider-contract.md §7.2.2.
//
// It is an explicit exhaustive enumeration with a default branch that ERRORS,
// never an `if status == 404 { remove }`. §7.2.1 names this conjunction in the
// review's "do not remove this mechanism" list, and for good reason: a wrong
// RemoveResource followed by an apply destroys and reissues a production
// certificate, and with `deletion_policy = "delete"` it soft-deletes the Key
// Vault object first.
type ReadAction int

const (
	// ReadActionUnset is the zero value and is never a valid decision. It exists
	// so that a code path which forgets to decide fails loudly instead of
	// defaulting to something.
	ReadActionUnset ReadAction = iota
	// ReadActionSuccess populates state.
	ReadActionSuccess
	// ReadActionRemove calls resp.State.RemoveResource. Reached ONLY through the
	// four-part conjunction.
	ReadActionRemove
	// ReadActionError errors and RETAINS state.
	ReadActionError
)

func (a ReadAction) String() string {
	switch a {
	case ReadActionSuccess:
		return "success"
	case ReadActionRemove:
		return "remove"
	case ReadActionError:
		return "error"
	default:
		return "unset"
	}
}

// ReadDecision is the outcome plus the diagnostic text §7.2.2 requires it to
// carry.
type ReadDecision struct {
	Action ReadAction
	// DiagnosticID is a provider-only identifier from §10, or "" for a decision
	// that raises no provider-specific diagnostic.
	DiagnosticID string
	Summary      string
	Detail       string
}

// ReadContext is everything the decision needs that is not in the error.
type ReadContext struct {
	// Endpoint is the configured base URL, which the untyped-404 diagnostic must
	// name so the user knows which value to check.
	Endpoint string
	// Address is the Terraform resource address, e.g. azureacme_certificate.api.
	Address string
	// PinnedServiceInstanceID is the id recorded at create. Empty means prior
	// state has none — an import in progress — and condition 4 is then satisfied.
	PinnedServiceInstanceID string
	// PinnedServiceInstanceName is a label for the diagnostic only.
	PinnedServiceInstanceName string
	// SkipInstanceCheck disables condition 4 ONLY. It never disables version
	// checking: one flag must never disable both (§2.2).
	SkipInstanceCheck bool
	// CredentialMethod names the credential actually used, which the 401
	// diagnostic must state.
	CredentialMethod string
}

// DecideRead maps a GET outcome to an action.
//
// THE FOUR-PART REMOVAL CONJUNCTION (§7.2.1). Remove if and only if ALL of:
//
//  1. the HTTP status is 404 or 410, AND
//  2. the content type is JSON and the body PARSES, AND
//  3. the code is exactly registration_not_found (404) or registration_deleted
//     (410), AND
//  4. body.service_instance_id equals the pinned id (or none is pinned).
//
// Condition 2 is discharged by the client's type system: an *APIError exists
// only when a JSON body parsed, and every other outcome is a *TransportError.
func DecideRead(err error, rc ReadContext) ReadDecision {
	if err == nil {
		return ReadDecision{Action: ReadActionSuccess}
	}

	if tErr, ok := client.AsTransportError(err); ok {
		switch tErr.Reason {
		case client.ReasonRedirect:
			return ReadDecision{
				Action: ReadActionError,
				Summary: fmt.Sprintf("The service endpoint returned a redirect (HTTP %d), not an API response",
					tErr.Status),
				Detail: fmt.Sprintf(
					"%s redirected to %q.\n\n"+
						"The service must be configured to return 401 rather than redirect to a sign-in page: Easy Auth's "+
						"`unauthenticatedClientAction` must be `Return401` with no `redirectToProvider`, and no /v1 path may "+
						"emit any 3xx.\n\n"+
						"Nothing has been removed from state. Terraform is refusing to interpret a redirect as an absent "+
						"certificate.\n\n"+
						"Request id: %s",
					rc.Endpoint, tErr.Location, tErr.RequestID),
			}
		case client.ReasonContentType:
			return ReadDecision{
				Action:  ReadActionError,
				Summary: fmt.Sprintf("The service endpoint returned %s, not JSON", displayCT(tErr.ContentType)),
				Detail: fmt.Sprintf(
					"Expected JSON, received %s from %s — the endpoint is probably an authentication portal, not the API.\n\n"+
						"Nothing has been removed from state. Verify the provider `endpoint` and that the service returns "+
						"401 rather than an HTML sign-in page.\n\n"+
						"Request id: %s",
					displayCT(tErr.ContentType), rc.Endpoint, tErr.RequestID),
			}
		case client.ReasonMalformedBody:
			if tErr.Status == http.StatusNotFound || tErr.Status == http.StatusGone {
				return ReadDecision{
					Action:  ReadActionError,
					Summary: fmt.Sprintf("Received an untyped HTTP %d from the service", tErr.Status),
					Detail: fmt.Sprintf(
						"Received an untyped %d from %s; refusing to remove %s from state.\n\n"+
							"A registration is removed from state only for a TYPED %d or 410 carrying "+
							"`registration_not_found` or `registration_deleted` and this service instance's id. An untyped "+
							"%d is far more likely to be a wrong `endpoint`, a proxy, or an unrelated service than a deleted "+
							"certificate.\n\n"+
							"Verify the provider `endpoint`.\n\nRequest id: %s",
						tErr.Status, rc.Endpoint, rc.Address, tErr.Status, tErr.Status, tErr.RequestID),
				}
			}
			return ReadDecision{
				Action:  ReadActionError,
				Summary: fmt.Sprintf("The service returned an unreadable HTTP %d response", tErr.Status),
				Detail:  fmt.Sprintf("The body carried a JSON content type but did not parse.\n\nRequest id: %s", tErr.RequestID),
			}
		case client.ReasonNetwork:
			return ReadDecision{
				Action:  ReadActionError,
				Summary: "Could not reach the certificate service",
				Detail: fmt.Sprintf(
					"%v\n\nNothing has been removed from state: a service outage, a TLS failure and a deleted registration "+
						"are three different things.\n\nRequest id: %s", tErr.Err, tErr.RequestID),
			}
		default:
			// The default branch of the transport switch. Reaching it is a defect.
			return ReadDecision{
				Action:  ReadActionError,
				Summary: "Unclassified transport failure reading the registration",
				Detail: fmt.Sprintf("reason=%q: %v\n\nThis is a provider defect: every transport reason must have a row "+
					"in the §7.2.2 table. Nothing has been removed from state.", tErr.Reason, tErr),
			}
		}
	}

	apiErr, ok := client.AsAPIError(err)
	if !ok {
		// Neither transport nor API: the default branch of the OUTER switch.
		return ReadDecision{
			Action:  ReadActionError,
			Summary: "Unclassified failure reading the registration",
			Detail: fmt.Sprintf("%v\n\nThis is a provider defect: the error is neither a transport failure nor a typed "+
				"service error. Nothing has been removed from state.", err),
		}
	}

	switch apiErr.Status {
	// --------------------------------------------------------------- 404 / 410
	case http.StatusNotFound, http.StatusGone:
		wantCode := contracts.CodeRegistrationNotFound
		if apiErr.Status == http.StatusGone {
			wantCode = contracts.CodeRegistrationDeleted
		}
		// --- condition 3: the typed code ---
		if apiErr.Code() != wantCode {
			return ReadDecision{
				Action: ReadActionError,
				Summary: fmt.Sprintf("The service returned HTTP %d with code %q, which does not mean the registration is gone",
					apiErr.Status, apiErr.Code()),
				Detail: fmt.Sprintf(
					"%s\n\n%s\n\nOnly %q on a %d removes a registration from state. Nothing has been removed.\n\nRequest id: %s",
					apiErr.Title(), nextActionLine(apiErr), wantCode, apiErr.Status, apiErr.RequestID()),
			}
		}
		// --- condition 4: the service instance ---
		if !rc.SkipInstanceCheck && rc.PinnedServiceInstanceID != "" {
			actual := apiErr.ServiceInstanceID()
			if actual == nil {
				return ReadDecision{
					Action:       ReadActionError,
					DiagnosticID: DiagServiceInstanceMismatch,
					Summary:      fmt.Sprintf("HTTP %d carried no service instance id", apiErr.Status),
					Detail: fmt.Sprintf(
						"This registration is pinned to service instance %s (%s), but the %d response from %s carried no "+
							"`service_instance_id`. The service contract makes that field MANDATORY on every 404 and 410 "+
							"precisely because it is one of the four conditions required before removing a resource from "+
							"state.\n\nRefusing to remove %s from state. Verify the provider `endpoint`.\n\nRequest id: %s",
						rc.PinnedServiceInstanceID, orUnknown(rc.PinnedServiceInstanceName), apiErr.Status, rc.Endpoint,
						rc.Address, apiErr.RequestID()),
				}
			}
			if *actual != rc.PinnedServiceInstanceID {
				return ReadDecision{
					Action:       ReadActionError,
					DiagnosticID: DiagServiceInstanceMismatch,
					Summary:      "The endpoint is a DIFFERENT service instance from the one this certificate was created against",
					Detail: fmt.Sprintf(
						"This registration is pinned to service instance %s (%s).\n"+
							"The endpoint %s reports instance %s.\n\n"+
							"Refusing to proceed. A single mistyped `endpoint` — a stale CI variable, a copy-pasted value, a "+
							"re-platformed service — makes every GET legitimately return `registration_not_found`. Without "+
							"this check Terraform would remove every certificate from state and the next apply would reissue "+
							"the entire fleet against the wrong service, or with `deletion_policy = \"delete\"` destroy the "+
							"real ones first.\n\n"+
							"Check the provider `endpoint`. If the migration to a new service instance was deliberate, remove "+
							"these resources from state and re-import them against the new instance.\n\nRequest id: %s",
						rc.PinnedServiceInstanceID, orUnknown(rc.PinnedServiceInstanceName), rc.Endpoint, *actual,
						apiErr.RequestID()),
				}
			}
		}
		// All four conditions hold.
		return ReadDecision{Action: ReadActionRemove}

	// ------------------------------------------------------------------- 401
	case http.StatusUnauthorized:
		summary := "Authentication to the certificate service failed"
		detail := fmt.Sprintf(
			"%s\n\nThe credential method used was %q.\n\n%s\n\nNothing has been removed from state: an authentication "+
				"failure is not an absent certificate.\n\nRequest id: %s",
			apiErr.Title(), rc.CredentialMethod, nextActionLine(apiErr), apiErr.RequestID())
		switch apiErr.Code() {
		case contracts.CodeTokenAudienceMismatch:
			summary = "The token audience does not match the service"
			detail = fmt.Sprintf(
				"%s\n\nThe provider requested a token for the configured `audience`, and the service rejected it.\n"+
					"Credential method: %q.\n\n%s\n\n%s\n\nNothing has been removed from state.\n\nRequest id: %s",
				apiErr.Title(), rc.CredentialMethod, detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID())
		case contracts.CodeTokenTenantMismatch:
			summary = "The token tenant does not match the service"
			detail = fmt.Sprintf(
				"%s\n\nCheck `tenant_id`. Credential method: %q.\n\n%s\n\n%s\n\nNothing has been removed from state.\n\nRequest id: %s",
				apiErr.Title(), rc.CredentialMethod, detailLine(apiErr), nextActionLine(apiErr), apiErr.RequestID())
		}
		return ReadDecision{Action: ReadActionError, Summary: summary, Detail: detail}

	// ------------------------------------------------------------------- 403
	//
	// 403 NEVER REMOVES. The server-side counterpart is mandatory: an
	// authenticated-but-unauthorised caller gets 403, never 404, and 403 is also
	// returned for a namespace that does not exist. The rich authorisation model
	// actively invites a 404-for-unauthorised implementation, and that convention
	// would convert ONE revoked role assignment into fleet-wide certificate
	// destruction.
	case http.StatusForbidden:
		return ReadDecision{
			Action:  ReadActionError,
			Summary: "Not authorised to read this registration",
			Detail: fmt.Sprintf(
				"%s\n\nNamespace: %s\n%s%s\n\nNothing has been removed from state. An authorisation failure is never "+
					"read as an absent certificate — that convention would turn one revoked role assignment into "+
					"fleet-wide certificate destruction.\n\nRequest id: %s",
				apiErr.Title(), namespaceFromAddress(rc.Address), missingGrantLine(apiErr), nextActionLine(apiErr),
				apiErr.RequestID()),
		}

	// ----------------------------------------------- retryable transport-ish
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return ReadDecision{
			Action:  ReadActionError,
			Summary: fmt.Sprintf("The certificate service returned HTTP %d", apiErr.Status),
			Detail: fmt.Sprintf("%s\n\n%s\n\nThe provider retried within `timeouts.read` and the condition persisted. "+
				"Nothing has been removed from state.\n\nRequest id: %s",
				apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()),
		}

	default:
		if apiErr.Status >= 500 {
			return ReadDecision{
				Action:  ReadActionError,
				Summary: fmt.Sprintf("The certificate service returned HTTP %d", apiErr.Status),
				Detail: fmt.Sprintf("%s\n\n%s\n\nThe provider retried within `timeouts.read` and the condition persisted. "+
					"Nothing has been removed from state: a service outage is not an absent certificate.\n\nRequest id: %s",
					apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()),
			}
		}
		// The DEFAULT BRANCH. Reaching it means §7.2.2 has grown a row this switch
		// does not implement. It errors, and it says so.
		return ReadDecision{
			Action:  ReadActionError,
			Summary: fmt.Sprintf("Unhandled HTTP %d from the certificate service", apiErr.Status),
			Detail: fmt.Sprintf(
				"code=%q title=%q\n\n%s\n\nThis status has no row in the provider's read decision table, which is a "+
					"provider defect. Nothing has been removed from state, which is always the safe answer.\n\nRequest id: %s",
				apiErr.Code(), apiErr.Title(), nextActionLine(apiErr), apiErr.RequestID()),
		}
	}
}

func displayCT(ct string) string {
	if ct == "" {
		return "a response with no Content-Type"
	}
	return ct
}

func orUnknown(s string) string {
	if s == "" {
		return "name unknown to this workspace"
	}
	return s
}

func nextActionLine(e *client.APIError) string {
	if na := e.NextAction(); na != "" {
		return "Next action: " + na
	}
	return ""
}

func detailLine(e *client.APIError) string {
	if d := e.Detail(); d != "" {
		return d
	}
	return ""
}

func missingGrantLine(e *client.APIError) string {
	if e.Known && e.Meta.Code == contracts.CodeRoleNotGranted {
		return "The caller is missing an application role on this namespace.\n"
	}
	if d := e.Detail(); d != "" {
		return d + "\n"
	}
	return ""
}

func namespaceFromAddress(addr string) string {
	if addr == "" {
		return "(unknown)"
	}
	return strings.TrimSpace(addr)
}
