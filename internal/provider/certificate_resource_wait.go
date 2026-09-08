package provider

import (
	"context"
	"math/rand"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// waitRequest names what is being waited for.
type waitRequest struct {
	Namespace        string
	Name             string
	OperationID      string
	TargetGeneration int64
	Deadline         time.Time
	// OperationTerminalIsSuccess switches the completion predicate from "the
	// target generation is published" to "the operation reached a terminal
	// success". DELETE needs it: there is no registration left to fulfil.
	OperationTerminalIsSuccess bool
}

// waitOutcome is the result of the polling loop.
type waitOutcome struct {
	// Published means fulfilled_generation >= target_generation AND phase ==
	// "ready". It is the ONLY thing that counts as success.
	Published      bool
	TimedOut       bool
	Failed         bool
	FailCode       contracts.Code
	FailMessage    string
	FailNextAction string
	LastPhase      string
	OperationID    string
	Registration   *contracts.CertificateRegistration
	Err            error
}

// waitForCompletion implements §7.1.3 (polling) and §7.1.4 (the timeout
// contract).
//
// THE TIMEOUT CONTRACT IS THE POINT. The source design timed out, errored, and
// let the next apply destroy and reissue. But the product's premise is that the
// service KEEPS WORKING after Terraform gives up — so between the timeout and the
// next apply the operation usually SUCCEEDS. Reporting that as a failure is what
// starts the destructive sequence. Therefore: on timeout, perform one final GET
// of the REGISTRATION and return SUCCESS if the certificate published.
func (r *certificateResource) waitForCompletion(ctx context.Context, w waitRequest) waitOutcome {
	ns, name, operationID := w.Namespace, w.Name, w.OperationID
	targetGeneration, deadline := w.TargetGeneration, w.Deadline
	out := waitOutcome{OperationID: operationID}
	lastPhase := ""
	next := 2 * time.Second
	fallbackToRegistration := operationID == ""

	for {
		if time.Now().After(deadline) {
			break
		}

		if !fallbackToRegistration {
			op, resp, err := r.data.Client.GetOperation(ctx, operationID)
			switch {
			case err == nil:
				if op.Phase != nil && string(*op.Phase) != lastPhase {
					lastPhase = string(*op.Phase)
					// TF_LOG=info is the documented, supported way to watch
					// progress: the Plugin Framework has NO channel for streaming
					// progress into Terraform's default CLI output.
					tflog.Info(ctx, "issuance phase changed", map[string]any{
						"operation_id": operationID, "phase": lastPhase, "state": string(op.State),
					})
				}
				out.LastPhase = lastPhase

				// A deferral discovered mid-wait is still a deferral.
				if op.State == contracts.OperationStateDeferred && op.EstimatedStart != nil {
					if start, perr := time.Parse(time.RFC3339, *op.EstimatedStart); perr == nil && start.After(deadline) {
						out.TimedOut = true
						out.Registration = r.finalRead(ctx, ns, name)
						return out
					}
				}

				switch op.State {
				case contracts.OperationStateSucceeded:
					if w.OperationTerminalIsSuccess {
						// DELETE has no registration left to fulfil: a terminal
						// succeeded operation IS the success condition. Requiring
						// fulfilment here would poll a tombstone until the timeout.
						out.Published = true
						return out
					}
					out.Registration = r.finalRead(ctx, ns, name)
					out.Published = isFulfilled(out.Registration, targetGeneration)
					if !out.Published {
						// The operation says succeeded but the registration has not
						// caught up. Keep polling the registration rather than
						// declaring either answer.
						fallbackToRegistration = true
					} else {
						return out
					}
				case contracts.OperationStateFailed, contracts.OperationStateCancelled,
					contracts.OperationStateSuperseded, contracts.OperationStateAbandoned:
					out.Failed = true
					if op.Error != nil {
						out.FailCode = contracts.Code(op.Error.Code)
						out.FailMessage = op.Error.Message
						if meta, known := contracts.Lookup(out.FailCode); known {
							out.FailNextAction = meta.NextAction
						}
					}
					out.Registration = r.finalRead(ctx, ns, name)
					return out
				}
				if resp != nil && resp.HasRetryAfter && resp.RetryAfter > 0 {
					next = resp.RetryAfter
				}

			default:
				if apiErr, ok := client.AsAPIError(err); ok &&
					(apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusGone) &&
					(apiErr.Code() == contracts.CodeOperationNotFound || apiErr.Code() == contracts.CodeOperationExpired) {
					// THE OPERATION-LOSS FALLBACK. This is the single most valuable
					// robustness property of the polling design: an apply survives
					// losing the operation record entirely.
					tflog.Info(ctx, "the operation record is gone; falling back to polling the registration",
						map[string]any{"operation_id": operationID, "code": string(apiErr.Code())})
					fallbackToRegistration = true
				} else {
					out.Err = err
					out.Registration = r.finalRead(ctx, ns, name)
					return out
				}
			}
		}

		if fallbackToRegistration {
			reg, gone := r.finalReadOrGone(ctx, ns, name)
			if w.OperationTerminalIsSuccess && gone {
				// The registration is already gone, which for a decommission is
				// exactly what was asked for.
				out.Published = true
				return out
			}
			out.Registration = reg
			if isFulfilled(reg, targetGeneration) {
				out.Published = true
				return out
			}
			if reg != nil && reg.Status.Operation != nil &&
				reg.Status.Operation.State == contracts.RegistrationOperationState(contracts.OperationStateFailed) {
				out.Failed = true
				if reg.Status.Operation.LastError != nil {
					out.FailCode = contracts.Code(reg.Status.Operation.LastError.Code)
					out.FailMessage = reg.Status.Operation.LastError.Message
					if meta, known := contracts.Lookup(out.FailCode); known {
						out.FailNextAction = meta.NextAction
					}
				}
				return out
			}
		}

		// Never poll faster than Retry-After even when the user's timeout is
		// short: rate-limiting the provider's own client is cheaper than a 429.
		wait := jitter(next)
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			break
		}
		if err := r.sleep(ctx, wait); err != nil {
			out.Err = err
			return out
		}
		next = nextBackoff(next)
	}

	// ---------------------- the timeout contract, §7.1.4 --------------------
	//
	// ONE FINAL GET of the registration. If it published while the client was
	// waiting out its backoff, this apply SUCCEEDS.
	out.TimedOut = true
	reg, gone := r.finalReadOrGone(ctx, ns, name)
	if w.OperationTerminalIsSuccess && gone {
		out.Published = true
		out.TimedOut = false
		return out
	}
	out.Registration = reg
	if isFulfilled(reg, targetGeneration) {
		out.Published = true
		out.TimedOut = false
		tflog.Info(ctx, "the wait timed out but the certificate had already published; returning success", map[string]any{
			"namespace": ns, "name": name,
		})
	}
	if reg != nil && reg.Status.Operation != nil && reg.Status.Operation.Phase != nil {
		out.LastPhase = string(*reg.Status.Operation.Phase)
	}
	return out
}

// isFulfilled is the ONE definition of "realised": the published generation has
// caught up with the target AND the phase is ready.
func isFulfilled(reg *contracts.CertificateRegistration, targetGeneration int64) bool {
	if reg == nil {
		return false
	}
	return reg.Status.ObservedGeneration >= targetGeneration && reg.Status.Phase == "ready"
}

func (r *certificateResource) finalRead(ctx context.Context, ns, name string) *contracts.CertificateRegistration {
	reg, _ := r.finalReadOrGone(ctx, ns, name)
	return reg
}

// finalReadOrGone reports whether the registration is typed-gone, which the
// delete path treats as success.
func (r *certificateResource) finalReadOrGone(ctx context.Context, ns, name string) (*contracts.CertificateRegistration, bool) {
	reg, _, err := r.data.Client.GetRegistration(ctx, ns, name, false)
	if err == nil {
		return reg, false
	}
	if apiErr, ok := client.AsAPIError(err); ok &&
		(apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusGone) {
		return nil, true
	}
	return nil, false
}

// nextBackoff is 2s -> 5s -> 10s -> 30s cap (§7.1.3 rule 1).
func nextBackoff(current time.Duration) time.Duration {
	switch {
	case current < 5*time.Second:
		return 5 * time.Second
	case current < 10*time.Second:
		return 10 * time.Second
	default:
		return 30 * time.Second
	}
}

// jitter spreads ±20%, so a fleet-wide apply does not synchronise its polls.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	delta := float64(d) * 0.2
	return time.Duration(float64(d) - delta + rand.Float64()*2*delta)
}
