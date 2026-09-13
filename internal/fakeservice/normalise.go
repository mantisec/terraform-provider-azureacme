package fakeservice

// THE FAKE NORMALISES. IT DOES NOT ECHO.
//
// This file exists because of a specific, expensive failure. The provider's
// eleven acceptance tests all passed while a real `terraform apply` against the
// real service produced a `terraform plan` that was not a diff but a HARD ERROR
// aborting the whole workspace. The reason the suite could not see it: the fake
// echoed the request back. `specReadFrom` copied `destination_id` and
// `verification` from the PUT body verbatim, so every round trip was trivially
// stable, and the single most important property of this provider — apply, then
// an empty plan — was being asserted against a server that could not violate it.
//
// A fake that echoes cannot catch a normalisation mismatch. So the fake
// normalises the way the service does:
//
//   - PROVISIONAL(D-20) `spec.destination.destination_id` is SERVER-RESOLVED.
//     The caller names a vault; the service resolves that name against the
//     namespace's destination policies and persists the POLICY's answer, whether
//     or not the caller supplied one. (The service persists the policy id rather
//     than the caller's assertion so that renewal can re-resolve from the policy;
//     see acmesvc.composition.catalogue.issuance_from_wire.)
//   - `spec.verification.consumer_probe` is MATERIALISED. Whatever the caller
//     sent — including nothing at all — is stored as a complete probe object:
//     `{enabled: false, expected_pickup: null, endpoints: []}` by default. See
//     acmesvc.api.specs.apply_defaults.
//
// Both are the same shape of normalisation, and both made the provider unusable.
// Whoever adds the next normalisation to the service: add it here in the same
// breath, or the acceptance suite will go on passing while the product breaks.
//
// NOTE FOR THE NEXT READER. The fake's `issuanceHash` deliberately does NOT
// cover `destination_id`, while the service's `_DESTINATION_FIELDS` does. That
// asymmetry in the service is what makes every repeat create a `409` rather than
// the `200` §4.2.3 promises (C2 Finding 3, item
// `API-CREATE-IDEMPOTENCY-REACHABLE`). Reproducing it here would wedge the
// provider's own create-idempotency tests against a service defect that is being
// fixed elsewhere, so it is recorded rather than modelled.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// DestinationPolicy is one namespace destination grant: the policy id the
// service resolves to, the vault it grants, and the vault's soft-delete
// posture as the destination policy records it.
type DestinationPolicy struct {
	ID         string
	KeyVaultID string
	// PurgeProtectionEnabled and SoftDeleteRetentionDays are POINTERS because
	// `nil` is a distinct answer on the wire: it means the policy does not
	// record the posture, and the provider must then warn rather than raise
	// §5.4's error. A bool would collapse "unknown" into "false", which is the
	// one mistake the field exists to prevent.
	PurgeProtectionEnabled  *bool
	SoftDeleteRetentionDays *int64
}

// DefaultDestinationPolicyID is the policy id the fake resolves
// DefaultKeyVaultID to, and the id /v1/namespaces/{ns} advertises.
const DefaultDestinationPolicyID = "payments"

// defaultDestinationPolicies is the grant table a fake starts with.
func defaultDestinationPolicies() []DestinationPolicy {
	return []DestinationPolicy{{ID: DefaultDestinationPolicyID, KeyVaultID: DefaultKeyVaultID}}
}

// resolveDestinationIDLocked is the server-side resolution of PROVISIONAL(D-20).
//
// A vault named by a configured policy resolves to that policy's id. A vault
// outside the table still resolves to SOMETHING — `dest-<vault name>` — rather
// than to nothing, so that every create in every test exercises the
// server-resolved path. A fake that only normalised for one blessed vault would
// leave the defect reachable through any other.
func (s *Server) resolveDestinationIDLocked(vaultID string) string {
	for _, p := range s.destinationPoliciesLocked() {
		if strings.EqualFold(strings.TrimSuffix(p.KeyVaultID, "/"), strings.TrimSuffix(vaultID, "/")) {
			return p.ID
		}
	}
	if name := vaultNameFromID(vaultID); name != "" && name != "kv-unknown" {
		return "dest-" + name
	}
	return ""
}

func (s *Server) destinationPoliciesLocked() []DestinationPolicy {
	if len(s.opts.DestinationPolicies) > 0 {
		return s.opts.DestinationPolicies
	}
	return defaultDestinationPolicies()
}

// permittedDestinationsLocked projects the grant table onto the namespace detail,
// so what /v1/namespaces/{ns} advertises and what a PUT resolves to are the same
// table rather than two literals that can drift.
func (s *Server) permittedDestinationsLocked() []contracts.DestinationPolicyView {
	policies := s.destinationPoliciesLocked()
	out := make([]contracts.DestinationPolicyView, 0, len(policies))
	for _, p := range policies {
		out = append(out, contracts.DestinationPolicyView{
			DestinationID:           p.ID,
			KeyVaultID:              p.KeyVaultID,
			PurgeProtectionEnabled:  p.PurgeProtectionEnabled,
			SoftDeleteRetentionDays: p.SoftDeleteRetentionDays,
		})
	}
	return out
}

// normaliseSpecLocked turns a spec the caller wrote into the spec the service
// PERSISTS. Call it on every write path and on every seed, so no stored
// registration is ever the caller's bytes.
//
// `previous` is the spec this write replaces, or nil on a create. It is needed
// because G-8 makes defaults apply AT CREATE ONLY: on an update a field the
// caller omitted takes the value already stored, not today's default.
func (s *Server) normaliseSpecLocked(reg *Registration, previous *contracts.CertificateSpecRead) {
	if reg.Spec.Destination != nil {
		// Server-resolved, not caller-asserted. This is the value that broke
		// `terraform plan`: the configuration says nothing and the response says
		// "payments".
		if resolved := s.resolveDestinationIDLocked(reg.Spec.Destination.KeyVaultID); resolved != "" {
			reg.Spec.Destination.DestinationID = ptr(resolved)
		}
	}
	var previousVerification *contracts.VerificationSpec
	if previous != nil {
		previousVerification = previous.Verification
	}
	reg.Spec.Verification = materialiseVerification(reg.Spec.Verification, previousVerification)
}

// materialiseVerification is acmesvc.api.specs.apply_defaults' treatment of
// `verification`: the block is ALWAYS stored complete, even when the caller sent
// no `verification` at all.
//
// AND IT INHERITS (G-8). A field the caller omitted takes the stored value, not
// the default. That is deliberately reproduced here, unattractive though it is,
// because it is the reason a provider that merely omits the block cannot turn a
// probe off: `enabled` would come back `true` from the previous spec for ever.
// A fake that applied today's default on every write would make the provider's
// revertibility tests pass against behaviour the service does not have.
func materialiseVerification(in, previous *contracts.VerificationSpec) *contracts.VerificationSpec {
	var probeIn, probePrev contracts.ConsumerProbe
	if in != nil && in.ConsumerProbe != nil {
		probeIn = *in.ConsumerProbe
	}
	if previous != nil && previous.ConsumerProbe != nil {
		probePrev = *previous.ConsumerProbe
	}
	enabled := false
	switch {
	case probeIn.Enabled != nil:
		enabled = *probeIn.Enabled
	case probePrev.Enabled != nil:
		// Defaults FALSE at CREATE; on an update the stored value stands.
		enabled = *probePrev.Enabled
	}
	pickup := probeIn.ExpectedPickup
	if pickup == nil {
		pickup = probePrev.ExpectedPickup
	}
	endpointsIn := probeIn.Endpoints
	if endpointsIn == nil {
		endpointsIn = probePrev.Endpoints
	}
	probe := contracts.ConsumerProbe{
		Enabled:        ptr(enabled),
		ExpectedPickup: pickup,
		// The allow-list of _ENDPOINT_FIELDS, rebuilt field by field so a field
		// the service does not know about cannot survive the round trip.
		Endpoints: make([]contracts.ProbeEndpoint, 0, len(endpointsIn)),
	}
	for _, e := range endpointsIn {
		probe.Endpoints = append(probe.Endpoints, contracts.ProbeEndpoint{Host: e.Host, Port: e.Port, SNI: e.SNI})
	}
	return &contracts.VerificationSpec{ConsumerProbe: &probe}
}

// rejectMismatchedDestinationIDLocked implements the contract sentence on
// `destination_id`: "Optional in v1; when supplied it MUST match the resolved
// policy or the request is rejected."
//
// It returns true when it has written a response.
func (s *Server) rejectMismatchedDestinationIDLocked(w http.ResponseWriter, spec contracts.CertificateSpecFields) bool {
	if spec.Destination == nil || spec.Destination.DestinationID == nil || spec.Destination.KeyVaultID == nil {
		return false
	}
	supplied := *spec.Destination.DestinationID
	if supplied == "" {
		return false
	}
	resolved := s.resolveDestinationIDLocked(*spec.Destination.KeyVaultID)
	if resolved == "" || strings.EqualFold(resolved, supplied) {
		return false
	}
	RespondProblem(http.StatusBadRequest, contracts.CodeDestinationNotAuthorised, s.opts.InstanceID,
		WithDetail("the supplied `destination_id` does not name the destination policy this vault resolves to"),
		WithFieldErrors(contracts.ProblemFieldError{
			Field:   "spec.destination.destination_id",
			Code:    string(contracts.CodeDestinationNotAuthorised),
			Message: "this namespace resolves the supplied key_vault_id to destination policy " + resolved,
		}),
	)(w, nil)
	return true
}

// ---------------------------------------------------------------------------
// A SERVICE THAT OMITS A FIELD ITS OWN CONTRACT MARKS REQUIRED
// ---------------------------------------------------------------------------

// NullCurrentCertificateField makes every subsequent GET of this registration
// return its REAL representation with one `status.current_certificate` field
// replaced by JSON `null`.
//
// It exists because that is what the shipped service did with `not_before`
// (C2 Finding 1, item `API-PUBLISH-COMMIT-NOT-BEFORE`): `publish_commit` never
// passed the `not_before_utc` that `ChainRef` already carried, so the projection
// emitted `"not_before": null` on every published registration. `not_before` is
// REQUIRED on `CurrentCertificate`, so the generated Go model decodes it
// non-pointer, `null` becomes "", and the apply died on `Invalid timestamp: ""` —
// after the certificate had already been issued and published.
//
// The knob writes a real JSON `null` rather than an empty string, because
// proving the DECODE is half the point: "" and `null` are indistinguishable after
// decoding into a non-pointer string, and that is exactly why the field being
// marked required buys no protection at all.
func (s *Server) NullCurrentCertificateField(namespace, name, field string) {
	s.AddRule(Rule{
		Match: Match{Method: http.MethodGet, Path: "/v1/namespaces/" + namespace + "/certificates/" + name},
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			s.mu.Lock()
			reg := s.registrations[key(namespace, name)]
			var body []byte
			var revision int64
			if reg != nil {
				revision = reg.Spec.Revision
				body, _ = json.Marshal(s.representationLocked(reg))
			}
			instanceID := s.opts.InstanceID
			s.mu.Unlock()
			if reg == nil {
				RespondProblem(http.StatusNotFound, contracts.CodeRegistrationNotFound, instanceID)(w, nil)
				return
			}
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err == nil {
				if status, ok := doc["status"].(map[string]any); ok {
					if cc, ok := status["current_certificate"].(map[string]any); ok {
						cc[field] = nil
					}
				}
				body, _ = json.Marshal(doc)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Service-Instance-Id", instanceID)
			w.Header().Set("ETag", `W/"`+strconv.FormatInt(revision, 10)+`"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		},
	})
}
