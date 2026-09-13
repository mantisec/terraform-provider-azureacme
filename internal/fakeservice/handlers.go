package fakeservice

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

func key(namespace, name string) string { return namespace + "/" + name }

// serve DISPATCHES ON THE CONTRACT, not on this file's reading of it.
//
// The route table it consults -- routes.gen.go -- is emitted from
// contracts/api/openapi.yaml by contracts/tools/generate.py, so a path renamed
// in the contract moves the fake with it and an operation withdrawn there stops
// this file COMPILING. That is the whole reason the routing half of the fake is
// generated: a fake hand-written from the specification prose and a client
// hand-written from the same prose share one wrong assumption, agree with each
// other, and prove nothing (terraform-provider-contract.md §11.1, §11.3).
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, RecordedRequest{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
		IfMatch: r.Header.Get("If-Match"), IfNoneMatch: r.Header.Get("If-None-Match"),
		IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: r.Header.Get("X-Request-Id"),
		UserAgent: r.Header.Get("User-Agent"), Authorization: r.Header.Get("Authorization"),
		Accept: r.Header.Get("Accept"), Body: string(body),
	})
	instanceID := s.opts.InstanceID
	s.mu.Unlock()

	if handler := s.takeRule(r); handler != nil {
		handler(w, r)
		return
	}

	w.Header().Set("X-Service-Instance-Id", instanceID)
	w.Header().Set("X-Api-Version", s.opts.APIVersion)
	if id := r.Header.Get("X-Request-Id"); id != "" {
		w.Header().Set("X-Request-Id", id)
	}

	route, params, ok := MatchRoute(r.Method, r.URL.Path)
	if !ok {
		// A documented address dialled with the wrong verb answers 405, not 404.
		// The two are not interchangeable to a test author: 404 reads as "the
		// contract has no such endpoint", which would send them to change the
		// contract rather than the request.
		if _, _, documented := RoutesForPath(r.URL.Path); documented {
			s.problem(w, http.StatusMethodNotAllowed, contracts.CodeInvalidSpec)
			return
		}
		s.problem(w, http.StatusNotFound, contracts.CodeRegistrationNotFound)
		return
	}

	cw := s.conformant(w, route)
	switch route.OperationID {
	case OpGetHealth:
		writeJSON(cw, http.StatusOK, map[string]string{"status": "ok"}, nil)
	case OpGetCapabilities:
		s.handleCapabilities(cw)
	case OpListNamespaces:
		s.handleListNamespaces(cw)
	case OpGetNamespace:
		s.handleGetNamespace(cw, params["namespace"])
	case OpListValidationBindings:
		s.handleListBindings(cw)
	case OpGetValidationBinding:
		s.handleGetBinding(cw, params["bindingId"])
	case OpListCertificates:
		s.handleListRegistrations(cw, r, params["namespace"])
	case OpGetCertificate:
		s.handleGetRegistration(cw, r, params["namespace"], params["name"])
	case OpPutCertificate:
		s.handlePutRegistration(cw, r, params["namespace"], params["name"], body, route)
	case OpDeleteCertificate:
		s.handleDeleteRegistration(cw, r, params["namespace"], params["name"])
	case OpGetOperation:
		s.handleOperation(cw, params["operationId"])
	case OpForceRenewCertificate:
		s.handleForceRenew(cw, params["namespace"], params["name"])
	default:
		s.notImplemented(w, route)
	}
}

// conformantWriter fails the test when the fake answers a matched operation with
// a status the contract does not declare for it.
//
// A fake that invents a status is a fake that teaches the client to handle a
// response the service will never send — the mirror image of the client and the
// fake sharing one wrong assumption, and just as invisible. The declared set
// comes from routes.gen.go, so it moves with the contract.
//
// Scripted responses are NOT checked: a rule installed with AddRule exists
// precisely to produce what the contract does not describe — a 302 to a sign-in
// page, an HTML 200 — and takeRule answers before dispatch ever reaches here.
type conformantWriter struct {
	http.ResponseWriter
	fail    func(format string, args ...any)
	route   Route
	written bool
}

func (c *conformantWriter) WriteHeader(status int) {
	if !c.written {
		c.written = true
		if !c.route.DeclaresStatus(status) {
			c.fail("the fake answered %s %s (%s) with %d, which contracts/api/openapi.yaml "+
				"does not declare for that operation. Declared: %v. Either the contract needs the "+
				"status (change contracts/api/openapi.yaml and run `make contracts-generate`) or "+
				"the fake is inventing a response the real service will never send.",
				c.route.Method, c.route.Path, c.route.OperationID, status, c.route.Statuses)
		}
	}
	c.ResponseWriter.WriteHeader(status)
}

func (s *Server) conformant(w http.ResponseWriter, route Route) http.ResponseWriter {
	return &conformantWriter{ResponseWriter: w, fail: s.failf, route: route}
}

// notImplemented answers an operation the contract declares and the fake does not
// model. It FAILS the test rather than returning a plausible-looking 404: a
// silent 404 from an address the service does serve is how a test comes to prove
// nothing at all.
func (s *Server) notImplemented(w http.ResponseWriter, route Route) {
	s.failf("the fake has no behaviour for %s %s (%s). It is a documented operation, so a "+
		"canned 404 would be a lie. Add the handler to internal/fakeservice/, or script the "+
		"response for this one test with AddRule.", route.Method, route.Path, route.OperationID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"detail":"the fake service does not implement ` +
		string(route.OperationID) + `"}` + "\n"))
}

func (s *Server) problem(w http.ResponseWriter, status int, code contracts.Code, opts ...ProblemOption) {
	s.mu.Lock()
	instanceID := s.opts.InstanceID
	s.mu.Unlock()
	RespondProblem(status, code, instanceID, opts...)(w, nil)
}

// ---------------------------------------------------------------- capabilities

func (s *Server) handleCapabilities(w http.ResponseWriter) {
	s.mu.Lock()
	o := s.opts
	s.mu.Unlock()

	profiles := make([]map[string]json.RawMessage, 0, len(o.ACMEProfiles))
	for _, p := range o.ACMEProfiles {
		maxIdentifiers := "100"
		if p == "tlsserver" {
			maxIdentifiers = "25"
		}
		profiles = append(profiles, map[string]json.RawMessage{
			"name":            json.RawMessage(strconv.Quote(p)),
			"max_identifiers": json.RawMessage(maxIdentifiers),
		})
	}
	caps := contracts.Capabilities{
		Caller: contracts.CallerIdentity{
			PrincipalID: o.CallerPrincipalID, PrincipalType: "ServicePrincipal",
			Roles: o.CallerRoles, Namespaces: []string{"payments-prod", "ci"},
		},
		Service: contracts.ServiceCapabilities{
			InstanceID: o.InstanceID, InstanceName: o.InstanceName,
			APIVersion: o.APIVersion, APIVersionsSupported: o.APIVersionsSupported,
			CatalogueSchemaVersion:   1,
			Features:                 o.Features,
			MinimumClientVersion:     o.MinimumClientVersion,
			DeprecatedClientVersion:  o.DeprecatedClientVersion,
			DeprecatedClientDeadline: o.DeprecatedClientDeadline,
			KeyPolicies:              *o.KeyPolicies,
			Limits:                   *o.Limits,
			ConsumerProfiles:         o.ConsumerProfiles,
			PublisherPrincipalID:     &o.PublisherPrincipalID,
			PublisherClientID:        &o.PublisherClientID,
			Audience:                 optionalString(o.ReportedAudience),
			ACME: contracts.AcmeCapabilities{
				DefaultProfile: o.DefaultACMEProfile, DirectoryURL: "https://localhost:14000/dir",
				Environment: "staging", Profiles: profiles,
			},
		},
	}
	writeJSON(w, http.StatusOK, caps, nil)
}

// optionalString renders "" as an absent field rather than an empty one, so a
// fake that was not told to report a value produces the same document a service
// that does not report one produces.
func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// ------------------------------------------------------------------ discovery

func (s *Server) handleListNamespaces(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []contracts.NamespaceSummary{}
	for _, ns := range s.namespaceNamesLocked() {
		items = append(items, contracts.NamespaceSummary{Namespace: ns, Enabled: true, CallerRoles: s.opts.CallerRoles})
	}
	writeJSON(w, http.StatusOK, contracts.NamespaceCollection{Items: items}, nil)
}

func (s *Server) namespaceNamesLocked() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range s.opts.Namespaces {
		if !seen[n.Namespace] {
			seen[n.Namespace] = true
			out = append(out, n.Namespace)
		}
	}
	for _, ns := range []string{"payments-prod", "ci"} {
		if !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleGetNamespace(w http.ResponseWriter, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.opts.Namespaces {
		if n.Namespace == name {
			writeJSON(w, http.StatusOK, n, nil)
			return
		}
	}
	detail := contracts.NamespaceDetail{
		Namespace: name, Enabled: true, PolicyRevision: 7,
		CallerRoles:                  s.opts.CallerRoles,
		MaxIdentifiersPerCertificate: 100,
		DefaultDeletionPolicy:        contracts.DeletionPolicyRetain,
		AllowedDeletionPolicies:      []contracts.DeletionPolicy{contracts.DeletionPolicyRetain, contracts.DeletionPolicyDelete},
		AllowedKeyPolicies:           []contracts.AllowedKeyPolicy{{Algorithm: "RSA", Sizes: []int64{2048, 3072, 4096}}},
		PermittedDomains:             []contracts.DomainRuleView{{Base: "example.com", Kind: "subtree", MaxLabelsBelow: ptr(int64(2))}},
		PermittedDestinations:        s.permittedDestinationsLocked(),
		WildcardPolicy:               map[string]json.RawMessage{"allowed": json.RawMessage("false")},
	}
	writeJSON(w, http.StatusOK, detail, nil)
}

func (s *Server) handleListBindings(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, contracts.ValidationBindingCollection{Items: s.opts.ValidationBindings}, nil)
}

func (s *Server) handleGetBinding(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.opts.ValidationBindings {
		if b.ID == id {
			writeJSON(w, http.StatusOK, b, nil)
			return
		}
	}
	RespondProblem(http.StatusNotFound, contracts.CodeValidationBindingNotAuthorised, s.opts.InstanceID)(w, nil)
}

// -------------------------------------------------------------- registrations

func (s *Server) handleListRegistrations(w http.ResponseWriter, r *http.Request, namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []string
	for k, reg := range s.registrations {
		if reg.Tombstoned || reg.Namespace != namespace {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pageSize := s.opts.PageSize
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pageSize = n
		}
	}
	start := 0
	if token := r.URL.Query().Get("page_token"); token != "" {
		if n, err := strconv.Atoi(token); err == nil {
			start = n
		}
	}
	end := start + pageSize
	if end > len(keys) {
		end = len(keys)
	}
	items := []contracts.RegistrationSummary{}
	for _, k := range keys[start:end] {
		reg := s.registrations[k]
		specJSON, _ := json.Marshal(reg.Spec)
		statusJSON, _ := json.Marshal(reg.Status)
		var specMap, statusMap map[string]json.RawMessage
		_ = json.Unmarshal(specJSON, &specMap)
		_ = json.Unmarshal(statusJSON, &statusMap)
		items = append(items, contracts.RegistrationSummary{
			Namespace: reg.Namespace, Name: reg.Name, RegistrationID: reg.RegistrationID,
			Spec: specMap, Status: statusMap,
			Links: contracts.Links{Self: "/v1/namespaces/" + reg.Namespace + "/certificates/" + reg.Name},
		})
	}
	out := contracts.RegistrationCollection{Items: items}
	if end < len(keys) {
		next := strconv.Itoa(end)
		out.NextPageToken = &next
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) handleGetRegistration(w http.ResponseWriter, _ *http.Request, namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := s.registrations[key(namespace, name)]
	if !ok {
		RespondProblem(http.StatusNotFound, contracts.CodeRegistrationNotFound, s.opts.InstanceID)(w, nil)
		return
	}
	if reg.Tombstoned {
		RespondProblem(http.StatusGone, contracts.CodeRegistrationDeleted, s.opts.InstanceID)(w, nil)
		return
	}
	writeJSON(w, http.StatusOK, s.representationLocked(reg), map[string]string{
		"ETag": `W/"` + strconv.FormatInt(reg.Spec.Revision, 10) + `"`,
	})
}

func (s *Server) handlePutRegistration(w http.ResponseWriter, r *http.Request, namespace, name string, body []byte, route Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ifNoneMatch := r.Header.Get("If-None-Match")
	ifMatch := r.Header.Get("If-Match")

	// The rule that makes lost updates structurally impossible, and that fails
	// the PROVIDER's own suite if it ever forgets a precondition (F-015).
	//
	// WHICH OPERATIONS CARRY IT IS THE CONTRACT'S ANSWER, not this file's:
	// route.RequiresPrecondition is generated from openapi.yaml and is true only
	// where the document declares `428` AND accepts both conditional headers.
	// DELETE takes an optional `If-Match` and declares no `428`, so it is not
	// swept up by a rule that said "every mutation needs a precondition".
	if route.RequiresPrecondition && s.behaviour.requirePrecondition() &&
		ifNoneMatch == "" && ifMatch == "" {
		RespondProblem(http.StatusPreconditionRequired, contracts.CodePreconditionRequired, s.opts.InstanceID)(w, nil)
		return
	}

	var envelope contracts.CertificateSpecEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		RespondProblem(http.StatusBadRequest, contracts.CodeInvalidSpec, s.opts.InstanceID,
			WithDetail("the request body did not parse"))(w, nil)
		return
	}
	incoming := envelope.Spec
	// PROVISIONAL(D-20): `destination_id` is optional, and when supplied it MUST
	// match the policy the vault resolves to or the request is rejected.
	if s.rejectMismatchedDestinationIDLocked(w, incoming) {
		return
	}
	newHash := issuanceHash(incoming)

	existing, exists := s.registrations[key(namespace, name)]
	if exists && existing.Tombstoned {
		exists = false
	}

	if ifNoneMatch == "*" {
		if exists {
			// §4.2.3: a matching hash AND a matching owner is the create
			// idempotency case and returns 200; anything else is a conflict.
			if existing.Spec.Hash == newHash && existing.OwnerPrincipalID == s.opts.CallerPrincipalID {
				writeJSON(w, http.StatusOK, s.representationLocked(existing), map[string]string{
					"ETag": `W/"` + strconv.FormatInt(existing.Spec.Revision, 10) + `"`,
				})
				return
			}
			RespondProblem(http.StatusConflict, contracts.CodeRegistrationExists, s.opts.InstanceID)(w, nil)
			return
		}
	} else {
		if !exists {
			RespondProblem(http.StatusNotFound, contracts.CodeRegistrationNotFound, s.opts.InstanceID)(w, nil)
			return
		}
		want := `W/"` + strconv.FormatInt(existing.Spec.Revision, 10) + `"`
		if ifMatch != want {
			RespondProblem(http.StatusPreconditionFailed, contracts.CodeSpecRevisionConflict, s.opts.InstanceID,
				WithDetail(fmt.Sprintf("the registration is at revision %d; the request carried %s. It was last changed by %s.",
					existing.Spec.Revision, ifMatch, "another-principal@example.com")))(w, nil)
			return
		}
	}

	reg := existing
	if !exists {
		reg = &Registration{
			Namespace: namespace, Name: name,
			RegistrationID:   s.nextID("reg_"),
			OwnerPrincipalID: s.opts.CallerPrincipalID,
			Status: contracts.RegistrationStatus{
				LifecycleState: "active", Phase: "pending", DeliveryStage: "pending",
				ObservedGeneration: 0,
			},
		}
		s.registrations[key(namespace, name)] = reg
	}

	previousHash := reg.Spec.Hash
	previousRevision := reg.Spec.Revision
	previousGeneration := reg.Spec.Generation
	// G-8: on an UPDATE an omitted field inherits the stored value, so the spec
	// being replaced has to be kept until normalisation has read it.
	var previousSpec *contracts.CertificateSpecRead
	if exists {
		stored := reg.Spec
		previousSpec = &stored
	}

	reg.Spec = specReadFrom(incoming)
	// THE FAKE NORMALISES, IT DOES NOT ECHO. See normalise.go: this is the line
	// whose absence let eleven green acceptance tests coexist with a `terraform
	// plan` that aborted the whole workspace.
	s.normaliseSpecLocked(reg, previousSpec)
	reg.Spec.Hash = newHash
	reg.Spec.Revision = previousRevision + 1
	reg.Spec.Generation = previousGeneration
	if newHash != previousHash {
		reg.Spec.Generation = previousGeneration + 1
	}
	s.refreshResolvedLocked(reg)

	if reg.Spec.Generation == previousGeneration && exists {
		// Metadata or policy-only change: no operation is started. spec.revision
		// still bumped — only spec.generation is conditional on the hash.
		writeJSON(w, http.StatusOK, s.representationLocked(reg), map[string]string{
			"ETag": `W/"` + strconv.FormatInt(reg.Spec.Revision, 10) + `"`,
		})
		return
	}

	op := s.startOperationLocked(reg, contracts.OperationTypeIssue)
	accepted := contracts.OperationAccepted{
		OperationID: op.op.ID, RegistrationID: reg.RegistrationID, Status: "accepted",
		TargetGeneration: reg.Spec.Generation,
		Registration:     ptr(s.representationLocked(reg)),
	}
	if s.behaviour.DeferOperation {
		start := s.behaviour.DeferEstimatedStart
		if start.IsZero() {
			start = time.Now().UTC().Add(7 * 24 * time.Hour)
		}
		formatted := primitives.FormatTimestamp(start)
		accepted.EstimatedStart = &formatted
		accepted.DeferralBudget = s.behaviour.DeferBudget
	}
	writeJSON(w, http.StatusAccepted, accepted, map[string]string{
		"Operation-Location": "/v1/operations/" + op.op.ID,
		"Retry-After":        "1",
		"ETag":               `W/"` + strconv.FormatInt(reg.Spec.Revision, 10) + `"`,
	})
}

func (s *Server) handleDeleteRegistration(w http.ResponseWriter, r *http.Request, namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, ok := s.registrations[key(namespace, name)]
	if !ok {
		RespondProblem(http.StatusNotFound, contracts.CodeRegistrationNotFound, s.opts.InstanceID)(w, nil)
		return
	}
	if reg.Tombstoned {
		RespondProblem(http.StatusGone, contracts.CodeRegistrationDeleted, s.opts.InstanceID)(w, nil)
		return
	}
	if s.behaviour.RecentlyPublishedGuard && reg.Status.CurrentCertificate != nil {
		// The anti-destruction guard. The certificate was published after the
		// revision the caller last observed, so destroying now would discard a
		// certificate this workspace has never seen.
		RespondProblem(http.StatusConflict, contracts.CodeDestinationRecentlyPublished, s.opts.InstanceID,
			WithDetail(fmt.Sprintf("the current certificate was published at %s, after the revision the caller last observed",
				orNow(reg.Status.CurrentCertificate.PublishedAt))))(w, nil)
		return
	}
	requested := r.URL.Query().Get("policy")
	persisted := string(contracts.DeletionPolicyRetain)
	if reg.Spec.DeletionPolicy != nil {
		persisted = string(*reg.Spec.DeletionPolicy)
	}
	// The persisted policy is AUTHORITATIVE and ?policy= may only NARROW.
	if requested == string(contracts.DeletionPolicyDelete) && persisted == string(contracts.DeletionPolicyRetain) {
		RespondProblem(http.StatusConflict, contracts.CodeDeletionPolicyConflict, s.opts.InstanceID,
			WithDetail(fmt.Sprintf("the persisted deletion policy is %q and the request asked for %q; "+
				"the persisted policy was set by %s and may only be narrowed.", persisted, requested, "platform-admin@example.com")))(w, nil)
		return
	}
	reg.Tombstoned = true
	op := s.startOperationLocked(reg, contracts.OperationTypeDelete)
	writeJSON(w, http.StatusAccepted, contracts.OperationAccepted{
		OperationID: op.op.ID, RegistrationID: reg.RegistrationID, Status: "accepted",
		TargetGeneration: reg.Spec.Generation,
	}, map[string]string{
		"Operation-Location": "/v1/operations/" + op.op.ID,
		"Retry-After":        "1",
	})
}

// ---------------------------------------------------------------- operations

func (s *Server) startOperationLocked(reg *Registration, opType contracts.OperationType) *operationState {
	id := s.nextID("op_")
	now := primitives.FormatTimestamp(time.Now().UTC())
	state := contracts.OperationStateRunning
	if s.behaviour.DeferOperation {
		state = contracts.OperationStateDeferred
	}
	regRef := map[string]json.RawMessage{
		"namespace": json.RawMessage(strconv.Quote(reg.Namespace)),
		"name":      json.RawMessage(strconv.Quote(reg.Name)),
	}
	op := &operationState{
		namespace: reg.Namespace, name: reg.Name, registrationID: reg.RegistrationID,
		op: contracts.Operation{
			ID: id, Type: opType, State: state, TargetGeneration: reg.Spec.Generation,
			CreatedAt: now, UpdatedAt: now, Registration: regRef,
			Phase: ptr(contracts.OperationPhaseQueued), RetryAfter: ptr("1"),
		},
	}
	if s.behaviour.DeferOperation {
		start := s.behaviour.DeferEstimatedStart
		if start.IsZero() {
			start = time.Now().UTC().Add(7 * 24 * time.Hour)
		}
		formatted := primitives.FormatTimestamp(start)
		op.op.EstimatedStart = &formatted
		op.op.DeferralReason = ptr(string(contracts.CodeACMERateLimited))
		op.op.DeferralBudget = s.behaviour.DeferBudget
	}
	s.operations[id] = op
	reg.Status.Operation = &contracts.OperationSummary{
		ID: &id, Type: &opType, State: contracts.RegistrationOperationState(state),
		Phase: ptr(contracts.OperationPhaseQueued), StartedAt: &now,
	}
	reg.Status.Phase = "issuing"
	return op
}

func (s *Server) handleOperation(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.operations[id]
	if !ok {
		RespondProblem(http.StatusNotFound, contracts.CodeOperationNotFound, s.opts.InstanceID)(w, nil)
		return
	}
	op.polls++
	if n := s.behaviour.OperationExpiresAfterPolls; n > 0 && op.polls > n {
		// The operation record aged out. The client MUST fall back to the
		// registration rather than failing the apply (§7.1.3 rule 3).
		s.maybeFulfilLocked(op)
		RespondProblem(http.StatusGone, contracts.CodeOperationExpired, s.opts.InstanceID)(w, nil)
		return
	}
	s.advanceOperationLocked(op)
	headers := map[string]string{}
	if !terminal(op.op.State) {
		headers["Retry-After"] = "1"
	}
	writeJSON(w, http.StatusOK, op.op, headers)
}

func terminal(state contracts.OperationState) bool {
	switch state {
	case contracts.OperationStateSucceeded, contracts.OperationStateFailed,
		contracts.OperationStateCancelled, contracts.OperationStateSuperseded, contracts.OperationStateAbandoned:
		return true
	}
	return false
}

func (s *Server) advanceOperationLocked(op *operationState) {
	b := s.behaviour
	op.op.UpdatedAt = primitives.FormatTimestamp(time.Now().UTC())

	// The stuck-issuance knobs model a stuck ISSUANCE. A decommission always
	// completes: modelling a permanently stuck delete would only make every
	// scenario's cleanup hang, and it is not a failure mode any test needs.
	if op.op.Type == contracts.OperationTypeDelete {
		op.op.State = contracts.OperationStateSucceeded
		op.op.Phase = ptr(contracts.OperationPhaseDone)
		completed := primitives.FormatTimestamp(time.Now().UTC())
		op.op.CompletedAt = &completed
		return
	}
	if b.DeferOperation {
		op.op.State = contracts.OperationStateDeferred
		return
	}
	if op.polls <= b.PollsBeforeTerminal {
		op.op.State = contracts.OperationStateRunning
		op.op.Phase = ptr(phaseForPoll(op.polls))
		s.syncOperationSummaryLocked(op)
		return
	}
	if b.OperationNeverCompletes {
		op.op.State = contracts.OperationStateRunning
		op.op.Phase = ptr(phaseForPoll(op.polls))
		s.syncOperationSummaryLocked(op)
		if b.CompleteRegistrationDespiteTimeout {
			// The operation record still says running, but the work FINISHED.
			// This is the case §7.1.4 exists for: the provider re-reads the
			// registration on timeout and must return SUCCESS.
			s.maybeFulfilLocked(op)
		}
		return
	}
	if b.OperationFails {
		code := b.OperationFailCode
		if code == "" {
			code = contracts.CodeACMEChallengeFailed
		}
		meta, _ := contracts.Lookup(code)
		op.op.State = contracts.OperationStateFailed
		op.op.Phase = ptr(contracts.OperationPhaseAwaitingValidation)
		op.op.Error = &contracts.OperationError{Code: string(code), Message: meta.Title, Retryable: meta.Retryable}
		completed := primitives.FormatTimestamp(time.Now().UTC())
		op.op.CompletedAt = &completed
		if reg := s.registrations[key(op.namespace, op.name)]; reg != nil {
			reg.Status.Phase = "failed"
			reg.Status.Operation = &contracts.OperationSummary{
				ID: &op.op.ID, Type: &op.op.Type, State: contracts.RegistrationOperationState(op.op.State),
				Phase: op.op.Phase,
				LastError: &contracts.OperationError{
					Code: string(code), Message: meta.Title, Retryable: meta.Retryable,
				},
			}
		}
		return
	}
	op.op.State = contracts.OperationStateSucceeded
	op.op.Phase = ptr(contracts.OperationPhaseDone)
	completed := primitives.FormatTimestamp(time.Now().UTC())
	op.op.CompletedAt = &completed
	s.maybeFulfilLocked(op)
}

func phaseForPoll(n int) contracts.OperationPhase {
	phases := []contracts.OperationPhase{
		contracts.OperationPhaseQueued,
		contracts.OperationPhaseCreatingOrder,
		contracts.OperationPhasePublishingChallenges,
		contracts.OperationPhaseAwaitingDnsPropagation,
		contracts.OperationPhaseAwaitingValidation,
		contracts.OperationPhaseFinalisingOrder,
		contracts.OperationPhasePublishingToKeyVault,
	}
	if n <= 0 {
		return phases[0]
	}
	if n >= len(phases) {
		return phases[len(phases)-1]
	}
	return phases[n]
}

func (s *Server) syncOperationSummaryLocked(op *operationState) {
	reg := s.registrations[key(op.namespace, op.name)]
	if reg == nil {
		return
	}
	reg.Status.Operation = &contracts.OperationSummary{
		ID: &op.op.ID, Type: &op.op.Type,
		State: contracts.RegistrationOperationState(op.op.State), Phase: op.op.Phase,
	}
}

// maybeFulfilLocked publishes the target generation: observed_generation catches
// up, phase becomes ready, delivery_stage becomes published, and
// current_certificate appears.
func (s *Server) maybeFulfilLocked(op *operationState) {
	reg := s.registrations[key(op.namespace, op.name)]
	if reg == nil {
		return
	}
	if op.op.Type == contracts.OperationTypeDelete {
		return
	}
	if reg.Status.ObservedGeneration >= op.op.TargetGeneration && reg.Status.CurrentCertificate != nil {
		return
	}
	reg.Status.ObservedGeneration = op.op.TargetGeneration
	reg.Status.Phase = "ready"
	reg.Status.DeliveryStage = "published"
	reg.Status.Operation = &contracts.OperationSummary{
		ID: &op.op.ID, Type: &op.op.Type,
		State: contracts.RegistrationOperationState(contracts.OperationStateSucceeded),
		Phase: ptr(contracts.OperationPhaseDone),
	}
	s.issueCertificateLocked(reg)
}

func orNow(v *string) string {
	if v == nil {
		return primitives.FormatTimestamp(time.Now().UTC())
	}
	return *v
}
