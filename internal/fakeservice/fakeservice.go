// Package fakeservice is the scriptable in-process fake of the certificate
// service (terraform-provider-contract.md §11.1, PROV-FAKE-SERVICE-HARNESS).
//
// WHY IT EXISTS. The dangerous logic in this provider — the four-part removal
// conjunction in Read, the create timeout contract, the destination-change plan
// error — can only be tested by producing failure modes ON DEMAND. A real service
// cannot be asked for a 302 to a sign-in page, an HTML 200, an untyped 404, or a
// 404 stamped with a DIFFERENT service instance id; those are exactly the
// responses that must not remove a live certificate from state.
//
// WHAT IT IS. An httptest.Server with real state (registrations, operations,
// generations, revisions) implementing the subset of contracts/api/openapi.yaml
// the provider uses, plus a rule engine that lets one test override any single
// response. It needs no network and no Azure credentials, and every response it
// produces is built from the GENERATED types in internal/contracts, so a field
// renamed in the contract breaks compilation here rather than surfacing as a
// mysterious decode failure in production.
//
// HOW TO USE IT FROM ANOTHER PACKAGE:
//
//	srv := fakeservice.New(t)                 // t.Cleanup closes it
//	srv.SeedRegistration(fakeservice.RegistrationSeed{...})
//	client, _ := client.New(client.Config{Endpoint: srv.URL()})
//
// and for a scripted failure:
//
//	srv.AddRule(fakeservice.Rule{
//	    Match:   fakeservice.Match{Method: "GET", PathSuffix: "/certificates/api"},
//	    Times:   1,
//	    Handler: fakeservice.RespondHTML(http.StatusOK),
//	})
package fakeservice

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// DefaultInstanceID is the service instance id the fake reports unless told
// otherwise. Service-instance pinning (§3.3) is checked against it.
const DefaultInstanceID = "01J9K3M7QW8ZC5VN0X4P6R2TAB"

// DefaultCallerPrincipalID is the caller identity reported by /v1/capabilities.
const DefaultCallerPrincipalID = "11111111-2222-3333-4444-555555555555"

// Options configures a fake service instance.
type Options struct {
	InstanceID               string
	InstanceName             string
	APIVersion               string
	APIVersionsSupported     []string
	MinimumClientVersion     string
	DeprecatedClientVersion  *string
	DeprecatedClientDeadline *string
	Features                 []string
	CallerPrincipalID        string
	CallerRoles              []string
	KeyPolicies              *contracts.KeyPolicies
	Limits                   *contracts.Limits
	ConsumerProfiles         []contracts.ConsumerProfile
	PublisherPrincipalID     string
	PublisherClientID        string
	ACMEProfiles             []string
	DefaultACMEProfile       string
	ValidationBindings       []contracts.ValidationBinding
	Namespaces               []contracts.NamespaceDetail
	// PageSize bounds a list page, so the pagination path is exercised without
	// seeding hundreds of registrations by hand.
	PageSize int
}

// Behaviour holds the scenario knobs that change how the fake drives an
// operation to completion.
type Behaviour struct {
	// PollsBeforeTerminal is how many GET /operations calls return a non-terminal
	// state before the operation succeeds. 0 means the operation is already
	// terminal on the first poll.
	PollsBeforeTerminal int
	// OperationNeverCompletes keeps the operation running forever. This is the
	// create-timeout scenario: the client must give up, and the SERVICE MUST KEEP
	// WORKING — which is what makes a destroy-and-reissue on the next apply so
	// destructive.
	OperationNeverCompletes bool
	// CompleteRegistrationDespiteTimeout completes the REGISTRATION (fulfilled
	// generation and phase ready) while leaving the operation record running.
	// This is the "timed out after it actually succeeded" case of §7.1.4, and the
	// provider must return SUCCESS.
	CompleteRegistrationDespiteTimeout bool
	// OperationExpiresAfterPolls makes GET /operations return 410
	// operation_expired after N polls, exercising the fallback to the
	// registration (§7.1.3 rule 3).
	OperationExpiresAfterPolls int
	// DeferOperation reports state "deferred" with EstimatedStart.
	DeferOperation      bool
	DeferEstimatedStart time.Time
	// OperationFails makes the operation terminate in `failed` with this code.
	OperationFails    bool
	OperationFailCode contracts.Code
	// RecentlyPublishedGuard makes DELETE refuse with
	// `409 destination_recently_published` whenever a certificate is published.
	//
	// It models the service-side anti-destruction guard of service contract
	// §4.5.3 — the guard that is what makes the client's taint-and-resume
	// recovery SAFE BY CONTRACT rather than by hope. It is opt-in because the
	// real guard is scoped to a revision window the fake does not track, and
	// leaving it on would refuse every destroy in every scenario.
	RecentlyPublishedGuard bool
	// RequirePrecondition rejects a PUT carrying neither If-None-Match nor
	// If-Match with 428. It is ON by default: the point is to fail the PROVIDER's
	// test suite if it ever forgets one.
	RequirePrecondition *bool
}

func (b Behaviour) requirePrecondition() bool {
	if b.RequirePrecondition == nil {
		return true
	}
	return *b.RequirePrecondition
}

// Server is the fake service.
type Server struct {
	t    *testing.T
	http *httptest.Server

	mu            sync.Mutex
	opts          Options
	behaviour     Behaviour
	registrations map[string]*Registration
	operations    map[string]*operationState
	rules         []*Rule
	requests      []RecordedRequest
	seq           int
}

// RecordedRequest is one observed request, for the "asserted by counting
// requests" acceptance criteria.
type RecordedRequest struct {
	Method         string
	Path           string
	Query          string
	IfMatch        string
	IfNoneMatch    string
	IdempotencyKey string
	RequestID      string
	UserAgent      string
	Authorization  string
	Accept         string
	Body           string
}

// Registration is the fake's stored state for one registration.
type Registration struct {
	Namespace        string
	Name             string
	RegistrationID   string
	Spec             contracts.CertificateSpecRead
	Status           contracts.RegistrationStatus
	OwnerPrincipalID string
	Tombstoned       bool
	Warnings         []contracts.Warning
	SystemLabels     map[string]string
}

type operationState struct {
	op             contracts.Operation
	namespace      string
	name           string
	polls          int
	registrationID string
}

// New starts a fake service with sensible defaults and registers cleanup.
func New(t *testing.T, opts ...func(*Options)) *Server {
	t.Helper()
	o := Options{
		InstanceID:           DefaultInstanceID,
		InstanceName:         "acme-ci",
		APIVersion:           "1.0",
		APIVersionsSupported: []string{"1.0"},
		MinimumClientVersion: "0.1.0",
		Features:             []string{},
		CallerPrincipalID:    DefaultCallerPrincipalID,
		CallerRoles:          []string{"Certificates.Read", "Certificates.Manage", "Certificates.Operate"},
		PublisherPrincipalID: "99999999-8888-7777-6666-555555555555",
		PublisherClientID:    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ACMEProfiles:         []string{"classic", "tlsserver"},
		DefaultACMEProfile:   "classic",
		PageSize:             50,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.KeyPolicies == nil {
		// v1 advertises RSA only and exportable [true]; EC stays REPRESENTABLE in
		// the schema so enabling it later is a service policy change.
		o.KeyPolicies = &contracts.KeyPolicies{
			Algorithms: []string{"RSA"},
			RSASizes:   []int64{2048, 3072, 4096},
			Curves:     []string{},
			Exportable: []bool{true},
		}
	}
	if o.Limits == nil {
		o.Limits = &contracts.Limits{
			MaxDNSNames:        ptr(int64(100)),
			MaxLabels:          ptr(int64(20)),
			MaxLabelKeyBytes:   ptr(int64(128)),
			MaxLabelValueBytes: ptr(int64(256)),
			MaxProbeEndpoints:  ptr(int64(10)),
			MaxPageSize:        ptr(int64(200)),
		}
	}
	if o.ConsumerProfiles == nil {
		o.ConsumerProfiles = []contracts.ConsumerProfile{
			{Name: "application_gateway", RequiresExportable: true, ExpectedPickup: ptr("4h")},
			{Name: "front_door", RequiresExportable: true, ExpectedPickup: ptr("72h")},
			{Name: "app_service", RequiresExportable: true, ExpectedPickup: ptr("48h")},
			{Name: "keyvault_crypto_only", RequiresExportable: false},
		}
	}
	if o.ValidationBindings == nil {
		o.ValidationBindings = []contracts.ValidationBinding{
			{ID: "example-com", Mode: "delegated", Healthy: true, WildcardsAllowed: false,
				PermittedNamePatterns: []string{"*.example.com", "example.com"}, ZoneID: ptr("example.com")},
			{ID: "wild-example-com", Mode: "delegated", Healthy: true, WildcardsAllowed: true,
				PermittedNamePatterns: []string{"*.wild.example.com"}, ZoneID: ptr("wild.example.com")},
		}
	}
	s := &Server{
		t:             t,
		opts:          o,
		registrations: map[string]*Registration{},
		operations:    map[string]*operationState{},
	}
	s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.http.Close)
	return s
}

// URL is the base endpoint, WITHOUT the /v1 prefix — exactly what the provider's
// `endpoint` attribute takes.
func (s *Server) URL() string { return s.http.URL }

// Close stops the server early. t.Cleanup already does this.
func (s *Server) Close() { s.http.Close() }

// InstanceID is the id the fake stamps into every 404 and 410, and reports at
// /v1/capabilities.
func (s *Server) InstanceID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.InstanceID
}

// SetBehaviour replaces the scenario knobs.
func (s *Server) SetBehaviour(b Behaviour) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behaviour = b
}

// Requests returns everything observed so far.
func (s *Server) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RecordedRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// RequestCount counts observed requests matching a method and path substring.
// Pass "" to match anything.
func (s *Server) RequestCount(method, pathSubstring string) int {
	n := 0
	for _, r := range s.Requests() {
		if method != "" && r.Method != method {
			continue
		}
		if pathSubstring != "" && !strings.Contains(r.Path, pathSubstring) {
			continue
		}
		n++
	}
	return n
}

// ResetRequests clears the recorded log, so a test can count only the requests
// made by the step it cares about.
func (s *Server) ResetRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}

func ptr[T any](v T) *T { return &v }

func (s *Server) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s%026d", prefix, s.seq)
}

func writeJSON(w http.ResponseWriter, status int, body any, headers map[string]string) {
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}
