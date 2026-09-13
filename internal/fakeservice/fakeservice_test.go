package fakeservice_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

func newClient(t *testing.T, srv *fakeservice.Server) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{
		Endpoint: srv.URL(), Audience: "api://mantisec-acme",
		Tokens:    client.StaticTokenSource{Value: "test-token"},
		UserAgent: "terraform-provider-azureacme/test (+terraform/test) Go/test",
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHarnessRunsWithNoNetworkAndNoCredentials.
//
// It binds to loopback through httptest and authenticates nothing. This test
// exists so the property is asserted rather than assumed.
func TestHarnessRunsWithNoNetworkAndNoCredentials(t *testing.T) {
	for _, k := range []string{
		"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "ARM_CLIENT_ID",
		"ARM_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_ENDPOINT", "MSI_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
	srv := fakeservice.New(t)
	if !strings.HasPrefix(srv.URL(), "http://127.0.0.1:") && !strings.HasPrefix(srv.URL(), "http://[::1]:") {
		t.Fatalf("the fake bound to %q; it must be loopback-only", srv.URL())
	}
	c, err := client.New(client.Config{Endpoint: srv.URL()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetCapabilities(context.Background()); err != nil {
		t.Fatalf("the harness needs no credentials: %v", err)
	}
}

// TestRoutesExistInTheOpenAPIContract is the drift check.
//
// Every route the fake serves must correspond to a path template in
// contracts/api/openapi.yaml. Without this the fake and the client could share
// the same wrong assumption about a path and the tests would prove nothing.
//
// It compares FULL paths — the address a client dials — not the templates
// relative to the document's server. That is the comparison that matters: the
// real service registers `v1/...` and `healthz` with the Functions host and is
// reachable at the document's paths only because host.json sets
// extensions.http.routePrefix to "" (API-HOST-ROUTE-PREFIX). A template-only
// comparison is satisfied by a service serving everything one segment away at
// /api/..., which is the failure the full-path form catches. The real service
// is held to the same document by its own conformance suite
// (functionapp-azureacme/tests/api/test_openapi_conformance.py and
// test_host_wiring.py), so this test is the provider half of "the harness and
// the service agree on the path set".
//
// LIMITATION, stated plainly: this checks the ROUTE SET, not the response
// schemas. The response bodies are built from internal/contracts, which IS
// generated from the same document, so a renamed FIELD breaks compilation here;
// a renamed PATH is what this test catches.
func TestRoutesExistInTheOpenAPIContract(t *testing.T) {
	documented := documentedFullPaths(t)

	// The routes the fake implements, as the FULL paths a client dials.
	served := []string{
		"/healthz",
		"/v1/capabilities",
		"/v1/namespaces",
		"/v1/namespaces/{namespace}",
		"/v1/namespaces/{namespace}/certificates",
		"/v1/namespaces/{namespace}/certificates/{name}",
		"/v1/namespaces/{namespace}/certificates/{name}/actions/force-renew",
		"/v1/operations/{operationId}",
		"/v1/validation-bindings",
		"/v1/validation-bindings/{bindingId}",
	}
	for _, route := range served {
		if !documented[route] {
			var known []string
			for p := range documented {
				known = append(known, p)
			}
			sort.Strings(known)
			t.Errorf("the fake serves %q, which is not a path in contracts/api/openapi.yaml.\nDocumented paths:\n  %s",
				route, strings.Join(known, "\n  "))
		}
	}
	// /healthz is served outside the /v1 prefix, exactly as the contract says:
	// the per-operation `servers` override takes the liveness route off the
	// compatibility boundary. A reader that resolves "server URL + path" and
	// ignores the override dials /v1/healthz and gets nothing.
	if !documented["/healthz"] {
		t.Error("the contract no longer documents /healthz at the root; the per-operation servers override is what puts it there")
	}
	if documented["/v1/healthz"] {
		t.Error("the contract documents /v1/healthz; liveness is deliberately outside the /v1 compatibility boundary")
	}
}

// TestFakeAnswersAtTheDocumentedAddresses proves the agreement is about serving
// and not about declaring: the fake answers on the paths the document gives,
// and on nothing under the Azure Functions default `api` route prefix. A fake
// that quietly moved its routes would let every client test pass against an
// address the real service does not serve.
func TestFakeAnswersAtTheDocumentedAddresses(t *testing.T) {
	documented := documentedFullPaths(t)
	for _, path := range []string{"/healthz", "/v1/capabilities"} {
		if !documented[path] {
			t.Fatalf("%s is no longer a documented path; this test is checking the wrong address", path)
		}
	}

	srv := fakeservice.New(t)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/healthz", http.StatusOK},
		{"/v1/capabilities", http.StatusOK},
		// The Functions default prefix. Nothing is served there, on either side.
		{"/api/healthz", http.StatusNotFound},
		{"/api/v1/capabilities", http.StatusNotFound},
	} {
		resp, err := c.Get(srv.URL() + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s returned %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}
}

// documentedFullPaths resolves contracts/api/openapi.yaml onto the addresses a
// client dials: the document's single server contributes `/v1`, and an
// operation carrying its own `servers` override is served at the root instead.
// Only /healthz does that today, and the override is deliberate (spec §4.1) —
// hence the guard below, so a formatting change cannot silently turn the
// override off and move liveness to /v1/healthz.
func documentedFullPaths(t *testing.T) map[string]bool {
	t.Helper()
	spec := readOpenAPI(t)

	pathRE := regexp.MustCompile(`^  (/[^\s:]*):\s*$`)
	methodRE := regexp.MustCompile(`^    (get|put|post|delete|patch|head|options):\s*$`)
	overrideRE := regexp.MustCompile(`^      servers:\s*$`)

	full := map[string]bool{}
	overrides := 0
	path, inOperation := "", false
	for _, line := range strings.Split(spec, "\n") {
		if m := pathRE.FindStringSubmatch(line); m != nil {
			if path != "" && !inOperation {
				t.Errorf("%s declares no operation; the parser expects `get:`-style keys at four spaces", path)
			}
			path, inOperation = m[1], false
			full["/v1"+path] = true
			continue
		}
		if path == "" {
			continue
		}
		if methodRE.MatchString(line) {
			inOperation = true
			continue
		}
		if inOperation && overrideRE.MatchString(line) {
			// The override moves the whole operation off the /v1 server.
			delete(full, "/v1"+path)
			full[path] = true
			overrides++
		}
	}

	if len(full) < 20 {
		t.Fatalf("only %d paths were parsed out of the OpenAPI document; the parser is wrong", len(full))
	}
	if overrides == 0 {
		t.Fatal("no per-operation `servers` override was parsed out of the OpenAPI document. /healthz carries one, so either it has been removed — which moves liveness inside the /v1 compatibility boundary — or this parser has stopped seeing it and is silently placing every path under /v1.")
	}
	return full
}

func readOpenAPI(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", "api", "openapi.yaml")
		if b, err := os.ReadFile(candidate); err == nil {
			return string(b)
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("contracts/api/openapi.yaml not found from the test working directory")
	return ""
}

// TestTheRouteTableIsGeneratedFromTheContract is the item's first acceptance
// criterion, Go half: the harness is GENERATED from contracts/api/openapi.yaml.
//
// It reads the emitted file's marker rather than trusting the package's shape.
// The marker is what contracts/tools/check_drift.py greps for, so a file that
// loses it stops being drift-checked while still looking generated — the exact
// silent failure that turns generated code into a stale copy.
func TestTheRouteTableIsGeneratedFromTheContract(t *testing.T) {
	first := strings.SplitN(readRepoFile(t, filepath.Join(
		"terraform-provider-azureacme", "internal", "fakeservice", "routes.gen.go")), "\n", 2)[0]

	if !strings.HasPrefix(first, "// Code generated ") || !strings.HasSuffix(first, "DO NOT EDIT.") {
		t.Fatalf("routes.gen.go does not open with a DO NOT EDIT marker: %q", first)
	}
	if !strings.Contains(first, " from contracts/api/openapi.yaml;") {
		t.Errorf("the marker does not name contracts/api/openapi.yaml as its source: %q", first)
	}
	if !regexp.MustCompile(`generate\.py v\d+\.\d+\.\d+`).MatchString(first) {
		t.Errorf("the marker does not name the generator version: %q", first)
	}

	// And the drift check must actually be watching it. `internal/fakeservice/`
	// is not one of the two generated PACKAGE directories check_drift.py walks,
	// so this file is only covered because it is named one by one in
	// GENERATED_FILES. An unnamed generated file is one the check silently stops
	// watching, which is why that list is asserted from here rather than assumed.
	drift := readRepoFile(t, filepath.Join("contracts", "tools", "check_drift.py"))
	if !strings.Contains(drift, `"routes.gen.go"`) {
		t.Error("contracts/tools/check_drift.py does not name routes.gen.go in GENERATED_FILES, " +
			"so a contract change that is not regenerated would pass CI unnoticed")
	}
}

// TestTheGeneratedRouteTableAgreesWithTheDocument reads the SAME document twice
// by two different routes — the generator's YAML parse, committed as
// routes.gen.go, and this suite's own regex parse of the raw text — and requires
// the two to produce the same set of dialled addresses.
//
// Two readings rather than one is the point. A single reading is satisfied by a
// generator that is confidently wrong, and the `/healthz` server override is
// exactly the kind of subtlety a reader gets wrong: resolve it naively and
// liveness moves inside the /v1 compatibility boundary.
func TestTheGeneratedRouteTableAgreesWithTheDocument(t *testing.T) {
	documented := documentedFullPaths(t)

	generated := map[string]bool{}
	seen := map[fakeservice.OperationID]string{}
	for _, route := range fakeservice.Routes {
		generated[route.Path] = true
		if previous, dup := seen[route.OperationID]; dup {
			t.Errorf("operation %q is emitted twice, for %s and %s; an operationId is unique in "+
				"an OpenAPI document and the fake dispatches on it",
				route.OperationID, previous, route.Path)
		}
		seen[route.OperationID] = route.Method + " " + route.Path
		if !documented[route.Path] {
			t.Errorf("the generated table serves %q, which this suite's own parse of "+
				"contracts/api/openapi.yaml does not find", route.Path)
		}
	}
	for path := range documented {
		if !generated[path] {
			t.Errorf("contracts/api/openapi.yaml documents %q and the generated route table has "+
				"no route for it; the fake would answer 404 at an address the service serves", path)
		}
	}
	if !generated["/healthz"] || generated["/v1/healthz"] {
		t.Error("the generated table did not honour the per-operation `servers` override on " +
			"/healthz; liveness must stay OUTSIDE the /v1 compatibility boundary")
	}
}

// TestTheFakeDispatchesOnTheGeneratedTable proves the table is load-bearing
// rather than decorative: the fake answers where the CONTRACT says it answers,
// tells a wrong verb apart from a wrong address, and takes the precondition rule
// from the document rather than from a hand-written list of mutating methods.
func TestTheFakeDispatchesOnTheGeneratedTable(t *testing.T) {
	put, _, ok := fakeservice.MatchRoute(http.MethodPut,
		"/v1/namespaces/payments-prod/certificates/api")
	if !ok {
		t.Fatal("PUT on a registration does not resolve to a contract operation")
	}
	if put.OperationID != fakeservice.OpPutCertificate {
		t.Errorf("PUT on a registration resolved to %q", put.OperationID)
	}
	if !put.RequiresPrecondition {
		t.Error("putCertificate does not carry RequiresPrecondition. It is derived from the " +
			"contract declaring 428 AND accepting both conditional headers, so this failing " +
			"means the fake would stop enforcing the rule that makes a lost update impossible")
	}
	del, _, ok := fakeservice.MatchRoute(http.MethodDelete,
		"/v1/namespaces/payments-prod/certificates/api")
	if !ok {
		t.Fatal("DELETE on a registration does not resolve to a contract operation")
	}
	if del.RequiresPrecondition {
		t.Error("deleteCertificate carries RequiresPrecondition. DELETE takes an OPTIONAL " +
			"If-Match and declares no 428; a rule that swept it up would be the fake's own " +
			"invention rather than the contract's")
	}
	if _, _, ok := fakeservice.MatchRoute(http.MethodPatch,
		"/v1/namespaces/payments-prod/certificates/api"); ok {
		t.Error("PATCH resolved to an operation; the contract declares none for that address")
	}
	if _, _, documented := fakeservice.RoutesForPath(
		"/v1/namespaces/payments-prod/certificates/api"); !documented {
		t.Error("the address itself is not documented, so the fake could not tell a wrong verb " +
			"from a wrong address")
	}
	if put.DeclaresStatus(http.StatusTeapot) {
		t.Error("putCertificate claims to declare 418")
	}
	if !put.DeclaresStatus(http.StatusPreconditionRequired) || !put.DeclaresStatus(503) {
		t.Error("putCertificate does not declare 428, or its 5XX wildcard does not cover 503")
	}

	// And end to end: a documented address dialled with a verb the contract does
	// not declare answers 405, not the 404 that would read as "no such endpoint".
	srv := fakeservice.New(t)
	req, err := http.NewRequest(http.MethodPatch,
		srv.URL()+"/v1/namespaces/payments-prod/certificates/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PATCH on a documented address returned %d, want 405", resp.StatusCode)
	}
}

// readRepoFile reads a repository-relative file from a test whose working
// directory is the package directory.
func readRepoFile(t *testing.T, relative string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, relative)); err == nil {
			return string(b)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("%s not found from the test working directory", relative)
	return ""
}

// TestPreconditionRequired: the fake returns 428 when a PUT carries neither
// precondition, and the test FAILS if the client ever reaches it.
func TestPreconditionRequired(t *testing.T) {
	srv := fakeservice.New(t)
	// Drive a raw PUT with no precondition, bypassing the client's own guard, to
	// prove the FAKE enforces the rule.
	req, err := http.NewRequest(http.MethodPut, srv.URL()+"/v1/namespaces/ns/certificates/api",
		strings.NewReader(`{"spec":{"dns_names":["api.example.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("a PUT with no precondition returned %d, want 428", resp.StatusCode)
	}

	// And the CLIENT never reaches it.
	c := newClient(t, srv)
	if _, err := c.PutRegistration(context.Background(), "ns", "api", contracts.CertificateSpecFields{}, client.PutOptions{}); err == nil {
		t.Fatal("the client issued a PUT with no precondition")
	}
}

// TestScenarioDSLProducesEveryDangerousResponse.
func TestScenarioDSLProducesEveryDangerousResponse(t *testing.T) {
	cases := []struct {
		name        string
		handler     http.HandlerFunc
		wantStatus  int
		wantCT      string
		wantBodySub string
	}{
		{"302 to a sign-in page", fakeservice.RespondRedirect(302, "https://login.microsoftonline.com/"), 302, "", ""},
		{"200 text/html", fakeservice.RespondHTML(200), 200, "text/html", "Sign in"},
		{"404 with an empty body", fakeservice.RespondEmptyBody(404), 404, "application/json", ""},
		{"404 with a mismatched instance", fakeservice.RespondProblem(404, contracts.CodeRegistrationNotFound, "01OTHER"),
			404, "application/problem+json", "01OTHER"},
		{"409 with Retry-After", fakeservice.RespondProblem(409, contracts.CodeDestinationAccessDenied,
			fakeservice.DefaultInstanceID, fakeservice.WithRetryAfterSeconds(30)), 409, "application/problem+json", "retry_after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeservice.New(t)
			srv.AddRule(fakeservice.Rule{Match: fakeservice.Match{}, Handler: tc.handler})
			c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := c.Get(srv.URL() + "/v1/capabilities")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantCT != "" && !strings.Contains(resp.Header.Get("Content-Type"), tc.wantCT) {
				t.Fatalf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), tc.wantCT)
			}
			if tc.wantBodySub != "" {
				buf := make([]byte, 4096)
				n, _ := resp.Body.Read(buf)
				if !strings.Contains(string(buf[:n]), tc.wantBodySub) {
					t.Fatalf("body does not contain %q: %s", tc.wantBodySub, buf[:n])
				}
			}
		})
	}
}

// TestSimulatedRenewalTouchesTheCertificateAndNothingElse is what makes the
// plan-stability proof possible.
func TestSimulatedRenewalTouchesTheCertificateAndNothingElse(t *testing.T) {
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: "ns", Name: "api"})
	c := newClient(t, srv)
	ctx := context.Background()

	before, _, err := c.GetRegistration(ctx, "ns", "api", false)
	if err != nil {
		t.Fatal(err)
	}
	srv.SimulateRenewal("ns", "api")
	after, _, err := c.GetRegistration(ctx, "ns", "api", false)
	if err != nil {
		t.Fatal(err)
	}

	if before.Spec.Revision != after.Spec.Revision {
		t.Errorf("the renewal bumped spec.revision (%d -> %d); the ETag covers the SPEC ONLY",
			before.Spec.Revision, after.Spec.Revision)
	}
	if before.Spec.Generation != after.Spec.Generation {
		t.Errorf("the renewal bumped spec.generation (%d -> %d)", before.Spec.Generation, after.Spec.Generation)
	}
	if before.Spec.Hash != after.Spec.Hash {
		t.Error("the renewal changed the issuance hash")
	}
	if before.Status.CurrentCertificate.ThumbprintSHA256 == after.Status.CurrentCertificate.ThumbprintSHA256 {
		t.Fatal("the renewal did not change the thumbprint, so it did not simulate a renewal at all")
	}
	if *before.Status.CurrentCertificate.VersionlessSecretID != *after.Status.CurrentCertificate.VersionlessSecretID {
		t.Error("the renewal changed the VERSIONLESS secret id; every consumer binds to it")
	}
	if after.Status.PreviousCertificate == nil {
		t.Error("the renewal did not record a previous certificate")
	}
}

// TestLabelInjectionIsVisible: the fake can violate guarantee G-6 on demand, so
// a test can prove the provider CATCHES it rather than absorbing it.
func TestLabelInjectionIsVisible(t *testing.T) {
	srv := fakeservice.New(t)
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: "ns", Name: "api", Labels: map[string]string{"team": "payments"}})
	srv.InjectServerLabel("ns", "api", "managed-by", "mantisec")
	c := newClient(t, srv)
	reg, _, err := c.GetRegistration(context.Background(), "ns", "api", false)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Spec.Labels["managed-by"] != "mantisec" {
		t.Fatal("the injected label is not visible on the wire, so no test could catch the violation")
	}
}

// TestPaginationOverManyRegistrations exercises the internal paging path.
func TestPaginationOverManyRegistrations(t *testing.T) {
	srv := fakeservice.New(t, func(o *fakeservice.Options) { o.PageSize = 50 })
	for i := 0; i < 260; i++ {
		srv.SeedRegistration(fakeservice.RegistrationSeed{
			Namespace: "ns", Name: "cert-" + pad(i),
		})
	}
	c := newClient(t, srv)
	ctx := context.Background()
	seen := 0
	pages := 0
	token := ""
	for {
		q := map[string][]string{}
		if token != "" {
			q["page_token"] = []string{token}
		}
		page, err := c.ListRegistrations(ctx, "ns", q)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		seen += len(page.Items)
		if page.NextPageToken == nil || *page.NextPageToken == "" {
			break
		}
		token = *page.NextPageToken
	}
	if seen != 260 {
		t.Fatalf("saw %d registrations, want 260", seen)
	}
	if pages < 2 {
		t.Fatalf("the listing took %d page(s); a 260-item collection must paginate", pages)
	}
}

func pad(i int) string {
	s := "000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestDeferredOperationCarriesAFarFutureEstimatedStart.
func TestDeferredOperationCarriesAFarFutureEstimatedStart(t *testing.T) {
	srv := fakeservice.New(t)
	srv.SetBehaviour(fakeservice.Behaviour{
		DeferOperation: true, DeferEstimatedStart: time.Now().UTC().Add(7 * 24 * time.Hour),
	})
	c := newClient(t, srv)
	result, err := c.PutRegistration(context.Background(), "ns", "api", contracts.CertificateSpecFields{
		DNSNames: []string{"api.example.com"},
	}, client.PutOptions{IfNoneMatchAny: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted == nil || result.Accepted.EstimatedStart == nil {
		t.Fatal("a deferred 202 must carry estimated_start")
	}
	start, err := time.Parse(time.RFC3339, *result.Accepted.EstimatedStart)
	if err != nil {
		t.Fatalf("estimated_start %q does not parse: %v", *result.Accepted.EstimatedStart, err)
	}
	if time.Until(start) < 24*time.Hour {
		t.Fatalf("estimated_start is only %s away; the deferral horizon is DAYS", time.Until(start))
	}
}

// TestTheFakeNormalisesRatherThanEchoing is the guard on the guard.
//
// Every plan-stability assertion in the provider's suite is worthless against a
// fake that echoes the request: the round trip is then stable by construction.
// That is not hypothetical — it is what happened. Eleven green acceptance tests
// coexisted with a real `terraform plan` that aborted the entire workspace,
// because `specReadFrom` copied `destination_id` and `verification` straight out
// of the PUT body (C2 Finding 2).
//
// So this test asserts the fake does what the service does, for each field the
// service is known to normalise. If someone "simplifies" normalise.go back into
// an echo, this fails here rather than silently disarming the provider's suite.
func TestTheFakeNormalisesRatherThanEchoing(t *testing.T) {
	ctx := context.Background()
	srv := fakeservice.New(t)
	c := newClient(t, srv)

	// A create that declares NEITHER normalised field — the six-concept minimum.
	spec := contracts.CertificateSpecFields{
		DNSNames: []string{"api.example.com"},
		Destination: &contracts.DestinationFields{
			KeyVaultID:      ptrTo(fakeservice.DefaultKeyVaultID),
			CertificateName: ptrTo("payments-api"),
			Type:            ptrTo("azure_key_vault"),
		},
	}
	result, err := c.PutRegistration(ctx, "payments-prod", "payments-api", spec,
		client.PutOptions{IfNoneMatchAny: true, IdempotencyKey: client.NewULID()})
	if err != nil {
		t.Fatalf("PutRegistration: %v", err)
	}
	reg := result.Registration
	if reg == nil {
		t.Fatal("the create returned no representation")
	}

	// 1. destination_id is SERVER-RESOLVED, not echoed. The caller sent none.
	if reg.Spec.Destination == nil || reg.Spec.Destination.DestinationID == nil {
		t.Fatal("the response carries no `destination_id`. PROVISIONAL(D-20) server-resolves the destination, so the " +
			"response names a destination POLICY whether or not the caller did. A fake that leaves it absent cannot " +
			"catch the normalisation mismatch that made `terraform plan` a hard error.")
	}
	if got := *reg.Spec.Destination.DestinationID; got != fakeservice.DefaultDestinationPolicyID {
		t.Errorf("destination_id = %q, want the resolved policy %q", got, fakeservice.DefaultDestinationPolicyID)
	}

	// 2. verification is MATERIALISED, not echoed. The caller sent none.
	if reg.Spec.Verification == nil || reg.Spec.Verification.ConsumerProbe == nil {
		t.Fatal("the response carries no `verification`. The service's apply_defaults materialises the whole block " +
			"for every registration, and that materialised block is the second permadiff of C2 Finding 2.")
	}
	if enabled := reg.Spec.Verification.ConsumerProbe.Enabled; enabled == nil || *enabled {
		t.Errorf("verification.consumer_probe.enabled = %v, want an explicit false — §5.7's documented default", enabled)
	}

	// 3. AND IT INHERITS ON UPDATE (G-8). A field the caller omits takes the
	//    stored value, not today's default. This is why the provider has to STATE
	//    `enabled` on every write rather than omitting the block.
	enabledSpec := spec
	enabledSpec.Verification = &contracts.VerificationSpec{
		ConsumerProbe: &contracts.ConsumerProbe{Enabled: ptrTo(true)},
	}
	revision := reg.Spec.Revision
	if _, err := c.PutRegistration(ctx, "payments-prod", "payments-api", enabledSpec,
		client.PutOptions{IfMatchRevision: &revision, IdempotencyKey: client.NewULID()}); err != nil {
		t.Fatalf("enabling the probe: %v", err)
	}
	stored := srv.Registration("payments-prod", "payments-api")
	revision = stored.Spec.Revision
	omitted := spec // no verification key at all
	if _, err := c.PutRegistration(ctx, "payments-prod", "payments-api", omitted,
		client.PutOptions{IfMatchRevision: &revision, IdempotencyKey: client.NewULID()}); err != nil {
		t.Fatalf("omitting verification: %v", err)
	}
	stored = srv.Registration("payments-prod", "payments-api")
	if enabled := stored.Spec.Verification.ConsumerProbe.Enabled; enabled == nil || !*enabled {
		t.Errorf("omitting `verification` on an update reset the probe to the default (enabled=%v). G-8 makes defaults "+
			"apply AT CREATE ONLY, so the stored value must stand — and reproducing that here is what forces the "+
			"provider to state `enabled` explicitly instead of relying on omission to turn a probe off.", enabled)
	}
}

func ptrTo[T any](v T) *T { return &v }
