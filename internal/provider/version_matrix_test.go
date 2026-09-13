package provider

// version_matrix_test.go — THE VERSION-NEGOTIATION MATRIX.
//
// CI-VERSION-MATRIX-SECRET-SURFACE. Runs this provider against a service one
// version BELOW it, at the SAME version, and one version ABOVE it, on each of the
// three axes a service and a client can disagree on, and asserts the outcome
// release-engineering.md §9.3 declares for that pairing:
//
//	major mismatch                fatal, in both directions
//	minor below the required one  fatal
//	minor above the known one     proceeds, ignoring what it does not recognise
//	feature not present           a PLAN-TIME attribute error NAMING THE FEATURE
//
// WHY A GENERATED MATRIX RATHER THAN NINE HAND-WRITTEN TESTS. The failure this
// job exists to catch is a pairing nobody thought about — a combination that
// reaches a fourth, undeclared outcome and looks like a pass because no test
// asserted anything about it. So the pairings are GENERATED from the axes and the
// three steps, every generated pairing must find a row in `declared`, and a
// pairing with no row FAILS. Adding an axis or a step therefore fails the job
// until somebody writes down what the new pairing is supposed to do.
//
// The feature axis is in the matrix on purpose, next to the two version axes.
// Feature gating is by NAME and never by version arithmetic (F-065), and putting
// the two side by side is what makes that visible: the feature pairing's outcome
// is reached with the version pairings all sitting at N.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/customtypes/armid"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// ---------------------------------------------------------------- the axes

// versionAxis is one dimension on which the service can differ from the provider.
type versionAxis string

const (
	// axisMajor is the /v1 compatibility boundary.
	axisMajor versionAxis = "major"
	// axisMinor is the feature-set level within one major.
	axisMinor versionAxis = "minor"
	// axisFeature is not a version at all, and that is the point: a capability is
	// present or absent by NAME, and no version comparison may stand in for it.
	axisFeature versionAxis = "feature"
)

var allAxes = []versionAxis{axisMajor, axisMinor, axisFeature}

// versionStep is the N−1 / N / N+1 position of the service relative to the
// provider.
type versionStep int

const (
	stepBelow versionStep = -1
	stepSame  versionStep = 0
	stepAbove versionStep = +1
)

var allSteps = []versionStep{stepBelow, stepSame, stepAbove}

func (s versionStep) String() string {
	switch s {
	case stepBelow:
		return "N-1"
	case stepSame:
		return "N"
	case stepAbove:
		return "N+1"
	default:
		return fmt.Sprintf("step(%d)", int(s))
	}
}

func pairingID(a versionAxis, s versionStep) string { return string(a) + "/" + s.String() }

// ------------------------------------------------------------- the outcomes

// negotiationOutcome is the DECLARED result of one pairing. Every value here
// corresponds to a row of the §9.3 rule table; `assertOutcome` below is the only
// place that knows how each is observed.
type negotiationOutcome string

const (
	// outcomeProceeds: Configure succeeds and the provider is usable.
	outcomeProceeds negotiationOutcome = "proceeds"
	// outcomeFatalMajorMismatch: Configure fails naming BOTH majors.
	outcomeFatalMajorMismatch negotiationOutcome = "fatal — the service speaks a different API major version"
	// outcomeFatalMinorBelowRequired: Configure fails naming the required minor.
	outcomeFatalMinorBelowRequired negotiationOutcome = "fatal — the service is older than this provider requires"
	// outcomeProceedsIgnoringUnknowns: Configure succeeds AND the provider ignores
	// unknown fields, features, enum values and error codes.
	outcomeProceedsIgnoringUnknowns negotiationOutcome = "proceeds, ignoring unknown fields, features, enum values and error codes"
	// outcomeFeatureAbsentPlanError: a PLAN-TIME attribute error that names the
	// feature. Not a version comparison, and not an apply-time failure.
	outcomeFeatureAbsentPlanError negotiationOutcome = "plan-time attribute error naming the absent feature"
)

// --------------------------------------------------------- the declared table

// declaredPairing is one row of the §9.3 rule table, made executable.
type declaredPairing struct {
	// outcome is what §9.3 says this pairing must do.
	outcome negotiationOutcome

	// serviceAPIVersion is what the fake service reports at /v1/capabilities.
	serviceAPIVersion string
	// features is what the fake service advertises.
	features []string

	// providerMinorRequired is the requirement the pairing is asserted AT. It
	// equals `apiMinorRequired` for every pairing reachable through the fake
	// service harness. It differs for exactly one row — see `viaClassifier`.
	providerMinorRequired int

	// viaClassifier marks a pairing that cannot be produced through the harness by
	// THIS build's constants, and states why in one line.
	//
	// There is exactly one: `apiMinorRequired` is 0, so no service version exists
	// whose minor is below it AND whose major matches — every candidate is caught
	// by the major rule first. The rule is still asserted, against
	// `classifyAPIVersion` with the provider requirement it needs, so it stays
	// live instead of quietly becoming untested until the constant rises. It is
	// NOT skipped: a skipped row is the silent pass this matrix exists to prevent.
	viaClassifier string
}

// declared is the rule table. A generated pairing with no row here FAILS.
var declared = map[string]declaredPairing{
	// -- the major axis: fatal in BOTH directions ----------------------------
	pairingID(axisMajor, stepBelow): {
		outcome:               outcomeFatalMajorMismatch,
		serviceAPIVersion:     "0.9",
		providerMinorRequired: apiMinorRequired,
	},
	pairingID(axisMajor, stepSame): {
		outcome:               outcomeProceeds,
		serviceAPIVersion:     "1.0",
		providerMinorRequired: apiMinorRequired,
	},
	pairingID(axisMajor, stepAbove): {
		outcome:               outcomeFatalMajorMismatch,
		serviceAPIVersion:     "2.0",
		providerMinorRequired: apiMinorRequired,
	},

	// -- the minor axis ------------------------------------------------------
	pairingID(axisMinor, stepBelow): {
		outcome:               outcomeFatalMinorBelowRequired,
		serviceAPIVersion:     "1.1",
		providerMinorRequired: 2,
		viaClassifier: "apiMinorRequired is 0, so every service minor below it also fails the " +
			"major rule; asserted against classifyAPIVersion at a provider requirement of 1.2",
	},
	pairingID(axisMinor, stepSame): {
		outcome:               outcomeProceeds,
		serviceAPIVersion:     "1.0",
		providerMinorRequired: apiMinorRequired,
	},
	pairingID(axisMinor, stepAbove): {
		outcome:               outcomeProceedsIgnoringUnknowns,
		serviceAPIVersion:     "1.9",
		features:              []string{FeatureDestinationMigration, "some_future_feature"},
		providerMinorRequired: apiMinorRequired,
	},

	// -- the feature axis: by NAME, at the SAME version ----------------------
	pairingID(axisFeature, stepBelow): {
		outcome:               outcomeFeatureAbsentPlanError,
		serviceAPIVersion:     "1.0",
		features:              []string{},
		providerMinorRequired: apiMinorRequired,
	},
	pairingID(axisFeature, stepSame): {
		outcome:               outcomeProceeds,
		serviceAPIVersion:     "1.0",
		features:              []string{FeatureDestinationMigration},
		providerMinorRequired: apiMinorRequired,
	},
	pairingID(axisFeature, stepAbove): {
		outcome:               outcomeProceeds,
		serviceAPIVersion:     "1.0",
		features:              []string{FeatureDestinationMigration, "a_feature_from_a_newer_service"},
		providerMinorRequired: apiMinorRequired,
	},
}

// ------------------------------------------------------------------ the job

// generatePairings enumerates every (axis, step) combination and splits it into
// the pairings the table declares and the pairings it does not.
//
// It is a pure function taking its axes, steps and table as arguments so
// TestVersionMatrix_AnUndeclaredPairingFailsTheJob can prove the guard actually
// fires. A guard that has only ever been observed passing is not a guard.
func generatePairings(axes []versionAxis, steps []versionStep, table map[string]declaredPairing) (declared, undeclared []string) {
	for _, axis := range axes {
		for _, step := range steps {
			id := pairingID(axis, step)
			if _, ok := table[id]; ok {
				declared = append(declared, id)
			} else {
				undeclared = append(undeclared, id)
			}
		}
	}
	sort.Strings(undeclared)
	return declared, undeclared
}

// orphanRows are declared rows no generated pairing reaches — a rule that asserts
// nothing because nothing runs it.
func orphanRows(generated []string, table map[string]declaredPairing) []string {
	reached := make(map[string]bool, len(generated))
	for _, id := range generated {
		reached[id] = true
	}
	var orphans []string
	for id := range table {
		if !reached[id] {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	return orphans
}

// TestVersionMatrix is the matrix job. `provider-ci.yml` runs it as a named step
// as well as inside `go test ./...`, so it is visible in the job log.
func TestVersionMatrix(t *testing.T) {
	ran, undeclared := generatePairings(allAxes, allSteps, declared)

	// THE POINT OF THE MATRIX. A pairing nobody wrote a rule for is not a pass; it
	// is an undeclared negotiation outcome shipping.
	for _, id := range undeclared {
		t.Errorf("PAIRING %s HAS NO DECLARED OUTCOME.\n\n"+
			"release-engineering.md §9.3 declares an outcome for every (provider, service) pairing, and this "+
			"matrix refuses to let one pass silently. Add a row to `declared` saying what %s must do, or "+
			"remove the axis/step that generated it.", id, id)
	}

	for _, id := range ran {
		row := declared[id]
		t.Run(id+" => "+string(row.outcome), func(t *testing.T) {
			runPairing(t, id, row)
		})
	}

	// The converse guard: a row nobody generates is a rule that is never run.
	if orphans := orphanRows(ran, declared); len(orphans) > 0 {
		t.Errorf("declared rows that no generated pairing reaches, so they assert nothing: %v", orphans)
	}

	if len(ran) != len(allAxes)*len(allSteps) {
		t.Fatalf("the matrix ran %d pairings, want %d", len(ran), len(allAxes)*len(allSteps))
	}
}

// TestVersionMatrix_AnUndeclaredPairingFailsTheJob proves the guard fires.
//
// The matrix's whole claim is "a pairing with no declared outcome FAILS rather
// than passing silently". Observed only in the green case, that claim is
// unfalsifiable: a lookup that always found a row would look identical. So a
// fourth axis is generated against the real table, and the guard must report
// every one of its three pairings as undeclared.
func TestVersionMatrix_AnUndeclaredPairingFailsTheJob(t *testing.T) {
	const invented versionAxis = "an_axis_nobody_declared_an_outcome_for"

	ran, undeclared := generatePairings(append(append([]versionAxis{}, allAxes...), invented), allSteps, declared)

	want := []string{
		pairingID(invented, stepBelow),
		pairingID(invented, stepSame),
		pairingID(invented, stepAbove),
	}
	sort.Strings(want)
	if strings.Join(undeclared, ",") != strings.Join(want, ",") {
		t.Fatalf("undeclared pairings = %v, want exactly %v.\n\n"+
			"If this is empty the guard is VACUOUS: an axis whose outcomes nobody wrote down would ship as a pass.",
			undeclared, want)
	}
	if len(ran) != len(allAxes)*len(allSteps) {
		t.Errorf("the declared half changed shape: %d pairings, want %d", len(ran), len(allAxes)*len(allSteps))
	}

	// And the converse guard, proved the same way: a row the generator never
	// reaches must be reported, not ignored.
	table := map[string]declaredPairing{}
	for id, row := range declared {
		table[id] = row
	}
	table["an_axis_that_is_never_generated/N"] = declaredPairing{outcome: outcomeProceeds}
	orphans := orphanRows(ran, table)
	if len(orphans) != 1 || orphans[0] != "an_axis_that_is_never_generated/N" {
		t.Fatalf("orphan rows = %v, want exactly [an_axis_that_is_never_generated/N]", orphans)
	}
}

func runPairing(t *testing.T, id string, row declaredPairing) {
	t.Helper()

	if row.viaClassifier != "" {
		// The classifier path. It asserts the same rule at a provider requirement
		// this build does not ship, and says in the log exactly which observation
		// it is standing in for.
		t.Logf("%s is asserted against classifyAPIVersion rather than the harness: %s", id, row.viaClassifier)
		got := classifyAPIVersion(apiMajor, row.providerMinorRequired, row.serviceAPIVersion)
		want := verdictFor(t, row.outcome)
		if got != want {
			t.Fatalf("classifyAPIVersion(major=%d, minorRequired=%d, %q) = %v, want %v (%s)",
				apiMajor, row.providerMinorRequired, row.serviceAPIVersion, got, want, row.outcome)
		}
		return
	}

	if row.providerMinorRequired != apiMinorRequired {
		t.Fatalf("%s declares providerMinorRequired=%d but is not marked viaClassifier; the harness can only run "+
			"this build's constant (%d)", id, row.providerMinorRequired, apiMinorRequired)
	}

	assertOutcome(t, id, row)
}

// verdictFor maps a declared outcome onto the classifier verdict that produces it.
func verdictFor(t *testing.T, outcome negotiationOutcome) apiVersionVerdict {
	t.Helper()
	switch outcome {
	case outcomeFatalMajorMismatch:
		return apiVersionMajorMismatch
	case outcomeFatalMinorBelowRequired:
		return apiVersionMinorBelowRequired
	case outcomeProceeds, outcomeProceedsIgnoringUnknowns:
		return apiVersionAcceptable
	case outcomeFeatureAbsentPlanError:
		t.Fatalf("%q is a PLAN-time outcome and has no classifier verdict: feature gating is by name, never by "+
			"version arithmetic", outcome)
	}
	t.Fatalf("no classifier verdict declared for outcome %q", outcome)
	return apiVersionUnreadable
}

// assertOutcome runs the pairing against the fake service harness.
func assertOutcome(t *testing.T, id string, row declaredPairing) {
	t.Helper()

	srv := fakeservice.New(t, func(o *fakeservice.Options) {
		o.APIVersion = row.serviceAPIVersion
		o.APIVersionsSupported = []string{row.serviceAPIVersion}
		if row.features != nil {
			o.Features = row.features
		}
	})

	switch row.outcome {
	case outcomeFatalMajorMismatch:
		resp := configureAgainst(t, srv)
		requireErrorNaming(t, id, resp.Diagnostics.Errors(),
			"different API major version", row.serviceAPIVersion)

	case outcomeFatalMinorBelowRequired:
		resp := configureAgainst(t, srv)
		requireErrorNaming(t, id, resp.Diagnostics.Errors(),
			"older than this provider requires", row.serviceAPIVersion)

	case outcomeProceeds:
		resp := configureAgainst(t, srv)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s must proceed; Configure failed: %v", id, resp.Diagnostics)
		}
		assertFeatureGatingIsByName(t, srv, row.features)

	case outcomeProceedsIgnoringUnknowns:
		resp := configureAgainst(t, srv)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s must proceed; Configure failed: %v", id, resp.Diagnostics)
		}
		assertFeatureGatingIsByName(t, srv, row.features)
		assertUnknownFieldIsIgnored(t, row.serviceAPIVersion)
		assertUnknownEnumValueIsIgnored(t)
		assertUnknownErrorCodeIsIgnored(t)

	case outcomeFeatureAbsentPlanError:
		assertAbsentFeatureIsAPlanTimeErrorNamingIt(t, id, srv)

	default:
		t.Fatalf("%s declares outcome %q, which nothing knows how to observe", id, row.outcome)
	}
}

func configureAgainst(t *testing.T, srv *fakeservice.Server) *fwprovider.ConfigureResponse {
	t.Helper()
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "api://mantisec-acme", "tenant", "")
	return configureWith(t, m, client.StaticTokenSource{Value: "tok"})
}

func requireErrorNaming(t *testing.T, id string, errs diag.Diagnostics, want ...string) {
	t.Helper()
	if len(errs) == 0 {
		t.Fatalf("%s must be FATAL at Configure; no error was raised", id)
	}
	combined := ""
	for _, d := range errs {
		combined += d.Summary() + "\n" + d.Detail() + "\n"
	}
	for _, w := range want {
		if !strings.Contains(combined, w) {
			t.Errorf("%s: the diagnostic must name %q; got:\n%s", id, w, combined)
		}
	}
}

// assertFeatureGatingIsByName is the F-065 assertion, run on every pairing that
// proceeds: an advertised name is present, an unadvertised one is absent, and
// neither answer is derived from the version.
func assertFeatureGatingIsByName(t *testing.T, srv *fakeservice.Server, features []string) {
	t.Helper()
	r := newTestResource(t, srv)
	for _, f := range features {
		if !r.data.HasFeature(f) {
			t.Errorf("HasFeature(%q) = false for a feature the service advertises", f)
		}
	}
	if r.data.HasFeature("a_feature_no_service_has_ever_advertised") {
		t.Error("HasFeature reported a feature the service does not advertise — gating is by NAME, " +
			"so an unadvertised name is absent whatever the version says")
	}
}

// assertUnknownFieldIsIgnored serves a capabilities document carrying fields this
// build has never heard of, at both the top level and inside `service`, and
// requires Configure to succeed anyway.
func assertUnknownFieldIsIgnored(t *testing.T, apiVersion string) {
	t.Helper()
	srv := fakeservice.New(t, func(o *fakeservice.Options) {
		o.APIVersion = apiVersion
		o.APIVersionsSupported = []string{apiVersion}
	})

	// Take the fake's own document rather than hand-writing one, so this stays a
	// test about UNKNOWN fields and not about a stale hand-copied contract.
	body := capabilitiesDocument(t, srv)
	body["a_field_from_a_newer_service"] = "ignore me"
	if service, ok := body["service"].(map[string]any); ok {
		service["a_service_field_from_a_newer_service"] = map[string]any{"nested": true}
	} else {
		t.Fatal("the fake's capabilities document has no `service` object")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshalling the capabilities document: %v", err)
	}
	srv.AddRule(fakeservice.Rule{
		Match:   fakeservice.Match{Method: http.MethodGet, PathSuffix: "/capabilities"},
		Handler: fakeservice.RespondRaw(http.StatusOK, "application/json", string(raw)),
	})

	resp := configureAgainst(t, srv)
	if resp.Diagnostics.HasError() {
		t.Fatalf("a capabilities document carrying unknown fields must be ACCEPTED, not rejected: %v", resp.Diagnostics)
	}
}

// capabilitiesDocument reads the fake's own /v1/capabilities as generic JSON.
func capabilitiesDocument(t *testing.T, srv *fakeservice.Server) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL()+"/v1/capabilities", nil)
	if err != nil {
		t.Fatalf("building the capabilities request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reading the fake's capabilities document: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the capabilities body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding the capabilities body: %v", err)
	}
	return doc
}

// assertUnknownEnumValueIsIgnored is the decode-layer half of "minor above known
// proceeds". A newer service adds enum members; a client that validates them
// against a compiled-in list turns every new member into a hard failure for every
// consumer, which is the wedge §9.3 forbids.
func assertUnknownEnumValueIsIgnored(t *testing.T) {
	t.Helper()
	const document = `{
	  "phase": "a_phase_from_a_newer_service",
	  "delivery_stage": "a_stage_from_a_newer_service"
	}`
	var status contracts.RegistrationStatus
	if err := json.Unmarshal([]byte(document), &status); err != nil {
		t.Fatalf("an unknown enum value must DECODE, not fail: %v", err)
	}
	if status.Phase != "a_phase_from_a_newer_service" {
		t.Errorf("phase = %q; the unknown value must be carried through verbatim", status.Phase)
	}
	if status.DeliveryStage != "a_stage_from_a_newer_service" {
		t.Errorf("delivery_stage = %q; the unknown value must be carried through verbatim", status.DeliveryStage)
	}
}

// assertUnknownErrorCodeIsIgnored requires an error code this build's taxonomy
// does not carry to be surfaced verbatim rather than rejected. The service is the
// authority on its own failures; a client that only understands codes it was
// compiled with cannot report a newer service's errors at all.
func assertUnknownErrorCodeIsIgnored(t *testing.T) {
	t.Helper()
	const future = contracts.Code("a_code_from_a_newer_service")
	if _, known := contracts.Lookup(future); known {
		t.Fatalf("%q is in the taxonomy, so it is not the unknown-code case; pick another", future)
	}

	srv := fakeservice.New(t)
	srv.AddRule(fakeservice.Rule{
		Match: fakeservice.Match{Method: http.MethodGet, PathSuffix: "/certificates/" + testName},
		Handler: fakeservice.RespondProblem(http.StatusConflict, future,
			fakeservice.DefaultInstanceID),
	})

	c := newFakeClient(t, srv)
	_, _, err := c.GetRegistration(context.Background(), testNamespace, testName, false)
	if err == nil {
		t.Fatal("a 409 must surface as an error")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("an unknown code must decode into an *client.APIError, not %T: %v", err, err)
	}
	if apiErr.Known {
		t.Errorf("Known = true for %q, which this build's taxonomy does not carry", future)
	}
	if apiErr.Code() != future {
		t.Errorf("Code() = %q, want the unknown code carried through verbatim (%q)", apiErr.Code(), future)
	}
}

// assertAbsentFeatureIsAPlanTimeErrorNamingIt is the F-065 assertion the item
// calls out by itself: the failure must be a PLAN-TIME ATTRIBUTE error, it must
// NAME THE FEATURE, and it must not be a version comparison.
func assertAbsentFeatureIsAPlanTimeErrorNamingIt(t *testing.T, id string, srv *fakeservice.Server) {
	t.Helper()
	ctx := context.Background()
	srv.SeedRegistration(fakeservice.RegistrationSeed{Namespace: testNamespace, Name: testName})
	r := newTestResource(t, srv)
	if r.data.HasFeature(FeatureDestinationMigration) {
		t.Fatalf("%s requires the feature to be ABSENT, but the harness advertises it", id)
	}

	const otherVault = "/subscriptions/8b1e6a2c-4f3d-4a5b-9c7e-1d2f3a4b5c6d/resourceGroups/rg-payments/" +
		"providers/Microsoft.KeyVault/vaults/kv-other"

	state := priorState(t, ctx, fakeservice.DefaultInstanceID)
	plan := planFrom(t, ctx, state, func(m *certificateResourceModel) {
		m.KeyVaultID = armid.NewValue(otherVault)
	})
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, fwresource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config(plan)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf("%s must fail at PLAN time; the plan succeeded", id)
	}

	var found, attributeScoped bool
	for _, d := range resp.Diagnostics.Errors() {
		if !strings.Contains(d.Summary(), "Changing the destination") {
			continue
		}
		found = true
		// It must be an ATTRIBUTE error, so the console points at the offending
		// line rather than at the resource as a whole.
		if withPath, ok := d.(diag.DiagnosticWithPath); ok && withPath.Path().String() != "" {
			attributeScoped = true
		}
		detail := d.Detail()
		// NAMES THE FEATURE.
		if !strings.Contains(detail, FeatureDestinationMigration) {
			t.Errorf("%s: the plan-time error must NAME the absent feature %q; got:\n%s",
				id, FeatureDestinationMigration, detail)
		}
		// AND IS NOT A VERSION COMPARISON. The service here is at exactly the
		// version the provider wants, so any version talk in this message would be
		// the version-arithmetic gating F-065 forbids.
		for _, forbidden := range []string{"api_version", "API major", "older than this provider requires",
			"minimum_client_version", "upgrade the provider", "Upgrade the provider"} {
			if strings.Contains(detail, forbidden) {
				t.Errorf("%s: the feature-absent error mentions %q. Feature gating is by NAME, never by version "+
					"arithmetic (F-065): the service is at the provider's own version and the constraint is a "+
					"capability, not a release. Got:\n%s", id, forbidden, detail)
			}
		}
	}
	if !found {
		t.Fatalf("%s: expected the destination-change plan error; got %v", id, resp.Diagnostics)
	}

	if !attributeScoped {
		t.Errorf("%s: the plan-time error must be an ATTRIBUTE error so the console points at the offending line", id)
	}
}
