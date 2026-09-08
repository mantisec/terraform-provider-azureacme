package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// TestNegotiation_APIMajorMismatchIsAHardError.
func TestNegotiation_APIMajorMismatchIsAHardError(t *testing.T) {
	srv := fakeservice.New(t, func(o *fakeservice.Options) {
		o.APIVersion = "2.0"
		o.APIVersionsSupported = []string{"2.0"}
	})
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if !resp.Diagnostics.HasError() {
		t.Fatal("a different API major must be a hard error: the major version IS the compatibility boundary")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "different API major version") {
			found = true
			if !strings.Contains(d.Detail(), "2.0") || !strings.Contains(d.Detail(), "major 1") {
				t.Errorf("the diagnostic must name BOTH versions; got:\n%s", d.Detail())
			}
		}
	}
	if !found {
		t.Fatalf("expected a major-version error; got %v", resp.Diagnostics)
	}
}

// TestNegotiation_HigherMinorProceeds.
//
// Feature gating is by NAME, never by version arithmetic, so a newer service
// simply works and its unknown fields are ignored.
func TestNegotiation_HigherMinorProceeds(t *testing.T) {
	srv := fakeservice.New(t, func(o *fakeservice.Options) {
		o.APIVersion = "1.9"
		o.Features = []string{"destination_migration", "some_future_feature"}
	})
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if resp.Diagnostics.HasError() {
		t.Fatalf("a HIGHER minor must proceed: %v", resp.Diagnostics)
	}
	data := resp.ResourceData.(*providerData)
	if !data.HasFeature("destination_migration") {
		t.Error("feature gating by name did not see an advertised feature")
	}
	if data.HasFeature("not_advertised") {
		t.Error("HasFeature reported a feature the service does not advertise")
	}
}

// TestNegotiation_MinimumAndDeprecatedClientVersions.
func TestNegotiation_MinimumAndDeprecatedClientVersions(t *testing.T) {
	t.Run("below minimum_client_version is a hard error", func(t *testing.T) {
		srv := fakeservice.New(t, func(o *fakeservice.Options) { o.MinimumClientVersion = "2.0.0" })
		m := nullProviderModel(t)
		m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
		resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
		if !resp.Diagnostics.HasError() {
			t.Fatal("a provider below minimum_client_version must fail")
		}
	})

	t.Run("below deprecated_client_version warns and names the deadline", func(t *testing.T) {
		deprecated := "1.5.0"
		deadline := "2027-01-31"
		srv := fakeservice.New(t, func(o *fakeservice.Options) {
			o.MinimumClientVersion = "0.1.0"
			o.DeprecatedClientVersion = &deprecated
			o.DeprecatedClientDeadline = &deadline
		})
		m := nullProviderModel(t)
		m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
		resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
		if resp.Diagnostics.HasError() {
			t.Fatalf("deprecation is a WARNING, not an error: %v", resp.Diagnostics)
		}
		found := false
		for _, d := range resp.Diagnostics.Warnings() {
			if strings.Contains(d.Summary(), DiagClientDeprecated) {
				found = true
				if !strings.Contains(d.Detail(), deadline) {
					t.Errorf("the warning must name deprecated_client_deadline; got:\n%s", d.Detail())
				}
			}
		}
		if !found {
			t.Fatalf("expected the %s warning; got %v", DiagClientDeprecated, resp.Diagnostics)
		}
	})
}

// TestNegotiation_ExactlyOneCapabilitiesRequestPerProviderInstance is §3.1: the
// document is cached for the provider's lifetime, so plan-time validation costs
// NO extra API calls.
func TestNegotiation_ExactlyOneCapabilitiesRequestPerProviderInstance(t *testing.T) {
	srv := fakeservice.New(t)
	m := nullProviderModel(t)
	m.ConnectionProfile = connectionProfileObject(t, srv.URL(), "aud", "tenant", "")
	resp := configureWith(t, m, client.StaticTokenSource{Value: "tok"})
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure: %v", resp.Diagnostics)
	}
	if got := srv.RequestCount("GET", "/capabilities"); got != 1 {
		t.Fatalf("/v1/capabilities was requested %d times per Configure, want exactly 1", got)
	}

	// And plan-time validation adds none.
	data := resp.ResourceData.(*providerData)
	r := &certificateResource{data: data, sleep: testSleep}
	ctx := t.Context()
	plan := planFor(t, ctx, func(mm *certificateResourceModel) {
		mm.ACMEProfile = types.StringValue("classic")
	})
	var planModel certificateResourceModel
	if diags := plan.Get(ctx, &planModel); diags.HasError() {
		t.Fatal(diags)
	}
	srv.ResetRequests()
	r.validateAgainstCapabilities(ctx, planModel, &resp.Diagnostics)
	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("plan-time validation issued %d requests; it must read the cache", got)
	}
}

// TestAPIMinorRequiredMayOnlyRiseInAProviderMajor pins the constant.
//
// Raising `apiMinorRequired` in a patch release makes a workspace UNPLANNABLE
// after a routine `terraform init -upgrade` — including certificates that use no
// new feature — until a platform team the consumer does not control deploys a
// service upgrade. The constant is therefore pinned here, and moving it is a
// deliberate two-file edit that a reviewer sees.
func TestAPIMinorRequiredMayOnlyRiseInAProviderMajor(t *testing.T) {
	const pinned = 0
	if apiMinorRequired != pinned {
		t.Fatalf("apiMinorRequired is %d, pinned at %d.\n\n"+
			"Raising it is permitted ONLY in a provider MAJOR version. If this is a deliberate major-version change, "+
			"update the pin here in the same commit and say so in the changelog.", apiMinorRequired, pinned)
	}
	if apiMajor != 1 {
		t.Fatalf("apiMajor is %d, want 1 — /v1 is the compatibility boundary", apiMajor)
	}
}
