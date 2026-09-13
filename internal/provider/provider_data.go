package provider

import (
	"github.com/mantisec/terraform-provider-azureacme/internal/client"
	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
)

// providerData is what Configure hands to every resource and data source.
//
// The CACHED capabilities document is the point: §3.1 keeps the full
// /v1/capabilities response for the provider's lifetime so that plan-time
// validators have `limits`, `acme.profiles`, `key_policies` and
// `consumer_profiles` without a single extra API call. Validation that costs a
// round trip is validation that gets moved to apply time.
type providerData struct {
	Client       *client.Client
	Capabilities *contracts.Capabilities
	// Environment drives the Key Vault DNS suffix used to construct the
	// versionless URIs at plan time.
	Environment string
	// SkipVersionCheck and SkipInstanceCheck are DELIBERATELY SEPARATE. As
	// originally specified one `skip_capability_check` flag skipped "all of the
	// above", so the documented workaround for a version wedge also disabled
	// service-instance pinning — re-opening the mistyped-endpoint catastrophe in
	// which every certificate is removed from state and reissued against the
	// wrong service. One flag must never disable both (§2.2, A4/T-6).
	SkipVersionCheck  bool
	SkipInstanceCheck bool
}

// ServiceInstanceID is the id reported by the endpoint at Configure.
func (d *providerData) ServiceInstanceID() string {
	if d == nil || d.Capabilities == nil {
		return ""
	}
	return d.Capabilities.Service.InstanceID
}

// ServiceInstanceName is the human-readable label. A DIFFERENT FIELD from the
// id, and the two must not be conflated: a rename must not change an id that
// must not change.
func (d *providerData) ServiceInstanceName() string {
	if d == nil || d.Capabilities == nil {
		return ""
	}
	return d.Capabilities.Service.InstanceName
}

// CallerPrincipalID is what import compares against
// status.ownership.owner_principal_id.
func (d *providerData) CallerPrincipalID() string {
	if d == nil || d.Capabilities == nil {
		return ""
	}
	return d.Capabilities.Caller.PrincipalID
}

// FeatureDestinationMigration is the one `/v1/capabilities.service.features` name
// this provider gates on today.
//
// It is a constant rather than a literal because it appears in TWO places that
// must never disagree: the `HasFeature` lookup, and the plan-time diagnostic that
// tells the operator which feature was absent. A diagnostic naming a feature the
// lookup does not ask for sends a platform team to enable the wrong thing
// (release-engineering.md §9.3, F-065).
const FeatureDestinationMigration = "destination_migration"

// HasFeature is NAME-based feature gating. Never version arithmetic: a client
// wanting `destination_migration` checks for the string, not for
// `api_version >= 1.6`.
func (d *providerData) HasFeature(name string) bool {
	if d == nil || d.Capabilities == nil {
		return false
	}
	for _, f := range d.Capabilities.Service.Features {
		if f == name {
			return true
		}
	}
	return false
}
