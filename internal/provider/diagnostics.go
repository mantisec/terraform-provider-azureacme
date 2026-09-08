package provider

// Provider-only diagnostic identifiers (terraform-provider-contract.md §10).
//
// These are NOT wire error codes and must never appear in contracts/errors/.
// They are stable identifiers for diagnostics the provider raises on its own, so
// documentation and support can reference them. Every one of them is included in
// the diagnostic's summary or detail text, because a support conversation that
// cannot name the diagnostic is a support conversation that starts from scratch.
const (
	DiagServiceInstanceMismatch      = "service_instance_mismatch"
	DiagEndpointUnknownAtPlan        = "endpoint_unknown_at_plan"
	DiagDestinationChangeUnsupported = "destination_change_unsupported"
	DiagReissueExpected              = "reissue_expected"
	DiagReplacementWillDeleteCert    = "replacement_will_delete_certificate"
	DiagConsumerInServiceOnDestroy   = "consumer_in_service_on_destroy"
	DiagCreateTimeoutStillRunning    = "create_timeout_still_running"
	DiagCreateDeferredBeyondTimeout  = "create_deferred_beyond_timeout"
	DiagUnpublishedURIWithheld       = "unpublished_uri_withheld"
	DiagClientDeprecated             = "client_deprecated"
	DiagCapabilityCheckSkipped       = "capability_check_skipped"
	DiagClientSecretFromEnvironment  = "client_secret_from_environment"
	DiagOwnershipTransferRequired    = "ownership_transfer_required"
	DiagAuthorizationRevoked         = "authorization_revoked"
	DiagRegistrationDecommissioning  = "registration_decommissioning"
)

// AllProviderDiagnosticIDs is exported so a test can assert none of them
// collides with a published wire error code.
var AllProviderDiagnosticIDs = []string{
	DiagServiceInstanceMismatch,
	DiagEndpointUnknownAtPlan,
	DiagDestinationChangeUnsupported,
	DiagReissueExpected,
	DiagReplacementWillDeleteCert,
	DiagConsumerInServiceOnDestroy,
	DiagCreateTimeoutStillRunning,
	DiagCreateDeferredBeyondTimeout,
	DiagUnpublishedURIWithheld,
	DiagClientDeprecated,
	DiagCapabilityCheckSkipped,
	DiagClientSecretFromEnvironment,
}
