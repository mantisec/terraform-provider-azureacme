package provider

// Provider-only diagnostic identifiers (terraform-provider-contract.md §10).
//
// These are NOT wire error codes and must never appear in contracts/errors/.
// They are stable identifiers for diagnostics the provider raises on its own, so
// documentation and support can reference them. Every one of them is included in
// the diagnostic's summary or detail text, because a support conversation that
// cannot name the diagnostic is a support conversation that starts from scratch.
//
// THE ONE RULE THAT MAKES THEM SAFE: no identifier here may equal a published wire
// error code. `service_instance_mismatch` is held out of the taxonomy for exactly
// this purpose -- the `rejected_aliases` entry whose `canonical` is null, which
// contracts/tools/check_contracts.py then permits in this package and nowhere a
// wire code is authored or emitted. That carve-out is only sound while the two
// namespaces stay disjoint: an identifier that collides makes a support answer
// ambiguous ("did the service say that, or did the provider?") and quietly widens
// the carve-out to cover a real code. `diagnostics_test.go` asserts the
// disjointness over every `Diag*` constant in this file, read from the source, so
// a new constant cannot escape it by being left out of the slice below.
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
	// The four credential-resolution diagnostics of §2.4 and ADR 0019. They are
	// separate identifiers because they are separate operator mistakes: two
	// methods configured, no method resolvable, a managed identity named
	// ambiguously, and an endpoint that disagrees about the audience.
	DiagMultipleCredentialMethods       = "multiple_credential_methods"
	DiagNoCredentialMethod              = "no_credential_method"
	DiagManagedIdentityClientIDRequired = "managed_identity_client_id_required"
	DiagAudienceMismatchReported        = "audience_mismatch_reported"
	// `import_ownership_transfer_required`, NOT `ownership_transfer_required`:
	// the bare name is a published wire code (409, the service refusing a PUT that
	// would transfer ownership). This diagnostic is a different event -- the
	// provider refusing an IMPORT locally, with no request made and no wire error
	// received -- and giving the two one name makes a support transcript unable to
	// say which happened.
	DiagImportOwnershipTransferRequired = "import_ownership_transfer_required"
	DiagAuthorizationRevoked            = "authorization_revoked"
	DiagRegistrationDecommissioning     = "registration_decommissioning"
)

// AllProviderDiagnosticIDs is exported so a test can assert none of them
// collides with a published wire error code. `diagnostics_test.go` also asserts
// that this slice holds EVERY `Diag*` constant declared above: a list that can be
// trimmed is a check that can be silenced by omission.
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
	DiagMultipleCredentialMethods,
	DiagNoCredentialMethod,
	DiagManagedIdentityClientIDRequired,
	DiagAudienceMismatchReported,
	DiagImportOwnershipTransferRequired,
	DiagAuthorizationRevoked,
	DiagRegistrationDecommissioning,
}
