package fakeservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mantisec/terraform-provider-azureacme/internal/contracts"
	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// DefaultKeyVaultID is the destination the seeds and examples use.
const DefaultKeyVaultID = "/subscriptions/8b1e6a2c-4f3d-4a5b-9c7e-1d2f3a4b5c6d/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-payments"

// RegistrationSeed describes a registration to place in the fake's state
// directly, without going through a PUT. Tests that exercise Read do not want to
// drive a create first.
type RegistrationSeed struct {
	Namespace         string
	Name              string
	DNSNames          []string
	KeyVaultID        string
	CertificateName   string
	ACMEProfile       string
	ValidationBinding string
	Description       string
	Labels            map[string]string
	DeletionPolicy    string
	ConsumerProfile   string
	OwnerPrincipalID  string
	// LifecycleState defaults to "active".
	LifecycleState string
	// DeliveryStage defaults to "published".
	DeliveryStage string
	// Published false leaves current_certificate null — the "never issued, or
	// issuance failed" row of §7.2.2, which is a SUCCESS with a null certificate.
	Unpublished bool
	// Expired makes not_after a past instant. Expiry is a STATUS, not an absence.
	Expired bool
	// OperationRunning models a scheduler-driven renewal overlapping a plan.
	OperationRunning bool
}

// SeedRegistration places a registration in the fake's state and returns it.
func (s *Server) SeedRegistration(seed RegistrationSeed) *Registration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seed.KeyVaultID == "" {
		seed.KeyVaultID = DefaultKeyVaultID
	}
	if seed.OwnerPrincipalID == "" {
		seed.OwnerPrincipalID = s.opts.CallerPrincipalID
	}
	if seed.LifecycleState == "" {
		seed.LifecycleState = "active"
	}
	if seed.DeliveryStage == "" {
		seed.DeliveryStage = "published"
	}
	if len(seed.DNSNames) == 0 {
		seed.DNSNames = []string{"api.example.com"}
	}

	spec := contracts.CertificateSpecRead{
		DNSNames: append([]string(nil), seed.DNSNames...),
		Destination: &contracts.DestinationRead{
			KeyVaultID: seed.KeyVaultID,
			CertificateName: func() string {
				if seed.CertificateName != "" {
					return seed.CertificateName
				}
				return seed.Name
			}(),
			Type: ptr("azure_key_vault"),
		},
		Key:         &contracts.KeyPolicyWrite{Algorithm: ptr("RSA"), Size: ptr(int64(2048)), Exportable: ptr(true)},
		ACMEProfile: ptr(orDefault(seed.ACMEProfile, "default")),
		Renewal:     &contracts.RenewalSpec{Mode: ptr("automatic"), UseARI: ptr(true)},
		Revision:    1,
		Generation:  1,
	}
	if seed.ValidationBinding != "" {
		spec.ValidationBinding = ptr(seed.ValidationBinding)
	} else {
		spec.ValidationBinding = ptr("auto")
	}
	if seed.Description != "" {
		spec.Description = ptr(seed.Description)
	}
	if len(seed.Labels) > 0 {
		spec.Labels = seed.Labels
	}
	if seed.DeletionPolicy != "" {
		dp := contracts.DeletionPolicy(seed.DeletionPolicy)
		spec.DeletionPolicy = &dp
	} else {
		dp := contracts.DeletionPolicyRetain
		spec.DeletionPolicy = &dp
	}
	if seed.ConsumerProfile != "" {
		spec.ConsumerProfile = ptr(seed.ConsumerProfile)
	}
	spec.Hash = issuanceHash(specWriteFrom(spec))

	reg := &Registration{
		Namespace: seed.Namespace, Name: seed.Name,
		RegistrationID:   s.nextID("reg_"),
		OwnerPrincipalID: seed.OwnerPrincipalID,
		Spec:             spec,
		Status: contracts.RegistrationStatus{
			LifecycleState: seed.LifecycleState, Phase: "ready",
			ObservedGeneration: 1, DeliveryStage: seed.DeliveryStage,
			PublicationMode: ptr("merge"),
			Ownership: &contracts.Ownership{
				OwnerPrincipalID:   &seed.OwnerPrincipalID,
				OwnerPrincipalType: ptr("ServicePrincipal"),
				Transferable:       ptr(false),
			},
			Audit: &contracts.Audit{
				CreatedAt: ptr(primitives.FormatTimestamp(time.Now().UTC().Add(-90 * 24 * time.Hour))),
				CreatedBy: ptr("ci@example.com"),
			},
		},
	}
	s.registrations[key(seed.Namespace, seed.Name)] = reg
	// A seeded registration is stored the way a WRITTEN one is: server-resolved
	// destination id, materialised verification block. A seed that looked like
	// the caller's bytes would make every Read test assert against a shape the
	// real service never returns (normalise.go).
	s.normaliseSpecLocked(reg, nil)
	s.refreshResolvedLocked(reg)
	if !seed.Unpublished {
		s.issueCertificateLocked(reg)
		if seed.Expired {
			reg.Status.CurrentCertificate.NotAfter = primitives.FormatTimestamp(time.Now().UTC().Add(-24 * time.Hour))
		}
	} else {
		reg.Status.Phase = "pending"
		reg.Status.ObservedGeneration = 0
		reg.Status.DeliveryStage = "pending"
	}
	if seed.OperationRunning {
		opID := s.nextID("op_")
		opType := contracts.OperationTypeRenew
		reg.Status.Operation = &contracts.OperationSummary{
			ID: &opID, Type: &opType,
			State: contracts.RegistrationOperationStateRunning,
			Phase: ptr(contracts.OperationPhaseAwaitingValidation),
		}
	}
	return reg
}

// Registration returns the stored registration, or nil.
func (s *Server) Registration(namespace, name string) *Registration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registrations[key(namespace, name)]
}

// SimulateRenewal is the plan-stability proof (§6.4, AP-6).
//
// It changes ONLY the certificate: a new thumbprint, a new serial, new version
// URIs, new validity, a new last_successful_renewal_at. It does NOT touch
// spec.revision or spec.generation, because the ETag covers the SPEC ONLY —
// which is what keeps a renewal from invalidating every client's If-Match and
// from producing a planned change.
func (s *Server) SimulateRenewal(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg := s.registrations[key(namespace, name)]
	if reg == nil || reg.Status.CurrentCertificate == nil {
		return
	}
	previous := reg.Status.CurrentCertificate
	reg.Status.PreviousCertificate = &contracts.PreviousCertificate{
		NotAfter: ptr(previous.NotAfter), ThumbprintSHA256: ptr(previous.ThumbprintSHA256),
		VersionSecretID: previous.VersionSecretID,
	}
	s.seq++
	version := fmt.Sprintf("%032x", s.seq*7919)
	now := time.Now().UTC()
	previous.ThumbprintSHA256 = hashHex("thumbprint", version)
	previous.SerialNumber = ptr(hashHex("serial", version)[:32])
	previous.NotBefore = primitives.FormatTimestamp(now)
	previous.NotAfter = primitives.FormatTimestamp(now.Add(45 * 24 * time.Hour))
	previous.IssuedAt = ptr(primitives.FormatTimestamp(now))
	previous.PublishedAt = ptr(primitives.FormatTimestamp(now))
	previous.VersionSecretID = ptr(*previous.VersionlessSecretID + "/" + version)
	previous.VersionCertificateID = ptr(*previous.VersionlessCertificateID + "/" + version)
	if reg.Status.Renewal == nil {
		reg.Status.Renewal = &contracts.RenewalStatus{}
	}
	reg.Status.Renewal.LastSuccessfulRenewalAt = ptr(primitives.FormatTimestamp(now))
	reg.Status.Renewal.Source = ptr("ari")
}

// InjectServerLabel writes a label into the CLIENT's labels map — a deliberate
// violation of guarantee G-6.
//
// It exists so a test can prove the violation is CAUGHT (as a perpetual diff
// the provider surfaces) rather than absorbed. A provider that silently merged
// server-side labels would hide plan-stability failure 5 of §6.4.
func (s *Server) InjectServerLabel(namespace, name, k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg := s.registrations[key(namespace, name)]
	if reg == nil {
		return
	}
	if reg.Spec.Labels == nil {
		reg.Spec.Labels = map[string]string{}
	}
	reg.Spec.Labels[k] = v
}

// SetLifecycleState drives the `deleting` and `authorization_revoked` rows of
// §7.2.2, both of which are SUCCESS-with-a-warning and must never remove.
func (s *Server) SetLifecycleState(namespace, name, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reg := s.registrations[key(namespace, name)]; reg != nil {
		reg.Status.LifecycleState = state
	}
}

// Tombstone marks a registration deleted, so GET returns 410 registration_deleted.
func (s *Server) Tombstone(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reg := s.registrations[key(namespace, name)]; reg != nil {
		reg.Tombstoned = true
	}
}

// Delete removes a registration entirely, so GET returns 404
// registration_not_found.
func (s *Server) Delete(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.registrations, key(namespace, name))
}

// ---------------------------------------------------------------- projections

func (s *Server) refreshResolvedLocked(reg *Registration) {
	certName := reg.Name
	if reg.Spec.Destination != nil && reg.Spec.Destination.CertificateName != "" {
		certName = reg.Spec.Destination.CertificateName
	}
	reg.Status.ResolvedCertificateName = ptr(certName)

	profile := s.opts.DefaultACMEProfile
	if reg.Spec.ACMEProfile != nil && *reg.Spec.ACMEProfile != "default" {
		profile = *reg.Spec.ACMEProfile
	}
	reg.Status.ResolvedACMEProfile = ptr(profile)

	binding := "example-com"
	if len(s.opts.ValidationBindings) > 0 {
		binding = s.opts.ValidationBindings[0].ID
	}
	if reg.Spec.ValidationBinding != nil && *reg.Spec.ValidationBinding != "auto" {
		binding = *reg.Spec.ValidationBinding
	}
	reg.Status.ResolvedValidationBinding = ptr(binding)
	if reg.Status.PublicationMode == nil {
		reg.Status.PublicationMode = ptr("merge")
	}
	if reg.Spec.Destination != nil {
		hash := primitives.DestinationHash(reg.Spec.Destination.KeyVaultID, certName)
		reg.Spec.Destination.DestinationHash = &hash
	}
}

func (s *Server) issueCertificateLocked(reg *Registration) {
	certName := reg.Name
	if reg.Status.ResolvedCertificateName != nil {
		certName = *reg.Status.ResolvedCertificateName
	}
	vault := "kv-unknown"
	if reg.Spec.Destination != nil {
		vault = vaultNameFromID(reg.Spec.Destination.KeyVaultID)
	}
	versionlessSecret := fmt.Sprintf("https://%s.vault.azure.net/secrets/%s", vault, certName)
	versionlessCert := fmt.Sprintf("https://%s.vault.azure.net/certificates/%s", vault, certName)
	s.seq++
	version := fmt.Sprintf("%032x", s.seq*104729)
	now := time.Now().UTC()
	reg.Status.CurrentCertificate = &contracts.CurrentCertificate{
		VersionlessSecretID:      &versionlessSecret,
		VersionlessCertificateID: &versionlessCert,
		VersionSecretID:          ptr(versionlessSecret + "/" + version),
		VersionCertificateID:     ptr(versionlessCert + "/" + version),
		ThumbprintSHA256:         hashHex("thumbprint", version),
		SerialNumber:             ptr(hashHex("serial", version)[:32]),
		NotBefore:                primitives.FormatTimestamp(now),
		NotAfter:                 primitives.FormatTimestamp(now.Add(45 * 24 * time.Hour)),
		IssuedAt:                 ptr(primitives.FormatTimestamp(now)),
		PublishedAt:              ptr(primitives.FormatTimestamp(now)),
		Issuer:                   ptr("CN=Pebble Intermediate CA"),
		ACMEProfile:              reg.Status.ResolvedACMEProfile,
		DNSNames:                 append([]string(nil), reg.Spec.DNSNames...),
	}
	if reg.Status.Renewal == nil {
		reg.Status.Renewal = &contracts.RenewalStatus{
			NextCheckAt: ptr(primitives.FormatTimestamp(now.Add(24 * time.Hour))),
			Source:      ptr("ari"),
		}
	}
}

func (s *Server) representationLocked(reg *Registration) contracts.CertificateRegistration {
	return contracts.CertificateRegistration{
		APIVersion: s.opts.APIVersion, Kind: "CertificateRegistration",
		Namespace: reg.Namespace, Name: reg.Name,
		RegistrationID: reg.RegistrationID, ServiceInstanceID: s.opts.InstanceID,
		Spec: reg.Spec, Status: reg.Status,
		SystemLabels: reg.SystemLabels,
		Warnings:     reg.Warnings,
		Links: contracts.Links{
			Self: "/v1/namespaces/" + reg.Namespace + "/certificates/" + reg.Name,
		},
	}
}

// handleAction implements the action subset the tests need.
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request, namespace, name, action string) {
	if r.Method != http.MethodPost {
		s.problem(w, http.StatusMethodNotAllowed, contracts.CodeInvalidSpec)
		return
	}
	switch action {
	case "force-renew":
		s.SimulateRenewal(namespace, name)
		s.mu.Lock()
		defer s.mu.Unlock()
		reg := s.registrations[key(namespace, name)]
		if reg == nil {
			RespondProblem(http.StatusNotFound, contracts.CodeRegistrationNotFound, s.opts.InstanceID)(w, nil)
			return
		}
		op := s.startOperationLocked(reg, contracts.OperationTypeRenew)
		op.op.State = contracts.OperationStateSucceeded
		reg.Status.Phase = "ready"
		reg.Status.Operation = &contracts.OperationSummary{
			ID: &op.op.ID, Type: &op.op.Type,
			State: contracts.RegistrationOperationStateSucceeded,
			Phase: ptr(contracts.OperationPhaseDone),
		}
		writeJSON(w, http.StatusAccepted, contracts.OperationAccepted{
			OperationID: op.op.ID, RegistrationID: reg.RegistrationID, Status: "accepted",
			TargetGeneration: reg.Spec.Generation,
		}, map[string]string{"Operation-Location": "/v1/operations/" + op.op.ID, "Retry-After": "1"})
	default:
		s.problem(w, http.StatusNotFound, contracts.CodeOperationNotPermitted)
	}
}

// ------------------------------------------------------------------- helpers

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func vaultNameFromID(id string) string {
	segs := strings.Split(strings.TrimSuffix(id, "/"), "/")
	if len(segs) == 0 {
		return "kv-unknown"
	}
	return segs[len(segs)-1]
}

func hashHex(prefix, seed string) string {
	sum := sha256.Sum256([]byte(prefix + "|" + seed))
	return hex.EncodeToString(sum[:])
}

// issuanceHash is the fake's stand-in for the server-side issuance hash: it
// covers exactly the ISSUANCE-RELEVANT fields, so a description or label edit
// bumps the revision without bumping the generation. Getting this wrong in the
// fake would hide the C-04 class of bug rather than expose it.
func issuanceHash(spec contracts.CertificateSpecFields) string {
	names := append([]string(nil), spec.DNSNames...)
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(strings.Join(names, ","))
	b.WriteString("|")
	if spec.Destination != nil {
		if spec.Destination.KeyVaultID != nil {
			b.WriteString(*spec.Destination.KeyVaultID)
		}
		b.WriteString("/")
		if spec.Destination.CertificateName != nil {
			b.WriteString(*spec.Destination.CertificateName)
		}
	}
	b.WriteString("|")
	if spec.Key != nil {
		keyJSON, _ := json.Marshal(spec.Key)
		b.Write(keyJSON)
	}
	b.WriteString("|")
	if spec.ACMEProfile != nil {
		b.WriteString(*spec.ACMEProfile)
	}
	b.WriteString("|")
	if spec.ValidationBinding != nil {
		b.WriteString(*spec.ValidationBinding)
	}
	if spec.CommonName != nil {
		b.WriteString("|" + *spec.CommonName)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func specReadFrom(in contracts.CertificateSpecFields) contracts.CertificateSpecRead {
	out := contracts.CertificateSpecRead{
		AcknowledgeIrreversibleDelete: in.AcknowledgeIrreversibleDelete,
		ACMEProfile:                   in.ACMEProfile,
		CommonName:                    in.CommonName,
		ConsumerProfile:               in.ConsumerProfile,
		DeletionPolicy:                in.DeletionPolicy,
		Description:                   in.Description,
		DNSNames:                      append([]string(nil), in.DNSNames...),
		Key:                           in.Key,
		Labels:                        in.Labels,
		Renewal:                       in.Renewal,
		ValidationBinding:             in.ValidationBinding,
		Verification:                  in.Verification,
	}
	if in.Destination != nil {
		dest := contracts.DestinationRead{Type: in.Destination.Type, DestinationID: in.Destination.DestinationID}
		if in.Destination.KeyVaultID != nil {
			dest.KeyVaultID = *in.Destination.KeyVaultID
		}
		if in.Destination.CertificateName != nil {
			dest.CertificateName = *in.Destination.CertificateName
		}
		out.Destination = &dest
	}
	return out
}

func specWriteFrom(in contracts.CertificateSpecRead) contracts.CertificateSpecFields {
	out := contracts.CertificateSpecFields{
		AcknowledgeIrreversibleDelete: in.AcknowledgeIrreversibleDelete,
		ACMEProfile:                   in.ACMEProfile,
		CommonName:                    in.CommonName,
		ConsumerProfile:               in.ConsumerProfile,
		DeletionPolicy:                in.DeletionPolicy,
		Description:                   in.Description,
		DNSNames:                      append([]string(nil), in.DNSNames...),
		Key:                           in.Key,
		Labels:                        in.Labels,
		Renewal:                       in.Renewal,
		ValidationBinding:             in.ValidationBinding,
		Verification:                  in.Verification,
	}
	if in.Destination != nil {
		out.Destination = &contracts.DestinationFields{
			Type: in.Destination.Type, DestinationID: in.Destination.DestinationID,
			KeyVaultID: ptr(in.Destination.KeyVaultID), CertificateName: ptr(in.Destination.CertificateName),
		}
	}
	return out
}

// Publish fulfils the registration's current generation: observed_generation
// catches up, the phase becomes ready, the delivery stage becomes published and
// a certificate appears.
//
// It exists so a scenario can model "the service finished the work after
// Terraform stopped waiting" — the case the create-timeout contract is built
// around, and the case a `wait_for = "accepted"` refresh has to observe.
func (s *Server) Publish(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg := s.registrations[key(namespace, name)]
	if reg == nil {
		return
	}
	reg.Status.ObservedGeneration = reg.Spec.Generation
	reg.Status.Phase = "ready"
	reg.Status.DeliveryStage = "published"
	if reg.Status.CurrentCertificate == nil {
		s.issueCertificateLocked(reg)
	}
}
