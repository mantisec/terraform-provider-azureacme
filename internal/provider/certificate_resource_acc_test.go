package provider_test

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
	"github.com/mantisec/terraform-provider-azureacme/internal/provider"
)

// The acceptance matrix of terraform-provider-contract.md §11.2, run against the
// IN-PROCESS FAKE SERVICE rather than a deployed instance.
//
// WHY THE FAKE. §11.2 as written requires a CI namespace, a DNS zone, a service
// instance on Let's Encrypt staging and a dedicated service principal. None of
// those exist yet, and the properties these tests protect — plan stability under
// renewal, UseStateForUnknown versus replacement, the destination-change plan
// error, the create-timeout recovery — are properties of the PROVIDER, not of
// the certificate authority. Running them against the fake makes them run on
// every commit instead of never.
//
// Where a test depends on something only a real service can produce, it is
// absent and is recorded as not delivered rather than faked into a green tick.
//
// These tests never reach the network: the fake binds to loopback, and no ACME
// directory, Azure subscription or Key Vault is touched.

const (
	accNamespace = "payments-prod"
	accName      = "payments-api"
	accVaultID   = fakeservice.DefaultKeyVaultID
)

// testAccPreCheck fails LOUDLY rather than skipping silently when the harness
// cannot run.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance tests skipped: set TF_ACC=1 to run them (they need the `terraform` binary; they need no network and no Azure credentials)")
	}
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		path, err := exec.LookPath("terraform")
		if err != nil {
			t.Fatalf("TF_ACC is set but no `terraform` binary is on PATH and TF_ACC_TERRAFORM_PATH is unset: %v", err)
		}
		t.Setenv("TF_ACC_TERRAFORM_PATH", path)
	}
}

// startFake boots a fake service and points the provider at it through the
// environment, which is exactly the `MANTISEC_ACME_ENDPOINT` CI ergonomics path
// §1.4 sanctions.
func startFake(t *testing.T, opts ...func(*fakeservice.Options)) *fakeservice.Server {
	t.Helper()
	srv := fakeservice.New(t, opts...)
	t.Setenv("MANTISEC_ACME_ENDPOINT", srv.URL())
	t.Setenv("MANTISEC_ACME_AUDIENCE", "api://mantisec-acme")
	t.Setenv("MANTISEC_ACME_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	// The documented pre-acquired-token path. No Azure credential is involved.
	t.Setenv("MANTISEC_ACME_TOKEN", "acceptance-test-bearer-token")
	return srv
}

func protoV6Factories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"azureacme": providerserver.NewProtocol6WithError(provider.New("1.0.0")()),
	}
}

// configMinimal is the SIX-CONCEPT configuration of §5.1, with NO `key` block at
// all — the default is correct for every consumer in the v1 matrix and the
// example is what people copy.
func configMinimal(extra string) string {
	return fmt.Sprintf(`
provider "azureacme" {}

resource "azureacme_certificate" "api" {
  namespace    = %q
  name         = %q
  dns_names    = ["api.example.com"]
  key_vault_id = %q
%s
}
`, accNamespace, accName, accVaultID, extra)
}

// AP-1, AP-2, AP-3: create → published, then plan stability, then refresh and
// plan again.
func TestAccCertificate_CreateAndPlanStability(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				// AP-1
				Config: configMinimal(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("azureacme_certificate.api", "id", accNamespace+"/"+accName),
					resource.TestCheckResourceAttrSet("azureacme_certificate.api", "versionless_secret_id"),
					resource.TestCheckResourceAttrSet("azureacme_certificate.api", "current_certificate.thumbprint_sha256"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "wait_for", "published"),
					// The sentinels are stored, not materialised.
					resource.TestCheckResourceAttr("azureacme_certificate.api", "acme_profile", "default"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "validation_binding", "auto"),
					// The default key policy is exportable.
					resource.TestCheckResourceAttr("azureacme_certificate.api", "key.exportable", "true"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "key.algorithm", "RSA"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "key.size", "2048"),
					// `certificate_name` omitted stays NULL and the resolved value
					// appears separately — the O+C trap is absent.
					resource.TestCheckNoResourceAttr("azureacme_certificate.api", "certificate_name"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_certificate_name", accName),
					checkNotAfterInTheFuture("azureacme_certificate.api"),
				),
			},
			{
				// AP-2: a PlanOnly step immediately after the apply. A non-empty
				// plan here is exactly what `-detailed-exitcode` would report as 2.
				Config:   configMinimal(""),
				PlanOnly: true,
			},
			{
				// AP-3: refresh, then plan. A RefreshState step carries no Config.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config:   configMinimal(""),
				PlanOnly: true,
			},
		},
	})
}

// AP-6: RENEWAL DOES NOT DIFF.
//
// This discharges the highest-blast-radius `[assumed]` in the design. If it
// failed, every CI pipeline gating on `terraform plan -detailed-exitcode` would
// fail the day after every renewal — roughly eight times per certificate per
// year, fleet-wide, with no configuration change to blame.
//
// BLOCKING TEST. Do not skip it, do not weaken it.
func TestAccCertificate_RenewalDoesNotDiff(t *testing.T) {
	testAccPreCheck(t)
	srv := startFake(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{Config: configMinimal("")},
			{
				// The service renews out of band, exactly as it does eight times a
				// year without Terraform running.
				PreConfig: func() { srv.SimulateRenewal(accNamespace, accName) },
				Config:    configMinimal(""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// And again as a pure plan. A PlanOnly step that produced a
				// non-empty plan fails here, which is exactly the condition that
				// makes `terraform plan -detailed-exitcode` return 2.
				Config:   configMinimal(""),
				PlanOnly: true,
			},
		},
	})
}

// AP-7: UseStateForUnknown VERSUS REPLACEMENT.
//
// BLOCKING TEST. It discharges §6.3's `[assumed]`: the modifier short-circuits
// on a null prior state, and safety therefore depends on Terraform Core
// re-planning the create half of a replacement with a null prior state. A bad
// assumption here means a replaced certificate silently keeps the OLD vault's
// URIs in state.
func TestAccCertificate_UseStateForUnknownVersusReplacement(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	// Rename, so the DESTINATION-DERIVED value genuinely changes: with
	// `certificate_name` omitted the Key Vault object is named after `name`, so
	// the replacement's versionless URI must be the NEW one. If the create half
	// of the replacement carried the prior state forward, the URI in state would
	// silently be the OLD object's — which is the exact failure §6.3 flags.
	const renamedName = "payments-api-v2"
	renamed := fmt.Sprintf(`
provider "azureacme" {}

resource "azureacme_certificate" "api" {
  namespace    = %q
  name         = %q
  dns_names    = ["api.example.com"]
  key_vault_id = %q
}
`, accNamespace, renamedName, accVaultID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{Config: configMinimal("")},
			{
				Config: renamed,
				Check: resource.ComposeAggregateTestCheckFunc(
					// THE PROPERTY §6.3 IS WORRIED ABOUT: the replaced object must NOT
					// keep the previous object's URI.
					resource.TestCheckResourceAttr("azureacme_certificate.api", "versionless_secret_id",
						"https://kv-payments.vault.azure.net/secrets/"+renamedName),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "id", accNamespace+"/"+renamedName),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_certificate_name", renamedName),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionDestroyBeforeCreate),
						// THE ASSERTION THAT DISCHARGES §6.3. UseStateForUnknown
						// short-circuits on a null prior state but does not itself
						// inspect RequiresReplace, so safety depends on Terraform Core
						// re-planning the CREATE HALF of a replacement with a null prior
						// state. If it did not, a replaced certificate would silently
						// keep the OLD vault's URI in state.
						// The certificate itself must be re-planned from scratch.
						plancheck.ExpectUnknownValue("azureacme_certificate.api", tfjsonpath.New("current_certificate")),
						plancheck.ExpectUnknownValue("azureacme_certificate.api", tfjsonpath.New("registration_id")),
					},
				},
			},
		},
	})
}

// AP-8: a destination change FAILS THE PLAN and plans no destroy.
func TestAccCertificate_DestinationChangeFailsThePlan(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	moved := fmt.Sprintf(`
provider "azureacme" {}

resource "azureacme_certificate" "api" {
  namespace    = %q
  name         = %q
  dns_names    = ["api.example.com"]
  key_vault_id = "/subscriptions/8b1e6a2c-4f3d-4a5b-9c7e-1d2f3a4b5c6d/resourceGroups/rg-payments/providers/Microsoft.KeyVault/vaults/kv-other"
}
`, accNamespace, accName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{Config: configMinimal("")},
			{
				Config:      moved,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`To unblock planning, revert .key_vault_id.`),
			},
		},
	})
}

// AP-4: a description-only update bumps spec_revision, leaves generation and the
// thumbprint alone, and keeps `current_certificate` KNOWN in the plan.
func TestAccCertificate_DescriptionOnlyUpdate(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	var thumbprintBefore, generationBefore string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureAttr("azureacme_certificate.api", "current_certificate.thumbprint_sha256", &thumbprintBefore),
					captureAttr("azureacme_certificate.api", "generation", &generationBefore),
				),
			},
			{
				Config: configMinimal(`  description = "the payments API listener certificate"`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkAttrEquals("azureacme_certificate.api", "current_certificate.thumbprint_sha256", &thumbprintBefore),
					checkAttrEquals("azureacme_certificate.api", "generation", &generationBefore),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "spec_revision", "2"),
				),
			},
			{Config: configMinimal(`  description = "the payments API listener certificate"`), PlanOnly: true},
		},
	})
}

// AP-5: a dns_names change is IN PLACE, produces a new certificate, and leaves
// `versionless_secret_id` UNCHANGED.
func TestAccCertificate_DNSNamesUpdateIsInPlace(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	var uriBefore, thumbprintBefore string
	widened := fmt.Sprintf(`
provider "azureacme" {}

resource "azureacme_certificate" "api" {
  namespace    = %q
  name         = %q
  dns_names    = ["api.example.com", "www.example.com"]
  key_vault_id = %q
}
`, accNamespace, accName, accVaultID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureAttr("azureacme_certificate.api", "versionless_secret_id", &uriBefore),
					captureAttr("azureacme_certificate.api", "current_certificate.thumbprint_sha256", &thumbprintBefore),
				),
			},
			{
				Config: widened,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkAttrEquals("azureacme_certificate.api", "versionless_secret_id", &uriBefore),
					checkAttrDiffers("azureacme_certificate.api", "current_certificate.thumbprint_sha256", &thumbprintBefore),
				),
			},
			{Config: widened, PlanOnly: true},
		},
	})
}

// TestAccCertificate_SentinelIsRevertible proves the O+C trap of §5.3.1 is
// ABSENT.
//
// The trap: for an Optional+Computed attribute, removing it from configuration
// does NOT revert it to the server default — the prior state value persists,
// because Terraform cannot distinguish "the user removed it" from "the provider
// computed it". A team sets `acme_profile = "tlsserver"` for an experiment,
// deletes the line, and silently keeps a 25-name cap and a 45-day lifetime while
// `terraform plan` reports no change.
//
// The sentinel removes the trap structurally: the STORED value is `"default"`,
// which the service resolves at each issuance, so deleting the line really does
// revert.
func TestAccCertificate_SentinelIsRevertible(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check:  resource.TestCheckResourceAttr("azureacme_certificate.api", "acme_profile", "default"),
			},
			{
				Config: configMinimal(`  acme_profile = "tlsserver"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("azureacme_certificate.api", "acme_profile", "tlsserver"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_acme_profile", "tlsserver"),
				),
			},
			{
				// The line is deleted. The plan must SHOW the change back to the
				// sentinel, and state must hold it.
				Config: configMinimal(""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("azureacme_certificate.api", "acme_profile", "default"),
					// And the resolved value tracks the service default again.
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_acme_profile", "classic"),
				),
			},
			{Config: configMinimal(""), PlanOnly: true},
		},
	})
}

// AP-9: import with ImportStateVerify.
func TestAccCertificate_Import(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{Config: configMinimal("")},
			{
				ResourceName:            "azureacme_certificate.api",
				ImportState:             true,
				ImportStateId:           accNamespace + "/" + accName,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts", "wait_for"},
			},
		},
	})
}

// AP-16: `wait_for = "accepted"` withholds the URIs.
func TestAccCertificate_WaitForAcceptedWithholdsTheURI(t *testing.T) {
	testAccPreCheck(t)
	srv := startFake(t)
	srv.SetBehaviour(fakeservice.Behaviour{OperationNeverCompletes: true})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(`  wait_for = "accepted"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					// NULL, not the constructed value. The versionless secret URI is
					// valid but EMPTY until a version exists, so handing it out here
					// produces a successful apply and a listener bound to nothing —
					// a failure Terraform cannot detect for you.
					resource.TestCheckNoResourceAttr("azureacme_certificate.api", "versionless_secret_id"),
					resource.TestCheckNoResourceAttr("azureacme_certificate.api", "versionless_certificate_id"),
				),
			},
			{
				// A later refresh, once the service has published, populates it.
				PreConfig: func() {
					srv.SetBehaviour(fakeservice.Behaviour{})
					srv.Publish(accNamespace, accName)
				},
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("azureacme_certificate.api", "versionless_secret_id"),
					resource.TestCheckResourceAttrSet("azureacme_certificate.api", "current_certificate.thumbprint_sha256"),
				),
			},
		},
	})
}

// AP-18: `exportable = false` is rejected at VALIDATION, before any API call.
func TestAccCertificate_ExportableFalseFailsAtPlan(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(`
  key = {
    algorithm  = "RSA"
    size       = 2048
    exportable = false
  }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`no consumer in the v1 matrix can use`),
			},
		},
	})
}

// AP-14: THE CREATE TIMEOUT AND ITS RECOVERY.
//
// This is the test that closes the worst sequence in the design, and it is the
// test that DISCHARGED THE `[assumed]` IN §7.1.4 — unfavourably.
//
// WHAT THIS TEST ESTABLISHED, on Terraform 1.12.2:
//
//	Returning an error from Create with non-null state DOES taint the object.
//	The next plan is `[delete create]` — a destroy-then-create — NOT an update.
//	The specification recorded the favourable resolution (no taint) as the safer
//	one and marked it `[assumed — confirm against the pinned Terraform version]`.
//	It is not what happens.
//
// WHY THE FLEET IS STILL SAFE. The destroy half is refused BY CONTRACT, not by
// hope: the service returns `409 destination_recently_published` for a
// certificate published after the caller last observed the registration, and
// `409 operation_in_flight` while an operation for the current spec is running.
// This test drives exactly that path and asserts that the live certificate
// SURVIVES the tainted apply.
//
// The user's route out is the command the timeout diagnostic gives them:
// `terraform untaint <address> && terraform apply`.
func TestAccCertificate_CreateTimeoutThenRecovery(t *testing.T) {
	testAccPreCheck(t)
	srv := startFake(t)
	// Case 3 of §7.1.4: the operation is GENUINELY still running when the client
	// gives up.
	srv.SetBehaviour(fakeservice.Behaviour{OperationNeverCompletes: true})

	cfg := configMinimal(`
  timeouts {
    create = "3s"
  }`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config:      cfg,
				ExpectError: regexp.MustCompile("terraform untaint <address> && terraform apply"),
			},
			{
				// Between the timeout and the next apply the service FINISHES THE
				// WORK. That is the expected outcome, not the exceptional one, and
				// it is exactly why reporting a timeout as a failure is dangerous.
				PreConfig: func() {
					srv.SetBehaviour(fakeservice.Behaviour{RecentlyPublishedGuard: true})
					srv.Publish(accNamespace, accName)
				},
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// DOCUMENTED, NOT DESIRED. Terraform plans a replacement for the
						// tainted object. If a future Terraform release stops tainting,
						// this check fails and the comment above must be revisited —
						// which is the point of pinning it.
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				// The destroy half is REFUSED by the service guard, so the apply
				// fails safely instead of destroying a live certificate.
				ExpectError: regexp.MustCompile(`published after this workspace last observed it`),
			},
			{
				// Lift the guard so the harness's own cleanup destroy can run. In
				// production the operator lifts it by running the untaint command
				// the timeout diagnostic gave them.
				PreConfig:    func() { srv.SetBehaviour(fakeservice.Behaviour{}) },
				RefreshState: true,
				// The plan is genuinely non-empty: the object is still TAINTED, so
				// Terraform still wants to replace it. That is the discovered
				// behaviour this test documents, and it is why the diagnostic hands
				// the operator `terraform untaint` rather than "just re-apply".
				ExpectNonEmptyPlan: true,
			},
		},
	})

	// THE PROPERTY THAT MATTERS: the certificate the service published is
	// untouched, and it was never reissued.
	reg := srv.Registration(accNamespace, accName)
	if reg == nil {
		t.Fatal("the registration is gone; the tainted apply destroyed it")
	}
	if reg.Status.CurrentCertificate == nil {
		t.Fatal("the published certificate is gone; the tainted apply destroyed it")
	}
	if puts := srv.RequestCount("PUT", "/certificates/"+accName); puts != 1 {
		t.Fatalf("the certificate was PUT %d times; a create timeout must never cause a second issuance", puts)
	}
}

// ------------------------------------------------------------------ helpers

func captureAttr(resourceName, attr string, into *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		v, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("attribute %s not present on %s", attr, resourceName)
		}
		*into = v
		return nil
	}
}

func checkAttrEquals(resourceName, attr string, want *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		if got := rs.Primary.Attributes[attr]; got != *want {
			return fmt.Errorf("%s.%s = %q, want the unchanged value %q", resourceName, attr, got, *want)
		}
		return nil
	}
}

func checkAttrDiffers(resourceName, attr string, was *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		if got := rs.Primary.Attributes[attr]; got == *was {
			return fmt.Errorf("%s.%s is still %q; a reissue must change it", resourceName, attr, got)
		}
		return nil
	}
}

func checkNotAfterInTheFuture(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		raw := rs.Primary.Attributes["current_certificate.not_after"]
		if raw == "" {
			return fmt.Errorf("current_certificate.not_after is empty")
		}
		notAfter, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("current_certificate.not_after %q does not parse: %w", raw, err)
		}
		if !notAfter.After(time.Now()) {
			return fmt.Errorf("current_certificate.not_after %s is not in the future", raw)
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// PROV-NORMALISED-ATTRIBUTE-DRIFT
//
// THE SINGLE MOST IMPORTANT PROPERTY OF THIS PROVIDER: apply, then the next plan
// is EMPTY. A provider that cannot re-plan is unusable in a pipeline regardless
// of what else works, and `terraform plan -detailed-exitcode` returning 2 — or,
// worse, 1 — on an unchanged configuration breaks every gate built on it.
//
// THESE TESTS ONLY MEAN ANYTHING BECAUSE THE FAKE NORMALISES. Until
// internal/fakeservice/normalise.go existed the fake ECHOED the request, so
// round-trip stability was guaranteed by construction and eleven green
// acceptance tests coexisted with a real `terraform plan` that aborted the whole
// workspace with `destination_change_unsupported` (C2 Finding 2). If a future
// change makes the fake echo `destination_id` or `verification` again, these
// tests go on passing and protect nothing — so the fake's own suite asserts that
// it normalises, and normalise.go says why.
// ---------------------------------------------------------------------------

// configVerification wraps a consumer_probe body in the `verification` attribute.
func configVerification(body string) string {
	return fmt.Sprintf(`
  verification = {
    consumer_probe = {
%s
    }
  }`, body)
}

// TestAccCertificate_ApplyThenSecondPlanIsEmpty is the permanent guard.
//
// Every case applies a configuration against a service that NORMALISES the
// request — server-resolving `destination_id` and materialising the whole
// `verification` block — and then asserts that the plan is empty four ways:
// immediately after the apply, after a refresh, as a standalone plan, and as a
// standalone plan after an explicit refresh. A normalisation the provider fails
// to absorb shows up in at least one of the four.
//
// BLOCKING TEST. Do not skip it, do not weaken it, and do not make the fake echo
// to make it pass.
func TestAccCertificate_ApplyThenSecondPlanIsEmpty(t *testing.T) {
	cases := []struct {
		name   string
		extra  string
		checks []resource.TestCheckFunc
	}{
		{
			name:  "the six-concept minimum declares neither attribute",
			extra: "",
			checks: []resource.TestCheckFunc{
				// THE DEFECT, ASSERTED AS FIXED. The service resolved a destination
				// policy; `destination_id` is Optional WITHOUT Computed, so the
				// resolved value must NOT be in it. Before the fix this value was
				// "payments", and ModifyPlan's destination-change check then aborted
				// the entire plan for every resource in the workspace.
				resource.TestCheckNoResourceAttr("azureacme_certificate.api", "destination_id"),
				resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_destination_id",
					fakeservice.DefaultDestinationPolicyID),
				// And the materialised probe stays out of the configured attribute.
				resource.TestCheckNoResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled"),
			},
		},
		{
			name:  "destination_id asserting the policy the service resolves",
			extra: fmt.Sprintf("  destination_id = %q", fakeservice.DefaultDestinationPolicyID),
			checks: []resource.TestCheckFunc{
				// The caller's assertion is kept VERBATIM, not replaced by an
				// identical server value, so the attribute still reads as what the
				// user wrote.
				resource.TestCheckResourceAttr("azureacme_certificate.api", "destination_id",
					fakeservice.DefaultDestinationPolicyID),
				resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_destination_id",
					fakeservice.DefaultDestinationPolicyID),
			},
		},
		{
			name: "a fully configured consumer probe",
			extra: configVerification(`      enabled         = true
      expected_pickup = "8h"
      endpoints       = [{ host = "api.example.com", port = 443, sni = "api.example.com" }]`),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled", "true"),
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.expected_pickup", "8h"),
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.endpoints.#", "1"),
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.endpoints.0.port", "443"),
			},
		},
		{
			name:  "a probe enabled with no endpoints block at all",
			extra: configVerification(`      enabled = true`),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled", "true"),
				// NULL is preserved as null. The service materialises `endpoints: []`,
				// and writing an empty list where the configuration wrote nothing is
				// the same permadiff in miniature.
				resource.TestCheckNoResourceAttr("azureacme_certificate.api", "verification.consumer_probe.endpoints.#"),
			},
		},
		{
			name: "a probe with an explicitly empty endpoint list",
			extra: configVerification(`      enabled   = true
      endpoints = []`),
			checks: []resource.TestCheckFunc{
				// And an EMPTY list is preserved as an empty list. Collapsing the two
				// in either direction is a diff on every plan.
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.endpoints.#", "0"),
			},
		},
		{
			name:  "a probe stated explicitly as disabled",
			extra: configVerification(`      enabled = false`),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled", "false"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testAccPreCheck(t)
			startFake(t)
			cfg := configMinimal(tc.extra)

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: protoV6Factories(),
				Steps: []resource.TestStep{
					{
						Config: cfg,
						ConfigPlanChecks: resource.ConfigPlanChecks{
							// The plan Terraform would produce the moment the apply
							// returns, and then the one it produces after reading the
							// registration back from the service. The SECOND is the one
							// that catches a normalisation mismatch, because the refresh
							// is what pulls the normalised values into state.
							PostApplyPreRefresh:  []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
							PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
						},
						Check: resource.ComposeAggregateTestCheckFunc(tc.checks...),
					},
					// A standalone plan. This is the step that would have FAILED before
					// the fix, and not with a diff: with
					// `Error: Changing the destination of an existing certificate
					// registration is not supported`.
					{Config: cfg, PlanOnly: true},
					// An explicit refresh, then a plan, which is what a pipeline does.
					{RefreshState: true, ExpectNonEmptyPlan: false},
					{Config: cfg, PlanOnly: true},
				},
			})
		})
	}
}

// TestAccCertificate_ServerResolvedDestinationIDIsRevertible is the test that
// JUSTIFIES THE SCHEMA CHOICE.
//
// `Optional + Computed` would also have silenced the plan error — and would have
// made this test fail. Under O+C, deleting `destination_id` from the
// configuration leaves the prior value in state, Terraform reports no change, and
// the workspace is pinned to a destination policy its HCL does not mention. §5.3.1
// names that exact failure: worst during a platform migration, when repointing a
// namespace's destination policy makes every pinned registration wrong at once.
//
// So the provider stores the CONFIGURED value, and this proves the line can be
// deleted.
func TestAccCertificate_ServerResolvedDestinationIDIsRevertible(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	asserted := configMinimal(fmt.Sprintf("  destination_id = %q", fakeservice.DefaultDestinationPolicyID))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("azureacme_certificate.api", "destination_id"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_destination_id",
						fakeservice.DefaultDestinationPolicyID),
				),
			},
			{
				// Adding the attribute to assert the policy already in effect must be
				// an ordinary update, NOT a destination change. Before the fix this
				// transition was itself a plan-aborting error, which is how C2's run
				// found the second permadiff behind the first.
				Config: asserted,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.TestCheckResourceAttr("azureacme_certificate.api", "destination_id",
					fakeservice.DefaultDestinationPolicyID),
			},
			{Config: asserted, PlanOnly: true},
			{
				// THE LINE IS DELETED. The plan must SHOW the removal and state must
				// end up null. Under Optional+Computed the plan here would be empty
				// and state would still say "payments".
				Config: configMinimal(""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("azureacme_certificate.api", "destination_id"),
					// And the server's answer is still visible, in the attribute that
					// is allowed to carry it.
					resource.TestCheckResourceAttr("azureacme_certificate.api", "resolved_destination_id",
						fakeservice.DefaultDestinationPolicyID),
				),
			},
			{Config: configMinimal(""), PlanOnly: true},
		},
	})
}

// TestAccCertificate_VerificationBlockIsRevertible is the same argument for
// `verification`, where the consequence of the O+C trap is worse than a confusing
// diff: a consumer probe left running against endpoints the HCL no longer
// mentions, producing `consumer_stale` alerts with no visible cause.
//
// It also pins the SERVER-SIDE half. The service applies defaults at create only
// (G-8), so an update that merely OMITS `verification` inherits the stored probe
// and the probe stays enabled for ever. The provider therefore always states
// `enabled` on the wire, and the fake reproduces the inheritance so that this
// test fails if the provider stops doing so.
func TestAccCertificate_VerificationBlockIsRevertible(t *testing.T) {
	testAccPreCheck(t)
	srv := startFake(t)

	probed := configMinimal(configVerification(`      enabled   = true
      endpoints = [{ host = "api.example.com" }]`))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check:  resource.TestCheckNoResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled"),
			},
			{
				Config: probed,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled", "true"),
					resource.TestCheckResourceAttr("azureacme_certificate.api", "verification.consumer_probe.endpoints.#", "1"),
				),
			},
			{Config: probed, PlanOnly: true},
			{
				// THE BLOCK IS DELETED.
				Config: configMinimal(""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("azureacme_certificate.api", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.TestCheckNoResourceAttr("azureacme_certificate.api", "verification.consumer_probe.enabled"),
			},
			{Config: configMinimal(""), PlanOnly: true},
		},
	})

	// THE PROPERTY THAT MATTERS, CHECKED ON THE SERVICE AND NOT ONLY IN STATE:
	// the probe is actually OFF. State saying the block is gone while the service
	// goes on probing would be the worst of the available outcomes.
	reg := srv.Registration(accNamespace, accName)
	if reg == nil {
		t.Fatal("the registration is gone")
	}
	if reg.Spec.Verification == nil || reg.Spec.Verification.ConsumerProbe == nil {
		t.Fatal("the service stored no verification block at all; the fake should always materialise one")
	}
	if enabled := reg.Spec.Verification.ConsumerProbe.Enabled; enabled == nil || *enabled {
		t.Fatalf("deleting the `verification` block left the consumer probe ENABLED server-side (enabled=%v). "+
			"The provider must STATE `enabled` on every write: the service applies defaults at create only, so an "+
			"omitted field inherits the stored value and the probe never turns off.", enabled)
	}
}

// TestAccCertificate_AssertingADifferentDestinationPolicyStillFailsThePlan keeps
// the relaxation honest.
//
// Making the plan stable for `destination_id` meant narrowing §6.2.1: three of the
// four transitions move nothing and must not abort the plan. The fourth still
// must. Without this test the narrowing could quietly become "never check
// `destination_id`", and a certificate could be pointed at a different destination
// policy by a plan that looked like an ordinary in-place update.
func TestAccCertificate_AssertingADifferentDestinationPolicyStillFailsThePlan(t *testing.T) {
	testAccPreCheck(t)
	startFake(t)

	elsewhere := configMinimal(`  destination_id = "some-other-policy"`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		Steps: []resource.TestStep{
			{Config: configMinimal("")},
			{
				Config:   elsewhere,
				PlanOnly: true,
				// And the instruction is one the reader can follow: the attribute was
				// not set before, so "revert it to \"\"" would be no instruction at all.
				ExpectError: regexp.MustCompile(`REMOVE .destination_id. from this resource`),
			},
		},
	})
}
