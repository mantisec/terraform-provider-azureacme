package provider_test

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/mantisec/terraform-provider-azureacme/internal/fakeservice"
)

// The token-hygiene acceptance test of AUTH-PROVIDER-CREDENTIAL-CHAIN, and the
// only one of this provider's checks that can see the artefacts a real
// `terraform apply` leaves on disk.
//
// WHY IT IS NOT A UNIT TEST. "The token is not in state" is a claim about files
// Terraform writes, not about a Go value. A unit test can assert the provider
// never puts a token in an attribute; only a real plan and apply can assert that
// nothing ELSE — the framework, the plan serialiser, a log sink — put it there
// anyway. `Sensitive` would not help: it suppresses display, and the value is
// still plaintext in state.
//
// The three artefacts, from the item's own wording: the state file, the plan
// file, and `TF_LOG=TRACE` output. All three are produced here, and all three are
// grepped for three distinct sentinels — a bearer token, a federated ASSERTION,
// and a client secret in the environment.

const (
	// Deliberately distinctive and deliberately not JWT-shaped in the middle, so
	// a hit is unambiguous and a near-miss cannot be explained away as masking.
	sentinelBearerToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.SENTINEL-BEARER-TOKEN-MUST-NOT-BE-PERSISTED.sig"
	sentinelAssertion   = "eyJhbGciOiJSUzI1NiJ9.SENTINEL-FEDERATED-ASSERTION-MUST-NOT-BE-PERSISTED.sig"
	sentinelEnvSecret   = "SENTINEL-ENV-SECRET-MUST-NOT-BE-PERSISTED"
)

// TestAccCredentialHygiene_NoTokenInStatePlanOrTrace.
func TestAccCredentialHygiene_NoTokenInStatePlanOrTrace(t *testing.T) {
	testAccPreCheck(t)

	// TF_ACC_PERSIST_WORKING_DIR keeps the state and plan files after the test
	// step finishes; without it the framework deletes exactly the artefacts this
	// test exists to read.
	baseDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "terraform-trace.log")
	t.Setenv("TF_ACC_PERSIST_WORKING_DIR", "1")
	t.Setenv("TF_ACC_LOG", "TRACE")
	t.Setenv("TF_ACC_LOG_PATH", logPath)

	// A federated assertion on disk, named by the environment. The provider must
	// never read it and send it, and it must never reach an artefact either.
	assertionFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(assertionFile, []byte(sentinelAssertion), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := fakeservice.New(t)
	t.Setenv("MANTISEC_ACME_ENDPOINT", srv.URL())
	t.Setenv("MANTISEC_ACME_AUDIENCE", "api://mantisec-acme")
	t.Setenv("MANTISEC_ACME_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("MANTISEC_ACME_TOKEN", sentinelBearerToken)
	t.Setenv("MANTISEC_ACME_OIDC_TOKEN_FILE_PATH", assertionFile)
	// §2.3: accepted from the ENVIRONMENT for compatibility, warned about, and
	// never echoed. There is no `client_secret` HCL attribute to test, precisely
	// because provider configuration IS captured in a saved plan file.
	t.Setenv("ARM_CLIENT_SECRET", sentinelEnvSecret)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories(),
		WorkingDir:               baseDir,
		Steps: []resource.TestStep{
			{
				Config: configMinimal(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("azureacme_certificate.api", "versionless_secret_id"),
				),
			},
			{
				// A second step so a saved plan exists for a NON-empty prior state
				// as well as for the create.
				Config:   configMinimal("  description = \"hygiene\"\n"),
				Check:    resource.ComposeAggregateTestCheckFunc(),
				PlanOnly: false,
			},
		},
	})

	artefacts := collectArtefacts(t, baseDir, logPath)

	// The vacuity guard. If the walk found no state and no plan, every assertion
	// below is trivially true and the test proves nothing at all.
	var sawState, sawPlan bool
	for name := range artefacts {
		base := filepath.Base(name)
		switch {
		case strings.HasPrefix(base, "terraform.tfstate"):
			sawState = true
		case base == "tfplan":
			sawPlan = true
		}
	}
	if !sawState {
		t.Fatalf("GUARD IS VACUOUS: no terraform.tfstate was found under %s, so \"no token in state\" asserts nothing.\n"+
			"Files seen: %s", baseDir, strings.Join(sortedKeys(artefacts), ", "))
	}
	if !sawPlan {
		t.Fatalf("GUARD IS VACUOUS: no saved plan file was found under %s, so \"no token in the plan\" asserts nothing.\n"+
			"Files seen: %s", baseDir, strings.Join(sortedKeys(artefacts), ", "))
	}
	var expandedPlanEntries int
	for name := range artefacts {
		if strings.Contains(name, string(filepath.Separator)+"tfplan!") {
			expandedPlanEntries++
		}
	}
	if expandedPlanEntries == 0 {
		t.Fatalf("GUARD IS VACUOUS: the saved plan file was not expanded, so the plan scan is reading DEFLATE output "+
			"rather than the plan. Files seen: %s", strings.Join(sortedKeys(artefacts), ", "))
	}
	if len(artefacts[logPath]) == 0 {
		t.Fatalf("GUARD IS VACUOUS: the TF_LOG=TRACE sink at %s is empty, so \"no token in TRACE output\" asserts nothing", logPath)
	}
	// …and the sink must actually contain provider traffic, or it is a Terraform
	// core log that never had a chance to print a token.
	if !strings.Contains(artefacts[logPath], "azureacme") {
		t.Fatalf("GUARD IS VACUOUS: the TRACE sink mentions no azureacme provider output")
	}

	for _, sentinel := range []struct {
		name  string
		value string
	}{
		{"the bearer token", sentinelBearerToken},
		{"the federated assertion", sentinelAssertion},
		{"the client secret from the environment", sentinelEnvSecret},
	} {
		for _, name := range sortedKeys(artefacts) {
			if strings.Contains(artefacts[name], sentinel.value) {
				t.Errorf("%s appears in %s.\n"+
					"Tokens, assertions and secrets never enter Terraform state, a saved plan file, `tflog` output or a "+
					"resource attribute. Marking a field `Sensitive` only suppresses DISPLAY — the value is still "+
					"plaintext in state, and CI systems routinely archive plan files as build artefacts.",
					sentinel.name, relativeTo(baseDir, name))
			}
		}
	}

	// The Authorization header itself, independently of the sentinel value, so a
	// future change that logs a DIFFERENT token still fails.
	for _, name := range sortedKeys(artefacts) {
		lower := strings.ToLower(artefacts[name])
		if strings.Contains(lower, "bearer ey") {
			t.Errorf("an Authorization header value appears in %s", relativeTo(baseDir, name))
		}
	}
}

// collectArtefacts reads every regular file under dir, plus the named log file.
//
// A SAVED PLAN FILE IS A ZIP ARCHIVE, so scanning its raw bytes would be a scan
// of DEFLATE output and would miss a token that is in it. Every archive is
// therefore expanded and its entries scanned as well — otherwise the plan-file
// half of this test would be nominal, which is worse than absent because it
// reads as covered.
func collectArtefacts(t *testing.T, dir, logPath string) map[string]string {
	t.Helper()
	out := map[string]string{}

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A working directory the framework is still tidying up is not a
			// reason to fail; the vacuity guard catches an empty walk.
			return nil //nolint:nilerr // deliberate: see comment
		}
		if d.IsDir() {
			return nil
		}
		b, readErr := os.ReadFile(p) //nolint:gosec // a path produced by walking a temp dir
		if readErr != nil {
			return nil //nolint:nilerr // deliberate: an unreadable artefact is not a hit
		}
		out[p] = readableText(b)
		for entry, content := range zipEntries(b) {
			out[p+"!"+entry] = content
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}

	if b, readErr := os.ReadFile(logPath); readErr == nil { //nolint:gosec // a path this test created
		out[logPath] = readableText(b)
	}
	return out
}

// zipEntries expands a zip archive, or returns nothing when the bytes are not
// one. A plan file that cannot be opened is reported by the caller's vacuity
// guard, not swallowed here.
func zipEntries(b []byte) map[string]string {
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, f := range r.File {
		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, 32<<20))
		_ = rc.Close()
		if readErr != nil {
			continue
		}
		out[f.Name] = readableText(content)
	}
	return out
}

// readableText renders bytes so a substring search behaves the same for a text
// file and for the text runs inside a binary one.
func readableText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func relativeTo(base, p string) string {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return rel
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
