package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
)

// attributeFacts is one row of the schema snapshot.
type attributeFacts struct {
	Path      string
	Type      string
	Required  bool
	Optional  bool
	Computed  bool
	Default   string
	Modifiers []string
}

func (f attributeFacts) String() string {
	mode := []string{}
	if f.Required {
		mode = append(mode, "Required")
	}
	if f.Optional {
		mode = append(mode, "Optional")
	}
	if f.Computed {
		mode = append(mode, "Computed")
	}
	line := fmt.Sprintf("%-46s type=%-28s mode=%s", f.Path, f.Type, strings.Join(mode, "+"))
	if f.Default != "" {
		line += " default=" + f.Default
	}
	if len(f.Modifiers) > 0 {
		line += " modifiers=[" + strings.Join(f.Modifiers, ",") + "]"
	}
	return line
}

func walkSchema(ctx context.Context, s schema.Schema) []attributeFacts {
	var out []attributeFacts
	walkAttributes(ctx, "", s.Attributes, &out)
	for name, block := range s.Blocks {
		if b, ok := block.(schema.SingleNestedBlock); ok {
			out = append(out, attributeFacts{Path: name, Type: "Block(SingleNested)"})
			walkAttributes(ctx, name+".", b.Attributes, &out)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func walkAttributes(ctx context.Context, prefix string, attrs map[string]schema.Attribute, out *[]attributeFacts) {
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		attr := attrs[name]
		path := prefix + name
		f := attributeFacts{
			Path:     path,
			Type:     fmt.Sprintf("%T", attr.GetType()),
			Required: attr.IsRequired(),
			Optional: attr.IsOptional(),
			Computed: attr.IsComputed(),
		}
		switch a := attr.(type) {
		case schema.StringAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
			f.Default = defaultString(ctx, a.Default)
		case schema.BoolAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
			f.Default = defaultBool(ctx, a.Default)
		case schema.Int64Attribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
			f.Default = defaultInt64(ctx, a.Default)
		case schema.SetAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
		case schema.MapAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
		case schema.ListAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
		case schema.SingleNestedAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
			f.Default = defaultObject(ctx, a.Default)
			*out = append(*out, f)
			walkAttributes(ctx, path+".", a.Attributes, out)
			continue
		case schema.ListNestedAttribute:
			f.Modifiers = modifierNames(a.PlanModifiers)
			*out = append(*out, f)
			walkAttributes(ctx, path+".", a.NestedObject.Attributes, out)
			continue
		}
		*out = append(*out, f)
	}
}

func modifierNames[T any](mods []T) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		name := fmt.Sprintf("%T", m)
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			name = name[idx+1:]
		}
		out = append(out, strings.TrimSuffix(name, "Modifier"))
	}
	return out
}

func defaultString(ctx context.Context, d defaults.String) string {
	if d == nil {
		return ""
	}
	var resp defaults.StringResponse
	d.DefaultString(ctx, defaults.StringRequest{}, &resp)
	return fmt.Sprintf("%q", resp.PlanValue.ValueString())
}

func defaultBool(ctx context.Context, d defaults.Bool) string {
	if d == nil {
		return ""
	}
	var resp defaults.BoolResponse
	d.DefaultBool(ctx, defaults.BoolRequest{}, &resp)
	return fmt.Sprintf("%v", resp.PlanValue.ValueBool())
}

func defaultInt64(ctx context.Context, d defaults.Int64) string {
	if d == nil {
		return ""
	}
	var resp defaults.Int64Response
	d.DefaultInt64(ctx, defaults.Int64Request{}, &resp)
	return fmt.Sprintf("%d", resp.PlanValue.ValueInt64())
}

func defaultObject(ctx context.Context, d defaults.Object) string {
	if d == nil {
		return ""
	}
	var resp defaults.ObjectResponse
	d.DefaultObject(ctx, defaults.ObjectRequest{}, &resp)
	return resp.PlanValue.String()
}

// TestCertificateSchemaSnapshot is the committed golden file of
// PROV-UNIT-TEST-SUITE: a change to any attribute's mode, default or type is a
// VISIBLE DIFF IN REVIEW rather than a silent behavioural change.
//
// Regenerate deliberately with: go test ./internal/provider -run Snapshot -update
func TestCertificateSchemaSnapshot(t *testing.T) {
	ctx := context.Background()
	facts := walkSchema(ctx, certificateResourceSchema())
	lines := make([]string, 0, len(facts))
	for _, f := range facts {
		lines = append(lines, f.String())
	}
	got := strings.Join(lines, "\n") + "\n"

	golden := filepath.Join("testdata", "certificate_schema.snapshot.txt")
	if os.Getenv("UPDATE_SNAPSHOTS") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("snapshot updated")
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading the committed snapshot: %v\n\nRegenerate with UPDATE_SNAPSHOTS=1 go test ./internal/provider -run Snapshot", err)
	}
	if string(want) != got {
		t.Fatalf("the certificate schema changed.\n\n--- committed ---\n%s\n--- current ---\n%s\n\n"+
			"If the change is intended, regenerate with UPDATE_SNAPSHOTS=1 and review the diff.", want, got)
	}
}

// TestSchemaInvariants asserts the four properties the snapshot exists to
// protect, by NAME rather than by diff, so a reviewer regenerating the snapshot
// carelessly still trips over them.
func TestSchemaInvariants(t *testing.T) {
	ctx := context.Background()
	s := certificateResourceSchema()
	facts := walkSchema(ctx, s)
	byPath := map[string]attributeFacts{}
	for _, f := range facts {
		byPath[f.Path] = f
	}

	// 1. key.exportable defaults to TRUE. `false` publishes a clean-looking
	//    certificate that Application Gateway silently cannot use.
	if got := byPath["key.exportable"]; got.Default != "true" {
		t.Errorf("key.exportable default = %q, want \"true\" — every consumer in the v1 matrix requires an exportable key", got.Default)
	}

	// 2. wait_for is a STRING. A Bool cannot express `consumer_observed` or
	//    `best_effort` and cannot become a String after registry publication.
	if got := byPath["wait_for"]; !strings.Contains(got.Type, "StringType") {
		t.Errorf("wait_for type = %q, want a String type", got.Type)
	}
	if got := byPath["wait_for"]; got.Default != `"published"` {
		t.Errorf("wait_for default = %q, want %q", got.Default, `"published"`)
	}

	// 3. NO SPEC ATTRIBUTE IS Optional+Computed WITHOUT A STATIC DEFAULT.
	//    For an O+C attribute, removing it from configuration does NOT revert it
	//    to the server default: the prior state value persists, because Terraform
	//    cannot distinguish "user removed it" from "provider computed it".
	for _, f := range facts {
		if f.Optional && f.Computed && f.Default == "" {
			t.Errorf("%s is Optional+Computed with no static default. §5.3.1: every spec attribute is Required, or "+
				"Optional with a static framework Default, or an Optional sentinel.", f.Path)
		}
	}

	// 4. timeouts.create is 60m — above the p99 issuance SLO of 45 minutes.
	if DefaultCreateTimeout != "60m" {
		t.Errorf("DefaultCreateTimeout = %q, want \"60m\": a 30-minute default reaches the timeout-recovery path "+
			"routinely by the design's own numbers", DefaultCreateTimeout)
	}
}

// TestNoComputedAttributeCarriesRequiresReplace is RULE R-2.
//
// It is the second most common way a renewal becomes a replacement, and there is
// no valid reason to do it here.
func TestNoComputedAttributeCarriesRequiresReplace(t *testing.T) {
	ctx := context.Background()
	for _, f := range walkSchema(ctx, certificateResourceSchema()) {
		if !f.Computed || f.Optional || f.Required {
			continue
		}
		for _, m := range f.Modifiers {
			if isRequiresReplace(m) {
				t.Errorf("RULE R-2 VIOLATION: computed attribute %q carries %q. A Computed attribute that requires "+
					"replacement turns an ordinary renewal into a destroy-and-recreate.", f.Path, m)
			}
		}
	}
}

// TestRequiresReplaceAppearsOnExactlyTwoAttributes is §6.1.
func TestRequiresReplaceAppearsOnExactlyTwoAttributes(t *testing.T) {
	ctx := context.Background()
	var found []string
	for _, f := range walkSchema(ctx, certificateResourceSchema()) {
		for _, m := range f.Modifiers {
			if isRequiresReplace(m) {
				found = append(found, f.Path)
			}
		}
	}
	sort.Strings(found)
	want := []string{"name", "namespace"}
	if strings.Join(found, ",") != strings.Join(want, ",") {
		t.Fatalf("RequiresReplace appears on %v, want exactly %v.\n\n"+
			"`key_vault_id` in particular MUST NOT be RequiresReplace: replacement plans destroy-then-create, which "+
			"under deletion_policy = \"delete\" soft-deletes the live certificate BEFORE its replacement is issued.",
			found, want)
	}
}

// TestSchemaImplementationIsValid catches tfsdk-tag and type mismatches.
func TestSchemaImplementationIsValid(t *testing.T) {
	ctx := context.Background()
	var resp fwresource.SchemaResponse
	NewCertificateResource().Schema(ctx, fwresource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema implementation invalid: %v", diags)
	}
	// Round-trip a fully-formed model through the schema, which is what proves the
	// `tfsdk` tags and the Go types agree.
	state := emptyState(t, ctx)
	plan := planFor(t, ctx, nil)
	var m certificateResourceModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("reading the model out of a plan: %v", diags)
	}
	if diags := state.Set(ctx, &m); diags.HasError() {
		t.Fatalf("the model does not round-trip through the schema: %v", diags)
	}
}

// TestSecretSurfaceIsAbsentFromEverySchema is the §9 allowlist, enforced by
// NAME across every resource and data source.
//
// Marking a field sensitive HIDES DISPLAY; it does not keep the value out of
// state. The rule is therefore that these attributes do not exist at all.
func TestSecretSurfaceIsAbsentFromEverySchema(t *testing.T) {
	forbidden := []string{
		"private", "pfx", "p12", "pkcs12", "secret_value", "password", "account_key", "csr",
		"private_key", "key_material", "account_key_pem",
	}
	ctx := context.Background()
	check := func(kind, name string, paths []string) {
		for _, p := range paths {
			lower := strings.ToLower(p)
			for _, bad := range forbidden {
				// `client_certificate_password` on the PROVIDER is an input, not an
				// output, and is excluded by only checking resources and data
				// sources here.
				if strings.Contains(lower, bad) {
					t.Errorf("%s %q exposes attribute %q, which matches the forbidden pattern %q. "+
						"For a Key Vault CERTIFICATE the sibling SECRET value is the PKCS#12 bundle INCLUDING THE PRIVATE KEY.",
						kind, name, p, bad)
				}
			}
		}
	}
	check("resource", "azureacme_certificate", pathsOf(walkSchema(ctx, certificateResourceSchema())))

	p := New("test")()
	for _, ctor := range p.DataSources(ctx) {
		ds := ctor()
		var meta datasource.MetadataResponse
		ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "azureacme"}, &meta)
		var sresp datasource.SchemaResponse
		ds.Schema(ctx, datasource.SchemaRequest{}, &sresp)
		if sresp.Diagnostics.HasError() {
			t.Fatalf("data source %q schema: %v", meta.TypeName, sresp.Diagnostics)
		}
		if diags := sresp.Schema.ValidateImplementation(ctx); diags.HasError() {
			t.Fatalf("data source %q schema is invalid: %v", meta.TypeName, diags)
		}
		check("data source", meta.TypeName, dataSourceAttributePaths(sresp.Schema))
	}
}

// isRequiresReplace recognises every RequiresReplace family member. The framework
// implements RequiresReplace(), RequiresReplaceIf() and RequiresReplaceIfConfigured()
// with the same underlying unexported type, so the check is on the name and is
// deliberately case-insensitive.
func isRequiresReplace(modifier string) bool {
	return strings.Contains(strings.ToLower(modifier), "requiresreplace")
}

func pathsOf(facts []attributeFacts) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, f.Path)
	}
	return out
}

// dataSourceAttributePaths flattens a data-source schema to attribute paths.
func dataSourceAttributePaths(s dsschema.Schema) []string {
	var out []string
	var walk func(prefix string, attrs map[string]dsschema.Attribute)
	walk = func(prefix string, attrs map[string]dsschema.Attribute) {
		names := make([]string, 0, len(attrs))
		for n := range attrs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			path := prefix + n
			out = append(out, path)
			switch a := attrs[n].(type) {
			case dsschema.SingleNestedAttribute:
				walk(path+".", a.Attributes)
			case dsschema.ListNestedAttribute:
				walk(path+".", a.NestedObject.Attributes)
			case dsschema.SetNestedAttribute:
				walk(path+".", a.NestedObject.Attributes)
			}
		}
	}
	walk("", s.Attributes)
	return out
}
