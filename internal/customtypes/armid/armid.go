// Package armid is the `armid.String` custom framework type of
// terraform-provider-contract.md §4.
//
// The service stores an ARM resource id VERBATIM and never normalises its casing
// (contracts primitives: NormaliseARMResourceIDCasing = false). That is the right
// server-side rule — an id is an opaque handle — but it means the value the
// server echoes may differ from the HCL in segment casing alone, which without
// this type is a perpetual diff on `key_vault_id` and therefore, through
// RequiresReplace-adjacent machinery, a reissue on every apply (plan-stability
// failure 3 of §6.4).
//
// Equality rule: path SEGMENT NAMES (`subscriptions`, `resourceGroups`,
// `providers`, the provider namespace and the type) compare case-INsensitively;
// RESOURCE NAMES compare case-SENSITIVELY; the subscription GUID is lower-cased.
package armid

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// StringType is the attr.Type for an ARM resource id.
type StringType struct {
	basetypes.StringType
}

var _ basetypes.StringTypable = StringType{}

func (t StringType) Equal(o attr.Type) bool {
	other, ok := o.(StringType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t StringType) String() string { return "armid.StringType" }

func (t StringType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return String{StringValue: in}, nil
}

func (t StringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", attrValue)
	}
	stringValuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to StringValuable: %v", diags)
	}
	return stringValuable, nil
}

func (t StringType) ValueType(context.Context) attr.Value { return String{} }

// String is the attr.Value for an ARM resource id.
type String struct {
	basetypes.StringValue
}

var (
	_ basetypes.StringValuableWithSemanticEquals = String{}
	_ xattr.ValidateableAttribute                = String{}
)

func (v String) Type(context.Context) attr.Type { return StringType{} }

func (v String) Equal(o attr.Value) bool {
	other, ok := o.(String)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v String) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(String)
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("expected armid.String, got %T. This is a provider defect.", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.StringValue.Equal(newValue.StringValue), diags
	}
	return Canonical(v.ValueString()) == Canonical(newValue.ValueString()), diags
}

// ValidateAttribute checks the shape only. A malformed id is a plan-time error
// rather than a `400` after apply has begun changing other resources (F-066).
func (v String) ValidateAttribute(_ context.Context, req xattr.ValidateAttributeRequest, resp *xattr.ValidateAttributeResponse) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	if _, err := Parse(v.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path,
			fmt.Sprintf("Invalid Azure resource id: %q", v.ValueString()),
			err.Error())
	}
}

// NewValue builds a known armid.String.
func NewValue(s string) String { return String{StringValue: basetypes.NewStringValue(s)} }

// NewNull builds a null armid.String.
func NewNull() String { return String{StringValue: basetypes.NewStringNull()} }

// NewUnknown builds an unknown armid.String.
func NewUnknown() String { return String{StringValue: basetypes.NewStringUnknown()} }

// ID is a parsed ARM resource id.
type ID struct {
	SubscriptionID    string
	ResourceGroup     string
	ProviderNamespace string
	// Types and Names are parallel: `vaults` / `kv-payments`. Nested types append.
	Types []string
	Names []string
}

// ResourceName is the last name segment — the Key Vault name for a vault id.
func (id ID) ResourceName() string {
	if len(id.Names) == 0 {
		return ""
	}
	return id.Names[len(id.Names)-1]
}

// FullType is `Microsoft.KeyVault/vaults`, lower-cased for comparison.
func (id ID) FullType() string {
	return strings.ToLower(id.ProviderNamespace + "/" + strings.Join(id.Types, "/"))
}

// Parse splits an ARM resource id. It is deliberately strict: a "nearly right"
// id that the provider accepts and the service rejects is a worse experience
// than a plan-time error naming the expected shape.
func Parse(s string) (ID, error) {
	var id ID
	if !strings.HasPrefix(s, "/") {
		return id, fmt.Errorf("an Azure resource id must begin with %q; got %q", "/", s)
	}
	segs := strings.Split(strings.TrimSuffix(s, "/")[1:], "/")
	if len(segs) < 8 {
		return id, fmt.Errorf("expected the form " +
			"/subscriptions/{subscriptionId}/resourceGroups/{group}/providers/{namespace}/{type}/{name}")
	}
	if !strings.EqualFold(segs[0], "subscriptions") {
		return id, fmt.Errorf("expected %q as the first segment, got %q", "subscriptions", segs[0])
	}
	id.SubscriptionID = strings.ToLower(segs[1])
	if !strings.EqualFold(segs[2], "resourceGroups") {
		return id, fmt.Errorf("expected %q as the third segment, got %q", "resourceGroups", segs[2])
	}
	id.ResourceGroup = segs[3]
	if !strings.EqualFold(segs[4], "providers") {
		return id, fmt.Errorf("expected %q as the fifth segment, got %q", "providers", segs[4])
	}
	id.ProviderNamespace = segs[5]
	rest := segs[6:]
	if len(rest)%2 != 0 {
		return id, fmt.Errorf("the type/name segments after %q are unbalanced: %v", "providers", rest)
	}
	for i := 0; i < len(rest); i += 2 {
		if rest[i] == "" || rest[i+1] == "" {
			return id, fmt.Errorf("empty type or name segment in %q", s)
		}
		id.Types = append(id.Types, rest[i])
		id.Names = append(id.Names, rest[i+1])
	}
	return id, nil
}

// Canonical is the comparison form. An unparseable id is returned unchanged, so
// two unparseable ids compare literally rather than collapsing to one value.
func Canonical(s string) string {
	id, err := Parse(s)
	if err != nil {
		return s
	}
	var b strings.Builder
	b.WriteString("/subscriptions/")
	b.WriteString(id.SubscriptionID)
	b.WriteString("/resourcegroups/")
	// The resource GROUP is a resource name: kept verbatim, per §4's
	// "resource names compared case-sensitively".
	b.WriteString(id.ResourceGroup)
	b.WriteString("/providers/")
	b.WriteString(strings.ToLower(id.ProviderNamespace))
	for i := range id.Types {
		b.WriteString("/")
		b.WriteString(strings.ToLower(id.Types[i]))
		b.WriteString("/")
		b.WriteString(id.Names[i])
	}
	return b.String()
}
