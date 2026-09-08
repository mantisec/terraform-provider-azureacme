// Package dnsname is the `dnsname.String` custom framework type of
// terraform-provider-contract.md §4.
//
// WHY A CUSTOM TYPE AND NOT "just ignore the server". Semantic equality is the
// framework's documented mechanism for absorbing a cosmetic round-trip
// difference without hiding genuine drift. The alternative — not writing the
// server's value into state — hides a real out-of-band change too.
//
// THE NORMALISATION RULE IS NOT DEFINED HERE. It comes from
// internal/primitives, the Go half of the shared cross-language primitives
// (§4, last paragraph): "a policy that permits a name and a client that
// normalises it differently is a silent authorisation bypass". This package
// only decides equality; primitives.Normalise decides what a name *is*.
package dnsname

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/mantisec/terraform-provider-azureacme/internal/primitives"
)

// StringType is the attr.Type for a DNS name.
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

func (t StringType) String() string { return "dnsname.StringType" }

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

// String is the attr.Value for a DNS name.
type String struct {
	basetypes.StringValue
}

var (
	_ basetypes.StringValuableWithSemanticEquals = String{}
	_ xattr.ValidateableAttribute                = String{}
)

// ValidateAttribute rejects anything primitives.Normalise rejects — including
// the fullwidth and ideographic full stops, which are REJECTED and never
// silently normalised (§4). Silently mapping a confusable would make the
// client's idea of a name differ from the policy engine's, which is the
// authorisation bypass this type exists to prevent.
//
// The rule travels with the type rather than living in a separate attribute
// validator, so an attribute that forgets its validator is not a hole.
func (v String) ValidateAttribute(_ context.Context, req xattr.ValidateAttributeRequest, resp *xattr.ValidateAttributeResponse) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	s := v.ValueString()
	if _, err := primitives.Normalise(s); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path,
			fmt.Sprintf("Invalid DNS name: %q", s),
			fmt.Sprintf("%q is not a valid IDNA A-label FQDN: %s\n\n"+
				"The rule is the shared identifier normalisation of the platform's authorisation model, "+
				"so a name this provider rejects is a name the service would also refuse.", s, err.Error()))
	}
}

func (v String) Type(context.Context) attr.Type { return StringType{} }

func (v String) Equal(o attr.Value) bool {
	other, ok := o.(String)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals absorbs case, a trailing dot, and a Unicode/A-label
// spelling difference — and NOTHING else. Two names that normalise differently
// are genuinely different and must produce a diff.
func (v String) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(String)
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("expected dnsname.String, got %T. This is a provider defect.", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.StringValue.Equal(newValue.StringValue), diags
	}
	oldCanonical, oldErr := primitives.Normalise(v.ValueString())
	newCanonical, newErr := primitives.Normalise(newValue.ValueString())
	if oldErr != nil || newErr != nil {
		// An unnormalisable value is compared literally rather than being
		// declared equal: declaring it equal would suppress a real diff.
		return v.ValueString() == newValue.ValueString(), diags
	}
	return oldCanonical == newCanonical, diags
}

// NewValue builds a known dnsname.String.
func NewValue(s string) String { return String{StringValue: basetypes.NewStringValue(s)} }

// NewNull builds a null dnsname.String.
func NewNull() String { return String{StringValue: basetypes.NewStringNull()} }

// NewUnknown builds an unknown dnsname.String.
func NewUnknown() String { return String{StringValue: basetypes.NewStringUnknown()} }
