// Package rfc3339 is the `rfc3339.String` custom framework type of
// terraform-provider-contract.md §4.
//
// The wire format is fixed at SECOND precision with no fractional part
// (primitives.RFC3339Second). This type exists as belt and braces for plan
// stability failure 8 of §6.4: if any code path on either side ever emits
// `…:01.000Z`, an idle registration must still plan clean rather than printing a
// drift note on every plan until someone notices.
package rfc3339

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// StringType is the attr.Type for a timestamp.
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

func (t StringType) String() string { return "rfc3339.StringType" }

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

// String is the attr.Value for a timestamp.
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

// StringSemanticEquals compares INSTANTS, so `…:01Z` and `…:01.000Z` are equal.
func (v String) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(String)
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("expected rfc3339.String, got %T. This is a provider defect.", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.StringValue.Equal(newValue.StringValue), diags
	}
	oldTime, oldErr := time.Parse(time.RFC3339, v.ValueString())
	newTime, newErr := time.Parse(time.RFC3339, newValue.ValueString())
	if oldErr != nil || newErr != nil {
		return v.ValueString() == newValue.ValueString(), diags
	}
	return oldTime.Equal(newTime), diags
}

// ValidateAttribute rejects a value that is not an RFC 3339 timestamp at all.
// A fractional-second value is ACCEPTED here and absorbed by semantic equality:
// the wire contract forbids it, but rejecting a value the server sent would turn
// a service defect into an unplannable workspace.
func (v String) ValidateAttribute(_ context.Context, req xattr.ValidateAttributeRequest, resp *xattr.ValidateAttributeResponse) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	if _, err := time.Parse(time.RFC3339, v.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path,
			fmt.Sprintf("Invalid timestamp: %q", v.ValueString()),
			"Expected an RFC 3339 timestamp such as 2026-11-28T04:11:01Z.")
	}
}

// NewValue builds a known rfc3339.String.
func NewValue(s string) String { return String{StringValue: basetypes.NewStringValue(s)} }

// NewNull builds a null rfc3339.String.
func NewNull() String { return String{StringValue: basetypes.NewStringNull()} }

// NewUnknown builds an unknown rfc3339.String.
func NewUnknown() String { return String{StringValue: basetypes.NewStringUnknown()} }

// NewValueFromPointer maps an optional wire timestamp to a value or null.
func NewValueFromPointer(s *string) String {
	if s == nil {
		return NewNull()
	}
	return NewValue(*s)
}
