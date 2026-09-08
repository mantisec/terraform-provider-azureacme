package primitives

import (
	"errors"
	"regexp"
	"time"
)

// RFC3339Second is THE wire timestamp format: RFC 3339, UTC, `Z` suffix, second
// precision, no fractional seconds (contracts-and-codegen.md §7.2, F-113).
//
// A naive datetime serialisation emits fractional seconds and produces a drift
// note on an idle registration every time a code path changes.
const RFC3339Second = "2006-01-02T15:04:05Z"

// ErrInvalidWireFormat is returned by the wire-format parsers.
var ErrInvalidWireFormat = errors.New("invalid_wire_format")

// FormatTimestamp renders a time in the one wire format.
func FormatTimestamp(t time.Time) string { return t.UTC().Format(RFC3339Second) }

// TimestampPattern is the SHAPE of a wire timestamp. Calendar validity
// (2026-02-29 is not a day) is a separate parse step — see ParseTimestamp.
//
// The shape check is not optional: time.Parse alone accepts a fractional-second
// field in the input even when the layout does not signify one, so a `.456Z`
// timestamp would round-trip silently.
const TimestampPattern = `^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$`

// HexPattern is lowercase hex with no separators.
const HexPattern = `^[0-9a-f]+$`

var wireTimestampRE = regexp.MustCompile(TimestampPattern)

// ParseTimestamp accepts only the one wire format — fractional seconds and
// non-`Z` offsets are rejected on the wire.
func ParseTimestamp(s string) (time.Time, error) {
	if !wireTimestampRE.MatchString(s) {
		return time.Time{}, ErrInvalidWireFormat
	}
	t, err := time.Parse(RFC3339Second, s)
	if err != nil {
		return time.Time{}, ErrInvalidWireFormat
	}
	return t.UTC(), nil
}

// ValidateHex accepts lowercase hex with no separators, of the expected length in
// characters. Thumbprints and serials use it; an uppercase thumbprint is rejected.
func ValidateHex(s string, length int) error {
	if length > 0 && len(s) != length {
		return ErrInvalidWireFormat
	}
	if len(s) == 0 {
		return ErrInvalidWireFormat
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return ErrInvalidWireFormat
		}
	}
	return nil
}
