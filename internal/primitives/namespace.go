package primitives

import "regexp"

// NamespacePattern is THE namespace and certificate-name grammar.
//
// authorisation-model.md §8.2 / contracts-and-codegen.md §7.2: reviewer 01 gives
// this form and reviewer 03 gives the same without the `?`, which rejects a
// one-character namespace that 01 accepts (E-01). The form WITH the optional
// group is normative, so a one-character namespace is accepted in both languages.
//
// There must be exactly one of these strings in the repository outside the
// generated package; a CI grep enforces it.
const NamespacePattern = `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`

var namespaceRE = regexp.MustCompile(NamespacePattern)

// ReservedNames may never be used as a namespace or a certificate name
// (authorisation-model.md §8.2). Anything beginning `_` is also reserved, and is
// already rejected by the grammar.
var ReservedNames = map[string]struct{}{
	"admin":    {},
	"system":   {},
	"platform": {},
	"policy":   {},
	"internal": {},
}

// ValidateNamespace enforces the grammar at routing, before any blob path is
// constructed. Certificate names within a namespace use the same grammar and the
// same enforcement point.
func ValidateNamespace(s string) error {
	if !namespaceRE.MatchString(s) {
		return reject("NS", "does not match "+NamespacePattern)
	}
	if _, ok := ReservedNames[s]; ok {
		return reject("NS", "reserved name")
	}
	return nil
}
