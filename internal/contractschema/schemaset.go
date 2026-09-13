// Package contractschema is the deliberately small JSON Schema reader the
// provider's contract-conformance suites share.
//
// WHY IT IS HAND-WRITTEN. The provider carries no JSON Schema library and does
// not gain one for a test: a published provider's dependency set is part of
// what consumers install, and the conformance suites are the only place in the
// module that would need it.
//
// The obvious risk of a hand-written validator is that it UNDER-validates and
// reports a silent pass. That is closed structurally rather than by care:
// Validate fails on any keyword it does not implement, so a schema that grows
// `patternProperties`, `dependentRequired` or `if`/`then` makes the suite go red
// and demands the keyword be implemented. It can be wrong; it cannot be quietly
// incomplete.
//
// `format` is an annotation here, matching the default behaviour of the Python
// side's jsonschema (the format-assertion vocabulary is opt-in). Both readers
// therefore ignore a `format: uri` and neither one is stricter than the other by
// accident.
//
// WHY IT IS A PACKAGE AND NOT A _test.go FILE. `contracts/policy/` and
// `contracts/catalogue/` are both cross-referencing sets of `*.schema.json`
// files, so their two conformance suites need the SAME reader. A `_test.go` file
// cannot be imported, so a reader living in one of them would have to be copied
// into the other — and a copied validator is a validator that drifts, which is
// the failure the whole cross-language harness exists to prevent. Nothing under
// `internal/` that ships imports this package, so it is not linked into the
// provider binary; `internal/apicontract` keeps its own reader because the
// OpenAPI document is one YAML file whose `$ref`s are all document-local.
package contractschema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Set holds every `*.schema.json` in one contract directory, keyed by file name.
// A `$ref` naming another file in the same directory resolves the way the Python
// side's `referencing` registry resolves it.
type Set struct {
	Dir  string
	Docs map[string]map[string]any
}

// FindDir locates a directory under `contracts/` — which lives OUTSIDE this Go
// module — by walking up from the working directory. The contract files are read
// at TEST time, never embedded and never shipped, so the "no build-time
// cross-deliverable file reference" rule of root FILE_MAP.md §6 is not engaged.
//
// env names an environment variable that overrides the walk, for a checkout
// whose layout the walk cannot guess. An empty string and no error means the
// directory is absent: the caller skips rather than fails, because a packaged
// checkout without `contracts/` is legitimate.
func FindDir(env, area string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", area)
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// DecodeJSON reads one JSON document. Numbers are decoded as json.Number so that
// `integer` and `minimum` are checked against what the file actually says rather
// than against a float64 the reader invented.
func DecodeJSON(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var out any
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return out, nil
}

// DecodeObject is DecodeJSON for a document that must be a JSON object.
func DecodeObject(path string) (map[string]any, error) {
	value, err := DecodeJSON(path)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", path)
	}
	return object, nil
}

// Load reads every `*.schema.json` in dir into a Set.
func Load(dir string) (*Set, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no schemas in %s", dir)
	}
	sort.Strings(matches)
	set := &Set{Dir: dir, Docs: map[string]map[string]any{}}
	for _, path := range matches {
		document, err := DecodeObject(path)
		if err != nil {
			return nil, err
		}
		set.Docs[filepath.Base(path)] = document
	}
	return set, nil
}

// Names lists the schema file names in the set, sorted.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.Docs))
	for name := range s.Docs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// EverySubschema yields every schema object reachable in a document, itself
// included. It mirrors the Python half's walker so the two sides scan the same
// nodes.
func EverySubschema(node map[string]any) []map[string]any {
	out := []map[string]any{node}
	for _, key := range SortedKeys(node) {
		switch key {
		case "properties", "$defs":
			children, _ := node[key].(map[string]any)
			for _, name := range SortedKeys(children) {
				if child, ok := children[name].(map[string]any); ok {
					out = append(out, EverySubschema(child)...)
				}
			}
		case "items", "additionalProperties", "not", "contains", "if", "then", "else":
			if child, ok := node[key].(map[string]any); ok {
				out = append(out, EverySubschema(child)...)
			}
		case "oneOf", "anyOf", "allOf", "prefixItems":
			children, _ := node[key].([]any)
			for _, entry := range children {
				if child, ok := entry.(map[string]any); ok {
					out = append(out, EverySubschema(child)...)
				}
			}
		}
	}
	return out
}

// Err is one validation error: the JSON pointer into the INSTANCE and the
// schema keyword that refused it. The manifest declares both for every negative
// fixture, so a fixture cannot pass by being rejected for the wrong reason.
type Err struct {
	Pointer string
	Keyword string
	Message string
}

func (e Err) String() string { return e.Pointer + ": " + e.Keyword + ": " + e.Message }

func PointerOf(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

var AnnotationKeywords = map[string]bool{
	"$schema": true, "$id": true, "$comment": true,
	"title": true, "description": true, "default": true, "examples": true,
	"$defs": true, "format": true,
	"deprecated": true, "readOnly": true, "writeOnly": true,
	// Not a JSON Schema keyword: `contracts/catalogue/destination-ownership.schema.json`
	// carries a prose note beside its `allOf`. JSON Schema 2020-12 treats an unrecognised
	// keyword as an annotation and the Python side's jsonschema ignores it, so naming it
	// here keeps the two readers reading one document the same way.
	"allOf_state_note": true,
}

var SupportedKeywords = map[string]bool{
	"$ref": true, "type": true, "enum": true, "const": true,
	"required": true, "properties": true, "additionalProperties": true,
	"maxProperties": true, "unevaluatedProperties": true,
	"items": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
	"oneOf": true, "anyOf": true, "allOf": true,
	"not": true, "if": true, "then": true, "else": true,
}

func (s *Set) Resolve(ref, base string) (map[string]any, string, error) {
	file, pointer, found := strings.Cut(ref, "#")
	if !found {
		return nil, "", fmt.Errorf("unsupported $ref %q: no fragment", ref)
	}
	if file == "" {
		file = base
	}
	doc, ok := s.Docs[file]
	if !ok {
		return nil, "", fmt.Errorf("unsupported $ref %q: no such schema document", ref)
	}
	node := any(doc)
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("$ref %q: %q is not an object", ref, part)
		}
		next, ok := object[part]
		if !ok {
			return nil, "", fmt.Errorf("$ref %q: %q is absent", ref, part)
		}
		node = next
	}
	target, ok := node.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("$ref %q does not name a schema object", ref)
	}
	return target, file, nil
}

// validate applies the keyword subset above. `base` is the schema document the
// current node came from, so a relative $ref resolves the way the Python
// registry resolves it.
func (s *Set) Validate(schema map[string]any, inst any, path, base string) []Err {
	var out []Err

	for keyword := range schema {
		if AnnotationKeywords[keyword] || SupportedKeywords[keyword] {
			continue
		}
		out = append(out, Err{PointerOf(path), "unsupported-keyword:" + keyword,
			"this reader does not implement the keyword; implement it rather than ignoring it"})
	}

	if ref, ok := schema["$ref"].(string); ok {
		target, targetBase, err := s.Resolve(ref, base)
		if err != nil {
			out = append(out, Err{PointerOf(path), "$ref", err.Error()})
		} else {
			out = append(out, s.Validate(target, inst, path, targetBase)...)
		}
	}

	if want, ok := schema["type"]; ok && !matchesType(want, inst) {
		out = append(out, Err{PointerOf(path), "type",
			fmt.Sprintf("%s is not of type %v", describe(inst), want)})
	}

	if allowed, ok := schema["enum"].([]any); ok {
		if !ContainsValue(allowed, inst) {
			out = append(out, Err{PointerOf(path), "enum",
				fmt.Sprintf("%s is not one of %v", describe(inst), allowed)})
		}
	}
	if fixed, ok := schema["const"]; ok && Canonical(fixed) != Canonical(inst) {
		out = append(out, Err{PointerOf(path), "const", describe(inst) + " is not the const value"})
	}

	out = append(out, s.validateObject(schema, inst, path, base)...)
	out = append(out, s.validateArray(schema, inst, path, base)...)
	out = append(out, validateString(schema, inst, path)...)
	out = append(out, validateNumber(schema, inst, path)...)
	out = append(out, s.validateCombinators(schema, inst, path, base)...)

	return out
}

func (s *Set) validateObject(schema map[string]any, inst any, path, base string) []Err {
	object, ok := inst.(map[string]any)
	if !ok {
		return nil
	}
	var out []Err

	if want, ok := asInt(schema["maxProperties"]); ok && len(object) > want {
		out = append(out, Err{PointerOf(path), "maxProperties",
			fmt.Sprintf("%d properties, maximum %d", len(object), want)})
	}

	// `unevaluatedProperties: true` is the only form this reader implements, because it is
	// the only form that constrains nothing: it needs no annotation collection to be
	// correct. Any other form is refused rather than ignored — an ignored
	// `unevaluatedProperties: false` is precisely the silent under-validation this reader
	// is structured to make impossible.
	if unevaluated, present := schema["unevaluatedProperties"]; present {
		if allowed, ok := unevaluated.(bool); !ok || !allowed {
			out = append(out, Err{PointerOf(path), "unevaluatedProperties",
				"this reader implements `unevaluatedProperties: true` only; implement the " +
					"annotation-collection form rather than letting the Go side under-validate"})
		}
	}

	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			key, ok := name.(string)
			if !ok {
				continue
			}
			if _, present := object[key]; !present {
				out = append(out, Err{PointerOf(path), "required",
					fmt.Sprintf("%q is a required property", key)})
			}
		}
	}

	properties, _ := schema["properties"].(map[string]any)
	for _, key := range SortedKeys(properties) {
		value, present := object[key]
		if !present {
			continue
		}
		subschema, ok := properties[key].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, s.Validate(subschema, value, path+"/"+escape(key), base)...)
	}

	if additional, present := schema["additionalProperties"]; present {
		for _, key := range SortedKeys(object) {
			if _, declared := properties[key]; declared {
				continue
			}
			switch typed := additional.(type) {
			case bool:
				if !typed {
					out = append(out, Err{PointerOf(path), "additionalProperties",
						fmt.Sprintf("%q is not one of the declared properties", key)})
				}
			case map[string]any:
				out = append(out, s.Validate(typed, object[key], path+"/"+escape(key), base)...)
			}
		}
	}
	return out
}

func (s *Set) validateArray(schema map[string]any, inst any, path, base string) []Err {
	items, ok := inst.([]any)
	if !ok {
		return nil
	}
	var out []Err

	if subschema, ok := schema["items"].(map[string]any); ok {
		for index, element := range items {
			out = append(out, s.Validate(subschema, element, fmt.Sprintf("%s/%d", path, index), base)...)
		}
	}
	if want, ok := asInt(schema["minItems"]); ok && len(items) < want {
		out = append(out, Err{PointerOf(path), "minItems",
			fmt.Sprintf("%d items, minimum %d", len(items), want)})
	}
	if want, ok := asInt(schema["maxItems"]); ok && len(items) > want {
		out = append(out, Err{PointerOf(path), "maxItems",
			fmt.Sprintf("%d items, maximum %d", len(items), want)})
	}
	if unique, ok := schema["uniqueItems"].(bool); ok && unique {
		seen := map[string]bool{}
		for _, element := range items {
			key := Canonical(element)
			if seen[key] {
				out = append(out, Err{PointerOf(path), "uniqueItems", "has non-unique elements"})
				break
			}
			seen[key] = true
		}
	}
	return out
}

func validateString(schema map[string]any, inst any, path string) []Err {
	value, ok := inst.(string)
	if !ok {
		return nil
	}
	var out []Err
	length := utf8.RuneCountInString(value)
	if want, ok := asInt(schema["minLength"]); ok && length < want {
		out = append(out, Err{PointerOf(path), "minLength",
			fmt.Sprintf("%d characters, minimum %d", length, want)})
	}
	if want, ok := asInt(schema["maxLength"]); ok && length > want {
		out = append(out, Err{PointerOf(path), "maxLength",
			fmt.Sprintf("%d characters, maximum %d", length, want)})
	}
	if pattern, ok := schema["pattern"].(string); ok {
		expression, err := regexp.Compile(pattern)
		if err != nil {
			// A pattern Go cannot compile is a real cross-language divergence,
			// not a test-harness limitation: the two readers would disagree.
			out = append(out, Err{PointerOf(path), "pattern",
				fmt.Sprintf("the schema pattern %q does not compile for this reader: %v", pattern, err)})
		} else if !expression.MatchString(value) {
			out = append(out, Err{PointerOf(path), "pattern",
				fmt.Sprintf("%q does not match %q", value, pattern)})
		}
	}
	return out
}

func validateNumber(schema map[string]any, inst any, path string) []Err {
	number, ok := inst.(json.Number)
	if !ok {
		return nil
	}
	value, err := number.Float64()
	if err != nil {
		return []Err{{PointerOf(path), "type", "unreadable number " + number.String()}}
	}
	var out []Err
	if bound, ok := asFloat(schema["minimum"]); ok && value < bound {
		out = append(out, Err{PointerOf(path), "minimum",
			fmt.Sprintf("%s is less than the minimum of %v", number, bound)})
	}
	if bound, ok := asFloat(schema["maximum"]); ok && value > bound {
		out = append(out, Err{PointerOf(path), "maximum",
			fmt.Sprintf("%s is greater than the maximum of %v", number, bound)})
	}
	return out
}

func (s *Set) validateCombinators(schema map[string]any, inst any, path, base string) []Err {
	var out []Err
	// WHY THE BRANCH ERRORS COME OUT TOO, when nothing matched.
	//
	// A `oneOf` refuses at the BRANCH POINT, so a fractional-seconds timestamp inside a
	// `oneOf`-ed block surfaces two levels above the member that actually offends. A reader
	// that reported only the branch point would let a negative fixture declaring
	// `/operation/acceptedUtc pattern` pass on a `/operation oneOf` — rejected, but for a
	// reason that says nothing about the shape the fixture was written to pin. The Python
	// side flattens `error.context` for exactly this reason; these are the same sub-errors.
	if branches, ok := schema["oneOf"].([]any); ok {
		matched := 0
		var branchErrors []Err
		for _, branch := range branches {
			subschema, ok := branch.(map[string]any)
			if !ok {
				continue
			}
			errs := s.Validate(subschema, inst, path, base)
			if len(errs) == 0 {
				matched++
			} else {
				branchErrors = append(branchErrors, errs...)
			}
		}
		if matched != 1 {
			out = append(out, Err{PointerOf(path), "oneOf",
				fmt.Sprintf("%s matched %d of the %d branches", describe(inst), matched, len(branches))})
			if matched == 0 {
				out = append(out, branchErrors...)
			}
		}
	}
	if branches, ok := schema["anyOf"].([]any); ok {
		matched := false
		var branchErrors []Err
		for _, branch := range branches {
			subschema, ok := branch.(map[string]any)
			if !ok {
				continue
			}
			errs := s.Validate(subschema, inst, path, base)
			if len(errs) == 0 {
				matched = true
			} else {
				branchErrors = append(branchErrors, errs...)
			}
		}
		if !matched {
			out = append(out, Err{PointerOf(path), "anyOf", describe(inst) + " matched no branch"})
			out = append(out, branchErrors...)
		}
	}
	if branches, ok := schema["allOf"].([]any); ok {
		for _, branch := range branches {
			if subschema, ok := branch.(map[string]any); ok {
				out = append(out, s.Validate(subschema, inst, path, base)...)
			}
		}
	}
	if subschema, ok := schema["not"].(map[string]any); ok {
		if len(s.Validate(subschema, inst, path, base)) == 0 {
			out = append(out, Err{PointerOf(path), "not",
				describe(inst) + " matches a schema it must not match"})
		}
	}
	// if/then/else. The condition's own errors are NOT reported: a failed `if` selects the
	// `else` branch, it does not make the instance invalid.
	if condition, ok := schema["if"].(map[string]any); ok {
		branch := "then"
		if len(s.Validate(condition, inst, path, base)) != 0 {
			branch = "else"
		}
		if subschema, ok := schema[branch].(map[string]any); ok {
			out = append(out, s.Validate(subschema, inst, path, base)...)
		}
	}
	return out
}

// ------------------------------------------------------------------ helpers

func matchesType(want any, inst any) bool {
	switch typed := want.(type) {
	case string:
		return matchesOneType(typed, inst)
	case []any:
		for _, candidate := range typed {
			if name, ok := candidate.(string); ok && matchesOneType(name, inst) {
				return true
			}
		}
	}
	return false
}

func matchesOneType(name string, inst any) bool {
	switch name {
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "null":
		return inst == nil
	case "number":
		_, ok := inst.(json.Number)
		return ok
	case "integer":
		number, ok := inst.(json.Number)
		if !ok {
			return false
		}
		_, err := number.Int64()
		return err == nil
	}
	return false
}

func Canonical(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(encoded)
}

func ContainsValue(allowed []any, inst any) bool {
	target := Canonical(inst)
	for _, candidate := range allowed {
		if Canonical(candidate) == target {
			return true
		}
	}
	return false
}

func describe(inst any) string {
	if inst == nil {
		return "null"
	}
	return Canonical(inst)
}

func asInt(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func asFloat(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Float64()
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func SortedKeys(object map[string]any) []string {
	out := make([]string, 0, len(object))
	for key := range object {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// escape encodes a property name for a JSON pointer segment (RFC 6901).
func escape(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}
