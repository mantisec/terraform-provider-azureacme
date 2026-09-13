package apicontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// A DELIBERATELY SMALL JSON SCHEMA READER, over the OpenAPI document.
//
// The provider carries no JSON Schema library and does not gain one for a test:
// a published provider's dependency set is part of what consumers install, and
// `internal/policycontract/` already established that the reader is written by
// hand here. `gopkg.in/yaml.v3` IS taken, because reading YAML bytes is I/O
// rather than an assertion — it was already in this module's dependency graph
// and its `h1:` hash was already in `go.sum`, so nothing new is downloaded — and
// because the alternative, a hand-rolled YAML subset parser, would be a second
// place for the contract to be misread.
//
// The obvious risk of a hand-written validator is that it UNDER-validates and
// reports a silent pass. That is closed structurally rather than by care:
// `validate` fails on any keyword it does not implement, and
// TestTheSchemasUseOnlyKeywordsThisReaderImplements walks every component schema
// looking for one. A schema that grows `patternProperties`, `dependentRequired`
// or `if`/`then` makes this suite go red and demands the keyword be implemented.
// It can be wrong; it cannot be quietly incomplete.
//
// `format` is an annotation here, matching the default behaviour of the Python
// side's jsonschema (the format-assertion vocabulary is opt-in). Neither reader
// is stricter than the other by accident.

// apiDirEnv points the suite at contracts/api/ when the walk up from the test's
// working directory cannot find it.
const apiDirEnv = "ACME_API_CONTRACTS"

// maxRefDepth bounds `$ref` following. A `$ref` does not descend into the
// instance, so a self-referential schema would otherwise spin forever rather
// than fail.
const maxRefDepth = 64

// apiDir locates contracts/api/, which lives OUTSIDE this Go module. It is read
// at test time, never embedded and never shipped, so the "no build-time
// cross-deliverable file reference" rule of root FILE_MAP.md §6 is not engaged.
func apiDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv(apiDirEnv); v != "" {
		return v
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "contracts", "api")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("contracts/api/ not found from the test working directory; set %s", apiDirEnv)
	return ""
}

// apiDoc is contracts/api/openapi.yaml, decoded into the same value shapes the
// JSON examples decode into: maps, slices, strings, bools and json.Number. The
// YAML is round-tripped through JSON precisely so that a `2048` in the schema
// and a `2048` in an example are the same kind of value; comparing an int
// against a float64 is how an `enum` check silently stops matching.
type apiDoc struct {
	path string
	root map[string]any
}

func loadOpenAPI(t *testing.T) *apiDoc {
	t.Helper()
	path := filepath.Join(apiDir(t), "openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var loose any
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		t.Fatalf("decoding %s as YAML: %v", path, err)
	}
	encoded, err := json.Marshal(loose)
	if err != nil {
		t.Fatalf("%s does not re-encode as JSON: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("re-decoding %s: %v", path, err)
	}
	if _, ok := componentSchemas(root); !ok {
		t.Fatalf("%s carries no components.schemas", path)
	}
	return &apiDoc{path: path, root: root}
}

func componentSchemas(root map[string]any) (map[string]any, bool) {
	components, ok := root["components"].(map[string]any)
	if !ok {
		return nil, false
	}
	schemas, ok := components["schemas"].(map[string]any)
	return schemas, ok
}

// verr is one validation error: the JSON pointer into the INSTANCE and the
// schema keyword that refused it. The manifest declares both for every negative
// fixture, so a fixture cannot pass by being rejected for the wrong reason.
type verr struct {
	pointer string
	keyword string
	message string
}

func (e verr) String() string { return e.pointer + ": " + e.keyword + ": " + e.message }

func pointerOf(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

var annotationKeywords = map[string]bool{
	"$schema": true, "$id": true, "$comment": true, "$defs": true,
	"title": true, "description": true, "default": true, "examples": true,
	"format": true, "deprecated": true, "readOnly": true, "writeOnly": true,
}

var supportedKeywords = map[string]bool{
	"$ref": true, "type": true, "enum": true, "const": true,
	"required": true, "properties": true, "additionalProperties": true,
	"unevaluatedProperties": true, "propertyNames": true,
	"minProperties": true, "maxProperties": true,
	"items": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
	"oneOf": true, "anyOf": true, "allOf": true,
}

// resolve follows a document-local `#/...` pointer. Every `$ref` in the OpenAPI
// document is document-local; a cross-file one is a contract change and fails
// here rather than being skipped.
func (d *apiDoc) resolve(ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q: not a document-local pointer", ref)
	}
	node := any(d.root)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q: %q is not an object", ref, part)
		}
		next, ok := object[part]
		if !ok {
			return nil, fmt.Errorf("$ref %q: %q is absent", ref, part)
		}
		node = next
	}
	target, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q does not name a schema object", ref)
	}
	return target, nil
}

func (d *apiDoc) validate(schema map[string]any, inst any, path string) []verr {
	return d.validateAt(schema, inst, path, 0)
}

func (d *apiDoc) validateAt(schema map[string]any, inst any, path string, depth int) []verr {
	var out []verr
	if depth > maxRefDepth {
		return []verr{{pointerOf(path), "$ref",
			"the schema recurses through $ref without descending into the instance"}}
	}

	for keyword := range schema {
		if annotationKeywords[keyword] || supportedKeywords[keyword] {
			continue
		}
		out = append(out, verr{pointerOf(path), "unsupported-keyword:" + keyword,
			"this reader does not implement the keyword; implement it rather than ignoring it"})
	}

	if ref, ok := schema["$ref"].(string); ok {
		target, err := d.resolve(ref)
		if err != nil {
			out = append(out, verr{pointerOf(path), "$ref", err.Error()})
		} else {
			out = append(out, d.validateAt(target, inst, path, depth+1)...)
		}
	}

	if want, ok := schema["type"]; ok && !matchesType(want, inst) {
		out = append(out, verr{pointerOf(path), "type",
			fmt.Sprintf("%s is not of type %v", describe(inst), want)})
	}
	if allowed, ok := schema["enum"].([]any); ok && !containsValue(allowed, inst) {
		out = append(out, verr{pointerOf(path), "enum",
			fmt.Sprintf("%s is not one of %v", describe(inst), allowed)})
	}
	if fixed, ok := schema["const"]; ok && canonical(fixed) != canonical(inst) {
		out = append(out, verr{pointerOf(path), "const", describe(inst) + " is not the const value"})
	}

	out = append(out, d.validateObject(schema, inst, path, depth)...)
	out = append(out, d.validateArray(schema, inst, path, depth)...)
	out = append(out, validateString(schema, inst, path)...)
	out = append(out, validateNumber(schema, inst, path)...)
	out = append(out, d.validateCombinators(schema, inst, path, depth)...)

	return out
}

func (d *apiDoc) validateObject(schema map[string]any, inst any, path string, depth int) []verr {
	object, ok := inst.(map[string]any)
	if !ok {
		return nil
	}
	var out []verr

	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			key, ok := name.(string)
			if !ok {
				continue
			}
			if _, present := object[key]; !present {
				out = append(out, verr{pointerOf(path), "required",
					fmt.Sprintf("%q is a required property", key)})
			}
		}
	}

	properties, _ := schema["properties"].(map[string]any)
	for _, key := range sortedKeys(properties) {
		value, present := object[key]
		if !present {
			continue
		}
		if subschema, ok := properties[key].(map[string]any); ok {
			out = append(out, d.validateAt(subschema, value, path+"/"+escape(key), depth)...)
		}
	}

	if additional, present := schema["additionalProperties"]; present {
		for _, key := range sortedKeys(object) {
			if _, declared := properties[key]; declared {
				continue
			}
			switch typed := additional.(type) {
			case bool:
				if !typed {
					out = append(out, verr{pointerOf(path), "additionalProperties",
						fmt.Sprintf("%q is not one of the declared properties", key)})
				}
			case map[string]any:
				out = append(out, d.validateAt(typed, object[key], path+"/"+escape(key), depth)...)
			}
		}
	}

	if names, ok := schema["propertyNames"].(map[string]any); ok {
		for _, key := range sortedKeys(object) {
			for _, e := range d.validateAt(names, key, path+"/"+escape(key), depth) {
				out = append(out, verr{pointerOf(path), "propertyNames",
					fmt.Sprintf("the property name %q is not permitted: %s", key, e.message)})
			}
		}
	}

	if want, ok := asInt(schema["minProperties"]); ok && len(object) < want {
		out = append(out, verr{pointerOf(path), "minProperties",
			fmt.Sprintf("%d properties, minimum %d", len(object), want)})
	}
	if want, ok := asInt(schema["maxProperties"]); ok && len(object) > want {
		out = append(out, verr{pointerOf(path), "maxProperties",
			fmt.Sprintf("%d properties, maximum %d", len(object), want)})
	}

	// `unevaluatedProperties` rather than `additionalProperties`, because the
	// read projection composes the same fields with the three counters and an
	// `additionalProperties` inside an `allOf` branch cannot see a sibling
	// branch's properties. It is what rejects a `PUT` body carrying
	// `spec.revision`.
	if unevaluated, present := schema["unevaluatedProperties"]; present {
		seen := map[string]bool{}
		d.evaluated(schema, inst, seen, 0)
		for _, key := range sortedKeys(object) {
			if seen[key] {
				continue
			}
			switch typed := unevaluated.(type) {
			case bool:
				if !typed {
					out = append(out, verr{pointerOf(path), "unevaluatedProperties",
						fmt.Sprintf("%q is not evaluated by any subschema; it is read-only, "+
							"reserved, or not part of this shape at all", key)})
				}
			case map[string]any:
				out = append(out, d.validateAt(typed, object[key], path+"/"+escape(key), depth)...)
			}
		}
	}

	return out
}

// evaluated collects the property names this schema and its applicable
// subschemas account for. `oneOf`/`anyOf` branches count only when they
// actually validate, which is what the keyword means.
func (d *apiDoc) evaluated(schema map[string]any, inst any, out map[string]bool, depth int) {
	object, ok := inst.(map[string]any)
	if !ok || depth > maxRefDepth {
		return
	}
	if ref, ok := schema["$ref"].(string); ok {
		if target, err := d.resolve(ref); err == nil {
			d.evaluated(target, inst, out, depth+1)
		}
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		for key := range properties {
			if _, present := object[key]; present {
				out[key] = true
			}
		}
	}
	// A schema-valued or `true` additionalProperties evaluates every remaining
	// property; `false` evaluates none and has already reported them itself.
	if additional, present := schema["additionalProperties"]; present {
		if allowed, isBool := additional.(bool); !isBool || allowed {
			for key := range object {
				out[key] = true
			}
		}
	}
	if branches, ok := schema["allOf"].([]any); ok {
		for _, branch := range branches {
			if subschema, ok := branch.(map[string]any); ok {
				d.evaluated(subschema, inst, out, depth+1)
			}
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		branches, ok := schema[keyword].([]any)
		if !ok {
			continue
		}
		for _, branch := range branches {
			subschema, ok := branch.(map[string]any)
			if !ok {
				continue
			}
			if len(d.validateAt(subschema, inst, "", depth+1)) == 0 {
				d.evaluated(subschema, inst, out, depth+1)
			}
		}
	}
}

func (d *apiDoc) validateArray(schema map[string]any, inst any, path string, depth int) []verr {
	items, ok := inst.([]any)
	if !ok {
		return nil
	}
	var out []verr

	if subschema, ok := schema["items"].(map[string]any); ok {
		for index, element := range items {
			out = append(out, d.validateAt(subschema, element,
				fmt.Sprintf("%s/%d", path, index), depth)...)
		}
	}
	if want, ok := asInt(schema["minItems"]); ok && len(items) < want {
		out = append(out, verr{pointerOf(path), "minItems",
			fmt.Sprintf("%d items, minimum %d", len(items), want)})
	}
	if want, ok := asInt(schema["maxItems"]); ok && len(items) > want {
		out = append(out, verr{pointerOf(path), "maxItems",
			fmt.Sprintf("%d items, maximum %d", len(items), want)})
	}
	if unique, ok := schema["uniqueItems"].(bool); ok && unique {
		seen := map[string]bool{}
		for _, element := range items {
			key := canonical(element)
			if seen[key] {
				out = append(out, verr{pointerOf(path), "uniqueItems", "has non-unique elements"})
				break
			}
			seen[key] = true
		}
	}
	return out
}

func validateString(schema map[string]any, inst any, path string) []verr {
	value, ok := inst.(string)
	if !ok {
		return nil
	}
	var out []verr
	length := utf8.RuneCountInString(value)
	if want, ok := asInt(schema["minLength"]); ok && length < want {
		out = append(out, verr{pointerOf(path), "minLength",
			fmt.Sprintf("%d characters, minimum %d", length, want)})
	}
	if want, ok := asInt(schema["maxLength"]); ok && length > want {
		out = append(out, verr{pointerOf(path), "maxLength",
			fmt.Sprintf("%d characters, maximum %d", length, want)})
	}
	if pattern, ok := schema["pattern"].(string); ok {
		expression, err := regexp.Compile(pattern)
		if err != nil {
			// A pattern Go cannot compile is a real cross-language divergence,
			// not a test-harness limitation: the two readers would disagree.
			out = append(out, verr{pointerOf(path), "pattern",
				fmt.Sprintf("the schema pattern %q does not compile for this reader: %v",
					pattern, err)})
		} else if !expression.MatchString(value) {
			out = append(out, verr{pointerOf(path), "pattern",
				fmt.Sprintf("%q does not match %q", value, pattern)})
		}
	}
	return out
}

func validateNumber(schema map[string]any, inst any, path string) []verr {
	number, ok := inst.(json.Number)
	if !ok {
		return nil
	}
	value, err := number.Float64()
	if err != nil {
		return []verr{{pointerOf(path), "type", "unreadable number " + number.String()}}
	}
	var out []verr
	if bound, ok := asFloat(schema["minimum"]); ok && value < bound {
		out = append(out, verr{pointerOf(path), "minimum",
			fmt.Sprintf("%s is less than the minimum of %v", number, bound)})
	}
	if bound, ok := asFloat(schema["maximum"]); ok && value > bound {
		out = append(out, verr{pointerOf(path), "maximum",
			fmt.Sprintf("%s is greater than the maximum of %v", number, bound)})
	}
	return out
}

// validateCombinators reports the branch point AND, when a `oneOf` or `anyOf`
// fails outright, the errors from inside every branch.
//
// The sub-errors are what make a negative fixture's declared reason checkable.
// `status.current_certificate` is `oneOf: [CurrentCertificate, null]`, so a
// fractional-seconds timestamp two levels down surfaces at the branch point; a
// check that saw only `oneOf` there would accept an example rejected for
// entirely the wrong reason. The Python side flattens jsonschema's `context` for
// exactly the same reason.
func (d *apiDoc) validateCombinators(schema map[string]any, inst any, path string, depth int) []verr {
	var out []verr

	if branches, ok := schema["oneOf"].([]any); ok {
		matched, nested := d.branchOutcomes(branches, inst, path, depth)
		if matched != 1 {
			out = append(out, verr{pointerOf(path), "oneOf",
				fmt.Sprintf("%s matched %d of the %d branches",
					describe(inst), matched, len(branches))})
			if matched == 0 {
				out = append(out, nested...)
			}
		}
	}
	if branches, ok := schema["anyOf"].([]any); ok {
		matched, nested := d.branchOutcomes(branches, inst, path, depth)
		if matched == 0 {
			out = append(out, verr{pointerOf(path), "anyOf", describe(inst) + " matched no branch"})
			out = append(out, nested...)
		}
	}
	if branches, ok := schema["allOf"].([]any); ok {
		for _, branch := range branches {
			if subschema, ok := branch.(map[string]any); ok {
				out = append(out, d.validateAt(subschema, inst, path, depth)...)
			}
		}
	}
	return out
}

func (d *apiDoc) branchOutcomes(branches []any, inst any, path string, depth int) (int, []verr) {
	matched := 0
	var nested []verr
	for _, branch := range branches {
		subschema, ok := branch.(map[string]any)
		if !ok {
			continue
		}
		errors := d.validateAt(subschema, inst, path, depth)
		if len(errors) == 0 {
			matched++
			continue
		}
		nested = append(nested, errors...)
	}
	return matched, nested
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

func canonical(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(encoded)
}

func containsValue(allowed []any, inst any) bool {
	target := canonical(inst)
	for _, candidate := range allowed {
		if canonical(candidate) == target {
			return true
		}
	}
	return false
}

func describe(inst any) string {
	if inst == nil {
		return "null"
	}
	return canonical(inst)
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

func sortedKeys(object map[string]any) []string {
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

// everySubschema yields the node and every schema nested inside it, so the
// keyword guard can walk the whole component set rather than only the parts an
// example happens to reach.
func everySubschema(node map[string]any) []map[string]any {
	out := []map[string]any{node}
	for _, keyword := range []string{"properties", "$defs"} {
		if children, ok := node[keyword].(map[string]any); ok {
			for _, key := range sortedKeys(children) {
				if child, ok := children[key].(map[string]any); ok {
					out = append(out, everySubschema(child)...)
				}
			}
		}
	}
	for _, keyword := range []string{"items", "additionalProperties", "unevaluatedProperties",
		"propertyNames"} {
		if child, ok := node[keyword].(map[string]any); ok {
			out = append(out, everySubschema(child)...)
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := node[keyword].([]any); ok {
			for _, branch := range branches {
				if child, ok := branch.(map[string]any); ok {
					out = append(out, everySubschema(child)...)
				}
			}
		}
	}
	return out
}
