package evidence

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The profile registry. profiles/ in this package is a byte-for-byte copy of
// profiles/ at the repository root, written by scripts/profiles.py --write;
// go:embed cannot reach outside the module. TestEmbeddedProfilesMatchRegistry
// and scripts/profiles.py --check fail when the copies differ.
//
//go:embed profiles
var profileFiles embed.FS

// profileSchemaKeywords are the JSON Schema keywords a profile schema may
// use. Profiles check required members and types only; members a profile
// does not name are always allowed, because minor versions within a major
// add members (SPEC.md section 3.4, profiles/README.md).
var profileSchemaKeywords = enum(
	"$schema", "$id", "$comment", "title", "description", "examples",
	"type", "required", "properties", "items",
)

var profileTypes = enum("object", "array", "string", "number", "integer", "boolean", "null")

var profileFilePattern = regexp.MustCompile(`^profiles/([a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+)/([1-9][0-9]*)\.schema\.json$`)

// profileNode is one compiled (sub)schema of a profile.
type profileNode struct {
	types      []string
	required   []string
	properties map[string]*profileNode
	propOrder  []string
	items      *profileNode
}

type profile struct {
	id   string
	raw  []byte
	root *profileNode
}

var profileRegistry = mustLoadProfiles()

func mustLoadProfiles() map[string]*profile {
	reg := map[string]*profile{}
	err := fs.WalkDir(profileFiles, "profiles", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := profileFilePattern.FindStringSubmatch(p)
		if m == nil {
			return fmt.Errorf("unexpected file %s in the profile registry", p)
		}
		raw, err := profileFiles.ReadFile(p)
		if err != nil {
			return err
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		root, err := compileProfileNode(doc, "")
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		id := m[1] + "/" + m[2]
		reg[id] = &profile{id: id, raw: raw, root: root}
		return nil
	})
	if err != nil {
		panic("evidence: profile registry: " + err.Error())
	}
	return reg
}

func compileProfileNode(doc any, where string) (*profileNode, error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: a schema must be an object", orRoot(where))
	}
	n := &profileNode{}
	for k := range obj {
		if !profileSchemaKeywords[k] {
			return nil, fmt.Errorf("%s: keyword %q is not allowed in a profile schema", orRoot(where), k)
		}
	}
	switch t := obj["type"].(type) {
	case nil:
	case string:
		n.types = []string{t}
	case []any:
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("%s: type must be a string or an array of strings", orRoot(where))
			}
			n.types = append(n.types, s)
		}
	default:
		return nil, fmt.Errorf("%s: type must be a string or an array of strings", orRoot(where))
	}
	for _, t := range n.types {
		if !profileTypes[t] {
			return nil, fmt.Errorf("%s: unknown type %q", orRoot(where), t)
		}
	}
	if r, ok := obj["required"]; ok {
		list, ok := r.([]any)
		if !ok {
			return nil, fmt.Errorf("%s: required must be an array of strings", orRoot(where))
		}
		for _, x := range list {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("%s: required must be an array of strings", orRoot(where))
			}
			n.required = append(n.required, s)
		}
	}
	if p, ok := obj["properties"]; ok {
		props, ok := p.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: properties must be an object", orRoot(where))
		}
		n.properties = map[string]*profileNode{}
		for name, sub := range props {
			c, err := compileProfileNode(sub, where+"/properties/"+name)
			if err != nil {
				return nil, err
			}
			n.properties[name] = c
			n.propOrder = append(n.propOrder, name)
		}
		sort.Strings(n.propOrder)
	}
	if it, ok := obj["items"]; ok {
		c, err := compileProfileNode(it, where+"/items")
		if err != nil {
			return nil, err
		}
		n.items = c
	}
	return n, nil
}

func orRoot(where string) string {
	if where == "" {
		return "schema root"
	}
	return where
}

// Profiles returns the identifiers (<name>/<major>) of the profiles this
// verifier knows, sorted.
func Profiles() []string {
	ids := make([]string, 0, len(profileRegistry))
	for id := range profileRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ProfileSchema returns the JSON Schema of a known profile as it is stored in
// the registry.
func ProfileSchema(id string) ([]byte, bool) {
	p, ok := profileRegistry[id]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), p.raw...), true
}

// ValidateProfilePayload checks a payload against a known profile and returns
// one message per problem, in a fixed order (type first, then required
// members in schema order, then named members in code point order, then
// array items). known is false when the profile is not in the registry.
func ValidateProfilePayload(id string, payload json.RawMessage) (known bool, problems []string) {
	p, ok := profileRegistry[id]
	if !ok {
		return false, nil
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return true, []string{"payload is missing"}
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return true, []string{"payload is not valid JSON: " + err.Error()}
	}
	p.root.validate(v, "payload", &problems)
	return true, problems
}

func (n *profileNode) validate(v any, at string, problems *[]string) {
	if len(n.types) > 0 && !matchesAnyType(v, n.types) {
		*problems = append(*problems, fmt.Sprintf("%s: expected %s, got %s", at, strings.Join(n.types, " or "), jsonTypeName(v)))
		return
	}
	if obj, ok := v.(map[string]any); ok {
		for _, name := range n.required {
			if _, ok := obj[name]; !ok {
				*problems = append(*problems, fmt.Sprintf("%s/%s: missing required member", at, pointerToken(name)))
			}
		}
		for _, name := range n.propOrder {
			if x, ok := obj[name]; ok {
				n.properties[name].validate(x, at+"/"+pointerToken(name), problems)
			}
		}
	}
	if arr, ok := v.([]any); ok && n.items != nil {
		for i, x := range arr {
			n.items.validate(x, at+"/"+strconv.Itoa(i), problems)
		}
	}
}

func pointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func matchesAnyType(v any, types []string) bool {
	for _, t := range types {
		if matchesType(v, t) {
			return true
		}
	}
	return false
}

// matchesType follows JSON Schema: "integer" is any number whose value has no
// fractional part (16.0 is an integer), "number" is any number.
func matchesType(v any, t string) bool {
	switch t {
	case "null":
		return v == nil
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0) && f == math.Trunc(f)
	}
	return false
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	}
	return "unknown"
}

// checkProfile evaluates the profile member of a decoded record. It returns
// the profile identifier (empty when the member is absent or not a string),
// the profile state, and a finding when there is something to report beyond
// the structural check (which reports a malformed profile member as
// schema_invalid).
func checkProfile(obj map[string]json.RawMessage, r *Record) (string, string, *Finding) {
	raw, ok := obj["profile"]
	if !ok {
		return "", ProfileNone, nil
	}
	if strings.TrimSpace(string(raw)) == "null" || !profilePattern.MatchString(r.Profile) {
		return r.Profile, StateInvalid, nil
	}
	known, problems := ValidateProfilePayload(r.Profile, obj["payload"])
	if !known {
		return r.Profile, StateOutsideScope, &Finding{Class: ClassProfileUnknown, Severity: SeverityNotice,
			Message: fmt.Sprintf("profile %s is not known to this verifier (known: %s); the payload was not checked against a profile", r.Profile, knownProfilesText())}
	}
	if len(problems) > 0 {
		return r.Profile, StateInvalid, &Finding{Class: ClassProfileInvalid, Severity: SeverityError,
			Message: fmt.Sprintf("payload does not match profile %s: %s", r.Profile, joinProblems(problems))}
	}
	return r.Profile, StateValid, nil
}

func knownProfilesText() string {
	ids := Profiles()
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

func joinProblems(problems []string) string {
	return strings.Join(problems, "; ")
}
