package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// The reading rules of SPEC.md section 2: a record line is exactly one JSON
// object, valid UTF-8, with unique member names in every object, no string
// with an unpaired surrogate, nested at most MaxDepth levels, and nothing but
// JSON white space around it. encoding/json does not check the last four
// (it keeps the last of two members with the same name, replaces unpaired
// surrogates and accepts data after the first value when it reads with a
// Decoder), so they are checked here. A line that breaks a rule is
// schema_invalid at step 1 of section 6.3.

// isJSONSpace reports whether c is JSON white space (RFC 8259): space, tab,
// line feed or carriage return.
func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// trimJSONSpace removes JSON white space from both ends of b. A line that is
// empty afterwards is blank.
func trimJSONSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isJSONSpace(b[i]) {
		i++
	}
	for j > i && isJSONSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

// decodeObject reads one record line under the rules above and returns its
// members as raw JSON.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("line is not valid UTF-8")
	}
	if nestingDepth(raw) > MaxDepth {
		return nil, fmt.Errorf("nesting deeper than %d levels", MaxDepth)
	}
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("record is not a JSON object")
	}
	if len(trimJSONSpace(raw[dec.InputOffset():])) > 0 {
		return nil, fmt.Errorf("data after the JSON object on the same line")
	}
	if err := checkNames(raw); err != nil {
		return nil, err
	}
	return obj, nil
}

// nestingDepth returns the deepest nesting of objects and arrays in raw,
// counting brackets outside strings. It does not need valid JSON.
func nestingDepth(raw []byte) int {
	depth, deepest := 0, 0
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case '}', ']':
			depth--
		}
	}
	return deepest
}

// nameFrame is one open object or array while checkNames walks a line.
type nameFrame struct {
	object    bool
	expectKey bool
	names     map[string]struct{}
}

// checkNames walks raw, which must already be valid JSON, decodes every
// string and reports an unpaired surrogate escape in any string or member
// name, and a member name that occurs twice in one object. Names are
// compared after their escapes are decoded, so "a" and "\u0061" are the same
// name.
func checkNames(raw []byte) error {
	var stack []*nameFrame
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			s, end, err := decodeString(raw, i)
			if err != nil {
				return err
			}
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				top := stack[n-1]
				if _, dup := top.names[s]; dup {
					return fmt.Errorf("duplicate member name %s", strconv.Quote(s))
				}
				top.names[s] = struct{}{}
				top.expectKey = false
			}
			i = end - 1
		case '{':
			stack = append(stack, &nameFrame{object: true, expectKey: true, names: map[string]struct{}{}})
		case '[':
			stack = append(stack, &nameFrame{})
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			if n := len(stack); n > 0 && stack[n-1].object {
				stack[n-1].expectKey = true
			}
		}
	}
	return nil
}

// decodeString decodes the JSON string that starts with the quote at
// raw[start] and returns it and the index just after its closing quote. An
// escaped high surrogate must be followed by an escaped low surrogate, and
// a low surrogate must not stand alone.
func decodeString(raw []byte, start int) (string, int, error) {
	var b []byte
	for i := start + 1; i < len(raw); {
		c := raw[i]
		switch {
		case c == '"':
			return string(b), i + 1, nil
		case c != '\\':
			b = append(b, c)
			i++
			continue
		}
		if i+1 >= len(raw) {
			break
		}
		switch e := raw[i+1]; e {
		case '"', '\\', '/':
			b = append(b, e)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			u, ok := hex4(raw, i+2)
			if !ok {
				return "", 0, fmt.Errorf("invalid JSON: malformed \\u escape")
			}
			i += 6
			r := rune(u)
			switch {
			case utf16.IsSurrogate(r) && u < 0xDC00:
				lo, ok := hex4(raw, i+2)
				if i+1 >= len(raw) || raw[i] != '\\' || raw[i+1] != 'u' || !ok || lo < 0xDC00 || lo > 0xDFFF {
					return "", 0, fmt.Errorf("string with an unpaired surrogate \\u%04x", u)
				}
				r = utf16.DecodeRune(r, rune(lo))
				i += 6
			case utf16.IsSurrogate(r):
				return "", 0, fmt.Errorf("string with an unpaired surrogate \\u%04x", u)
			}
			b = utf8.AppendRune(b, r)
			continue
		default:
			return "", 0, fmt.Errorf("invalid JSON: unknown escape \\%c", e)
		}
		i += 2
	}
	return "", 0, fmt.Errorf("invalid JSON: unterminated string")
}

// hex4 parses the four hexadecimal digits at raw[at:at+4].
func hex4(raw []byte, at int) (uint16, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[at:at+4]), 16, 16)
	return uint16(v), err == nil
}
