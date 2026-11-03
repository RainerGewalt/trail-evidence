package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize returns the RFC 8785 (JCS) form of already encoded JSON.
func Canonicalize(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("jcs: empty input")
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	return out, nil
}

// HashBytes returns "sha256:" followed by the lowercase hex SHA-256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// HashJSON canonicalises raw JSON and hashes the result.
func HashJSON(raw []byte) (string, error) {
	c, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	return HashBytes(c), nil
}

// ContentHash computes the content_hash of a payload.
func ContentHash(payload json.RawMessage) (string, error) {
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	return HashJSON(payload)
}

// marshalNoEscape encodes v as compact JSON with HTML escaping disabled.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// coreJCS assembles the chain core from the raw members of a record object
// and returns its canonical bytes. contentHash replaces the declared
// content_hash. Working on the raw members (rather than on re-encoded
// structs) keeps the verifiers byte-identical even for inputs that a struct
// round trip would normalise, and hashes every member, seq included, as it
// is written in the record.
func coreJCS(obj map[string]json.RawMessage, contentHash string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for _, k := range coreMembers {
		v, ok := obj[k]
		if k == "content_hash" {
			v, ok = json.RawMessage(`"`+contentHash+`"`), true
		}
		if !ok {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return Canonicalize(buf.Bytes())
}

// Hashes holds the recomputed digests of a record.
type Hashes struct {
	PayloadJCS  []byte
	ContentHash string
	CoreJCS     []byte
	ChainHash   string
}

// ComputeHashes recomputes content_hash and chain_hash for a raw record.
// It uses the record's own payload and its declared core members; the
// declared content_hash is replaced by the recomputed one before the core is
// canonicalised, so a tampered payload shows up in chain_hash as well.
func ComputeHashes(raw []byte) (Hashes, error) {
	obj, err := decodeObject(raw)
	if err != nil {
		return Hashes{}, err
	}
	return computeHashes(obj)
}

func computeHashes(obj map[string]json.RawMessage) (Hashes, error) {
	payload, ok := obj["payload"]
	if !ok {
		return Hashes{}, fmt.Errorf("record has no payload member")
	}
	pj, err := Canonicalize(payload)
	if err != nil {
		return Hashes{}, fmt.Errorf("payload: %w", err)
	}
	h := Hashes{PayloadJCS: pj, ContentHash: HashBytes(pj)}
	cj, err := coreJCS(obj, h.ContentHash)
	if err != nil {
		return Hashes{}, fmt.Errorf("core: %w", err)
	}
	h.CoreJCS = cj
	h.ChainHash = HashBytes(cj)
	return h, nil
}

func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("record is not a JSON object")
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err == nil {
		return nil, fmt.Errorf("trailing data after record")
	}
	return obj, nil
}
