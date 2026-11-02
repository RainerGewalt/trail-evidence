package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	hashPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	recordedAtPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,9}Z$`)
	timestampPattern  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	eventTypePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$`)
	jsonPointer       = regexp.MustCompile(`^(/([^/~]|~0|~1)*)*$`)
)

var (
	producerKinds = enum(ProducerBroker, ProducerTransferWorker, ProducerSourceBridge, ProducerMLPipeline, ProducerPersistence, ProducerOther)
	timeSources   = enum(TimeSourceSystem, TimeSourceNTP, TimeSourceTSA, TimeSourceSeqReconstructed, TimeSourceUnknown)
	actorAuths    = enum(AuthBrokerAuthenticated, AuthSelfDeclared, AuthOperatorToken, AuthNone)
	policyStates  = enum(PolicyDraft, PolicyValidated, PolicyApproved, PolicyActive, PolicyRetired)
	anchorKinds   = enum("trailmq", "tsa", "worm", "other")
)

var requiredMembers = []string{
	"schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
	"time", "actor", "policy", "payload", "content_hash", "chain_hash",
}

var knownMembers = enum(
	"schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
	"time", "actor", "policy", "payload", "content_hash", "chain_hash",
	"chain_restart", "anchor_hash", "signature", "correlation_id", "job_id",
	"decision_id", "context", "redaction", "anchor",
)

func enum(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// decodeRecord parses raw strictly into a Record. Unknown members anywhere in
// the typed part of the record are an error, as are type mismatches.
func decodeRecord(raw []byte) (*Record, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// validateStructure performs the schema checks that do not need the JSON
// Schema file: required members, enumerations, patterns and the restart
// invariants. It returns one message per problem, sorted for stable output.
func validateStructure(obj map[string]json.RawMessage, r *Record) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	for _, k := range requiredMembers {
		if _, ok := obj[k]; !ok {
			add("missing required member %q", k)
		}
	}
	var unknown []string
	for k := range obj {
		if !knownMembers[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		add("unknown member %q", k)
	}
	if r == nil {
		return problems
	}
	var nulls []string
	for k, v := range obj {
		if k != "payload" && string(bytes.TrimSpace(v)) == "null" {
			nulls = append(nulls, k)
		}
	}
	sort.Strings(nulls)
	for _, k := range nulls {
		add("member %q must not be null", k)
	}
	if _, ok := obj["schema"]; ok && r.Schema != Schema {
		add("schema must be %q, got %q", Schema, r.Schema)
	}
	if _, ok := obj["producer"]; ok {
		if !producerKinds[r.Producer.Kind] {
			add("producer.kind %q is not a known kind", r.Producer.Kind)
		}
		if r.Producer.ID == "" {
			add("producer.id must not be empty")
		}
		if r.Producer.Version == "" {
			add("producer.version must not be empty")
		}
	}
	if _, ok := obj["stream_id"]; ok && r.StreamID == "" {
		add("stream_id must not be empty")
	}
	if _, ok := obj["prev_hash"]; ok && !hashPattern.MatchString(r.PrevHash) {
		add("prev_hash does not match sha256:<64 hex>")
	}
	if _, ok := obj["event_type"]; ok && !eventTypePattern.MatchString(r.EventType) {
		add("event_type %q is not of the form <domain>.<noun>.<verb>", r.EventType)
	}
	if _, ok := obj["time"]; ok {
		if !recordedAtPattern.MatchString(r.Time.RecordedAt) {
			add("time.recorded_at must be RFC 3339 UTC with at least millisecond precision and a Z suffix")
		}
		if r.Time.OccurredAt != "" && !timestampPattern.MatchString(r.Time.OccurredAt) {
			add("time.occurred_at must be RFC 3339 UTC with a Z suffix")
		}
		if r.Time.ReadAt != "" && !timestampPattern.MatchString(r.Time.ReadAt) {
			add("time.read_at must be RFC 3339 UTC with a Z suffix")
		}
		if !timeSources[r.Time.Source] {
			add("time.source %q is not a known source", r.Time.Source)
		}
	}
	if _, ok := obj["actor"]; ok && !actorAuths[r.Actor.Auth] {
		add("actor.auth %q is not a known value", r.Actor.Auth)
	}
	if _, ok := obj["policy"]; ok {
		if r.Policy.ID == "" {
			add("policy.id must not be empty")
		}
		if r.Policy.Version == "" {
			add("policy.version must not be empty")
		}
		if !hashPattern.MatchString(r.Policy.Hash) {
			add("policy.hash does not match sha256:<64 hex>")
		}
		if r.Policy.Status != "" && !policyStates[r.Policy.Status] {
			add("policy.status %q is not a known state", r.Policy.Status)
		}
	}
	if _, ok := obj["content_hash"]; ok && !hashPattern.MatchString(r.ContentHash) {
		add("content_hash does not match sha256:<64 hex>")
	}
	if _, ok := obj["chain_hash"]; ok && !hashPattern.MatchString(r.ChainHash) {
		add("chain_hash does not match sha256:<64 hex>")
	}
	restartRaw, hasRestart := obj["chain_restart"]
	_, hasAnchor := obj["anchor_hash"]
	if hasRestart && string(bytes.TrimSpace(restartRaw)) != "true" {
		add("chain_restart, when present, must be true")
	}
	if hasRestart && !hasAnchor {
		add("chain_restart requires anchor_hash")
	}
	if hasAnchor && !hasRestart {
		add("anchor_hash is only allowed together with chain_restart")
	}
	if hasAnchor {
		if !hashPattern.MatchString(r.AnchorHash) {
			add("anchor_hash does not match sha256:<64 hex>")
		} else if hasRestart && r.PrevHash != r.AnchorHash {
			add("restart record must carry anchor_hash as prev_hash")
		}
	}
	if r.Signature != nil {
		if r.Signature.Alg != "ed25519" {
			add("signature.alg must be \"ed25519\"")
		}
		if r.Signature.KeyID == "" {
			add("signature.key_id must not be empty")
		}
		if sig, err := base64.RawURLEncoding.DecodeString(r.Signature.Sig); err != nil || len(sig) != 64 {
			add("signature.sig must be base64url without padding of a 64-byte Ed25519 signature")
		}
	}
	if r.Redaction != nil {
		if r.Redaction.Method == "" {
			add("redaction.method must not be empty")
		}
		for _, f := range r.Redaction.Fields {
			if !jsonPointer.MatchString(f) {
				add("redaction.fields entry %q is not a JSON pointer", f)
			}
		}
	}
	if r.Anchor != nil {
		if !anchorKinds[r.Anchor.Kind] {
			add("anchor.kind %q is not a known kind", r.Anchor.Kind)
		}
		if r.Anchor.Ref == "" {
			add("anchor.ref must not be empty")
		}
	}
	if ctx, ok := obj["context"]; ok && !bytes.HasPrefix(bytes.TrimSpace(ctx), []byte("{")) {
		add("context must be an object")
	}
	for _, k := range []string{"correlation_id", "job_id", "decision_id"} {
		if v, ok := obj[k]; ok && strings.TrimSpace(string(v)) == `""` {
			add("%s must not be empty when present", k)
		}
	}
	return problems
}
