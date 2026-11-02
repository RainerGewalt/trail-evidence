package evidence

import "encoding/json"

// Schema is the only schema identifier accepted by this implementation.
const Schema = "trail.evidence/1"

// HashPrefix precedes every hex-encoded SHA-256 digest in a record.
const HashPrefix = "sha256:"

// GenesisHash is the prev_hash of the first record in a stream and the
// anchor_hash of a restart whose predecessor is unknown.
const GenesisHash = HashPrefix + "0000000000000000000000000000000000000000000000000000000000000000"

// Producer kinds.
const (
	ProducerBroker         = "broker"
	ProducerTransferWorker = "transfer-worker"
	ProducerSourceBridge   = "source-bridge"
	ProducerMLPipeline     = "ml-pipeline"
	ProducerPersistence    = "persistence"
	ProducerOther          = "other"
)

// Time sources.
const (
	TimeSourceSystem           = "system"
	TimeSourceNTP              = "ntp"
	TimeSourceTSA              = "tsa"
	TimeSourceSeqReconstructed = "seq-reconstructed"
	TimeSourceUnknown          = "unknown"
)

// Actor authentication classes.
const (
	AuthBrokerAuthenticated = "broker-authenticated"
	AuthSelfDeclared        = "self-declared"
	AuthOperatorToken       = "operator-token"
	AuthNone                = "none"
)

// Policy lifecycle states.
const (
	PolicyDraft     = "draft"
	PolicyValidated = "validated"
	PolicyApproved  = "approved"
	PolicyActive    = "active"
	PolicyRetired   = "retired"
)

// Producer identifies the instance that sealed the record.
type Producer struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Time carries the timestamps of a record. RecordedAt is the moment of
// sealing and is required; the others describe the fact itself.
type Time struct {
	RecordedAt string `json:"recorded_at"`
	OccurredAt string `json:"occurred_at,omitempty"`
	ReadAt     string `json:"read_at,omitempty"`
	Source     string `json:"source"`
}

// Actor records who caused the record to exist and how that identity was
// established.
type Actor struct {
	Auth  string   `json:"auth"`
	ID    string   `json:"id,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// Policy names the rule, recipe or configuration that governed the event.
type Policy struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Hash    string `json:"hash"`
	Status  string `json:"status,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// NoPolicy is the policy object to use when no policy applies.
var NoPolicy = Policy{ID: "none", Version: "0", Hash: GenesisHash}

// Signature is a detached Ed25519 signature over the ASCII bytes of chain_hash.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

// Redaction documents which payload fields were masked before hashing.
type Redaction struct {
	Fields []string `json:"fields"`
	Method string   `json:"method"`
}

// Anchor points to an external anchoring of this record's chain_hash.
type Anchor struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// Record is one Trail Evidence Record. Field order matches the layout used in
// the specification; JCS sorts members anyway, so order never affects hashes.
type Record struct {
	Schema        string          `json:"schema"`
	Producer      Producer        `json:"producer"`
	StreamID      string          `json:"stream_id"`
	Seq           uint64          `json:"seq"`
	ChainRestart  bool            `json:"chain_restart,omitempty"`
	AnchorHash    string          `json:"anchor_hash,omitempty"`
	PrevHash      string          `json:"prev_hash"`
	EventType     string          `json:"event_type"`
	Time          Time            `json:"time"`
	Actor         Actor           `json:"actor"`
	Policy        Policy          `json:"policy"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	JobID         string          `json:"job_id,omitempty"`
	DecisionID    string          `json:"decision_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	Redaction     *Redaction      `json:"redaction,omitempty"`
	ContentHash   string          `json:"content_hash"`
	ChainHash     string          `json:"chain_hash"`
	Signature     *Signature      `json:"signature,omitempty"`
	Anchor        *Anchor         `json:"anchor,omitempty"`
	Context       json.RawMessage `json:"context,omitempty"`
}

// coreMembers lists the top-level members that chain_hash covers. Optional
// members are included only when present in the record.
var coreMembers = []string{
	"schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
	"time", "actor", "policy", "content_hash", "chain_restart", "anchor_hash",
}

// MarshalJSON renders the record as compact JSON without HTML escaping, so the
// bytes written to a journal are exactly what a reader will canonicalise.
func (r *Record) MarshalJSON() ([]byte, error) {
	type plain Record
	return marshalNoEscape((*plain)(r))
}
