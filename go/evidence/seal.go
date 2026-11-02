package evidence

import (
	"encoding/json"
	"fmt"
)

// Seal links r to prevHash and computes content_hash and chain_hash.
//
// prevHash is the chain_hash of the previous record in the stream, or
// GenesisHash for the first record. For a restart record (ChainRestart set)
// the caller puts the last known chain_hash of the previous segment into
// AnchorHash and passes the same value as prevHash; Seal rejects a restart
// whose prev_hash and anchor_hash differ.
//
// Seal does not validate the record against the schema; use VerifyRecord on
// the sealed bytes when that matters. It does require the structural
// invariants it depends on: Schema set to Schema and a non-empty payload.
func Seal(r *Record, prevHash string) error {
	if r == nil {
		return fmt.Errorf("seal: nil record")
	}
	if r.Schema == "" {
		r.Schema = Schema
	}
	if r.Schema != Schema {
		return fmt.Errorf("seal: unsupported schema %q", r.Schema)
	}
	if len(r.Payload) == 0 {
		return fmt.Errorf("seal: payload is required (use null for an empty payload)")
	}
	if r.ChainRestart {
		if r.AnchorHash == "" {
			return fmt.Errorf("seal: chain_restart requires anchor_hash")
		}
		if prevHash != r.AnchorHash {
			return fmt.Errorf("seal: restart record must use anchor_hash as prev_hash")
		}
	} else if r.AnchorHash != "" {
		return fmt.Errorf("seal: anchor_hash is only allowed with chain_restart")
	}
	r.PrevHash = prevHash
	r.Signature = nil
	r.ContentHash = ""
	r.ChainHash = ""

	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	h, err := ComputeHashes(raw)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	r.ContentHash = h.ContentHash
	r.ChainHash = h.ChainHash
	return nil
}
