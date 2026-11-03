package evidence

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

// Finding classes. Every finding a verifier reports belongs to exactly one.
// SPEC.md section 6.2 defines them.
const (
	// Errors: the record is in state invalid.
	ClassSchemaInvalid    = "schema_invalid"
	ClassHashMismatch     = "hash_mismatch"
	ClassChainBreak       = "chain_break"
	ClassSeqMismatch      = "seq_mismatch"
	ClassSignatureInvalid = "signature_invalid"
	ClassProfileInvalid   = "profile_invalid"

	// Notices. seq_gap makes the record unknown; outside_scope marks a
	// record that is not checked. With Options.Strict, seq_gap,
	// outside_scope and profile_unknown are reported with severity error.
	ClassSeqGap           = "seq_gap"
	ClassOutsideScope     = "outside_scope"
	ClassProfileUnknown   = "profile_unknown"
	ClassRestart          = "restart"
	ClassAfterUnknown     = "after_unknown"
	ClassLegacyIntegerSeq = "legacy_integer_seq"
	// ClassNumberPrecision: payload carries an integer outside +/-2^53,
	// which JCS (ES6 number semantics) cannot represent exactly.
	ClassNumberPrecision = "number_precision"
)

// Finding severities.
const (
	SeverityError  = "error"
	SeverityNotice = "notice"
)

// Record states (SPEC.md section 6.1). A record's state depends on the
// record and its stream, never on Options.Strict.
const (
	StateValid        = "valid"
	StateInvalid      = "invalid"
	StateUnknown      = "unknown"
	StateOutsideScope = "outside_scope"
)

// Profile states. A profile state is ProfileNone, or one of StateValid,
// StateInvalid and StateOutsideScope.
const ProfileNone = "none"

// errorClasses put a record into state invalid.
var errorClasses = enum(ClassSchemaInvalid, ClassHashMismatch, ClassChainBreak, ClassSeqMismatch, ClassSignatureInvalid, ClassProfileInvalid)

// strictClasses are notices that strict verification reports as errors.
var strictClasses = enum(ClassSeqGap, ClassOutsideScope, ClassProfileUnknown)

// Finding is one observation about one record. Seq is the record's seq when
// it is usable; it is encoded as a decimal string.
type Finding struct {
	Index    int     `json:"index"`
	Line     int     `json:"line"`
	StreamID string  `json:"stream_id,omitempty"`
	Seq      *uint64 `json:"seq,omitempty,string"`
	Class    string  `json:"class"`
	Severity string  `json:"severity"`
	Message  string  `json:"message"`
}

// StreamSummary describes one hash chain seen while verifying a journal.
// Records counts the records that took part in the chain checks.
type StreamSummary struct {
	StreamID      string `json:"stream_id"`
	Records       int    `json:"records"`
	FirstSeq      uint64 `json:"first_seq,string"`
	LastSeq       uint64 `json:"last_seq,string"`
	LastChainHash string `json:"last_chain_hash"`
	Restarts      int    `json:"restarts"`
}

// StateCounts counts records per state.
type StateCounts struct {
	Valid        int `json:"valid"`
	Invalid      int `json:"invalid"`
	Unknown      int `json:"unknown"`
	OutsideScope int `json:"outside_scope"`
}

// ProfileStateCounts counts records per profile state.
type ProfileStateCounts struct {
	None         int `json:"none"`
	Valid        int `json:"valid"`
	Invalid      int `json:"invalid"`
	OutsideScope int `json:"outside_scope"`
}

// RecordResult is the verdict on one record of a journal.
type RecordResult struct {
	Index        int     `json:"index"`
	Line         int     `json:"line"`
	StreamID     string  `json:"stream_id,omitempty"`
	Seq          *uint64 `json:"seq,omitempty,string"`
	State        string  `json:"state"`
	Profile      string  `json:"profile,omitempty"`
	ProfileState string  `json:"profile_state"`
}

// Report is the outcome of VerifyStream.
type Report struct {
	OK                 bool               `json:"ok"`
	Strict             bool               `json:"strict"`
	Records            int                `json:"records"`
	Errors             int                `json:"errors"`
	Restarts           int                `json:"restarts"`
	SignedRecords      int                `json:"signed_records"`
	SignaturesVerified int                `json:"signatures_verified"`
	UnsignedRecords    int                `json:"unsigned_records"`
	Notices            int                `json:"notices"`
	States             StateCounts        `json:"states"`
	ProfileStates      ProfileStateCounts `json:"profile_states"`
	Streams            []StreamSummary    `json:"streams"`
	Results            []RecordResult     `json:"results"`
	Findings           []Finding          `json:"findings"`
}

// Options control VerifyStream.
type Options struct {
	// PublicKey, when set, is used to verify every signature in the journal.
	PublicKey ed25519.PublicKey
	// RequireSignatures reports an unsigned record as signature_invalid.
	// It only has an effect together with PublicKey.
	RequireSignatures bool
	// Strict reports seq_gap, outside_scope and profile_unknown with
	// severity error, so that the journal verifies only when every record
	// is valid and every profile was checked.
	Strict bool
}

// Summary renders the report in one line, in the style of
// "OK: 4 record(s) in 1 stream(s), hash chain intact".
func (r Report) Summary() string {
	var b strings.Builder
	if r.OK {
		b.WriteString("OK")
	} else {
		b.WriteString("FAIL")
	}
	if r.Strict {
		b.WriteString(" (strict)")
	}
	fmt.Fprintf(&b, ": %d record(s) in %d stream(s)", r.Records, len(r.Streams))
	switch {
	case r.OK && r.States.Unknown == 0:
		b.WriteString(", hash chain intact")
	case r.OK:
		b.WriteString(", no invalid record")
	default:
		fmt.Fprintf(&b, ", %d error(s)", r.Errors)
	}
	if r.States.Unknown > 0 {
		fmt.Fprintf(&b, ", %d unknown", r.States.Unknown)
	}
	if r.States.OutsideScope > 0 {
		fmt.Fprintf(&b, ", %d outside scope", r.States.OutsideScope)
	}
	if r.Restarts > 0 {
		fmt.Fprintf(&b, ", %d restart(s)", r.Restarts)
	}
	if r.SignedRecords > 0 {
		fmt.Fprintf(&b, ", %d signed record(s)", r.SignedRecords)
		if r.SignaturesVerified > 0 || r.UnsignedRecords > 0 {
			fmt.Fprintf(&b, ", %d signature(s) verified", r.SignaturesVerified)
		}
	}
	return b.String()
}

// RecordCheck is the outcome of checking one record on its own, without the
// stream around it.
type RecordCheck struct {
	// Record is nil when the bytes are not a decodable record of this
	// contract (not JSON, not an object, unknown members, wrong types, or
	// outside the scope of this verifier).
	Record   *Record
	Findings []Finding
	// State is StateValid, StateInvalid or StateOutsideScope. StateUnknown
	// needs the stream and is only assigned by VerifyStream.
	State        string
	Profile      string
	ProfileState string

	seq     seqInfo
	restart bool // chain_restart is true and anchor_hash is present
}

// positioned reports whether the record has a place in a stream: a decoded
// record with a non-empty stream_id and a usable seq. Only positioned records
// take part in the chain checks.
func (c RecordCheck) positioned() bool {
	return c.Record != nil && c.Record.StreamID != "" && c.seq.ok
}

// CheckRecord checks one record on its own: scope, strict decoding,
// structural rules, both hashes and the profile. Chain checks need the
// stream and are done by VerifyStream. Findings have Index and Line zero.
func CheckRecord(raw []byte) RecordCheck {
	c := RecordCheck{ProfileState: ProfileNone}
	obj, err := decodeObject(raw)
	if err != nil {
		c.Findings = []Finding{schemaFinding([]string{err.Error()})}
		c.State = StateInvalid
		return c
	}
	if name, ok := foreignSchema(obj); ok {
		c.Findings = []Finding{{Class: ClassOutsideScope, Severity: SeverityNotice,
			Message: fmt.Sprintf("schema %q is not %s; the record is not checked and does not take part in any chain", name, Schema)}}
		c.State = StateOutsideScope
		return c
	}
	c.seq = parseSeq(obj)
	rec, err := decodeRecord(raw)
	if err != nil {
		problems := append([]string{err.Error()}, validateStructure(obj, nil, c.seq)...)
		c.Findings = []Finding{schemaFinding(problems)}
		c.State = StateInvalid
		return c
	}
	if c.seq.ok {
		rec.Seq = c.seq.value
	}
	c.Record = rec
	_, hasAnchor := obj["anchor_hash"]
	c.restart = rec.ChainRestart && hasAnchor

	problems := validateStructure(obj, rec, c.seq)
	h, herr := computeHashes(obj)
	if herr != nil {
		problems = append(problems, herr.Error())
	}
	if len(problems) > 0 {
		c.Findings = append(c.Findings, schemaFinding(problems))
	}
	if herr == nil {
		if h.ContentHash != rec.ContentHash {
			c.Findings = append(c.Findings, Finding{Class: ClassHashMismatch, Severity: SeverityError,
				Message: fmt.Sprintf("content_hash mismatch: recorded %s, computed %s", rec.ContentHash, h.ContentHash)})
		}
		if h.ChainHash != rec.ChainHash {
			c.Findings = append(c.Findings, Finding{Class: ClassHashMismatch, Severity: SeverityError,
				Message: fmt.Sprintf("chain_hash mismatch: recorded %s, computed %s", rec.ChainHash, h.ChainHash)})
		}
		if n := unsafeIntegers(rec.Payload); n > 0 {
			c.Findings = append(c.Findings, Finding{Class: ClassNumberPrecision, Severity: SeverityNotice,
				Message: fmt.Sprintf("payload contains %d integer(s) outside +/-2^53; JCS renders them as IEEE-754 doubles, transport such values as strings", n)})
		}
	}
	if c.seq.legacy && c.seq.ok {
		c.Findings = append(c.Findings, Finding{Class: ClassLegacyIntegerSeq, Severity: SeverityNotice,
			Message: fmt.Sprintf("seq %d is a JSON number; write it as the string \"%d\" (accepted during 0.x, schema_invalid from 1.0)", c.seq.value, c.seq.value)})
	}
	var pf *Finding
	c.Profile, c.ProfileState, pf = checkProfile(obj, rec)
	if pf != nil {
		c.Findings = append(c.Findings, *pf)
	}
	c.State = stateOf(c.Findings)
	return c
}

// VerifyRecord checks one record on its own: strict decoding, structural
// rules, both hashes and the profile. It returns the decoded record (nil when
// the bytes could not be decoded or are outside the scope of this verifier)
// and the findings; findings have Index and Line zero. CheckRecord returns
// the record's state as well.
func VerifyRecord(raw []byte) (*Record, []Finding) {
	c := CheckRecord(raw)
	return c.Record, c.Findings
}

func schemaFinding(problems []string) Finding {
	return Finding{Class: ClassSchemaInvalid, Severity: SeverityError, Message: strings.Join(problems, "; ")}
}

// stateOf derives a record state from its findings, by class: any error
// class makes the record invalid, otherwise seq_gap makes it unknown.
func stateOf(fs []Finding) string {
	state := StateValid
	for _, f := range fs {
		if errorClasses[f.Class] {
			return StateInvalid
		}
		if f.Class == ClassSeqGap {
			state = StateUnknown
		}
	}
	return state
}

// maxSafeInteger is the largest integer JCS (ES6 number semantics) keeps exact.
var maxSafeInteger = new(big.Int).Lsh(big.NewInt(1), 53)

// unsafeIntegers counts integer literals in raw JSON whose magnitude exceeds
// 2^53. Literals with a fraction or exponent are floats by intent and are
// not counted.
func unsafeIntegers(raw json.RawMessage) int {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	n := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return n
		}
		num, ok := tok.(json.Number)
		if !ok || strings.ContainsAny(string(num), ".eE") {
			continue
		}
		v, ok := new(big.Int).SetString(string(num), 10)
		if ok && v.CmpAbs(maxSafeInteger) > 0 {
			n++
		}
	}
}

type streamState struct {
	summary     StreamSummary
	seen        bool
	lastUnknown bool // the last positioned record of the stream is unknown
}

// VerifyStream reads a JSON Lines journal and checks every record against
// SPEC.md: scope, schema, content_hash, chain_hash, prev_hash link, seq,
// restarts, profiles and, when a key is given, signatures. Blank lines are
// skipped. Verification continues after an error so that a report lists
// every problem; chain state is advanced with the record's declared
// chain_hash.
func VerifyStream(rd io.Reader, opts Options) Report {
	rep := Report{OK: true, Strict: opts.Strict, Findings: []Finding{}, Streams: []StreamSummary{}, Results: []RecordResult{}}
	streams := map[string]*streamState{}
	br := bufio.NewReader(rd)
	line := 0
	index := -1
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) == 0 && err != nil {
			break
		}
		line++
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			if err != nil {
				break
			}
			continue
		}
		index++
		rep.Records++
		rep.verifyLine(streams, trimmed, index, line, opts)
		if err != nil {
			break
		}
	}
	ids := make([]string, 0, len(streams))
	for id := range streams {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rep.Streams = append(rep.Streams, streams[id].summary)
	}
	return rep
}

func (rep *Report) verifyLine(streams map[string]*streamState, raw []byte, index, line int, opts Options) {
	c := CheckRecord(raw)
	res := RecordResult{Index: index, Line: line, Profile: c.Profile, ProfileState: c.ProfileState}
	fs := c.Findings
	if c.Record != nil {
		res.StreamID = c.Record.StreamID
		if c.seq.ok {
			seq := c.seq.value
			res.Seq = &seq
		}
		if c.positioned() {
			st := streams[c.Record.StreamID]
			if st == nil {
				st = &streamState{summary: StreamSummary{StreamID: c.Record.StreamID, FirstSeq: c.seq.value}}
				streams[c.Record.StreamID] = st
			}
			fs = append(fs, checkChain(st, c)...)
		}
		fs = append(fs, checkSignature(opts, c.Record, rep)...)
	}
	if c.State == StateOutsideScope {
		res.State = StateOutsideScope
	} else {
		res.State = stateOf(fs)
	}
	if c.positioned() {
		streams[c.Record.StreamID].lastUnknown = res.State == StateUnknown
	}
	for i := range fs {
		fs[i].Index = index
		fs[i].Line = line
		fs[i].StreamID = res.StreamID
		fs[i].Seq = res.Seq
	}
	rep.add(opts.Strict, fs...)
	rep.Results = append(rep.Results, res)
	switch res.State {
	case StateValid:
		rep.States.Valid++
	case StateInvalid:
		rep.States.Invalid++
	case StateUnknown:
		rep.States.Unknown++
	case StateOutsideScope:
		rep.States.OutsideScope++
	}
	switch res.ProfileState {
	case ProfileNone:
		rep.ProfileStates.None++
	case StateValid:
		rep.ProfileStates.Valid++
	case StateInvalid:
		rep.ProfileStates.Invalid++
	case StateOutsideScope:
		rep.ProfileStates.OutsideScope++
	}
}

func (r *Report) add(strict bool, fs ...Finding) {
	for _, f := range fs {
		if strict && strictClasses[f.Class] {
			f.Severity = SeverityError
		}
		r.Findings = append(r.Findings, f)
		switch f.Severity {
		case SeverityError:
			r.Errors++
			r.OK = false
		case SeverityNotice:
			r.Notices++
		}
		if f.Class == ClassRestart {
			r.Restarts++
		}
	}
}

func chainFinding(class, severity, msg string) Finding {
	return Finding{Class: class, Severity: severity, Message: msg}
}

// checkChain judges a positioned record against the state of its stream
// (SPEC.md section 6.3, step 5). For a stream not seen before, the expected
// predecessor is the genesis hash and the expected seq is 0.
func checkChain(st *streamState, c RecordCheck) []Finding {
	rec := c.Record
	seq := c.seq.value
	var fs []Finding
	last := st.summary.LastChainHash
	if c.restart {
		msg := fmt.Sprintf("chain restart at seq %d, anchor %s", seq, rec.AnchorHash)
		if !st.seen && rec.AnchorHash != GenesisHash {
			msg += " (previous segment not in this journal)"
		}
		if st.seen && rec.AnchorHash == GenesisHash {
			msg += " (anchor unknown: genesis)"
		}
		fs = append(fs, chainFinding(ClassRestart, SeverityNotice, msg))
		st.summary.Restarts++
		if st.seen && rec.AnchorHash != GenesisHash && rec.AnchorHash != last {
			fs = append(fs, chainFinding(ClassChainBreak, SeverityError,
				fmt.Sprintf("anchor_hash %s does not match the last chain_hash %s of the previous segment", rec.AnchorHash, last)))
		} else if st.seen && st.lastUnknown && rec.AnchorHash == last {
			fs = append(fs, chainFinding(ClassAfterUnknown, SeverityNotice, afterUnknownMessage))
		}
	} else {
		expectPrev := GenesisHash
		if st.seen {
			expectPrev = last
		}
		linked := rec.PrevHash == expectPrev
		// pos compares seq with the expected seq without overflow:
		// -1 behind (repeated or backwards), 0 next, +1 ahead.
		pos := 0
		switch {
		case !st.seen && seq > 0:
			pos = 1
		case st.seen && seq <= st.summary.LastSeq:
			pos = -1
		case st.seen && seq-st.summary.LastSeq > 1:
			pos = 1
		}
		switch {
		case linked && pos == 0:
			if st.seen && st.lastUnknown {
				fs = append(fs, chainFinding(ClassAfterUnknown, SeverityNotice, afterUnknownMessage))
			}
		case linked && pos > 0 && !st.seen:
			fs = append(fs, chainFinding(ClassSeqMismatch, SeverityError,
				fmt.Sprintf("first record of stream links to genesis but has seq %d, expected 0", seq)))
		case linked && pos > 0:
			fs = append(fs, chainFinding(ClassSeqMismatch, SeverityError,
				fmt.Sprintf("seq %d, expected %d: prev_hash links to the record with seq %d, so no record can be missing in between", seq, st.summary.LastSeq+1, st.summary.LastSeq)))
		case linked:
			fs = append(fs, chainFinding(ClassSeqMismatch, SeverityError, seqBehindMessage(seq, st.summary.LastSeq)))
		case pos == 0 && !st.seen:
			fs = append(fs, chainFinding(ClassChainBreak, SeverityError,
				fmt.Sprintf("first record of stream has seq 0 but prev_hash %s instead of genesis and is not marked chain_restart", rec.PrevHash)))
		case pos == 0:
			fs = append(fs, chainFinding(ClassChainBreak, SeverityError,
				fmt.Sprintf("prev_hash %s does not match previous chain_hash %s", rec.PrevHash, last)))
		case pos > 0 && !st.seen:
			fs = append(fs, chainFinding(ClassSeqGap, SeverityNotice,
				fmt.Sprintf("first record of stream has seq %d and prev_hash %s: its predecessor is not in this journal", seq, rec.PrevHash)))
		case pos > 0:
			fs = append(fs, chainFinding(ClassSeqGap, SeverityNotice,
				fmt.Sprintf("seq %d after seq %d, and prev_hash %s does not link to the last checked record: its predecessor is not in this journal", seq, st.summary.LastSeq, rec.PrevHash)))
		default:
			fs = append(fs,
				chainFinding(ClassChainBreak, SeverityError,
					fmt.Sprintf("prev_hash %s does not match previous chain_hash %s", rec.PrevHash, last)),
				chainFinding(ClassSeqMismatch, SeverityError, seqBehindMessage(seq, st.summary.LastSeq)))
		}
	}
	st.seen = true
	st.summary.Records++
	st.summary.LastSeq = seq
	st.summary.LastChainHash = rec.ChainHash
	return fs
}

const afterUnknownMessage = "links to a record in state unknown; this record is valid relative to that record, not to the start of the stream"

func seqBehindMessage(seq, last uint64) string {
	if seq == last {
		return fmt.Sprintf("seq %d repeats the seq of the previous record", seq)
	}
	return fmt.Sprintf("seq %d goes backwards (previous seq %d)", seq, last)
}

func checkSignature(opts Options, rec *Record, rep *Report) []Finding {
	if rec.Signature == nil {
		if opts.PublicKey != nil {
			rep.UnsignedRecords++
			if opts.RequireSignatures {
				return []Finding{{Class: ClassSignatureInvalid, Severity: SeverityError, Message: "record is not signed"}}
			}
		}
		return nil
	}
	rep.SignedRecords++
	if opts.PublicKey == nil {
		return nil
	}
	if err := VerifySignature(opts.PublicKey, rec.ChainHash, rec.Signature); err != nil {
		return []Finding{{Class: ClassSignatureInvalid, Severity: SeverityError, Message: err.Error()}}
	}
	rep.SignaturesVerified++
	return nil
}
