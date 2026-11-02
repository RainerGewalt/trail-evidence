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
const (
	ClassHashMismatch     = "hash_mismatch"
	ClassChainBreak       = "chain_break"
	ClassSeqGap           = "seq_gap"
	ClassRestart          = "restart"
	ClassSignatureInvalid = "signature_invalid"
	ClassSchemaInvalid    = "schema_invalid"
	// ClassNumberPrecision is a notice: payload carries an integer outside
	// +/-2^53, which JCS (ES6 number semantics) cannot represent exactly.
	ClassNumberPrecision = "number_precision"
)

// Finding severities. ClassRestart and ClassNumberPrecision are notices;
// everything else is an error that makes the report fail.
const (
	SeverityError  = "error"
	SeverityNotice = "notice"
)

// Finding is one observation about one record.
type Finding struct {
	Index    int     `json:"index"`
	Line     int     `json:"line"`
	StreamID string  `json:"stream_id,omitempty"`
	Seq      *uint64 `json:"seq,omitempty"`
	Class    string  `json:"class"`
	Severity string  `json:"severity"`
	Message  string  `json:"message"`
}

// StreamSummary describes one hash chain seen while verifying a journal.
type StreamSummary struct {
	StreamID      string `json:"stream_id"`
	Records       int    `json:"records"`
	FirstSeq      uint64 `json:"first_seq"`
	LastSeq       uint64 `json:"last_seq"`
	LastChainHash string `json:"last_chain_hash"`
	Restarts      int    `json:"restarts"`
}

// Report is the outcome of VerifyStream.
type Report struct {
	OK                 bool            `json:"ok"`
	Records            int             `json:"records"`
	Errors             int             `json:"errors"`
	Restarts           int             `json:"restarts"`
	SignedRecords      int             `json:"signed_records"`
	SignaturesVerified int             `json:"signatures_verified"`
	UnsignedRecords    int             `json:"unsigned_records"`
	Notices            int             `json:"notices"`
	Streams            []StreamSummary `json:"streams"`
	Findings           []Finding       `json:"findings"`
}

// Options control VerifyStream.
type Options struct {
	// PublicKey, when set, is used to verify every signature in the journal.
	PublicKey ed25519.PublicKey
	// RequireSignatures reports an unsigned record as signature_invalid.
	// It only has an effect together with PublicKey.
	RequireSignatures bool
}

// Summary renders the report in one line, in the style of
// "OK: 4 record(s) in 1 stream(s), hash chain intact".
func (r Report) Summary() string {
	var b strings.Builder
	if r.OK {
		b.WriteString("OK: ")
	} else {
		b.WriteString("FAIL: ")
	}
	fmt.Fprintf(&b, "%d record(s) in %d stream(s)", r.Records, len(r.Streams))
	if r.OK {
		b.WriteString(", hash chain intact")
	} else {
		fmt.Fprintf(&b, ", %d error(s)", r.Errors)
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

// VerifyRecord checks one record on its own: strict decoding, structural
// rules and both hashes. Chain checks need the stream and are done by
// VerifyStream. The returned Record is nil when the bytes could not be
// decoded; findings have Index and Line zero.
func VerifyRecord(raw []byte) (*Record, []Finding) {
	var findings []Finding
	obj, err := decodeObject(raw)
	if err != nil {
		return nil, []Finding{{Class: ClassSchemaInvalid, Severity: SeverityError, Message: err.Error()}}
	}
	rec, err := decodeRecord(raw)
	if err != nil {
		findings = append(findings, Finding{Class: ClassSchemaInvalid, Severity: SeverityError, Message: err.Error()})
		for _, p := range validateStructure(obj, nil) {
			findings = append(findings, Finding{Class: ClassSchemaInvalid, Severity: SeverityError, Message: p})
		}
		return nil, findings
	}
	for _, p := range validateStructure(obj, rec) {
		findings = append(findings, Finding{Class: ClassSchemaInvalid, Severity: SeverityError, Message: p})
	}
	h, err := ComputeHashes(raw)
	if err != nil {
		findings = append(findings, Finding{Class: ClassSchemaInvalid, Severity: SeverityError, Message: err.Error()})
		return rec, findings
	}
	if h.ContentHash != rec.ContentHash {
		findings = append(findings, Finding{Class: ClassHashMismatch, Severity: SeverityError,
			Message: fmt.Sprintf("content_hash mismatch: recorded %s, computed %s", rec.ContentHash, h.ContentHash)})
	}
	if h.ChainHash != rec.ChainHash {
		findings = append(findings, Finding{Class: ClassHashMismatch, Severity: SeverityError,
			Message: fmt.Sprintf("chain_hash mismatch: recorded %s, computed %s", rec.ChainHash, h.ChainHash)})
	}
	if n := unsafeIntegers(rec.Payload); n > 0 {
		findings = append(findings, Finding{Class: ClassNumberPrecision, Severity: SeverityNotice,
			Message: fmt.Sprintf("payload contains %d integer(s) outside +/-2^53; JCS renders them as IEEE-754 doubles, transport such values as strings", n)})
	}
	return rec, findings
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
	summary StreamSummary
	seen    bool
}

// VerifyStream reads a JSON Lines journal and checks every record against
// SPEC.md: schema, content_hash, chain_hash, prev_hash link, seq continuity,
// restarts and, when a key is given, signatures. Blank lines are skipped.
// Verification continues after an error so that a report lists every problem;
// chain state is advanced with the record's declared chain_hash.
func VerifyStream(rd io.Reader, opts Options) Report {
	rep := Report{OK: true, Findings: []Finding{}, Streams: []StreamSummary{}}
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
		rec, findings := VerifyRecord(trimmed)
		for i := range findings {
			findings[i].Index = index
			findings[i].Line = line
			if rec != nil {
				findings[i].StreamID = rec.StreamID
				seq := rec.Seq
				findings[i].Seq = &seq
			}
		}
		rep.add(findings...)
		if rec == nil {
			if err != nil {
				break
			}
			continue
		}
		rep.add(checkChain(streams, rec, index, line)...)
		rep.add(checkSignature(opts, rec, index, line, &rep)...)
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

func (r *Report) add(fs ...Finding) {
	for _, f := range fs {
		r.Findings = append(r.Findings, f)
		switch f.Severity {
		case SeverityError:
			r.Errors++
			r.OK = false
		case SeverityNotice:
			r.Notices++
			if f.Class == ClassRestart {
				r.Restarts++
			}
		}
	}
}

func finding(rec *Record, index, line int, class, severity, msg string) Finding {
	seq := rec.Seq
	return Finding{Index: index, Line: line, StreamID: rec.StreamID, Seq: &seq, Class: class, Severity: severity, Message: msg}
}

func checkChain(streams map[string]*streamState, rec *Record, index, line int) []Finding {
	var fs []Finding
	st := streams[rec.StreamID]
	if st == nil {
		st = &streamState{summary: StreamSummary{StreamID: rec.StreamID, FirstSeq: rec.Seq}}
		streams[rec.StreamID] = st
	}
	switch {
	case rec.ChainRestart:
		msg := fmt.Sprintf("chain restart at seq %d, anchor %s", rec.Seq, rec.AnchorHash)
		if !st.seen && rec.AnchorHash != GenesisHash {
			msg += " (previous segment not in this journal)"
		}
		if st.seen && rec.AnchorHash == GenesisHash {
			msg += " (anchor unknown: genesis)"
		}
		fs = append(fs, finding(rec, index, line, ClassRestart, SeverityNotice, msg))
		st.summary.Restarts++
		if st.seen && rec.AnchorHash != GenesisHash && rec.AnchorHash != st.summary.LastChainHash {
			fs = append(fs, finding(rec, index, line, ClassChainBreak, SeverityError,
				fmt.Sprintf("anchor_hash %s does not match the last chain_hash %s of the previous segment", rec.AnchorHash, st.summary.LastChainHash)))
		}
	case !st.seen:
		if rec.PrevHash != GenesisHash {
			fs = append(fs, finding(rec, index, line, ClassChainBreak, SeverityError,
				fmt.Sprintf("first record of stream has prev_hash %s instead of genesis and is not marked chain_restart", rec.PrevHash)))
		} else if rec.Seq != 0 {
			fs = append(fs, finding(rec, index, line, ClassSeqGap, SeverityError,
				fmt.Sprintf("first record of stream has seq %d, expected 0", rec.Seq)))
		}
	default:
		if rec.PrevHash != st.summary.LastChainHash {
			fs = append(fs, finding(rec, index, line, ClassChainBreak, SeverityError,
				fmt.Sprintf("prev_hash %s does not match previous chain_hash %s", rec.PrevHash, st.summary.LastChainHash)))
		}
		if rec.Seq != st.summary.LastSeq+1 {
			fs = append(fs, finding(rec, index, line, ClassSeqGap, SeverityError,
				fmt.Sprintf("seq %d, expected %d", rec.Seq, st.summary.LastSeq+1)))
		}
	}
	st.seen = true
	st.summary.Records++
	st.summary.LastSeq = rec.Seq
	st.summary.LastChainHash = rec.ChainHash
	return fs
}

func checkSignature(opts Options, rec *Record, index, line int, rep *Report) []Finding {
	if rec.Signature == nil {
		if opts.PublicKey != nil {
			rep.UnsignedRecords++
			if opts.RequireSignatures {
				return []Finding{finding(rec, index, line, ClassSignatureInvalid, SeverityError, "record is not signed")}
			}
		}
		return nil
	}
	rep.SignedRecords++
	if opts.PublicKey == nil {
		return nil
	}
	if err := VerifySignature(opts.PublicKey, rec.ChainHash, rec.Signature); err != nil {
		return []Finding{finding(rec, index, line, ClassSignatureInvalid, SeverityError, err.Error())}
	}
	rep.SignaturesVerified++
	return nil
}
