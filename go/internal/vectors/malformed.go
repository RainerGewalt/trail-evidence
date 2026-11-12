package vectors

import (
	"encoding/json"
	"strings"

	"github.com/RainerGewalt/trail-evidence/go/evidence"
)

// The fixtures in this file pin the reading rules of SPEC.md section 2 (a
// record line is one JSON object: valid UTF-8, unique member names, no
// unpaired surrogate, at most evidence.MaxDepth levels, nothing after the
// object) and the documented limits of section 6.6. Each one is a case on
// which the Go, Python and JavaScript verifiers once reached different
// verdicts, or on which a verdict is easy to misread. A line that breaks a
// reading rule is schema_invalid at step 1 of section 6.3 and has no
// position, so the next record of its stream is judged against the last
// record that had one.

// coreNames lists the members chain_hash covers (SPEC.md section 4.1).
var coreNames = []string{
	"schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
	"time", "actor", "policy", "content_hash", "chain_restart", "anchor_hash",
	"profile",
}

// sealUnchecked seals r like evidence.Seal but hashes payload and core with
// the canonicaliser directly, without the reading rules. It is only for
// fixtures whose lines must break those rules (a payload nested deeper than
// evidence.MaxDepth), so that the record is correctly sealed and the reading
// rule is the only thing wrong with it.
func sealUnchecked(r *evidence.Record, prev string) {
	payload := r.Payload
	r.Payload = json.RawMessage("null")
	seal(r, prev)
	contentHash, err := evidence.HashJSON(payload)
	if err != nil {
		panic(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encode(r)), &obj); err != nil {
		panic(err)
	}
	core := map[string]json.RawMessage{}
	for _, k := range coreNames {
		if v, ok := obj[k]; ok {
			core[k] = v
		}
	}
	core["content_hash"] = json.RawMessage(`"` + contentHash + `"`)
	coreJSON, err := json.Marshal(core)
	if err != nil {
		panic(err)
	}
	chainHash, err := evidence.HashJSON(coreJSON)
	if err != nil {
		panic(err)
	}
	r.Payload = payload
	r.ContentHash = contentHash
	r.ChainHash = chainHash
}

// nestedArrays returns a JSON array nested n levels deep around 0.
func nestedArrays(n int) string {
	return strings.Repeat("[", n) + "0" + strings.Repeat("]", n)
}

// afterRejectedFirst is the outcome of a transfer-worker journal whose first
// line breaks a reading rule: record 0 is schema_invalid without a position,
// record 1 links to a record the chain does not have (seq_gap, unknown),
// record 2 links correctly to it (after_unknown), record 3 is valid.
func afterRejectedFirst(file, desc string, first string) StreamCase {
	t := lines(transferWorker()...)
	t[0] = first
	return StreamCase{File: file, Description: desc,
		OK: false, Records: 4, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassSchemaInvalid}, {Index: 1, Class: evidence.ClassSeqGap}, {Index: 2, Class: evidence.ClassAfterUnknown}},
		States: states("iuvv"), ProfileStates: none(4), Lines: t}
}

func buildReadingRuleStreams() []StreamCase {
	var cases []StreamCase
	tw := lines(transferWorker()...)
	ev := "test.reading.rule"

	// Duplicate member names. A parser that keeps the last of two members
	// reads the original record, so the hashes match; one that keeps the
	// first reads the forged value.
	cases = append(cases, afterRejectedFirst("dup-payload-member.jsonl",
		"Record 0 carries the member status twice in its payload, \"failed\" before the original \"ok\". A parser that keeps the last value sees the sealed record and matching hashes, one that keeps the first sees a failed job. Duplicate member names are not allowed at any depth (SPEC.md section 2): record 0 is schema_invalid and has no position, so record 1 links to a predecessor the chain does not have (seq_gap, unknown) and record 2 is valid relative to it (after_unknown).",
		replaceOnce(tw[0], `"status":"ok"`, `"status":"failed","status":"ok"`)))
	cases = append(cases, afterRejectedFirst("dup-top-payload.jsonl",
		"Record 0 has a second, forged payload member before the sealed one. schema_invalid (duplicate member name), no position; the rest as in dup-payload-member.jsonl.",
		replaceOnce(tw[0], `"job_id":"job-1001",`, `"job_id":"job-1001","payload":{"status":"forged"},`)))
	cases = append(cases, afterRejectedFirst("dup-top-seq.jsonl",
		"Record 0 carries seq twice, \"5\" before the sealed \"0\". schema_invalid (duplicate member name), no position; the rest as in dup-payload-member.jsonl.",
		replaceOnce(tw[0], `"seq":"0"`, `"seq":"5","seq":"0"`)))
	cases = append(cases, afterRejectedFirst("dup-escaped-name.jsonl",
		"Record 0 carries \"st\\u0061tus\":\"failed\" before \"status\":\"ok\". Names are compared after their escapes are decoded, so both are the member status: schema_invalid (duplicate member name), no position; the rest as in dup-payload-member.jsonl.",
		replaceOnce(tw[0], `"status":"ok"`, `"st\u0061tus":"failed","status":"ok"`)))

	// Duplicates below the top level: in an object inside an array of the
	// payload, in a typed sub-object of the core and in context, which is
	// never hashed.
	dn := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"items":[{"a":1}]}`, `{"n":2}`, `{"n":3}`, `{"n":4}`)
	dn[3].Context = json.RawMessage(`{"a":1}`)
	dl := lines(dn...)
	dl[1] = replaceOnce(dl[1], `{"a":1}`, `{"a":2,"a":1}`)
	dl[2] = replaceOnce(dl[2], `"producer":{`, `"producer":{"id":"forged",`)
	dl[3] = replaceOnce(dl[3], `"context":{"a":1}`, `"context":{"a":0,"a":1}`)
	cases = append(cases, StreamCase{File: "dup-nested-member.jsonl",
		Description: "Duplicate member names below the top level: record 1 in an object inside an array of its payload, record 2 in producer, record 3 in context, which is not hashed. Each is schema_invalid and has no position. Record 4 links to record 3, which the chain therefore does not have: seq_gap, unknown.",
		OK:          false, Records: 5, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}, {Index: 4, Class: evidence.ClassSeqGap}},
		States: states("viiiu"), ProfileStates: none(5), Lines: dl})

	// Data after the object on the same line.
	tl := lines(transferWorker()...)
	cases = append(cases, StreamCase{File: "trailing-data.jsonl",
		Description: "Nothing but JSON white space may follow the object on a line. Line 1 ends in \" x\" (not JSON), line 2 holds two records separated by a carriage return, which is white space and not a line break, line 3 ends in \" {}\". Each line is one schema_invalid record without a position.",
		OK:          false, Records: 3, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassSchemaInvalid}, {Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}},
		States: states("iii"), ProfileStates: none(3), Lines: []string{tl[0] + " x", tl[1] + "\r" + tl[2], tl[3] + " {}"}})

	// Invalid UTF-8. Record 0 was sealed with U+FFFD in a payload string;
	// in the file the three bytes of U+FFFD were replaced by the single byte
	// 0xFF. A reader that decodes with replacement sees the sealed record.
	u := chain(evidence.ProducerOther, "p", "s", ev, `{"note":"x`+"\uFFFD"+`y"}`, `{"n":1}`)
	ul := lines(u...)
	ul[0] = replaceOnce(ul[0], "\uFFFD", "\xff")
	cases = append(cases, StreamCase{File: "invalid-utf8-in-string.jsonl",
		Description: "Record 0 was sealed with U+FFFD inside a payload string; in the file the three bytes of U+FFFD were replaced by the byte 0xFF, which is not UTF-8. A reader that decodes with replacement characters sees the sealed record and matching hashes. A line must be valid UTF-8: record 0 is schema_invalid, no position, record 1 is unknown (seq_gap).",
		OK:          false, Records: 2, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassSchemaInvalid}, {Index: 1, Class: evidence.ClassSeqGap}},
		States: states("iu"), ProfileStates: none(2), Lines: ul})
	ib := lines(transferWorker()...)
	cases = append(cases, StreamCase{File: "invalid-utf8-line.jsonl",
		Description: "Line 2 is not UTF-8 at all (bytes 0xB1 0x8F 0xFF and text): schema_invalid, no position. The records around it are chained and valid.",
		OK:          false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}}, States: states("viv"), ProfileStates: none(3),
		Lines: []string{ib[0], "\xb1\x8f\xff not utf-8", ib[1]}})

	// Nesting depth. Every record is sealed correctly; the record object is
	// level 1, so a payload of n nested arrays makes the record n+1 deep.
	deep := []*evidence.Record{}
	r0 := base(evidence.ProducerOther, "p", "s", 0, ev, "2026-11-02T14:00:00.000Z", nestedArrays(evidence.MaxDepth-1))
	seal(&r0, evidence.GenesisHash)
	r1 := base(evidence.ProducerOther, "p", "s", 1, ev, "2026-11-02T14:00:01.000Z", nestedArrays(evidence.MaxDepth))
	sealUnchecked(&r1, r0.ChainHash)
	r2 := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T14:00:02.000Z", nestedArrays(2999))
	sealUnchecked(&r2, r1.ChainHash)
	deep = append(deep, &r0, &r1, &r2)
	cases = append(cases, StreamCase{File: "nesting-depth.jsonl",
		Description: "Record 0 is nested exactly 64 levels deep (the record object and 63 arrays in its payload) and valid. Record 1 is 65 levels deep and record 2 3000 levels deep; both are correctly sealed, but a line may nest at most 64 levels: schema_invalid, no position.",
		OK:          false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}},
		States: states("vii"), ProfileStates: none(3), Lines: lines(deep...)})

	// Unpaired surrogates, escaped (raw ones are not UTF-8).
	ls := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"s":"ok"}`, `{"n":2}`, `{"s":"ok"}`)
	ls[2].Context = json.RawMessage(`{"a":"b"}`)
	ll := lines(ls...)
	ll[1] = replaceOnce(ll[1], `"s":"ok"`, `"s":"ok\ud800"`)
	ll[2] = replaceOnce(ll[2], `"context":{"a":"b"}`, `"context":{"a":"\udc00"}`)
	ll[3] = replaceOnce(ll[3], `"s":"ok"`, `"s":"\ud800\u0041"`)
	cases = append(cases, StreamCase{File: "unpaired-surrogate.jsonl",
		Description: "Strings with an unpaired surrogate escape: record 1 a high surrogate at the end of a payload string, record 2 a low surrogate in context, which is not hashed, record 3 a high surrogate followed by \\u0041. Such strings have no defined UTF-8 form: schema_invalid, no position.",
		OK:          false, Records: 4, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}},
		States: states("viii"), ProfileStates: none(4), Lines: ll})

	// White space: only JSON white space (space, tab, CR) may surround the
	// object, and only a line of JSON white space is blank.
	ws := lines(transferWorker()...)
	cases = append(cases, StreamCase{File: "json-whitespace.jsonl",
		Description: "Only space, tab and carriage return are white space around a record, and only a line of them is blank. Record 0 is surrounded by a tab and spaces and valid. Record 1 starts with U+00A0, record 2 is a line with only U+3000, record 3 a line with only U+001C, record 4 a line with only a vertical tab and a form feed: schema_invalid each, no position. Record 5 links to record 1 (seq_gap, unknown), record 6 is valid after it (after_unknown). The blank lines between them are skipped.",
		OK:          false, Records: 7, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}, {Index: 4, Class: evidence.ClassSchemaInvalid}, {Index: 5, Class: evidence.ClassSeqGap}, {Index: 6, Class: evidence.ClassAfterUnknown}},
		States: states("viiiiuv"), ProfileStates: none(7),
		Lines: []string{"\t" + ws[0] + "  \r", " \t", "\u00a0" + ws[1], "\u3000", "\x1c", "\v\f", "", ws[2], ws[3]}})
	return cases
}

// buildLimitStreams pins what a passing verdict does not cover (SPEC.md
// section 6.6). The verdicts are valid on purpose.
func buildLimitStreams() []StreamCase {
	var cases []StreamCase
	t := transferWorker()
	cases = append(cases, StreamCase{File: "tail-truncated.jsonl",
		Description: "The first two of the four records of examples/transfer-worker.jsonl: the last two were cut off. The remaining records still link to each other, so the journal is valid. Nothing in a journal shows that records are missing at its end (SPEC.md section 6.6).",
		OK:          true, Records: 2, Findings: []ExpectedFinding{}, States: states("vv"), ProfileStates: none(2), Lines: lines(t[0], t[1])})

	u := transferWorker()
	u[0].JobID = "job-9999"
	u[1].Context = json.RawMessage(`{"note":"added after sealing"}`)
	u[2].Redaction = &evidence.Redaction{Fields: []string{"/source"}, Method: "hmac-sha256"}
	u[3].CorrelationID = "corr-added-later"
	cases = append(cases, StreamCase{File: "unhashed-members-changed.jsonl",
		Description: "examples/transfer-worker.jsonl after sealing: job_id of record 0 changed, context added to record 1, a redaction member added to record 2 that claims a payload member was masked, correlation_id added to record 3. None of these members is hashed (SPEC.md section 4.1), so the journal is valid (section 6.6).",
		OK:          true, Records: 4, Findings: []ExpectedFinding{}, States: states("vvvv"), ProfileStates: none(4), Lines: lines(u...)})

	// The records of signed.jsonl without their signatures. A signature is not
	// part of the core, so the chain is the same.
	sl := lines(chain(evidence.ProducerOther, "p", "s", "test.stream.step", `{"n":0}`, `{"n":1}`, `{"n":2}`)...)
	cases = append(cases, StreamCase{File: "signatures-stripped.jsonl", PublicKey: "../keys/test-ed25519.pub",
		Description: "The records of signed.jsonl with every signature removed, verified with the test public key but without --require-signatures: valid, because a key alone checks only the signatures that are present (SPEC.md section 6.6).",
		OK:          true, Records: 3, Findings: []ExpectedFinding{}, States: states("vvv"), ProfileStates: none(3), Lines: sl})
	cases = append(cases, StreamCase{File: "signatures-stripped.jsonl", PublicKey: "../keys/test-ed25519.pub", RequireSignatures: true,
		Description: "The same journal with --require-signatures: every record is signature_invalid.",
		OK:          false, Records: 3, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassSignatureInvalid}, {Index: 1, Class: evidence.ClassSignatureInvalid}, {Index: 2, Class: evidence.ClassSignatureInvalid}},
		States: states("iii"), ProfileStates: none(3), Lines: sl})
	return cases
}

// buildEmptyStreams: a journal without a record shows nothing, so it never
// passes, not even with --allow-incomplete (SPEC.md section 6.4).
func buildEmptyStreams() []StreamCase {
	return []StreamCase{
		{File: "empty.jsonl", Description: "An empty file (0 bytes). A journal without a record shows nothing about any record, so its verdict is incomplete, which fails (exit code 3).",
			OK: false, Records: 0, Findings: []ExpectedFinding{}, States: []string{}, ProfileStates: []string{}},
		{File: "empty.jsonl", AllowIncomplete: true, Description: "The same file with --allow-incomplete: a journal without a record still fails (exit code 3); allow incomplete accepts journals with unknown or outside_scope records, not journals without any.",
			OK: false, Records: 0, Findings: []ExpectedFinding{}, States: []string{}, ProfileStates: []string{}},
		{File: "blank-lines.jsonl", Description: "Only blank lines (empty, a space, a tab with a carriage return): no record, verdict incomplete, exit code 3.",
			OK: false, Records: 0, Findings: []ExpectedFinding{}, States: []string{}, ProfileStates: []string{}, Lines: []string{"", " ", "\t\r"}},
	}
}
