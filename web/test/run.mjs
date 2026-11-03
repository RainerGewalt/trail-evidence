#!/usr/bin/env node
// Tests for web/verify.js against the shared test data. Run with Node 18+:
//
//   node web/test/run.mjs                 run all checks
//   node web/test/run.mjs report <file.jsonl> [--pubkey <hex|file>] [--require-signatures]
//                                         print the JSON report (exit 0 ok, 1 fail, 2 usage)
//
// The report mode is what scripts/crosscheck.sh uses to compare this
// implementation with Go and Python.

import { createRequire } from "node:module";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const major = Number(process.versions.node.split(".")[0]);
if (major < 18) {
  console.error(`web/test/run.mjs needs Node 18 or newer, found ${process.versions.node}`);
  process.exit(2);
}

const require = createRequire(import.meta.url);
const te = require("../verify.js");

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const VECTORS = path.join(ROOT, "testdata", "vectors.json");
const STREAMS = path.join(ROOT, "testdata", "streams");
const EXAMPLES = path.join(ROOT, "examples");
const TAMPERED = path.join(EXAMPLES, "tampered");
const WEB_EXAMPLES = path.join(ROOT, "web", "examples");

const read = (p) => readFileSync(p, "utf8");

// ---------------------------------------------------------------- report mode

function loadKey(spec) {
  try {
    return te.parsePublicKey(spec);
  } catch (err) {
    // not an inline key: treat as a file
  }
  return te.parsePublicKey(read(spec));
}

async function reportMode(args) {
  let file = null;
  let pubkey = null;
  let requireSignatures = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--pubkey") {
      pubkey = args[++i];
    } else if (a.startsWith("--pubkey=")) {
      pubkey = a.slice("--pubkey=".length);
    } else if (a === "--require-signatures") {
      requireSignatures = true;
    } else if (a.startsWith("-")) {
      console.error(`unknown flag ${a}`);
      return 2;
    } else if (file === null) {
      file = a;
    } else {
      console.error("usage: run.mjs report <file.jsonl> [--pubkey <hex|file>] [--require-signatures]");
      return 2;
    }
  }
  if (file === null) {
    console.error("usage: run.mjs report <file.jsonl> [--pubkey <hex|file>] [--require-signatures]");
    return 2;
  }
  if (requireSignatures && !pubkey) {
    console.error("--require-signatures needs --pubkey");
    return 2;
  }
  let publicKey = null;
  if (pubkey) {
    try {
      publicKey = loadKey(pubkey);
    } catch (err) {
      console.error(err.message);
      return 2;
    }
  }
  const report = await te.verifyStream(read(file), { publicKey, requireSignatures });
  if (report.signature_check === "unavailable") {
    console.error("Ed25519 is not available in this Node runtime; signatures were not checked");
    return 2;
  }
  process.stdout.write(JSON.stringify(te.reportToJSON(report), null, 2) + "\n");
  return report.ok ? 0 : 1;
}

// ---------------------------------------------------------------- test helpers

let failures = 0;
let checks = 0;

function check(cond, message) {
  checks++;
  if (!cond) {
    failures++;
    console.error("  FAIL: " + message);
  }
}

function eq(got, want, message) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  check(g === w, `${message}\n        got:  ${g}\n        want: ${w}`);
}

function section(name) {
  console.log("== " + name);
}

// Raw record texts straight from vectors.json, so that number literals such
// as 9007199254740993 reach verifyRecord unrounded (JSON.parse would round
// them before re-serialisation).
function rawRecords(vectorsText) {
  const top = te.json.memberSpans(vectorsText);
  const out = new Map();
  for (const item of te.json.arrayItems(top.get("vectors"))) {
    const spans = te.json.memberSpans(item);
    out.set(JSON.parse(spans.get("name")), spans.get("record"));
  }
  return out;
}

// ---------------------------------------------------------------- tests

async function testJcs() {
  section("JCS (RFC 8785) examples");
  // RFC 8785 section 3.2.3: member sorting by UTF-16 code units.
  const sorted = te.canonicalize(JSON.parse('{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}'));
  eq(sorted, '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}', "RFC 8785 3.2.3 key order and escaping");
  // RFC 8785 section 3.2.3 nested example.
  const nested = te.canonicalize(JSON.parse('{"1":{"f":{"f":"hi","F":5},"\\n":56.0},"10":{},"":"empty","a":{},"111":[{"e":"yes","E":"no"}],"A":{}}'));
  eq(nested, '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}', "RFC 8785 nested example");
  // ES6 number formatting (RFC 8785 appendix B flavoured).
  const numbers = [
    ["1.0", "1"], ["1e21", "1e+21"], ["1E+21", "1e+21"], ["0.000001", "0.000001"], ["1e-7", "1e-7"],
    ["-0", "0"], ["-0.0", "0"], ["100.0", "100"], ["5e-324", "5e-324"], ["1.5e300", "1.5e+300"],
    ["333333333.33333329", "333333333.3333333"], ["9007199254740993", "9007199254740992"],
    ["123456789012345680000", "123456789012345680000"], ["0.1", "0.1"], ["-42.25", "-42.25"],
    ["4.50", "4.5"], ["1e400", null],
  ];
  for (const [lit, want] of numbers) {
    const v = JSON.parse(lit);
    if (want === null) {
      let threw = false;
      try {
        te.formatNumber(v);
      } catch (err) {
        threw = true;
      }
      check(threw, `formatNumber(${lit}) must reject a non-finite value`);
    } else {
      eq(te.formatNumber(v), want, `formatNumber(${lit})`);
    }
  }
  eq(te.escapeString("tab\tnl\ncr\rbs\bff\fnul\u0000unit\u001fdel\u007fq\"bs\\slash/"), '"tab\\tnl\\ncr\\rbs\\bff\\fnul\\u0000unit\\u001fdel\u007fq\\"bs\\\\slash/"', "minimal string escaping");
  eq(te.canonicalize({ b: [true, false, null, "x"], a: {} }), '{"a":{},"b":[true,false,null,"x"]}', "literals and containers");
  // Number literal scanning for the number_precision notice.
  eq(te.json.unsafeIntegers('{"a":9007199254740993,"b":"9007199254740993","c":9007199254740992,"d":-9007199254740993,"e":1e300,"f":[9007199254740993.0]}'), 2, "unsafeIntegers counts integer literals beyond 2^53 only");
}

async function testVectors() {
  section("testdata/vectors.json");
  const text = read(VECTORS);
  const data = JSON.parse(text);
  const raws = rawRecords(text);
  check(data.vectors.length >= 8, "at least eight vectors");
  const byName = {};
  for (const v of data.vectors) {
    const h = await te.computeHashes(v.record);
    eq(h.payload_jcs, v.expected_payload_jcs, `${v.name}: payload JCS`);
    eq(h.content_hash, v.expected_content_hash, `${v.name}: content_hash`);
    eq(h.core_jcs, v.expected_core_jcs, `${v.name}: core JCS`);
    eq(h.chain_hash, v.expected_chain_hash, `${v.name}: chain_hash`);
    const raw = raws.get(v.name);
    check(typeof raw === "string", `${v.name}: raw record text found`);
    const { record, findings } = await te.verifyRecord(raw);
    check(record !== null, `${v.name}: record decodes`);
    const errors = findings.filter((f) => f.severity === te.ERROR).map((f) => f.class);
    const notices = findings.filter((f) => f.severity === te.NOTICE).map((f) => f.class);
    eq(notices, v.expected_notices || [], `${v.name}: notices`);
    if (v.expected_valid) {
      eq(errors, [], `${v.name}: no errors`);
    } else {
      check(errors.includes(v.expected_error), `${v.name}: expected ${v.expected_error}, got ${JSON.stringify(errors)}`);
    }
    byName[v.name] = v.expected_chain_hash;
  }
  check(byName["context-absent"] === byName["context-present"], "context does not change chain_hash");
  check(byName["genesis-minimal"] !== byName["second-chained"], "different records hash differently");
  console.log(`  ${data.vectors.length} vectors reproduced byte for byte`);
}

async function testSignedVector() {
  section("Ed25519 (signed vector, test key)");
  const available = await te.ed25519Available();
  check(available, "Ed25519 verification available in this Node runtime (WebCrypto or node:crypto)");
  if (!available) return;
  const data = JSON.parse(read(VECTORS));
  const pub = te.bytes.fromHex(data.test_key.public_hex);
  eq(await te.keyId(pub), data.test_key.key_id, "key id of the test key");
  const signed = data.vectors.find((v) => v.name === "signed");
  eq(await te.verifySignature(pub, signed.record.chain_hash, signed.record.signature), null, "signature verifies with the test key");
  const wrong = await te.verifySignature(new Uint8Array(32), signed.record.chain_hash, signed.record.signature);
  check(typeof wrong === "string", "signature fails with another key");
  const sig = signed.record.signature.sig;
  const flipped = Object.assign({}, signed.record.signature, { sig: sig.slice(0, 10) + (sig[10] === "A" ? "B" : "A") + sig.slice(11) });
  check(typeof (await te.verifySignature(pub, signed.record.chain_hash, flipped)) === "string", "altered signature fails");
  check(typeof (await te.verifySignature(pub, signed.record.chain_hash, Object.assign({}, signed.record.signature, { sig: signed.record.signature.sig + "=" }))) === "string", "padded base64url is rejected");
  // Public key input forms accepted by the page.
  const b64url = Buffer.from(pub).toString("base64url");
  const pem = "-----BEGIN PUBLIC KEY-----\n" + Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pub)]).toString("base64") + "\n-----END PUBLIC KEY-----\n";
  for (const [label, input] of [["hex", data.test_key.public_hex], ["HEX", data.test_key.public_hex.toUpperCase()], ["base64url", b64url], ["base64", Buffer.from(pub).toString("base64")], ["PEM", pem], ["padded", read(path.join(ROOT, "testdata", "keys", "test-ed25519.pub"))]]) {
    eq(te.bytes.hex(te.parsePublicKey(input)), data.test_key.public_hex, `parsePublicKey(${label})`);
  }
  for (const bad of ["", "abc", "0".repeat(63), "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"]) {
    let threw = false;
    try {
      te.parsePublicKey(bad);
    } catch (err) {
      threw = true;
    }
    check(threw, `parsePublicKey rejects ${JSON.stringify(bad.slice(0, 20))}`);
  }
}

async function checkIndex(dir) {
  const index = JSON.parse(read(path.join(dir, "expected.json")));
  check(index.cases.length > 0, "cases present");
  for (const c of index.cases) {
    let publicKey = null;
    if (c.pubkey) publicKey = te.parsePublicKey(read(path.join(dir, c.pubkey)));
    const report = await te.verifyStream(read(path.join(dir, c.file)), { publicKey, requireSignatures: !!c.require_signatures });
    check(report.signature_check !== "unavailable", `${c.file}: signatures were checked`);
    eq(report.ok, c.ok, `${c.file}: ok (${te.summary(report)})`);
    eq(report.records, c.records, `${c.file}: records`);
    eq(report.restarts, c.restarts, `${c.file}: restarts`);
    const got = [];
    for (const f of report.findings) {
      const key = `${f.index}:${f.class}`;
      if (!got.includes(key)) got.push(key);
    }
    eq(got, c.findings.map((f) => `${f.index}:${f.class}`), `${c.file}: distinct (index, class) findings`);
  }
  return index.cases.length;
}

async function testStreams() {
  section("testdata/streams/expected.json");
  const n = await checkIndex(STREAMS);
  console.log(`  ${n} stream fixtures agree`);
  // Summary lines must read exactly like the Go and Python CLIs.
  const pub = te.parsePublicKey(read(path.join(ROOT, "testdata", "keys", "test-ed25519.pub")));
  const lines = [
    ["seq-gap.jsonl", {}, "FAIL: 3 record(s) in 1 stream(s), 1 error(s)"],
    ["restart.jsonl", {}, "OK: 4 record(s) in 1 stream(s), hash chain intact, 1 restart(s)"],
    ["signed.jsonl", { publicKey: pub, requireSignatures: true }, "OK: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified"],
    ["signed.jsonl", {}, "OK: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s)"],
    ["signature-invalid.jsonl", { publicKey: pub, requireSignatures: true }, "FAIL: 3 record(s) in 1 stream(s), 2 error(s), 2 signed record(s), 1 signature(s) verified"],
  ];
  for (const [file, opts, want] of lines) {
    eq(te.summary(await te.verifyStream(read(path.join(STREAMS, file)), opts)), want, `${file}: summary line`);
  }
  // Blank lines and CRLF line endings are tolerated, line numbers count every line.
  const crlf = read(path.join(STREAMS, "seq-gap.jsonl")).split("\n").join("\r\n").replace(/\r\n/, "\r\n\r\n");
  const rep = await te.verifyStream(crlf);
  eq([rep.records, rep.findings.map((f) => [f.index, f.line])], [3, [[2, 4]]], "CRLF journal with a blank line");
}

async function testExamples() {
  section("examples/*.jsonl");
  const files = readdirSync(EXAMPLES).filter((f) => f.endsWith(".jsonl")).sort();
  check(files.length >= 4, "at least four examples");
  for (const name of files) {
    const report = await te.verifyStream(read(path.join(EXAMPLES, name)));
    check(report.ok, `${name}: ${te.summary(report)}`);
    check(report.records >= 3 && report.records <= 5, `${name}: 3 to 5 records`);
  }
  for (const copy of ["transfer-worker.jsonl", "tampered/hash-mismatch.jsonl"]) {
    eq(read(path.join(WEB_EXAMPLES, copy)), read(path.join(EXAMPLES, copy)), `web/examples/${copy} is identical to examples/${copy}`);
  }
  section("examples/tampered/expected.json");
  const n = await checkIndex(TAMPERED);
  console.log(`  ${n} tampered examples agree`);
}

async function testSchemaGate() {
  section("decode gate and structural checks");
  const base = JSON.parse(read(path.join(STREAMS, "valid-chain.jsonl")).split("\n")[0]);
  const cases = [
    ["extra top-level member", (d) => { d.extra = 1; }, true],
    ["unknown producer member", (d) => { d.producer.x = 1; }, true],
    ["string seq", (d) => { d.seq = "0"; }, true],
    ["float seq literal", (d) => { d.seq = "__FLOAT__"; }, true],
    ["negative seq", (d) => { d.seq = -1; }, true],
    ["unknown time.source", (d) => { d.time.source = "wall-clock"; }, false],
    ["bad event_type", (d) => { d.event_type = "Created"; }, false],
    ["upper-case hash prefix", (d) => { d.prev_hash = "SHA256:" + "0".repeat(64); }, false],
    ["recorded_at without fraction", (d) => { d.time.recorded_at = "2026-11-02T00:00:00Z"; }, false],
    ["chain_restart false", (d) => { d.chain_restart = false; }, false],
    ["null producer", (d) => { d.producer = null; }, false],
  ];
  for (const [label, mutate, skipped] of cases) {
    const d = JSON.parse(JSON.stringify(base));
    mutate(d);
    const raw = JSON.stringify(d).replace('"__FLOAT__"', "0.0");
    const { record, findings } = await te.verifyRecord(raw);
    check(findings.some((f) => f.class === te.SCHEMA_INVALID), `${label}: schema_invalid reported`);
    eq(record === null, skipped, `${label}: record ${skipped ? "skipped" : "kept"}`);
  }
  for (const raw of ["[1,2]", "not json", "", "null", '{"a":1} {"b":2}']) {
    const { record, findings } = await te.verifyRecord(raw);
    check(record === null && findings[0].class === te.SCHEMA_INVALID, `non-record ${JSON.stringify(raw)} is schema_invalid`);
  }
  // Missing payload: schema_invalid, but the record still takes part in the chain.
  const noPayload = JSON.parse(JSON.stringify(base));
  delete noPayload.payload;
  const r = await te.verifyRecord(JSON.stringify(noPayload));
  check(r.record !== null && r.findings.every((f) => f.class === te.SCHEMA_INVALID), "missing payload keeps the record for chain checks");
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "report") {
    process.exit(await reportMode(args.slice(1)));
  }
  console.log(`node ${process.versions.node}, web/verify.js`);
  await testJcs();
  await testVectors();
  await testSignedVector();
  await testStreams();
  await testExamples();
  await testSchemaGate();
  if (failures) {
    console.error(`\n${failures} of ${checks} checks failed`);
    process.exit(1);
  }
  console.log(`\nall ${checks} checks passed`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
