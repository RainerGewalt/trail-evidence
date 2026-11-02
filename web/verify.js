/*
 * Trail Evidence Verifier: RFC 8785 canonicalisation, SHA-256 hashing,
 * chain and signature checks for trail.evidence/1 journals (SPEC.md).
 *
 * Runs unchanged in a browser (plain <script src="verify.js">, exposes
 * window.TrailEvidence) and in Node 18+ (require("./verify.js")). No
 * dependencies: SHA-256 and Ed25519 come from WebCrypto (crypto.subtle).
 * The results must match the Go and Python reference implementations;
 * web/test/run.mjs checks that against testdata/.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module && module.exports) {
    module.exports = api;
  } else {
    root.TrailEvidence = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SCHEMA = "trail.evidence/1";
  const HASH_PREFIX = "sha256:";
  const GENESIS_HASH = HASH_PREFIX + "0".repeat(64);
  const SIGNATURE_ALG = "ed25519";
  const MAX_SAFE_INTEGER = 9007199254740992n; // 2^53

  // Finding classes and severities, exactly as in Go and Python.
  const HASH_MISMATCH = "hash_mismatch";
  const CHAIN_BREAK = "chain_break";
  const SEQ_GAP = "seq_gap";
  const RESTART = "restart";
  const SIGNATURE_INVALID = "signature_invalid";
  const SCHEMA_INVALID = "schema_invalid";
  const NUMBER_PRECISION = "number_precision";
  const ERROR = "error";
  const NOTICE = "notice";

  const PRODUCER_KINDS = new Set(["broker", "transfer-worker", "source-bridge", "ml-pipeline", "persistence", "other"]);
  const TIME_SOURCES = new Set(["system", "ntp", "tsa", "seq-reconstructed", "unknown"]);
  const ACTOR_AUTHS = new Set(["broker-authenticated", "self-declared", "operator-token", "none"]);
  const POLICY_STATES = new Set(["draft", "validated", "approved", "active", "retired"]);
  const ANCHOR_KINDS = new Set(["trailmq", "tsa", "worm", "other"]);

  const CORE_MEMBERS = [
    "schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
    "time", "actor", "policy", "content_hash", "chain_restart", "anchor_hash",
  ];
  const REQUIRED_MEMBERS = [
    "schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
    "time", "actor", "policy", "payload", "content_hash", "chain_hash",
  ];
  const KNOWN_MEMBERS = new Set(REQUIRED_MEMBERS.concat([
    "chain_restart", "anchor_hash", "signature", "correlation_id", "job_id",
    "decision_id", "context", "redaction", "anchor",
  ]));
  const OBJECT_MEMBERS = {
    producer: new Set(["kind", "id", "version"]),
    time: new Set(["recorded_at", "occurred_at", "read_at", "source"]),
    actor: new Set(["auth", "id", "roles"]),
    policy: new Set(["id", "version", "hash", "status", "kind"]),
    signature: new Set(["alg", "key_id", "sig"]),
    redaction: new Set(["fields", "method"]),
    anchor: new Set(["kind", "ref"]),
  };
  const STRING_MEMBERS = ["schema", "stream_id", "prev_hash", "event_type", "content_hash",
    "chain_hash", "anchor_hash", "correlation_id", "job_id", "decision_id"];
  const NESTED_STRINGS = {
    producer: ["kind", "id", "version"],
    time: ["recorded_at", "occurred_at", "read_at", "source"],
    actor: ["auth", "id"],
    policy: ["id", "version", "hash", "status", "kind"],
    signature: ["alg", "key_id", "sig"],
    redaction: ["method"],
    anchor: ["kind", "ref"],
  };
  const NESTED_STRING_LISTS = { actor: ["roles"], redaction: ["fields"] };

  const HASH_RE = /^sha256:[0-9a-f]{64}$/;
  const RECORDED_AT_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,9}Z$/;
  const TIMESTAMP_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$/;
  const EVENT_TYPE_RE = /^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$/;
  const JSON_POINTER_RE = /^(\/([^/~]|~0|~1)*)*$/;
  // A JSON integer literal that a strict uint64 decoder (Go) accepts.
  const SEQ_LITERAL_RE = /^(?:0|[1-9][0-9]*)$/;
  const NUMBER_LITERAL_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

  const textEncoder = new TextEncoder();

  // ---------------------------------------------------------------- crypto

  function subtle() {
    if (typeof globalThis.crypto === "object" && globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto.subtle;
    }
    if (typeof require === "function") {
      // Node 18 has WebCrypto, but not as a global.
      const wc = require("node:crypto").webcrypto;
      if (wc && wc.subtle) return wc.subtle;
    }
    throw new Error("WebCrypto (crypto.subtle) is not available; the page needs a secure context (https, localhost or a local file)");
  }

  function cryptoAvailable() {
    try {
      subtle();
      return true;
    } catch (err) {
      return false;
    }
  }

  function hex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }

  function fromHex(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  function base64urlDecode(s) {
    // base64url without padding (RFC 4648 section 5); padding is rejected
    // like the Python implementation does.
    if (typeof s !== "string" || s.includes("=") || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
      throw new Error("not base64url without padding");
    }
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
    return base64Decode(b64);
  }

  function base64Decode(b64) {
    if (typeof atob === "function") {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return new Uint8Array(Buffer.from(b64, "base64"));
  }

  async function sha256Hex(bytes) {
    const digest = await subtle().digest("SHA-256", bytes);
    return hex(new Uint8Array(digest));
  }

  /** "sha256:" followed by the lowercase hex SHA-256 of bytes. */
  async function hashBytes(bytes) {
    return HASH_PREFIX + (await sha256Hex(bytes));
  }

  /** Recommended key identifier: "ed25519:" + first 16 hex of SHA-256(pub). */
  async function keyId(pub) {
    return "ed25519:" + (await sha256Hex(pub)).slice(0, 16);
  }

  // Ed25519 through WebCrypto, with a node:crypto fallback for Node versions
  // whose WebCrypto lacks the algorithm. Thrown Ed25519Unavailable means the
  // runtime cannot check signatures at all; that is reported, not an error.
  class Ed25519Unavailable extends Error {
    constructor() {
      super("Ed25519 is not available in this runtime's WebCrypto");
      this.name = "Ed25519Unavailable";
    }
  }

  const SPKI_PREFIX = fromHex("302a300506032b6570032100");
  const keyCache = new Map();

  function importEd25519(pub) {
    const k = hex(pub);
    if (!keyCache.has(k)) {
      keyCache.set(k, subtle().importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]).catch((err) => {
        keyCache.delete(k);
        throw err;
      }));
    }
    return keyCache.get(k);
  }

  async function ed25519Verify(pub, message, sig) {
    let key;
    try {
      key = await importEd25519(pub);
    } catch (err) {
      if (typeof require === "function") {
        try {
          const nc = require("node:crypto");
          const der = new Uint8Array(SPKI_PREFIX.length + pub.length);
          der.set(SPKI_PREFIX, 0);
          der.set(pub, SPKI_PREFIX.length);
          const keyObject = nc.createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
          return nc.verify(null, message, keyObject, sig);
        } catch (err2) {
          // fall through
        }
      }
      throw new Ed25519Unavailable();
    }
    try {
      return await subtle().verify({ name: "Ed25519" }, key, sig, message);
    } catch (err) {
      return false;
    }
  }

  /** Resolves to true when this runtime can verify Ed25519 signatures. */
  async function ed25519Available() {
    try {
      // RFC 8032 test vector 1: public key and signature over the empty message.
      const pub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
      const sig = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
      return (await ed25519Verify(pub, new Uint8Array(0), sig)) === true;
    } catch (err) {
      return false;
    }
  }

  // ---------------------------------------------------------------- JCS (RFC 8785)

  /** Escape a string per RFC 8785 section 3.2.2.2, quotes included. */
  function escapeString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      const c = s.charCodeAt(i);
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
      else out += ch;
    }
    return out + '"';
  }

  /** Render a number like ECMAScript Number.prototype.toString (RFC 8785 3.2.2.3). */
  function formatNumber(v) {
    if (typeof v !== "number" || !Number.isFinite(v)) {
      throw new TypeError("NaN and Infinity are not valid JSON numbers");
    }
    if (v === 0) return "0"; // also -0
    return String(v);
  }

  function writeValue(value, out) {
    if (value === null) {
      out.push("null");
    } else if (value === true) {
      out.push("true");
    } else if (value === false) {
      out.push("false");
    } else if (typeof value === "string") {
      out.push(escapeString(value));
    } else if (typeof value === "number") {
      out.push(formatNumber(value));
    } else if (Array.isArray(value)) {
      out.push("[");
      for (let i = 0; i < value.length; i++) {
        if (i) out.push(",");
        writeValue(value[i], out);
      }
      out.push("]");
    } else if (typeof value === "object") {
      // Default string comparison in JavaScript orders by UTF-16 code
      // units, which is what RFC 8785 section 3.2.3 prescribes.
      const keys = Object.keys(value).sort();
      out.push("{");
      for (let i = 0; i < keys.length; i++) {
        if (i) out.push(",");
        out.push(escapeString(keys[i]), ":");
        writeValue(value[keys[i]], out);
      }
      out.push("}");
    } else {
      throw new TypeError("unsupported JSON type " + typeof value);
    }
  }

  /** Return the JCS form of a parsed JSON value as a string. */
  function canonicalize(value) {
    const out = [];
    writeValue(value, out);
    return out.join("");
  }

  /** JCS as UTF-8 bytes (what gets hashed). */
  function canonicalBytes(value) {
    return textEncoder.encode(canonicalize(value));
  }

  // ---------------------------------------------------------------- raw JSON scanning
  //
  // JSON.parse turns 9007199254740993 into 9007199254740992 and 1.0 into 1,
  // so the number_precision notice and the strict seq check need the literal
  // text. These helpers locate member spans in text that JSON.parse has
  // already accepted; they are not a general parser.

  function skipWs(t, i) {
    while (i < t.length) {
      const c = t.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
    return i;
  }

  function scanString(t, i) {
    i++;
    while (i < t.length) {
      const ch = t[i];
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === '"') return i + 1;
      i++;
    }
    throw new SyntaxError("unterminated string");
  }

  /** Index just after the JSON value that starts at (or after whitespace from) i. */
  function scanValue(t, i) {
    i = skipWs(t, i);
    const c = t[i];
    if (c === '"') return scanString(t, i);
    if (c === "{" || c === "[") {
      let depth = 0;
      for (; i < t.length; i++) {
        const ch = t[i];
        if (ch === '"') {
          i = scanString(t, i) - 1;
        } else if (ch === "{" || ch === "[") {
          depth++;
        } else if (ch === "}" || ch === "]") {
          depth--;
          if (depth === 0) return i + 1;
        }
      }
      throw new SyntaxError("unterminated container");
    }
    let j = i;
    while (j < t.length && !/[\s,\]}]/.test(t[j])) j++;
    return j;
  }

  /** Map of member name to raw value text for a JSON object text (last duplicate wins). */
  function memberSpans(t) {
    const spans = new Map();
    let i = skipWs(t, 0);
    if (t[i] !== "{") throw new SyntaxError("not an object");
    i = skipWs(t, i + 1);
    if (t[i] === "}") return spans;
    for (;;) {
      i = skipWs(t, i);
      const keyEnd = scanString(t, i);
      const key = JSON.parse(t.slice(i, keyEnd));
      i = skipWs(t, keyEnd);
      if (t[i] !== ":") throw new SyntaxError("expected ':'");
      const start = skipWs(t, i + 1);
      const end = scanValue(t, start);
      spans.set(key, t.slice(start, end));
      i = skipWs(t, end);
      if (t[i] === ",") {
        i++;
        continue;
      }
      if (t[i] === "}") return spans;
      throw new SyntaxError("expected ',' or '}'");
    }
  }

  /** Raw item texts of a JSON array text. */
  function arrayItems(t) {
    const items = [];
    let i = skipWs(t, 0);
    if (t[i] !== "[") throw new SyntaxError("not an array");
    i = skipWs(t, i + 1);
    if (t[i] === "]") return items;
    for (;;) {
      const start = skipWs(t, i);
      const end = scanValue(t, start);
      items.push(t.slice(start, end));
      i = skipWs(t, end);
      if (t[i] === ",") {
        i++;
        continue;
      }
      if (t[i] === "]") return items;
      throw new SyntaxError("expected ',' or ']'");
    }
  }

  /**
   * Count integer literals in raw JSON text whose magnitude exceeds 2^53.
   * Literals with a fraction or exponent are doubles by intent and are not
   * counted (same rule as Go and Python).
   */
  function unsafeIntegers(t) {
    let n = 0;
    for (let i = 0; i < t.length; i++) {
      const ch = t[i];
      if (ch === '"') {
        i = scanString(t, i) - 1;
        continue;
      }
      if (ch === "-" || (ch >= "0" && ch <= "9")) {
        NUMBER_LITERAL_RE.lastIndex = i;
        const m = NUMBER_LITERAL_RE.exec(t);
        if (!m) continue;
        const lit = m[0];
        if (!/[.eE]/.test(lit)) {
          const v = BigInt(lit);
          if ((v < 0n ? -v : v) > MAX_SAFE_INTEGER) n++;
        }
        i += lit.length - 1;
      }
    }
    return n;
  }

  // ---------------------------------------------------------------- hashing

  function coreOf(record) {
    const core = {};
    for (const k of CORE_MEMBERS) {
      if (Object.prototype.hasOwnProperty.call(record, k)) core[k] = record[k];
    }
    return core;
  }

  /**
   * Recompute payload JCS, content_hash, core JCS and chain_hash of a parsed
   * record. The declared content_hash is replaced by the recomputed one
   * before the core is canonicalised, exactly like Go and Python.
   */
  async function computeHashes(record) {
    if (!Object.prototype.hasOwnProperty.call(record, "payload")) {
      throw new Error("record has no payload member");
    }
    const payloadJcs = canonicalize(record.payload);
    const contentHash = await hashBytes(textEncoder.encode(payloadJcs));
    const core = coreOf(record);
    core.content_hash = contentHash;
    const coreJcs = canonicalize(core);
    const chainHash = await hashBytes(textEncoder.encode(coreJcs));
    return { payload_jcs: payloadJcs, content_hash: contentHash, core_jcs: coreJcs, chain_hash: chainHash };
  }

  // ---------------------------------------------------------------- keys and signatures

  /**
   * Parse an Ed25519 public key given as 64 hex characters, as base64url
   * (43 characters, no padding) or base64 of the 32 raw bytes, or as a PEM
   * "PUBLIC KEY" block (PKIX SubjectPublicKeyInfo). Returns 32 bytes.
   */
  function parsePublicKey(text) {
    const s = String(text).trim();
    if (s === "") throw new Error("public key is empty");
    if (/^[0-9a-fA-F]{64}$/.test(s)) return fromHex(s.toLowerCase());
    if (s.includes("-----BEGIN")) {
      const body = s.split(/\r?\n/).filter((l) => !l.startsWith("-----")).join("").replace(/\s+/g, "");
      let der;
      try {
        der = base64Decode(body);
      } catch (err) {
        throw new Error("public key: PEM block is not valid base64");
      }
      if (der.length !== 44 || hex(der.subarray(0, 12)) !== hex(SPKI_PREFIX)) {
        throw new Error("public key: PEM block is not an Ed25519 SubjectPublicKeyInfo");
      }
      return der.subarray(12);
    }
    if (/^[A-Za-z0-9_-]{43}=?=?$/.test(s) || /^[A-Za-z0-9+/]{43}=?=?$/.test(s)) {
      const b64 = s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/") + "=";
      let raw;
      try {
        raw = base64Decode(b64);
      } catch (err) {
        throw new Error("public key: not valid base64url");
      }
      if (raw.length === 32) return raw;
    }
    throw new Error("public key must be 64 hex characters, 43 base64url characters or a PEM PUBLIC KEY block");
  }

  /**
   * Check a record signature over the ASCII bytes of chain_hash. Resolves to
   * null when the signature verifies, else to an error message. Throws
   * Ed25519Unavailable when the runtime has no Ed25519 implementation.
   */
  async function verifySignature(pub, chainHash, signature) {
    if (signature === null || typeof signature !== "object" || Array.isArray(signature)) {
      return "record carries no signature";
    }
    if (signature.alg !== SIGNATURE_ALG) {
      return "unsupported signature algorithm " + JSON.stringify(signature.alg === undefined ? null : signature.alg);
    }
    if (!(pub instanceof Uint8Array) || pub.length !== 32) {
      return "invalid public key length " + (pub ? pub.length : 0);
    }
    let raw;
    try {
      raw = base64urlDecode(signature.sig === undefined ? "" : signature.sig);
    } catch (err) {
      return "signature is not base64url without padding";
    }
    if (raw.length !== 64) {
      return "signature has " + raw.length + " bytes, want 64";
    }
    const ok = await ed25519Verify(pub, textEncoder.encode(String(chainHash)), raw);
    if (!ok) {
      return "signature does not verify with key " + (await keyId(pub));
    }
    return null;
  }

  // ---------------------------------------------------------------- validation

  const isStr = (v) => typeof v === "string";
  const nonempty = (v) => typeof v === "string" && v !== "";
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const q = (v) => JSON.stringify(v === undefined ? null : v);

  function sortedKeys(obj) {
    return Object.keys(obj).sort(compareCodePoints);
  }

  // Go sorts strings by UTF-8 bytes and Python by code points; both equal
  // code point order, which differs from the UTF-16 default for astral
  // characters.
  function compareCodePoints(a, b) {
    const ia = a[Symbol.iterator]();
    const ib = b[Symbol.iterator]();
    for (;;) {
      const x = ia.next();
      const y = ib.next();
      if (x.done && y.done) return 0;
      if (x.done) return -1;
      if (y.done) return 1;
      const cx = x.value.codePointAt(0);
      const cy = y.value.codePointAt(0);
      if (cx !== cy) return cx < cy ? -1 : 1;
    }
  }

  /**
   * Type-level checks that decide whether a record is decodable at all. A
   * record that fails here is schema_invalid and skipped entirely: it does
   * not advance the stream state. Mirrors Go's strict typed decoder and the
   * Python decode_problems. null passes this gate and is rejected later.
   */
  function decodeProblems(record, spans) {
    const problems = [];
    const add = (m) => problems.push(m);
    for (const k of sortedKeys(record)) {
      if (!KNOWN_MEMBERS.has(k)) add("unknown member " + q(k));
    }
    for (const k of STRING_MEMBERS) {
      if (has(record, k) && record[k] !== null && !isStr(record[k])) add(k + " must be a string");
    }
    if (has(record, "seq") && record.seq !== null) {
      const lit = spans ? spans.get("seq") : undefined;
      const ok = typeof record.seq === "number" && (lit === undefined ? Number.isInteger(record.seq) && record.seq >= 0 : SEQ_LITERAL_RE.test(lit));
      if (!ok) add("seq must be a non-negative integer");
    }
    if (has(record, "chain_restart") && record.chain_restart !== null && typeof record.chain_restart !== "boolean") {
      add("chain_restart must be a boolean");
    }
    for (const name of Object.keys(OBJECT_MEMBERS)) {
      if (!has(record, name) || record[name] === null) continue;
      const obj = record[name];
      if (!isObj(obj)) {
        add(name + " must be an object");
        continue;
      }
      for (const k of sortedKeys(obj)) {
        if (!OBJECT_MEMBERS[name].has(k)) add("unknown member " + q(name + "." + k));
      }
      for (const k of NESTED_STRINGS[name] || []) {
        if (has(obj, k) && obj[k] !== null && !isStr(obj[k])) add(name + "." + k + " must be a string");
      }
      for (const k of NESTED_STRING_LISTS[name] || []) {
        if (has(obj, k) && obj[k] !== null && !(Array.isArray(obj[k]) && obj[k].every(isStr))) {
          add(name + "." + k + " must be an array of strings");
        }
      }
    }
    return problems;
  }

  /** Structural checks (SPEC.md section 6, step 2). Returns messages. */
  function validateStructure(record) {
    const problems = [];
    const add = (m) => problems.push(m);
    for (const k of REQUIRED_MEMBERS) {
      if (!has(record, k)) add("missing required member " + q(k));
    }
    for (const k of sortedKeys(record)) {
      if (!KNOWN_MEMBERS.has(k)) add("unknown member " + q(k));
    }
    for (const k of sortedKeys(record)) {
      if (k !== "payload" && record[k] === null) add("member " + q(k) + " must not be null");
    }
    for (const name of Object.keys(OBJECT_MEMBERS)) {
      if (has(record, name) && record[name] !== null) {
        if (!isObj(record[name])) {
          add(name + " must be an object");
        } else {
          for (const k of sortedKeys(record[name])) {
            if (!OBJECT_MEMBERS[name].has(k)) add("unknown member " + q(name + "." + k));
          }
        }
      }
    }
    if (has(record, "schema") && record.schema !== SCHEMA) {
      add("schema must be " + q(SCHEMA) + ", got " + q(record.schema));
    }
    const p = record.producer;
    if (isObj(p)) {
      if (!PRODUCER_KINDS.has(p.kind)) add("producer.kind " + q(p.kind) + " is not a known kind");
      if (!nonempty(p.id)) add("producer.id must not be empty");
      if (!nonempty(p.version)) add("producer.version must not be empty");
    }
    if (has(record, "stream_id") && !nonempty(record.stream_id)) add("stream_id must not be empty");
    if (has(record, "seq") && record.seq !== null && !(typeof record.seq === "number" && Number.isInteger(record.seq) && record.seq >= 0)) {
      add("seq must be a non-negative integer");
    }
    if (has(record, "prev_hash") && !(isStr(record.prev_hash) && HASH_RE.test(record.prev_hash))) {
      add("prev_hash does not match sha256:<64 hex>");
    }
    if (has(record, "event_type") && !(isStr(record.event_type) && EVENT_TYPE_RE.test(record.event_type))) {
      add("event_type " + q(record.event_type) + " is not of the form <domain>.<noun>.<verb>");
    }
    const t = record.time;
    if (isObj(t)) {
      if (!(isStr(t.recorded_at) && RECORDED_AT_RE.test(t.recorded_at))) {
        add("time.recorded_at must be RFC 3339 UTC with at least millisecond precision and a Z suffix");
      }
      for (const k of ["occurred_at", "read_at"]) {
        if (t[k] !== undefined && t[k] !== null && !(isStr(t[k]) && TIMESTAMP_RE.test(t[k]))) {
          add("time." + k + " must be RFC 3339 UTC with a Z suffix");
        }
      }
      if (!TIME_SOURCES.has(t.source)) add("time.source " + q(t.source) + " is not a known source");
    }
    const a = record.actor;
    if (isObj(a)) {
      if (!ACTOR_AUTHS.has(a.auth)) add("actor.auth " + q(a.auth) + " is not a known value");
      if (a.roles !== undefined && a.roles !== null && !(Array.isArray(a.roles) && a.roles.every(isStr))) {
        add("actor.roles must be an array of strings");
      }
    }
    const pol = record.policy;
    if (isObj(pol)) {
      if (!nonempty(pol.id)) add("policy.id must not be empty");
      if (!nonempty(pol.version)) add("policy.version must not be empty");
      if (!(isStr(pol.hash) && HASH_RE.test(pol.hash))) add("policy.hash does not match sha256:<64 hex>");
      if (pol.status !== undefined && pol.status !== null && !POLICY_STATES.has(pol.status)) {
        add("policy.status " + q(pol.status) + " is not a known state");
      }
    }
    for (const k of ["content_hash", "chain_hash"]) {
      if (has(record, k) && !(isStr(record[k]) && HASH_RE.test(record[k]))) add(k + " does not match sha256:<64 hex>");
    }
    const hasRestart = has(record, "chain_restart");
    const hasAnchor = has(record, "anchor_hash");
    if (hasRestart && record.chain_restart !== true) add("chain_restart, when present, must be true");
    if (hasRestart && !hasAnchor) add("chain_restart requires anchor_hash");
    if (hasAnchor && !hasRestart) add("anchor_hash is only allowed together with chain_restart");
    if (hasAnchor) {
      const ah = record.anchor_hash;
      if (!(isStr(ah) && HASH_RE.test(ah))) add("anchor_hash does not match sha256:<64 hex>");
      else if (hasRestart && record.prev_hash !== ah) add("restart record must carry anchor_hash as prev_hash");
    }
    const sig = record.signature;
    if (isObj(sig)) {
      if (sig.alg !== SIGNATURE_ALG) add('signature.alg must be "ed25519"');
      if (!nonempty(sig.key_id)) add("signature.key_id must not be empty");
      let ok = false;
      try {
        ok = base64urlDecode(sig.sig === undefined ? "" : sig.sig).length === 64;
      } catch (err) {
        ok = false;
      }
      if (!ok) add("signature.sig must be base64url without padding of a 64-byte Ed25519 signature");
    }
    const red = record.redaction;
    if (isObj(red)) {
      if (!nonempty(red.method)) add("redaction.method must not be empty");
      if (red.fields === undefined || red.fields === null) {
        add("redaction.fields must be an array");
      } else {
        for (const f of red.fields) {
          if (!(isStr(f) && JSON_POINTER_RE.test(f))) add("redaction.fields entry " + q(f) + " is not a JSON pointer");
        }
      }
    }
    const anc = record.anchor;
    if (isObj(anc)) {
      if (!ANCHOR_KINDS.has(anc.kind)) add("anchor.kind " + q(anc.kind) + " is not a known kind");
      if (!nonempty(anc.ref)) add("anchor.ref must not be empty");
    }
    if (has(record, "context") && record.context !== null && !isObj(record.context)) add("context must be an object");
    for (const k of ["correlation_id", "job_id", "decision_id"]) {
      if (has(record, k) && record[k] !== null && !nonempty(record[k])) add(k + " must be a non-empty string when present");
    }
    return problems;
  }

  // ---------------------------------------------------------------- verification

  function finding(cls, severity, message) {
    return { index: 0, line: 0, class: cls, severity, message };
  }

  function withRecord(f, record) {
    const out = { index: f.index, line: f.line };
    if (record) {
      out.stream_id = isStr(record.stream_id) ? record.stream_id : "";
      out.seq = typeof record.seq === "number" ? record.seq : null;
    }
    out.class = f.class;
    out.severity = f.severity;
    out.message = f.message;
    return out;
  }

  /**
   * Check one record (raw JSON text) on its own: structure and both hashes.
   * Resolves to {record, findings}; record is null when the text is not a
   * decodable record. Findings carry index and line 0.
   */
  async function verifyRecord(raw) {
    let record;
    try {
      record = JSON.parse(raw);
    } catch (err) {
      return { record: null, findings: [finding(SCHEMA_INVALID, ERROR, "invalid JSON: " + err.message)] };
    }
    if (!isObj(record)) {
      return { record: null, findings: [finding(SCHEMA_INVALID, ERROR, "record is not a JSON object")] };
    }
    let spans = null;
    try {
      spans = memberSpans(raw);
    } catch (err) {
      spans = null;
    }
    const findings = [];
    const undecodable = decodeProblems(record, spans);
    if (undecodable.length) {
      for (const m of undecodable) findings.push(finding(SCHEMA_INVALID, ERROR, m));
      for (const k of REQUIRED_MEMBERS) {
        if (!has(record, k)) findings.push(finding(SCHEMA_INVALID, ERROR, "missing required member " + q(k)));
      }
      return { record: null, findings };
    }
    for (const m of validateStructure(record)) findings.push(finding(SCHEMA_INVALID, ERROR, m));
    let h;
    try {
      h = await computeHashes(record);
    } catch (err) {
      findings.push(finding(SCHEMA_INVALID, ERROR, err.message));
      return { record, findings };
    }
    if (h.content_hash !== record.content_hash) {
      findings.push(finding(HASH_MISMATCH, ERROR, "content_hash mismatch: recorded " + record.content_hash + ", computed " + h.content_hash));
    }
    if (h.chain_hash !== record.chain_hash) {
      findings.push(finding(HASH_MISMATCH, ERROR, "chain_hash mismatch: recorded " + record.chain_hash + ", computed " + h.chain_hash));
    }
    const payloadRaw = spans ? spans.get("payload") : undefined;
    const n = payloadRaw === undefined ? 0 : unsafeIntegers(payloadRaw);
    if (n > 0) {
      findings.push(finding(NUMBER_PRECISION, NOTICE, "payload contains " + n + " integer(s) outside +/-2^53; JCS renders them as IEEE-754 doubles, transport such values as strings"));
    }
    return { record, findings };
  }

  function checkChain(streams, record, index, line) {
    const sid = isStr(record.stream_id) ? record.stream_id : "";
    const seq = typeof record.seq === "number" ? record.seq : null;
    const seqNum = seq === null ? 0 : seq;
    let st = streams.get(sid);
    if (!st) {
      st = { summary: { stream_id: sid, records: 0, first_seq: seqNum, last_seq: 0, last_chain_hash: "", restarts: 0 }, seen: false };
      streams.set(sid, st);
    }
    const out = [];
    const f = (cls, sev, msg) => ({ index, line, stream_id: sid, seq, class: cls, severity: sev, message: msg });
    const s = st.summary;
    const prevHash = record.prev_hash;
    if (record.chain_restart === true && has(record, "anchor_hash")) {
      const anchor = record.anchor_hash;
      let msg = "chain restart at seq " + seqNum + ", anchor " + anchor;
      if (!st.seen && anchor !== GENESIS_HASH) msg += " (previous segment not in this journal)";
      if (st.seen && anchor === GENESIS_HASH) msg += " (anchor unknown: genesis)";
      out.push(f(RESTART, NOTICE, msg));
      s.restarts++;
      if (st.seen && anchor !== GENESIS_HASH && anchor !== s.last_chain_hash) {
        out.push(f(CHAIN_BREAK, ERROR, "anchor_hash " + anchor + " does not match the last chain_hash " + s.last_chain_hash + " of the previous segment"));
      }
    } else if (!st.seen) {
      if (prevHash !== GENESIS_HASH) {
        out.push(f(CHAIN_BREAK, ERROR, "first record of stream has prev_hash " + prevHash + " instead of genesis and is not marked chain_restart"));
      } else if (seqNum !== 0) {
        out.push(f(SEQ_GAP, ERROR, "first record of stream has seq " + seqNum + ", expected 0"));
      }
    } else {
      if (prevHash !== s.last_chain_hash) {
        out.push(f(CHAIN_BREAK, ERROR, "prev_hash " + prevHash + " does not match previous chain_hash " + s.last_chain_hash));
      }
      if (seqNum !== s.last_seq + 1) {
        out.push(f(SEQ_GAP, ERROR, "seq " + seqNum + ", expected " + (s.last_seq + 1)));
      }
    }
    st.seen = true;
    s.records++;
    s.last_seq = seqNum;
    s.last_chain_hash = isStr(record.chain_hash) ? record.chain_hash : "";
    return out;
  }

  async function checkSignature(report, record, index, line, opts, state) {
    const sid = isStr(record.stream_id) ? record.stream_id : "";
    const seq = typeof record.seq === "number" ? record.seq : null;
    const f = (msg) => ({ index, line, stream_id: sid, seq, class: SIGNATURE_INVALID, severity: ERROR, message: msg });
    const sig = record.signature;
    if (sig === undefined || sig === null) {
      if (opts.publicKey) {
        report.unsigned_records++;
        if (opts.requireSignatures) return [f("record is not signed")];
      }
      return [];
    }
    report.signed_records++;
    if (!opts.publicKey || state.ed25519 === false) return [];
    let err;
    try {
      err = await verifySignature(opts.publicKey, isStr(record.chain_hash) ? record.chain_hash : "", sig);
    } catch (e) {
      if (e instanceof Ed25519Unavailable) {
        state.ed25519 = false;
        report.signature_check = "unavailable";
        return [];
      }
      throw e;
    }
    if (err) return [f(err)];
    report.signatures_verified++;
    return [];
  }

  function addFindings(report, findings) {
    for (const f of findings) {
      report.findings.push(f);
      if (f.severity === ERROR) {
        report.errors++;
        report.ok = false;
      } else {
        report.notices++;
        if (f.class === RESTART) report.restarts++;
      }
    }
  }

  // Go's bytes.TrimSpace set: ASCII space characters, U+0085, U+00A0 and
  // the Unicode Z categories, but not the byte order mark.
  const TRIM_RE = /^(?:[^\S﻿]|\u0085)+|(?:[^\S﻿]|\u0085)+$/g;

  /**
   * Verify a JSON Lines journal given as text. Options: publicKey
   * (Uint8Array of 32 bytes, optional), requireSignatures (boolean),
   * onProgress(recordsSoFar) called every 500 records. Resolves to a report
   * with the same members as the Go and Python JSON reports, plus
   * signature_check: "unavailable" when a key was given but this runtime
   * cannot verify Ed25519 signatures.
   */
  async function verifyStream(text, options) {
    const opts = Object.assign({ publicKey: null, requireSignatures: false, onProgress: null }, options || {});
    if (opts.requireSignatures && !opts.publicKey) {
      throw new Error("requireSignatures needs a publicKey");
    }
    const report = {
      ok: true, records: 0, errors: 0, restarts: 0, signed_records: 0,
      signatures_verified: 0, unsigned_records: 0, notices: 0, streams: [], findings: [],
    };
    const streams = new Map();
    const state = { ed25519: null };
    const lines = String(text).split("\n");
    let index = -1;
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].replace(TRIM_RE, "");
      if (trimmed === "") continue;
      const line = i + 1;
      index++;
      report.records++;
      const { record, findings } = await verifyRecord(trimmed);
      addFindings(report, findings.map((f) => withRecord({ ...f, index, line }, record)));
      if (record === null) continue;
      addFindings(report, checkChain(streams, record, index, line));
      addFindings(report, await checkSignature(report, record, index, line, opts, state));
      if (opts.onProgress && report.records % 500 === 0) {
        opts.onProgress(report.records);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    const ids = Array.from(streams.keys()).sort(compareCodePoints);
    for (const id of ids) report.streams.push(streams.get(id).summary);
    return report;
  }

  /** One-line summary in the style of the Go and Python CLIs. */
  function summary(r) {
    let s = (r.ok ? "OK: " : "FAIL: ") + r.records + " record(s) in " + r.streams.length + " stream(s)";
    s += r.ok ? ", hash chain intact" : ", " + r.errors + " error(s)";
    if (r.restarts > 0) s += ", " + r.restarts + " restart(s)";
    if (r.signed_records > 0) {
      s += ", " + r.signed_records + " signed record(s)";
      if (r.signatures_verified > 0 || r.unsigned_records > 0) {
        s += ", " + r.signatures_verified + " signature(s) verified";
      }
    }
    return s;
  }

  /** Report findings as JSON exactly like the Go CLI (seq omitted when unknown). */
  function reportToJSON(report) {
    const out = Object.assign({}, report);
    delete out.signature_check;
    out.findings = report.findings.map((f) => {
      const o = { index: f.index, line: f.line };
      if (f.stream_id !== undefined && f.stream_id !== null) o.stream_id = f.stream_id;
      if (f.seq !== undefined && f.seq !== null) o.seq = f.seq;
      o.class = f.class;
      o.severity = f.severity;
      o.message = f.message;
      return o;
    });
    if (report.signature_check) out.signature_check = report.signature_check;
    return out;
  }

  return {
    SCHEMA, HASH_PREFIX, GENESIS_HASH, SIGNATURE_ALG,
    HASH_MISMATCH, CHAIN_BREAK, SEQ_GAP, RESTART, SIGNATURE_INVALID, SCHEMA_INVALID, NUMBER_PRECISION,
    ERROR, NOTICE,
    ERROR_CLASSES: [SCHEMA_INVALID, HASH_MISMATCH, CHAIN_BREAK, SEQ_GAP, SIGNATURE_INVALID],
    NOTICE_CLASSES: [RESTART, NUMBER_PRECISION],
    canonicalize, canonicalBytes, escapeString, formatNumber,
    hashBytes, keyId, computeHashes,
    parsePublicKey, verifySignature, ed25519Available, Ed25519Unavailable, cryptoAvailable,
    decodeProblems, validateStructure, verifyRecord, verifyStream, summary, reportToJSON,
    json: { memberSpans, arrayItems, scanValue, unsafeIntegers },
    bytes: { hex, fromHex, base64urlDecode },
  };
});
