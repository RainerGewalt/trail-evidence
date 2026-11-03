"""Sealing and verification of Trail Evidence Records (SPEC.md)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, TextIO, Union

from . import ed25519
from . import registry as _profiles
from .jcs import canonicalize

SCHEMA = "trail.evidence/1"
MAX_SEQ = 2**64 - 1
HASH_PREFIX = "sha256:"
GENESIS_HASH = HASH_PREFIX + "0" * 64
NO_POLICY = {"id": "none", "version": "0", "hash": GENESIS_HASH}
SIGNATURE_ALG = "ed25519"

PRODUCER_KINDS = {"broker", "transfer-worker", "source-bridge", "ml-pipeline", "persistence", "other"}
TIME_SOURCES = {"system", "ntp", "tsa", "seq-reconstructed", "unknown"}
ACTOR_AUTHS = {"broker-authenticated", "self-declared", "operator-token", "none"}
POLICY_STATES = {"draft", "validated", "approved", "active", "retired"}
ANCHOR_KINDS = {"trailmq", "tsa", "worm", "other"}

CORE_MEMBERS = (
    "schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
    "time", "actor", "policy", "content_hash", "chain_restart", "anchor_hash",
    "profile",
)
REQUIRED_MEMBERS = (
    "schema", "producer", "stream_id", "seq", "prev_hash", "event_type",
    "time", "actor", "policy", "payload", "content_hash", "chain_hash",
)
KNOWN_MEMBERS = set(REQUIRED_MEMBERS) | {
    "chain_restart", "anchor_hash", "signature", "correlation_id", "job_id",
    "decision_id", "context", "redaction", "anchor", "profile",
}
_OBJECT_MEMBERS = {
    "producer": {"kind", "id", "version"},
    "time": {"recorded_at", "occurred_at", "read_at", "source"},
    "actor": {"auth", "id", "roles"},
    "policy": {"id", "version", "hash", "status", "kind"},
    "signature": {"alg", "key_id", "sig"},
    "redaction": {"fields", "method"},
    "anchor": {"kind", "ref"},
}

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORDED_AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,9}Z$")
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$")
EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$")
JSON_POINTER_RE = re.compile(r"^(/([^/~]|~0|~1)*)*$")
SEQ_RE = re.compile(r"^(0|[1-9][0-9]*)$")
PROFILE_RE = _profiles.PROFILE_RE
SCHEMA_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*/(0|[1-9][0-9]*)$")

# Finding classes (SPEC.md section 6.2). Errors make a record invalid.
SCHEMA_INVALID = "schema_invalid"
HASH_MISMATCH = "hash_mismatch"
CHAIN_BREAK = "chain_break"
SEQ_MISMATCH = "seq_mismatch"
SIGNATURE_INVALID = "signature_invalid"
PROFILE_INVALID = "profile_invalid"
# Notices. seq_gap makes a record unknown; with strict verification seq_gap,
# outside_scope and profile_unknown are reported as errors.
SEQ_GAP = "seq_gap"
OUTSIDE_SCOPE = "outside_scope"
PROFILE_UNKNOWN = "profile_unknown"
RESTART = "restart"
AFTER_UNKNOWN = "after_unknown"
LEGACY_INTEGER_SEQ = "legacy_integer_seq"
NUMBER_PRECISION = "number_precision"

ERROR_CLASSES = (SCHEMA_INVALID, HASH_MISMATCH, CHAIN_BREAK, SEQ_MISMATCH, SIGNATURE_INVALID, PROFILE_INVALID)
NOTICE_CLASSES = (SEQ_GAP, OUTSIDE_SCOPE, PROFILE_UNKNOWN, RESTART, AFTER_UNKNOWN, LEGACY_INTEGER_SEQ, NUMBER_PRECISION)
STRICT_CLASSES = (SEQ_GAP, OUTSIDE_SCOPE, PROFILE_UNKNOWN)

# Record states and profile states (SPEC.md section 6.1).
VALID = "valid"
INVALID = "invalid"
UNKNOWN = "unknown"
OUTSIDE = "outside_scope"
PROFILE_NONE = "none"
STATES = (VALID, INVALID, UNKNOWN, OUTSIDE)
PROFILE_STATES = (PROFILE_NONE, VALID, INVALID, OUTSIDE)

MAX_SAFE_INTEGER = 2**53

ERROR = "error"
NOTICE = "notice"

AFTER_UNKNOWN_MESSAGE = ("links to a record in state unknown; this record is valid relative to that record, "
                         "not to the start of the stream")


@dataclass
class Finding:
    """One observation about one record. seq is the record's usable seq."""

    index: int
    line: int
    cls: str
    severity: str
    message: str
    stream_id: Optional[str] = None
    seq: Optional[int] = None

    def to_dict(self) -> dict:
        d: dict = {"index": self.index, "line": self.line}
        if self.stream_id:
            d["stream_id"] = self.stream_id
        if self.seq is not None:
            d["seq"] = str(self.seq)
        d.update({"class": self.cls, "severity": self.severity, "message": self.message})
        return d


@dataclass
class StreamSummary:
    stream_id: str
    records: int = 0
    first_seq: int = 0
    last_seq: int = 0
    last_chain_hash: str = ""
    restarts: int = 0
    seen: bool = field(default=False, repr=False, compare=False)
    last_unknown: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "records": self.records,
            "first_seq": str(self.first_seq),
            "last_seq": str(self.last_seq),
            "last_chain_hash": self.last_chain_hash,
            "restarts": self.restarts,
        }


@dataclass
class RecordResult:
    """The verdict on one record of a journal."""

    index: int
    line: int
    state: str
    profile_state: str = PROFILE_NONE
    stream_id: Optional[str] = None
    seq: Optional[int] = None
    profile: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"index": self.index, "line": self.line}
        if self.stream_id:
            d["stream_id"] = self.stream_id
        if self.seq is not None:
            d["seq"] = str(self.seq)
        d["state"] = self.state
        if self.profile:
            d["profile"] = self.profile
        d["profile_state"] = self.profile_state
        return d


@dataclass
class Report:
    ok: bool = True
    strict: bool = False
    records: int = 0
    errors: int = 0
    restarts: int = 0
    signed_records: int = 0
    signatures_verified: int = 0
    unsigned_records: int = 0
    notices: int = 0
    states: dict = field(default_factory=lambda: {s: 0 for s in STATES})
    profile_states: dict = field(default_factory=lambda: {s: 0 for s in PROFILE_STATES})
    streams: list = field(default_factory=list)
    results: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        for f in findings:
            if self.strict and f.cls in STRICT_CLASSES:
                f.severity = ERROR
            self.findings.append(f)
            if f.severity == ERROR:
                self.errors += 1
                self.ok = False
            else:
                self.notices += 1
            if f.cls == RESTART:
                self.restarts += 1

    def summary(self) -> str:
        head = ("OK" if self.ok else "FAIL") + (" (strict)" if self.strict else "")
        s = f"{head}: {self.records} record(s) in {len(self.streams)} stream(s)"
        if self.ok and not self.states[UNKNOWN]:
            s += ", hash chain intact"
        elif self.ok:
            s += ", no invalid record"
        else:
            s += f", {self.errors} error(s)"
        if self.states[UNKNOWN]:
            s += f", {self.states[UNKNOWN]} unknown"
        if self.states[OUTSIDE]:
            s += f", {self.states[OUTSIDE]} outside scope"
        if self.restarts:
            s += f", {self.restarts} restart(s)"
        if self.signed_records:
            s += f", {self.signed_records} signed record(s)"
            if self.signatures_verified or self.unsigned_records:
                s += f", {self.signatures_verified} signature(s) verified"
        return s

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "strict": self.strict,
            "records": self.records,
            "errors": self.errors,
            "restarts": self.restarts,
            "signed_records": self.signed_records,
            "signatures_verified": self.signatures_verified,
            "unsigned_records": self.unsigned_records,
            "notices": self.notices,
            "states": dict(self.states),
            "profile_states": dict(self.profile_states),
            "streams": [s.to_dict() for s in self.streams],
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------- hashing

def hash_bytes(data: bytes) -> str:
    """Return ``sha256:`` plus the lowercase hex SHA-256 of data."""
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def hash_json(value: Any) -> str:
    """Canonicalise a parsed JSON value and hash it."""
    return hash_bytes(canonicalize(value))


def core_of(record: dict) -> dict:
    """Return the chain core: the hashed members of a record."""
    return {k: record[k] for k in CORE_MEMBERS if k in record}


def compute_hashes(record: dict) -> dict:
    """Recompute payload JCS, content_hash, core JCS and chain_hash.

    The declared content_hash is replaced by the recomputed one before the
    core is canonicalised, exactly like the Go implementation.
    """
    if "payload" not in record:
        raise ValueError("record has no payload member")
    payload_jcs = canonicalize(record["payload"])
    content_hash = hash_bytes(payload_jcs)
    core = core_of(record)
    core["content_hash"] = content_hash
    core_jcs = canonicalize(core)
    return {
        "payload_jcs": payload_jcs,
        "content_hash": content_hash,
        "core_jcs": core_jcs,
        "chain_hash": hash_bytes(core_jcs),
    }


# ---------------------------------------------------------------- sealing

def seal(record: dict, prev_hash: str) -> dict:
    """Link record to prev_hash and set content_hash and chain_hash in place.

    ``seq`` may be given as an int or a decimal string; it is written as the
    canonical decimal string (SPEC.md section 3.1). For a restart record
    (``chain_restart`` true) ``anchor_hash`` must be set and prev_hash must
    equal it. Any existing signature is dropped.
    """
    record.setdefault("schema", SCHEMA)
    if record["schema"] != SCHEMA:
        raise ValueError(f"unsupported schema {record['schema']!r}")
    seq = record.get("seq")
    if isinstance(seq, int) and not isinstance(seq, bool) and 0 <= seq <= MAX_SEQ:
        record["seq"] = str(seq)
    elif not (isinstance(seq, str) and SEQ_RE.match(seq) and int(seq) <= MAX_SEQ):
        raise ValueError(f"seq must be an integer or decimal string from 0 to {MAX_SEQ}, got {seq!r}")
    if "payload" not in record:
        raise ValueError("payload is required (use None for an empty payload)")
    if record.get("chain_restart"):
        if "anchor_hash" not in record:
            raise ValueError("chain_restart requires anchor_hash")
        if prev_hash != record["anchor_hash"]:
            raise ValueError("restart record must use anchor_hash as prev_hash")
    elif "chain_restart" in record:
        raise ValueError("chain_restart, when present, must be true")
    elif "anchor_hash" in record:
        raise ValueError("anchor_hash is only allowed with chain_restart")
    record["prev_hash"] = prev_hash
    record.pop("signature", None)
    h = compute_hashes(record)
    record["content_hash"] = h["content_hash"]
    record["chain_hash"] = h["chain_hash"]
    return record


def key_id(pub: bytes) -> str:
    """Recommended key identifier: ``ed25519:`` + first 16 hex of SHA-256(pub)."""
    return "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]


def sign(record: dict, seed: bytes, kid: Optional[str] = None) -> dict:
    """Attach an Ed25519 signature over the ASCII bytes of chain_hash."""
    if not record.get("chain_hash"):
        raise ValueError("record is not sealed")
    pub = ed25519.public_key(seed)
    sig = ed25519.sign(seed, record["chain_hash"].encode("ascii"))
    record["signature"] = {
        "alg": SIGNATURE_ALG,
        "key_id": kid or key_id(pub),
        "sig": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
    }
    return record


def _b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s:
        raise ValueError("not base64url without padding")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify_signature(pub: bytes, chain_hash: str, signature: Any) -> Optional[str]:
    """Return None when the signature verifies, else an error message."""
    if not isinstance(signature, dict):
        return "record carries no signature"
    if signature.get("alg") != SIGNATURE_ALG:
        return f"unsupported signature algorithm {signature.get('alg')!r}"
    if len(pub) != 32:
        return f"invalid public key length {len(pub)}"
    try:
        raw = _b64url_decode(signature.get("sig", ""))
    except (ValueError, binascii.Error):
        return "signature is not base64url without padding"
    if len(raw) != 64:
        return f"signature has {len(raw)} bytes, want 64"
    if not ed25519.verify(pub, chain_hash.encode("ascii"), raw):
        return f"signature does not verify with key {key_id(pub)}"
    return None


def parse_public_key(value: str) -> bytes:
    """Accept 64 hex characters or a file with hex or PEM (PKIX) content."""
    value = value.strip()
    try:
        return _hex_key(value)
    except ValueError:
        pass
    try:
        with open(value, "r", encoding="utf-8") as fh:
            text = fh.read().strip()
    except OSError:
        raise ValueError(f"public key: {value!r} is neither a 64-character hex key nor a readable file")
    if "-----BEGIN" in text:
        body = "".join(line for line in text.splitlines() if not line.startswith("-----"))
        der = base64.b64decode(body)
        # PKIX Ed25519 SubjectPublicKeyInfo is 44 bytes: 12-byte prefix + key.
        prefix = bytes.fromhex("302a300506032b6570032100")
        if len(der) != 44 or not der.startswith(prefix):
            raise ValueError("public key: PEM block is not an Ed25519 SubjectPublicKeyInfo")
        return der[12:]
    return _hex_key(text)


def _hex_key(s: str) -> bytes:
    if len(s) != 64:
        raise ValueError("expected 64 hex characters")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("not a hex string")


# ---------------------------------------------------------------- validation

_STRING_MEMBERS = ("schema", "stream_id", "prev_hash", "event_type", "content_hash",
                   "chain_hash", "anchor_hash", "correlation_id", "job_id", "decision_id",
                   "profile")
_NESTED_STRINGS = {
    "producer": ("kind", "id", "version"),
    "time": ("recorded_at", "occurred_at", "read_at", "source"),
    "actor": ("auth", "id"),
    "policy": ("id", "version", "hash", "status", "kind"),
    "signature": ("alg", "key_id", "sig"),
    "redaction": ("method",),
    "anchor": ("kind", "ref"),
}
_NESTED_STRING_LISTS = {"actor": ("roles",), "redaction": ("fields",)}


class _IntLiteral(int):
    """An int parsed from JSON that remembers its literal text ("-0" vs "0")."""

    literal: str

    def __new__(cls, text: str):
        obj = int.__new__(cls, text)
        obj.literal = text
        return obj


def _reject_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


def _loads(raw: Union[str, bytes]) -> Any:
    # Integer literals keep their text (seq "-0" is not "0"); NaN and
    # Infinity, which the json module accepts by default, are rejected like
    # every strict JSON parser does.
    return json.loads(raw, parse_int=_IntLiteral, parse_constant=_reject_constant)


@dataclass
class SeqInfo:
    present: bool = False  # the member exists (it may be null or malformed)
    ok: bool = False       # usable: canonical decimal string or legacy integer, <= MAX_SEQ
    legacy: bool = False   # usable, written as a JSON number (0.1 form)
    value: int = 0


def parse_seq(record: dict) -> SeqInfo:
    """Read seq: a canonical decimal string, or the legacy integer form.

    The value is taken from the literal text and compared as an integer of
    arbitrary size; it must not exceed 2^64 - 1.
    """
    if "seq" not in record:
        return SeqInfo()
    v = record["seq"]
    if isinstance(v, str):
        text, legacy = v, False
    elif isinstance(v, int) and not isinstance(v, bool):
        text, legacy = getattr(v, "literal", str(v)), True
    else:
        return SeqInfo(present=True)
    if not SEQ_RE.match(text):
        return SeqInfo(present=True)
    value = int(text)
    if value > MAX_SEQ:
        return SeqInfo(present=True)
    return SeqInfo(present=True, ok=True, legacy=legacy, value=value)


def foreign_schema(record: dict) -> Optional[str]:
    """The schema name when the record names another format or major version."""
    s = record.get("schema")
    if isinstance(s, str) and s != SCHEMA and SCHEMA_ID_RE.match(s):
        return s
    return None


def decode_problems(record: dict) -> list:
    """Type-level checks that decide whether a record is *decodable*.

    A record that is not decodable (unknown members in the typed part, or a
    typed member with the wrong JSON type) is reported as schema_invalid and
    skipped entirely: it takes no part in chain checks and does not advance
    the stream state. This mirrors a strict typed decoder, so that every
    implementation treats such lines the same way. ``null`` passes this gate
    (a typed decoder accepts it) and is rejected by validate_structure.
    ``seq`` is not checked here: a malformed seq is a structural problem
    (validate_structure) of an otherwise readable record.
    """
    problems: list = []
    add = problems.append
    for k in sorted(set(record) - KNOWN_MEMBERS):
        add(f'unknown member "{k}"')
    for k in _STRING_MEMBERS:
        if k in record and record[k] is not None and not isinstance(record[k], str):
            add(f"{k} must be a string")
    if "chain_restart" in record and record["chain_restart"] is not None and not isinstance(record["chain_restart"], bool):
        add("chain_restart must be a boolean")
    for name, allowed in _OBJECT_MEMBERS.items():
        if name not in record or record[name] is None:
            continue
        obj = record[name]
        if not isinstance(obj, dict):
            add(f"{name} must be an object")
            continue
        for k in sorted(set(obj) - allowed):
            add(f'unknown member "{name}.{k}"')
        for k in _NESTED_STRINGS.get(name, ()):
            if k in obj and obj[k] is not None and not isinstance(obj[k], str):
                add(f"{name}.{k} must be a string")
        for k in _NESTED_STRING_LISTS.get(name, ()):
            v = obj.get(k)
            if k in obj and v is not None and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                add(f"{name}.{k} must be an array of strings")
    return problems


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _nonempty(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def validate_structure(record: dict, seq: Optional[SeqInfo] = None) -> list:
    """Structural checks (SPEC.md section 6.3, step 3). Returns messages."""
    if seq is None:
        seq = parse_seq(record)
    problems: list = []
    add = problems.append
    for k in REQUIRED_MEMBERS:
        if k not in record:
            add(f'missing required member "{k}"')
    for k in sorted(set(record) - KNOWN_MEMBERS):
        add(f'unknown member "{k}"')
    for k in sorted(record):
        if k != "payload" and record[k] is None:
            add(f'member "{k}" must not be null')
    for name, allowed in _OBJECT_MEMBERS.items():
        if name in record and record[name] is not None:
            if not isinstance(record[name], dict):
                add(f"{name} must be an object")
            else:
                for k in sorted(set(record[name]) - allowed):
                    add(f'unknown member "{name}.{k}"')
    if "schema" in record and record["schema"] != SCHEMA:
        add(f'schema must be "{SCHEMA}", got {record["schema"]!r}')
    p = record.get("producer")
    if isinstance(p, dict):
        if p.get("kind") not in PRODUCER_KINDS:
            add(f"producer.kind {p.get('kind')!r} is not a known kind")
        if not _nonempty(p.get("id")):
            add("producer.id must not be empty")
        if not _nonempty(p.get("version")):
            add("producer.version must not be empty")
    if "stream_id" in record and not _nonempty(record["stream_id"]):
        add("stream_id must not be empty")
    if seq.present and not seq.ok and record.get("seq") is not None:
        add(f'seq must be a decimal string from "0" to "{MAX_SEQ}" without sign, leading zeros or fraction, got {record["seq"]!r}')
    if "profile" in record and record["profile"] is not None and not (_is_str(record["profile"]) and PROFILE_RE.match(record["profile"])):
        add(f"profile {record['profile']!r} is not of the form <name>/<major>")
    if "prev_hash" in record and not (_is_str(record["prev_hash"]) and HASH_RE.match(record["prev_hash"])):
        add("prev_hash does not match sha256:<64 hex>")
    if "event_type" in record and not (_is_str(record["event_type"]) and EVENT_TYPE_RE.match(record["event_type"])):
        add(f"event_type {record.get('event_type')!r} is not of the form <domain>.<noun>.<verb>")
    t = record.get("time")
    if isinstance(t, dict):
        ra = t.get("recorded_at")
        if not (_is_str(ra) and RECORDED_AT_RE.match(ra)):
            add("time.recorded_at must be RFC 3339 UTC with at least millisecond precision and a Z suffix")
        for k in ("occurred_at", "read_at"):
            if t.get(k) is not None and not (_is_str(t[k]) and TIMESTAMP_RE.match(t[k])):
                add(f"time.{k} must be RFC 3339 UTC with a Z suffix")
        if t.get("source") not in TIME_SOURCES:
            add(f"time.source {t.get('source')!r} is not a known source")
    a = record.get("actor")
    if isinstance(a, dict):
        if a.get("auth") not in ACTOR_AUTHS:
            add(f"actor.auth {a.get('auth')!r} is not a known value")
        if a.get("roles") is not None and not (isinstance(a["roles"], list) and all(_is_str(r) for r in a["roles"])):
            add("actor.roles must be an array of strings")
    pol = record.get("policy")
    if isinstance(pol, dict):
        if not _nonempty(pol.get("id")):
            add("policy.id must not be empty")
        if not _nonempty(pol.get("version")):
            add("policy.version must not be empty")
        if not (_is_str(pol.get("hash")) and HASH_RE.match(pol["hash"])):
            add("policy.hash does not match sha256:<64 hex>")
        if pol.get("status") is not None and pol["status"] not in POLICY_STATES:
            add(f"policy.status {pol['status']!r} is not a known state")
    for k in ("content_hash", "chain_hash"):
        if k in record and not (_is_str(record[k]) and HASH_RE.match(record[k])):
            add(f"{k} does not match sha256:<64 hex>")
    has_restart = "chain_restart" in record
    has_anchor = "anchor_hash" in record
    if has_restart and record["chain_restart"] is not True:
        add("chain_restart, when present, must be true")
    if has_restart and not has_anchor:
        add("chain_restart requires anchor_hash")
    if has_anchor and not has_restart:
        add("anchor_hash is only allowed together with chain_restart")
    if has_anchor:
        ah = record["anchor_hash"]
        if not (_is_str(ah) and HASH_RE.match(ah)):
            add("anchor_hash does not match sha256:<64 hex>")
        elif has_restart and record.get("prev_hash") != ah:
            add("restart record must carry anchor_hash as prev_hash")
    sig = record.get("signature")
    if isinstance(sig, dict):
        if sig.get("alg") != SIGNATURE_ALG:
            add('signature.alg must be "ed25519"')
        if not _nonempty(sig.get("key_id")):
            add("signature.key_id must not be empty")
        try:
            ok = len(_b64url_decode(sig.get("sig", ""))) == 64
        except (ValueError, binascii.Error):
            ok = False
        if not ok:
            add("signature.sig must be base64url without padding of a 64-byte Ed25519 signature")
    red = record.get("redaction")
    if isinstance(red, dict):
        if not _nonempty(red.get("method")):
            add("redaction.method must not be empty")
        fields = red.get("fields")
        if fields is None:
            add("redaction.fields must be an array")
        else:
            for f in fields:
                if not (_is_str(f) and JSON_POINTER_RE.match(f)):
                    add(f"redaction.fields entry {f!r} is not a JSON pointer")
    anc = record.get("anchor")
    if isinstance(anc, dict):
        if anc.get("kind") not in ANCHOR_KINDS:
            add(f"anchor.kind {anc.get('kind')!r} is not a known kind")
        if not _nonempty(anc.get("ref")):
            add("anchor.ref must not be empty")
    if "context" in record and record["context"] is not None and not isinstance(record["context"], dict):
        add("context must be an object")
    for k in ("correlation_id", "job_id", "decision_id"):
        if record.get(k) is not None and not _nonempty(record[k]):
            add(f"{k} must be a non-empty string when present")
    return problems


# ---------------------------------------------------------------- verification

def _parse_record(raw: Union[str, bytes]):
    try:
        value = _loads(raw)
    except ValueError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(value, dict):
        return None, "record is not a JSON object"
    return value, None


@dataclass
class RecordCheck:
    """The outcome of checking one record on its own (no stream around it).

    ``record`` is None when the input is not a decodable record of this
    contract (not JSON, not an object, not decodable, or outside the scope).
    ``state`` is valid, invalid or outside_scope; unknown needs the stream.
    """

    record: Optional[dict]
    findings: list
    state: str
    profile: Optional[str] = None
    profile_state: str = PROFILE_NONE
    seq: SeqInfo = field(default_factory=SeqInfo)
    restart: bool = False

    @property
    def positioned(self) -> bool:
        """A decoded record with a non-empty stream_id and a usable seq."""
        return self.record is not None and _nonempty(self.record.get("stream_id")) and self.seq.ok


def _schema_finding(problems: list) -> Finding:
    return Finding(0, 0, SCHEMA_INVALID, ERROR, "; ".join(problems))


def _state_of(findings: Iterable[Finding]) -> str:
    state = VALID
    for f in findings:
        if f.cls in ERROR_CLASSES:
            return INVALID
        if f.cls == SEQ_GAP:
            state = UNKNOWN
    return state


def _check_profile(record: dict):
    """Return (profile, profile_state, finding or None) for a decoded record."""
    if "profile" not in record:
        return None, PROFILE_NONE, None
    pid = record["profile"]
    if not (_is_str(pid) and PROFILE_RE.match(pid)):
        return (pid if _is_str(pid) else None), INVALID, None
    known, problems = _profiles.REGISTRY.validate(pid, record.get("payload"), "payload" in record)
    if not known:
        listed = ", ".join(_profiles.profiles()) or "none"
        return pid, OUTSIDE, Finding(0, 0, PROFILE_UNKNOWN, NOTICE,
                                     f"profile {pid} is not known to this verifier (known: {listed}); "
                                     "the payload was not checked against a profile")
    if problems:
        return pid, INVALID, Finding(0, 0, PROFILE_INVALID, ERROR,
                                     f"payload does not match profile {pid}: " + "; ".join(problems))
    return pid, VALID, None


def check_record(raw: Union[str, bytes, dict]) -> RecordCheck:
    """Check one record on its own: scope, decoding, structure, hashes, profile."""
    if isinstance(raw, dict):
        record = raw
    else:
        record, err = _parse_record(raw)
        if record is None:
            return RecordCheck(None, [_schema_finding([err])], INVALID)
    name = foreign_schema(record)
    if name is not None:
        return RecordCheck(None, [Finding(0, 0, OUTSIDE_SCOPE, NOTICE,
                                          f'schema "{name}" is not {SCHEMA}; the record is not checked '
                                          "and does not take part in any chain")], OUTSIDE)
    seq = parse_seq(record)
    undecodable = decode_problems(record)
    if undecodable:
        missing = [f'missing required member "{k}"' for k in REQUIRED_MEMBERS if k not in record]
        return RecordCheck(None, [_schema_finding(undecodable + missing)], INVALID, seq=seq)
    findings: list = []
    problems = validate_structure(record, seq)
    h = None
    try:
        h = compute_hashes(record)
    except (TypeError, ValueError) as exc:
        problems.append(str(exc))
    if problems:
        findings.append(_schema_finding(problems))
    if h is not None:
        if h["content_hash"] != record.get("content_hash"):
            findings.append(Finding(0, 0, HASH_MISMATCH, ERROR,
                                    f"content_hash mismatch: recorded {record.get('content_hash')}, computed {h['content_hash']}"))
        if h["chain_hash"] != record.get("chain_hash"):
            findings.append(Finding(0, 0, HASH_MISMATCH, ERROR,
                                    f"chain_hash mismatch: recorded {record.get('chain_hash')}, computed {h['chain_hash']}"))
        n = unsafe_integers(record["payload"])
        if n:
            findings.append(Finding(0, 0, NUMBER_PRECISION, NOTICE,
                                    f"payload contains {n} integer(s) outside +/-2^53; JCS renders them as IEEE-754 doubles, transport such values as strings"))
    if seq.ok and seq.legacy:
        findings.append(Finding(0, 0, LEGACY_INTEGER_SEQ, NOTICE,
                                f'seq {seq.value} is a JSON number; write it as the string "{seq.value}" '
                                "(accepted during 0.x, schema_invalid from 1.0)"))
    profile, profile_state, pf = _check_profile(record)
    if pf is not None:
        findings.append(pf)
    restart = record.get("chain_restart") is True and "anchor_hash" in record
    return RecordCheck(record, findings, _state_of(findings), profile, profile_state, seq, restart)


def verify_record(raw: Union[str, bytes, dict]):
    """Check one record on its own: structure, hashes and profile.

    Returns ``(record, findings)``; record is None when the input could not
    be parsed as a JSON object, is not decodable (see decode_problems) or is
    outside the scope of this verifier. Findings have index and line 0.
    ``check_record`` returns the record's state as well.
    """
    c = check_record(raw)
    return c.record, c.findings


def unsafe_integers(value: Any) -> int:
    """Count integers in a parsed JSON value whose magnitude exceeds 2^53.

    Floats (literals with a fraction or exponent) are not counted; they are
    doubles by intent.
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return 1 if abs(value) > MAX_SAFE_INTEGER else 0
    if isinstance(value, list):
        return sum(unsafe_integers(v) for v in value)
    if isinstance(value, dict):
        return sum(unsafe_integers(v) for v in value.values())
    return 0


def _seq_behind(seq: int, last: int) -> str:
    if seq == last:
        return f"seq {seq} repeats the seq of the previous record"
    return f"seq {seq} goes backwards (previous seq {last})"


def _check_chain(st: StreamSummary, c: RecordCheck) -> list:
    """Judge a positioned record against its stream (SPEC.md section 6.3, step 5)."""
    record = c.record
    seq = c.seq.value
    out: list = []

    def f(cls: str, sev: str, msg: str) -> Finding:
        return Finding(0, 0, cls, sev, msg)

    last = st.last_chain_hash
    prev_hash = record.get("prev_hash")
    if c.restart:
        anchor = record["anchor_hash"]
        msg = f"chain restart at seq {seq}, anchor {anchor}"
        if not st.seen and anchor != GENESIS_HASH:
            msg += " (previous segment not in this journal)"
        if st.seen and anchor == GENESIS_HASH:
            msg += " (anchor unknown: genesis)"
        out.append(f(RESTART, NOTICE, msg))
        st.restarts += 1
        if st.seen and anchor != GENESIS_HASH and anchor != last:
            out.append(f(CHAIN_BREAK, ERROR,
                         f"anchor_hash {anchor} does not match the last chain_hash {last} of the previous segment"))
        elif st.seen and st.last_unknown and anchor == last:
            out.append(f(AFTER_UNKNOWN, NOTICE, AFTER_UNKNOWN_MESSAGE))
    else:
        linked = prev_hash == (last if st.seen else GENESIS_HASH)
        expected = st.last_seq + 1 if st.seen else 0
        pos = (seq > expected) - (seq < expected)  # -1 behind, 0 next, +1 ahead
        if linked and pos == 0:
            if st.seen and st.last_unknown:
                out.append(f(AFTER_UNKNOWN, NOTICE, AFTER_UNKNOWN_MESSAGE))
        elif linked and pos > 0 and not st.seen:
            out.append(f(SEQ_MISMATCH, ERROR, f"first record of stream links to genesis but has seq {seq}, expected 0"))
        elif linked and pos > 0:
            out.append(f(SEQ_MISMATCH, ERROR,
                         f"seq {seq}, expected {expected}: prev_hash links to the record with seq {st.last_seq}, "
                         "so no record can be missing in between"))
        elif linked:
            out.append(f(SEQ_MISMATCH, ERROR, _seq_behind(seq, st.last_seq)))
        elif pos == 0 and not st.seen:
            out.append(f(CHAIN_BREAK, ERROR,
                         f"first record of stream has seq 0 but prev_hash {prev_hash} instead of genesis "
                         "and is not marked chain_restart"))
        elif pos == 0:
            out.append(f(CHAIN_BREAK, ERROR, f"prev_hash {prev_hash} does not match previous chain_hash {last}"))
        elif pos > 0 and not st.seen:
            out.append(f(SEQ_GAP, NOTICE,
                         f"first record of stream has seq {seq} and prev_hash {prev_hash}: "
                         "its predecessor is not in this journal"))
        elif pos > 0:
            out.append(f(SEQ_GAP, NOTICE,
                         f"seq {seq} after seq {st.last_seq}, and prev_hash {prev_hash} does not link to the "
                         "last checked record: its predecessor is not in this journal"))
        else:
            out.append(f(CHAIN_BREAK, ERROR, f"prev_hash {prev_hash} does not match previous chain_hash {last}"))
            out.append(f(SEQ_MISMATCH, ERROR, _seq_behind(seq, st.last_seq)))
    st.seen = True
    st.records += 1
    st.last_seq = seq
    st.last_chain_hash = record.get("chain_hash") if isinstance(record.get("chain_hash"), str) else ""
    return out


def _check_signature(report: Report, record: dict, public_key: Optional[bytes], require: bool) -> list:
    sig = record.get("signature")
    if sig is None:
        if public_key is not None:
            report.unsigned_records += 1
            if require:
                return [Finding(0, 0, SIGNATURE_INVALID, ERROR, "record is not signed")]
        return []
    report.signed_records += 1
    if public_key is None:
        return []
    err = verify_signature(public_key, str(record.get("chain_hash", "")), sig)
    if err:
        return [Finding(0, 0, SIGNATURE_INVALID, ERROR, err)]
    report.signatures_verified += 1
    return []


def verify_stream(lines: Union[TextIO, Iterable[Union[str, bytes]]],
                  public_key: Optional[bytes] = None,
                  require_signatures: bool = False,
                  strict: bool = False) -> Report:
    """Verify a JSON Lines journal (file object or iterable of lines).

    Blank lines are skipped. Verification continues after an error so that
    the report lists every problem; chain state advances with the record's
    declared chain_hash. Every record gets a state (valid, invalid, unknown,
    outside_scope) and a profile state. With ``strict`` the journal verifies
    only when every record is valid and every profile was checked.
    """
    report = Report(strict=strict)
    streams: dict = {}
    index = -1
    for line_no, raw in enumerate(lines, start=1):
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not raw.strip():
            continue
        index += 1
        report.records += 1
        c = check_record(raw)
        res = RecordResult(index, line_no, c.state, c.profile_state, profile=c.profile)
        findings = list(c.findings)
        if c.record is not None:
            sid = c.record.get("stream_id")
            res.stream_id = sid if _nonempty(sid) else None
            res.seq = c.seq.value if c.seq.ok else None
            if c.positioned:
                st = streams.get(sid)
                if st is None:
                    st = StreamSummary(stream_id=sid, first_seq=c.seq.value)
                    streams[sid] = st
                findings += _check_chain(st, c)
            findings += _check_signature(report, c.record, public_key, require_signatures)
        else:
            res.profile = None
        if c.state != OUTSIDE:
            res.state = _state_of(findings)
        if c.positioned:
            streams[c.record["stream_id"]].last_unknown = res.state == UNKNOWN
        for fnd in findings:
            fnd.index, fnd.line = index, line_no
            fnd.stream_id, fnd.seq = res.stream_id, res.seq
        report.add(*findings)
        report.results.append(res)
        report.states[res.state] += 1
        report.profile_states[res.profile_state] += 1
    report.streams = [streams[k] for k in sorted(streams)]
    return report
