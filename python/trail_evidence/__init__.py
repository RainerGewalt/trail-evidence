"""Trail Evidence Record v1 reference implementation (standard library only).

Public API::

    from trail_evidence import seal, sign, check_record, verify_stream

See SPEC.md at the repository root for the normative description.
"""

from __future__ import annotations

from .jcs import canonicalize
from .registry import profile_schema, profiles, validate_payload
from .record import (
    GENESIS_HASH,
    HASH_PREFIX,
    MAX_SEQ,
    NO_POLICY,
    SCHEMA,
    Finding,
    RecordCheck,
    RecordResult,
    Report,
    StreamSummary,
    check_record,
    compute_hashes,
    hash_bytes,
    key_id,
    parse_public_key,
    seal,
    sign,
    verify_record,
    verify_signature,
    verify_stream,
)

__all__ = [
    "GENESIS_HASH",
    "HASH_PREFIX",
    "MAX_SEQ",
    "NO_POLICY",
    "SCHEMA",
    "Finding",
    "RecordCheck",
    "RecordResult",
    "Report",
    "StreamSummary",
    "canonicalize",
    "check_record",
    "compute_hashes",
    "hash_bytes",
    "key_id",
    "parse_public_key",
    "profile_schema",
    "profiles",
    "seal",
    "sign",
    "validate_payload",
    "verify_record",
    "verify_signature",
    "verify_stream",
]

__version__ = "0.2.1"
