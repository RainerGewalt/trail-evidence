"""Trail Evidence Record v1 reference implementation (standard library only).

Public API::

    from trail_evidence import seal, sign, verify_record, verify_stream

See SPEC.md at the repository root for the normative description.
"""

from __future__ import annotations

from .jcs import canonicalize
from .record import (
    GENESIS_HASH,
    HASH_PREFIX,
    NO_POLICY,
    SCHEMA,
    Finding,
    Report,
    StreamSummary,
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
    "NO_POLICY",
    "SCHEMA",
    "Finding",
    "Report",
    "StreamSummary",
    "canonicalize",
    "compute_hashes",
    "hash_bytes",
    "key_id",
    "parse_public_key",
    "seal",
    "sign",
    "verify_record",
    "verify_signature",
    "verify_stream",
]

__version__ = "0.1.0"
