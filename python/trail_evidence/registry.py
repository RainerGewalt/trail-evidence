"""Profile registry and payload checks (SPEC.md section 3.4).

The registry ships as package data under ``trail_evidence/profiles/``: a
byte-for-byte copy of ``profiles/`` at the repository root, written by
``scripts/profiles.py --write``. A profile schema uses a subset of JSON
Schema: ``type``, ``required``, ``properties`` and ``items``, plus
annotations. Members a profile does not name are always allowed, because
minor versions within a major only add members.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple

PROFILE_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+/[1-9][0-9]*$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$")
_MAJOR_RE = re.compile(r"^[1-9][0-9]*$")

KEYWORDS = {"$schema", "$id", "$comment", "title", "description", "examples",
            "type", "required", "properties", "items"}
TYPES = {"object", "array", "string", "number", "integer", "boolean", "null"}


class _Node:
    __slots__ = ("types", "required", "properties", "items")

    def __init__(self) -> None:
        self.types: List[str] = []
        self.required: List[str] = []
        self.properties: Dict[str, "_Node"] = {}
        self.items: Optional["_Node"] = None


def compile_schema(doc: Any, where: str = "") -> _Node:
    """Compile a profile schema; raise ValueError for anything outside the subset."""
    at = where or "schema root"
    if not isinstance(doc, dict):
        raise ValueError(f"{at}: a schema must be an object")
    for k in doc:
        if k not in KEYWORDS:
            raise ValueError(f"{at}: keyword {k!r} is not allowed in a profile schema")
    n = _Node()
    t = doc.get("type")
    if isinstance(t, str):
        n.types = [t]
    elif isinstance(t, list) and all(isinstance(x, str) for x in t):
        n.types = list(t)
    elif t is not None:
        raise ValueError(f"{at}: type must be a string or an array of strings")
    for x in n.types:
        if x not in TYPES:
            raise ValueError(f"{at}: unknown type {x!r}")
    if "required" in doc:
        r = doc["required"]
        if not (isinstance(r, list) and all(isinstance(x, str) for x in r)):
            raise ValueError(f"{at}: required must be an array of strings")
        n.required = list(r)
    if "properties" in doc:
        p = doc["properties"]
        if not isinstance(p, dict):
            raise ValueError(f"{at}: properties must be an object")
        for name in sorted(p):
            n.properties[name] = compile_schema(p[name], f"{where}/properties/{name}")
    if "items" in doc:
        n.items = compile_schema(doc["items"], f"{where}/items")
    return n


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, list):
        return "array"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (int, float)):
        return "number"
    return "unknown"


def _matches(v: Any, t: str) -> bool:
    # JSON Schema semantics: "integer" is any number without a fractional
    # part (16.0 counts), "number" any number.
    if t == "null":
        return v is None
    if t == "boolean":
        return isinstance(v, bool)
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if isinstance(v, bool):
        return False
    if t == "number":
        return isinstance(v, (int, float))
    if t == "integer":
        if isinstance(v, int):
            return True
        return isinstance(v, float) and math.isfinite(v) and v.is_integer()
    return False


def _token(name: str) -> str:
    return name.replace("~", "~0").replace("/", "~1")


def _validate(n: _Node, v: Any, at: str, problems: List[str]) -> None:
    if n.types and not any(_matches(v, t) for t in n.types):
        problems.append(f"{at}: expected {' or '.join(n.types)}, got {_type_name(v)}")
        return
    if isinstance(v, dict):
        for name in n.required:
            if name not in v:
                problems.append(f"{at}/{_token(name)}: missing required member")
        for name, sub in n.properties.items():  # compiled in code point order
            if name in v:
                _validate(sub, v[name], f"{at}/{_token(name)}", problems)
    if isinstance(v, list) and n.items is not None:
        for i, x in enumerate(v):
            _validate(n.items, x, f"{at}/{i}", problems)


class Registry:
    """The profiles a verifier knows, keyed by ``<name>/<major>``."""

    def __init__(self, schemas: Dict[str, bytes]):
        self.raw: Dict[str, bytes] = {}
        self._compiled: Dict[str, _Node] = {}
        for pid, raw in schemas.items():
            if not PROFILE_RE.match(pid):
                raise ValueError(f"profile id {pid!r} is not <name>/<major>")
            self.raw[pid] = raw
            self._compiled[pid] = compile_schema(json.loads(raw.decode("utf-8")))

    def ids(self) -> List[str]:
        return sorted(self.raw)

    def validate(self, pid: str, payload: Any, present: bool = True) -> Tuple[bool, List[str]]:
        """Return (known, problems) for a payload under profile pid."""
        node = self._compiled.get(pid)
        if node is None:
            return False, []
        if not present:
            return True, ["payload is missing"]
        problems: List[str] = []
        _validate(node, payload, "payload", problems)
        return True, problems


def _load_package_registry() -> Registry:
    schemas: Dict[str, bytes] = {}
    try:
        from importlib.resources import files  # Python 3.9+
    except ImportError:  # pragma: no cover
        return Registry(schemas)
    base = files("trail_evidence") / "profiles"
    if not base.is_dir():
        return Registry(schemas)
    for name_dir in base.iterdir():
        if not name_dir.is_dir() or not _NAME_RE.match(name_dir.name):
            continue
        for f in name_dir.iterdir():
            fname = f.name
            if not fname.endswith(".schema.json"):
                continue
            major = fname[: -len(".schema.json")]
            if _MAJOR_RE.match(major):
                schemas[f"{name_dir.name}/{major}"] = f.read_bytes()
    return Registry(schemas)


REGISTRY = _load_package_registry()


def profiles() -> List[str]:
    """Identifiers of the profiles this verifier knows, sorted."""
    return REGISTRY.ids()


def profile_schema(pid: str) -> Optional[bytes]:
    """The JSON Schema of a known profile as stored in the registry."""
    return REGISTRY.raw.get(pid)


def validate_payload(pid: str, payload: Any) -> Tuple[bool, List[str]]:
    """Check a parsed payload against a known profile: (known, problems)."""
    return REGISTRY.validate(pid, payload)
