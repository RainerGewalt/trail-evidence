"""RFC 8785 JSON Canonicalization Scheme (JCS) for parsed JSON values.

The input is the result of ``json.loads`` (dict, list, str, int, float, bool,
None). Output is UTF-8 bytes:

* object members sorted by the UTF-16 code units of their names;
* strings escaped minimally (``\\" \\\\ \\b \\f \\n \\r \\t`` and ``\\u00xx``
  in lowercase for other control characters), everything else literal;
* numbers rendered like ECMAScript ``Number.prototype.toString``, which is
  what RFC 8785 requires. Python ``repr`` already yields the shortest
  round-trip digits; this module only reformats exponent and decimal point.

Integers outside +/-2**53 are treated as IEEE-754 doubles, as any JCS
implementation that parses JSON numbers into doubles would do.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

_MAX_SAFE = 2**53

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def canonicalize(value: Any) -> bytes:
    """Return the JCS bytes of a parsed JSON value."""
    parts: list[str] = []
    _write(value, parts)
    return "".join(parts).encode("utf-8")


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(escape_string(value))
    elif isinstance(value, (int, float)):
        out.append(format_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value.keys(), key=_utf16_key):
            if not isinstance(key, str):
                raise TypeError("object member names must be strings")
            if not first:
                out.append(",")
            first = False
            out.append(escape_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise TypeError(f"unsupported JSON type {type(value).__name__}")


def _utf16_key(name: str) -> bytes:
    # Big-endian UTF-16 compares byte-wise exactly like a sequence of 16-bit
    # code units, which is the order RFC 8785 section 3.2.3 prescribes.
    return name.encode("utf-16-be", "surrogatepass")


def escape_string(s: str) -> str:
    """Escape a string per RFC 8785 section 3.2.2.2 (quotes included)."""
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def format_number(value: Any) -> str:
    """Render a number like ECMAScript Number.prototype.toString."""
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        if -_MAX_SAFE <= value <= _MAX_SAFE:
            return str(value)
        value = float(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    tup = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(str(d) for d in tup.digits).rstrip("0")
    exponent = int(tup.exponent) + (len(tup.digits) - len(digits))
    k = len(digits)
    n = k + exponent  # value = 0.digits * 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body
