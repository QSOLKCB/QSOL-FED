#!/usr/bin/env python3
"""Independent Python implementation of qsol-fed-canonical-json/1."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

PROFILE = "qsol-fed-canonical-json/1"
PROTOCOL = "qsol-fed/1"
MESSAGE_ID_DOMAIN = b"qsol-fed-message-id/1\x00"
SAFE_INTEGER_MIN = -(2**53 - 1)
SAFE_INTEGER_MAX = 2**53 - 1
MAX_INPUT_BYTES = 65536
MAX_DEPTH = 32
MAX_STRING_UTF8 = 8192
MAX_ARRAY_ITEMS = 1024
MAX_OBJECT_MEMBERS = 1024


class CanonicalError(ValueError):
    pass


class PairObject(list):
    """Object pair list preserving duplicates until validation."""


def _reject_float(_: str) -> None:
    raise CanonicalError("non_integer_number")


def _reject_constant(_: str) -> None:
    raise CanonicalError("non_finite_number")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> PairObject:
    return PairObject(pairs)


def _nfc(value: str) -> str:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise CanonicalError("lone_surrogate")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > MAX_STRING_UTF8:
        raise CanonicalError("string_too_large")
    return normalized


def _normalize(value: Any, depth: int = 1) -> Any:
    if depth > MAX_DEPTH:
        raise CanonicalError("max_depth_exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not SAFE_INTEGER_MIN <= value <= SAFE_INTEGER_MAX:
            raise CanonicalError("integer_out_of_range")
        return value
    if isinstance(value, str):
        return _nfc(value)
    if isinstance(value, PairObject):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise CanonicalError("too_many_object_members")
        raw_seen: set[str] = set()
        normalized_seen: set[str] = set()
        result: dict[str, Any] = {}
        for raw_key, child in value:
            if raw_key in raw_seen:
                raise CanonicalError("duplicate_key")
            raw_seen.add(raw_key)
            key = _nfc(raw_key)
            if key in normalized_seen:
                raise CanonicalError("normalized_duplicate_key")
            normalized_seen.add(key)
            result[key] = _normalize(child, depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise CanonicalError("too_many_array_items")
        return [_normalize(child, depth + 1) for child in value]
    raise CanonicalError(f"unsupported_value:{type(value).__name__}")


def parse(raw: str) -> Any:
    encoded = raw.encode("utf-8", errors="strict")
    if len(encoded) > MAX_INPUT_BYTES:
        raise CanonicalError("input_too_large")
    if encoded.startswith(b"\xef\xbb\xbf"):
        raise CanonicalError("utf8_bom_forbidden")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalError("malformed_json") from exc
    return _normalize(parsed)


def _escape_string(value: str) -> str:
    value = _nfc(value)
    output = ['"']
    escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    for char in value:
        if char in escapes:
            output.append(escapes[char])
        elif ord(char) < 0x20:
            output.append(f"\\u{ord(char):04x}")
        else:
            output.append(char)
    output.append('"')
    return "".join(output)


def serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not SAFE_INTEGER_MIN <= value <= SAFE_INTEGER_MAX:
            raise CanonicalError("integer_out_of_range")
        return str(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(serialize(child) for child in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            _escape_string(key) + ":" + serialize(value[key]) for key in sorted(value)
        ) + "}"
    raise CanonicalError(f"unsupported_value:{type(value).__name__}")


def canonicalize(raw: str) -> bytes:
    return serialize(parse(raw)).encode("utf-8")


def object_id(raw: str) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(raw)).hexdigest()


def derive_message_id(raw_envelope: str) -> str:
    value = parse(raw_envelope)
    if not isinstance(value, dict):
        raise CanonicalError("envelope_must_be_object")
    if "message_id" not in value or "signature" not in value:
        raise CanonicalError("envelope_projection_fields_missing")
    projection = dict(value)
    projection.pop("message_id")
    projection.pop("signature")
    projection_bytes = serialize(projection).encode("utf-8")
    digest = hashlib.sha256(MESSAGE_ID_DOMAIN + projection_bytes).hexdigest()
    return "sha256:" + digest


def supported_protocol(protocol: str) -> bool:
    return protocol == PROTOCOL
