#!/usr/bin/env python3
"""Independent Python reference implementation of qsol-fed-sdk/1."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

SDK_CONTRACT = "qsol-fed-sdk/1"
BOOTSTRAP_PROTOCOL = "qsol-fed/0"
WIRE_PROTOCOL = "qsol-fed/1"
PROVENANCE_SCHEMA = "qsol-fed-provenance/1"
THIRD_PARTY_PROFILE = "third-party-node-profile/1"
MESSAGE_ID_DOMAIN = b"qsol-fed-message-id/1\x00"
SAFE_INTEGER_MIN = -(2**53 - 1)
SAFE_INTEGER_MAX = 2**53 - 1
MAX_INPUT_BYTES = 65_536
MAX_DEPTH = 32
MAX_STRING_UTF8 = 8_192
MAX_ARRAY_ITEMS = 1_024
MAX_OBJECT_MEMBERS = 1_024

NODE_ID = re.compile(r"^fed:qsol:[a-z0-9][a-z0-9._-]{0,127}$")
SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*/[1-9][0-9]*$")
MESSAGE_CLASSES = {
    "hello", "capabilities", "evidence.offer", "evidence.request", "hypothesis",
    "challenge", "response", "council.report", "minority.report",
    "experiment.receipt", "citation", "publication",
}


class SdkError(ValueError):
    pass


class PairObject(list):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> PairObject:
    return PairObject(pairs)


def _reject_float(_: str) -> None:
    raise SdkError("non_integer_number")


def _reject_constant(_: str) -> None:
    raise SdkError("non_finite_number")


def _nfc(value: str) -> str:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise SdkError("lone_surrogate")
    value = unicodedata.normalize("NFC", value)
    if len(value.encode("utf-8")) > MAX_STRING_UTF8:
        raise SdkError("string_too_large")
    return value


def _normalize(value: Any, depth: int = 1) -> Any:
    if depth > MAX_DEPTH:
        raise SdkError("max_depth_exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not SAFE_INTEGER_MIN <= value <= SAFE_INTEGER_MAX:
            raise SdkError("integer_out_of_range")
        return value
    if isinstance(value, str):
        return _nfc(value)
    if isinstance(value, PairObject):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise SdkError("too_many_object_members")
        raw_seen: set[str] = set()
        nfc_seen: set[str] = set()
        result: dict[str, Any] = {}
        for raw_key, child in value:
            if raw_key in raw_seen:
                raise SdkError("duplicate_key")
            raw_seen.add(raw_key)
            key = _nfc(raw_key)
            if key in nfc_seen:
                raise SdkError("normalized_duplicate_key")
            nfc_seen.add(key)
            result[key] = _normalize(child, depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise SdkError("too_many_array_items")
        return [_normalize(child, depth + 1) for child in value]
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise SdkError("too_many_object_members")
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise SdkError("object_key_not_string")
            key = _nfc(raw_key)
            if key in result:
                raise SdkError("normalized_duplicate_key")
            result[key] = _normalize(child, depth + 1)
        return result
    raise SdkError("unsupported_value")


def parse(raw: str) -> Any:
    if not isinstance(raw, str):
        raise SdkError("malformed_json")
    encoded = raw.encode("utf-8", errors="strict")
    if len(encoded) > MAX_INPUT_BYTES:
        raise SdkError("input_too_large")
    if encoded.startswith(b"\xef\xbb\xbf"):
        raise SdkError("utf8_bom_forbidden")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_reject_float, parse_constant=_reject_constant)
    except SdkError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SdkError("malformed_json") from exc
    return _normalize(value)


def _escape(value: str) -> str:
    value = _nfc(value)
    out = ['"']
    escapes = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}
    for char in value:
        if char in escapes:
            out.append(escapes[char])
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def serialize(value: Any) -> str:
    value = _normalize(value)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, list):
        return "[" + ",".join(serialize(child) for child in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_escape(key) + ":" + serialize(value[key]) for key in sorted(value)) + "}"
    raise SdkError("unsupported_value")


def canonicalize(value: Any) -> bytes:
    if isinstance(value, bytes):
        try:
            raw = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SdkError("invalid_utf8") from exc
        normalized = parse(raw)
    elif isinstance(value, str):
        normalized = parse(value)
    else:
        normalized = _normalize(value)
    data = serialize(normalized).encode("utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise SdkError("output_too_large")
    return data


def object_id(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


def derive_message_id(envelope: dict[str, Any]) -> str:
    if "message_id" not in envelope or "signature" not in envelope:
        raise SdkError("envelope_projection_fields_missing")
    projection = dict(envelope)
    projection.pop("message_id")
    projection.pop("signature")
    return "sha256:" + hashlib.sha256(MESSAGE_ID_DOMAIN + canonicalize(projection)).hexdigest()


def classify_protocol(protocol: str) -> str:
    return "supported" if protocol == WIRE_PROTOCOL else "unsupported_major"


def validate_capability_id(value: str) -> bool:
    return isinstance(value, str) and bool(CAPABILITY.fullmatch(value))


def _is_node_id(value: Any) -> bool:
    return isinstance(value, str) and bool(NODE_ID.fullmatch(value))


def _is_sha256_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA256_REF.fullmatch(value))


def _is_timestamp(value: Any) -> bool:
    return isinstance(value, str) and bool(TIMESTAMP.fullmatch(value))


def build_node_manifest(node_id: str, capabilities: list[str]) -> dict[str, Any]:
    manifest = {"protocol": BOOTSTRAP_PROTOCOL, "node_id": node_id, "capabilities": list(capabilities), "authority_claim": "none"}
    validate_node_manifest(manifest)
    return manifest


def validate_node_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {"protocol", "node_id", "capabilities", "authority_claim"}:
        raise SdkError("sdk_node_manifest_invalid")
    caps = manifest["capabilities"]
    if (manifest["protocol"] != BOOTSTRAP_PROTOCOL or not _is_node_id(manifest["node_id"])
            or manifest["authority_claim"] != "none" or not isinstance(caps, list)
            or len(caps) > 64 or len(set(caps)) != len(caps)
            or not all(validate_capability_id(cap) for cap in caps)):
        raise SdkError("sdk_node_manifest_invalid")


def validate_third_party_profile(profile: dict[str, Any]) -> None:
    required = {"schema", "implementation", "governance_model", "qsol_governance_adopted", "nexus_required", "council_required"}
    if not isinstance(profile, dict) or set(profile) != required or profile["schema"] != THIRD_PARTY_PROFILE or profile["governance_model"] != "local":
        raise SdkError("third_party_profile_invalid")
    if not isinstance(profile["implementation"], str) or not profile["implementation"] or len(profile["implementation"]) > 128:
        raise SdkError("third_party_profile_invalid")
    if profile["qsol_governance_adopted"] is not False or profile["nexus_required"] is not False or profile["council_required"] is not False:
        raise SdkError("third_party_profile_invalid")


def build_provenance(
    source_node: str,
    source_object: str,
    relation: str,
    parents: list[str],
    created_at: str,
) -> dict[str, Any]:
    value = {
        "schema": PROVENANCE_SCHEMA,
        "source_node": source_node,
        "source_object": source_object,
        "relation": relation,
        "parents": list(parents),
        "created_at": created_at,
    }
    validate_provenance(value)
    return value


def validate_provenance(value: dict[str, Any]) -> None:
    required = {"schema", "source_node", "source_object", "relation", "parents", "created_at"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != PROVENANCE_SCHEMA or not _is_node_id(value["source_node"]):
        raise SdkError("sdk_provenance_invalid")
    if not _is_sha256_ref(value["source_object"]) or not isinstance(value["relation"], str) or value["relation"] not in {"observed", "derived", "quoted", "transported"}:
        raise SdkError("sdk_provenance_invalid")
    parents = value["parents"]
    if not isinstance(parents, list) or len(parents) > 64 or len(set(parents)) != len(parents) or not all(_is_sha256_ref(p) for p in parents):
        raise SdkError("sdk_provenance_invalid")
    if not _is_timestamp(value["created_at"]):
        raise SdkError("sdk_provenance_invalid")


def _validate_envelope_spec(spec: dict[str, Any], error: str) -> None:
    required = {"sender", "recipient", "message_class", "payload_ref", "provenance_ref", "issued_at", "expires_at"}
    if not isinstance(spec, dict) or set(spec) != required or not _is_node_id(spec["sender"]) or not _is_node_id(spec["recipient"]):
        raise SdkError(error)
    if not isinstance(spec["message_class"], str) or spec["message_class"] not in MESSAGE_CLASSES or not _is_sha256_ref(spec["payload_ref"]):
        raise SdkError(error)
    if spec["provenance_ref"] is not None and not _is_sha256_ref(spec["provenance_ref"]):
        raise SdkError(error)
    if not _is_timestamp(spec["issued_at"]) or (spec["expires_at"] is not None and not _is_timestamp(spec["expires_at"])):
        raise SdkError(error)


def build_unsigned_envelope(spec: dict[str, Any]) -> dict[str, Any]:
    _validate_envelope_spec(spec, "sdk_envelope_input_invalid")
    envelope = {
        "protocol": WIRE_PROTOCOL,
        "message_id": "sha256:" + "0" * 64,
        "sender": spec["sender"],
        "recipient": spec["recipient"],
        "message_class": spec["message_class"],
        "payload_ref": spec["payload_ref"],
        "provenance_ref": spec["provenance_ref"],
        "issued_at": spec["issued_at"],
        "expires_at": spec["expires_at"],
        "authority_claim": "none",
        "signature": None,
    }
    envelope["message_id"] = derive_message_id(envelope)
    validate_unsigned_envelope(envelope)
    return envelope


def validate_unsigned_envelope(envelope: dict[str, Any]) -> None:
    required = {"protocol", "message_id", "sender", "recipient", "message_class", "payload_ref", "provenance_ref", "issued_at", "expires_at", "authority_claim", "signature"}
    if not isinstance(envelope, dict) or set(envelope) != required or envelope["protocol"] != WIRE_PROTOCOL or envelope["authority_claim"] != "none" or envelope["signature"] is not None:
        raise SdkError("sdk_envelope_invalid")
    spec = {key: envelope[key] for key in ("sender", "recipient", "message_class", "payload_ref", "provenance_ref", "issued_at", "expires_at")}
    _validate_envelope_spec(spec, "sdk_envelope_invalid")
    if not _is_sha256_ref(envelope["message_id"]) or derive_message_id(envelope) != envelope["message_id"]:
        raise SdkError("sdk_envelope_invalid")


def conformance_result(fixture: dict[str, Any]) -> dict[str, Any]:
    if fixture.get("schema") != "qsol-fed-sdk-conformance/1" or fixture.get("wire_protocol") != WIRE_PROTOCOL:
        raise SdkError("phase6_fixture_contract_invalid")
    validate_node_manifest(fixture["node_manifest"])
    validate_third_party_profile(fixture["third_party_profile"])
    source = fixture["provenance"]
    provenance = build_provenance(source["source_node"], source["source_object"], source["relation"], source["parents"], source["created_at"])
    hello = build_unsigned_envelope(fixture["hello"])
    evidence = build_unsigned_envelope(fixture["evidence_offer"])
    result = {
        "schema": "qsol-fed-sdk-conformance-result/1",
        "implementation": "language-neutral",
        "node_manifest_canonical": canonicalize(fixture["node_manifest"]).decode(),
        "node_manifest_object_id": object_id(fixture["node_manifest"]),
        "profile_canonical": canonicalize(fixture["third_party_profile"]).decode(),
        "profile_object_id": object_id(fixture["third_party_profile"]),
        "payload_canonical": canonicalize(fixture["payload"]).decode(),
        "payload_object_id": object_id(fixture["payload"]),
        "provenance_canonical": canonicalize(provenance).decode(),
        "provenance_object_id": object_id(provenance),
        "hello_canonical": canonicalize(hello).decode(),
        "hello_message_id": hello["message_id"],
        "evidence_canonical": canonicalize(evidence).decode(),
        "evidence_message_id": evidence["message_id"],
        "qsol_governance_adopted": fixture["third_party_profile"]["qsol_governance_adopted"],
        "nexus_required": fixture["third_party_profile"]["nexus_required"],
        "council_required": fixture["third_party_profile"]["council_required"],
        "authority_effect": "none",
    }
    expected = fixture["expected"]
    for key, value in expected.items():
        if result.get(key) != value:
            raise SdkError(f"phase6_expected_mismatch:{key}")
    return result
