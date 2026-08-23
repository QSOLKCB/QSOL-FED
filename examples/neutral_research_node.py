#!/usr/bin/env python3
"""Minimal third-party federation participant using only qsol-fed-sdk/1."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk/python"
sys.path.insert(0, str(SDK))

from qsol_fed_sdk import (
    build_node_manifest,
    build_unsigned_envelope,
    canonicalize,
    object_id,
    validate_provenance,
    validate_third_party_profile,
)


def build_participation() -> dict:
    profile = {
        "schema": "third-party-node-profile/1",
        "implementation": "neutral-research-node",
        "governance_model": "local",
        "qsol_governance_adopted": False,
        "nexus_required": False,
        "council_required": False,
    }
    validate_third_party_profile(profile)

    manifest = build_node_manifest(
        "fed:qsol:neutral-lab-01",
        ["evidence.exchange/1", "federation.sdk/1"],
    )
    payload = {
        "schema": "third-party-payload/1",
        "kind": "research.notice",
        "note": "Neutral laboratory result available",
    }
    payload_ref = object_id(payload)
    provenance = {
        "schema": "qsol-fed-provenance/1",
        "source_node": manifest["node_id"],
        "source_object": payload_ref,
        "relation": "observed",
        "parents": [],
        "created_at": "2026-08-23T00:00:00Z",
    }
    validate_provenance(provenance)

    hello = build_unsigned_envelope({
        "sender": manifest["node_id"],
        "recipient": "fed:qsol:reference-node",
        "message_class": "hello",
        "payload_ref": object_id(manifest),
        "provenance_ref": None,
        "issued_at": "2026-08-23T00:00:00Z",
        "expires_at": None,
    })
    evidence = build_unsigned_envelope({
        "sender": manifest["node_id"],
        "recipient": "fed:qsol:reference-node",
        "message_class": "evidence.offer",
        "payload_ref": payload_ref,
        "provenance_ref": object_id(provenance),
        "issued_at": "2026-08-23T00:00:01Z",
        "expires_at": None,
    })

    return {
        "schema": "third-party-federation-participation/1",
        "participant": "neutral-research-node",
        "wire_protocol": "qsol-fed/1",
        "governance_model": "local",
        "qsol_governance_adopted": False,
        "nexus_required": False,
        "council_required": False,
        "oracle_required": False,
        "ark_required": False,
        "holodeck_required": False,
        "authority_effect": "none",
        "node_manifest_object_id": object_id(manifest),
        "payload_object_id": payload_ref,
        "provenance_object_id": object_id(provenance),
        "hello_message_id": hello["message_id"],
        "evidence_message_id": evidence["message_id"],
        "hello_canonical": canonicalize(hello).decode("utf-8"),
        "evidence_canonical": canonicalize(evidence).decode("utf-8"),
    }


def main() -> None:
    sys.stdout.buffer.write(canonicalize(build_participation()) + b"\n")


if __name__ == "__main__":
    main()
