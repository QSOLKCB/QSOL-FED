#!/usr/bin/env python3
"""Adversarial regressions for the independent Phase 6 Python SDK."""
from __future__ import annotations

import unittest

from qsol_fed_sdk import (
    SdkError,
    build_provenance,
    build_unsigned_envelope,
    canonicalize,
    derive_message_id,
    validate_third_party_profile,
    validate_unsigned_envelope,
)


class Phase6PythonSdkAdversarialTests(unittest.TestCase):
    def test_raw_canonical_output_limit_applies_after_nfc(self) -> None:
        chunk = "\u0344" * 2040
        raw = "[" + ",".join('"' + chunk + '"' for _ in range(15)) + "]"
        self.assertLess(len(raw.encode("utf-8")), 65_536)
        with self.assertRaisesRegex(SdkError, "output_too_large"):
            canonicalize(raw)

    def test_timestamp_digits_are_ascii_only(self) -> None:
        with self.assertRaisesRegex(SdkError, "sdk_provenance_invalid"):
            build_provenance(
                "fed:qsol:neutral-lab-01",
                "sha256:" + "1" * 64,
                "observed",
                [],
                "٢٠٢٦-٠٨-٢٣T٠٠:٠٠:٠٠Z",
            )

    def test_caller_supplied_envelope_validates_every_wire_field(self) -> None:
        envelope = build_unsigned_envelope({
            "sender": "fed:qsol:neutral-lab-01",
            "recipient": "fed:qsol:reference-node",
            "message_class": "hello",
            "payload_ref": "sha256:" + "2" * 64,
            "provenance_ref": None,
            "issued_at": "2026-08-23T00:00:00Z",
            "expires_at": None,
        })
        envelope["sender"] = "not-a-node"
        envelope["message_id"] = derive_message_id(envelope)
        with self.assertRaisesRegex(SdkError, "sdk_envelope_invalid"):
            validate_unsigned_envelope(envelope)

    def test_profile_length_counts_unicode_scalar_values(self) -> None:
        base = {
            "schema": "third-party-node-profile/1",
            "governance_model": "local",
            "qsol_governance_adopted": False,
            "nexus_required": False,
            "council_required": False,
        }
        validate_third_party_profile({**base, "implementation": "🛰" * 128})
        with self.assertRaisesRegex(SdkError, "third_party_profile_invalid"):
            validate_third_party_profile({**base, "implementation": "🛰" * 129})


if __name__ == "__main__":
    unittest.main()
