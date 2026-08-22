# QSOL-FED Canonical JSON / 1

**Profile:** `qsol-fed-canonical-json/1`

This document freezes the byte-level JSON contract used by QSOL-FED Phase 1. It is intentionally smaller than general-purpose JSON so independent implementations can produce byte-identical data without depending on language-specific floating-point formatting or permissive parser behavior.

## Accepted value domain

Canonical wire values may contain only:

- `null`;
- booleans;
- Unicode strings;
- arrays;
- objects with string keys;
- integers in the inclusive range `[-9007199254740991, 9007199254740991]`.

Floating-point and decimal JSON numbers are not part of this v1 profile. `NaN`, `Infinity`, `-Infinity`, exponent forms, decimal forms, and integers outside the safe range are rejected.

## Input rules

1. Input MUST be UTF-8 without a BOM.
2. Duplicate object keys MUST be rejected before canonicalization.
3. Every key and string value is normalized to Unicode NFC.
4. If two distinct input keys normalize to the same NFC key, the object MUST be rejected.
5. Lone Unicode surrogate code points are invalid.
6. Trailing non-whitespace data is invalid.
7. Parsers MUST reject unsupported JSON extensions, comments, trailing commas, and non-finite numeric tokens.

## Resource limits

The Phase 1 reference profile freezes these parser limits:

```text
max_input_bytes     = 65536
max_depth           = 32
max_string_utf8     = 8192
max_array_items     = 1024
max_object_members  = 1024
```

These are conformance limits, not claims of production network DoS hardening.

## Serialization

Canonical output is UTF-8 with no BOM and no trailing newline.

- no insignificant whitespace;
- object keys sorted by normalized Unicode scalar-value order;
- array order preserved;
- integers emitted in base 10 with no leading zero and `0` used for negative zero input;
- strings emitted in NFC;
- `/` is never escaped;
- `"` and `\\` are escaped;
- U+0008, U+000C, U+000A, U+000D and U+0009 use `\b`, `\f`, `\n`, `\r`, `\t`;
- other U+0000..U+001F code points use lowercase `\u00xx` escapes;
- all other Unicode scalar values are emitted directly as UTF-8.

## Object identity

For any accepted canonical object `X`:

```text
object_id(X) = "sha256:" + lowercase_hex(SHA-256(canonical_bytes(X)))
```

The digest is always 64 lowercase hexadecimal characters.

## Federation message ID

For a Federation envelope `E`, define projection `P(E)` by removing exactly the top-level fields `message_id` and `signature`.

Then:

```text
preimage = UTF8("qsol-fed-message-id/1") || 0x00 || canonical_bytes(P(E))
message_id(E) = "sha256:" + lowercase_hex(SHA-256(preimage))
```

The domain separator prevents the message identifier from being confused with ordinary object identity. Signatures are deliberately excluded so Phase 2 signing does not alter message identity.

## Independent implementations

Phase 1 ships two separate implementations:

- Rust: `src/canonical.rs`;
- Python: `tools/qsol_canonical.py`.

Both are tested against the same language-neutral golden vectors. Phase 1 is not considered complete unless both produce byte-identical canonical bytes, SHA-256 object identities, and message IDs for all positive vectors, while rejecting the adversarial corpus.
