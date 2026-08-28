# QSOL-FED Phase 10 Lean 4 Formalization

Phase 10 is a **post-tag formalization layer** over the immutable QSOL-FED v0.11.0 Phase 9 source release.

## Frozen source target

The only source target for this theorem batch is:

```text
release  = v0.11.0
commit   = c953463724cdf218802e66e16f582ae8d600ca47
tree     = 93f23cd7eda6dd92ae13b7bb96bee01935b80731
immutable = true
```

The formalization files are intentionally **not** part of v0.11.0. They are a later layer proving selected propositions about the contracts frozen by that release.

```text
MOVING MAIN != FORMALIZATION TARGET
TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER
```

## What is formalized

The graduation set contains 47 named Lean theorems covering the 13 initial Phase 10 target families from the frozen ROADMAP:

1. Prime Directive admission.
2. Signature / trust / authority separation.
3. Peering / capability separation.
4. Import non-authority.
5. Lifecycle monotonicity.
6. Partition sovereignty.
7. Provenance preservation.
8. Canonical identity determinism.
9. Holodeck separation and safeguards.
10. Adapter non-authority.
11. SDK conformance boundaries.
12. Assembly sovereignty.
13. Transport identity and provenance independence.

The abstract model is in `QSOLFed/Model.lean`; graduation theorems are in `QSOLFed/Theorems.lean`; `QSOLFed/TypeAudit.lean` ascribes the fully elaborated environment type of every graduation theorem to its exact expected proposition; and `QSOLFed/AxiomAudit.lean` audits kernel axiom dependencies. `machine/lean-phase10-manifest.json` maps every graduation theorem to frozen source contracts and boundary IDs.

## What is not formalized

The Lean package does **not** claim whole-program verification of the Rust, Python, or TypeScript implementations. It does not prove that every implementation path refines the abstract model, prove deployment hardening, prove host or VM isolation, prove real-world principal uniqueness, or prove SHA-256 collision resistance.

The canonical-identity theorem proves determinism **given equal canonical bytes and an identity function**. Correctness of the production canonicalizers and cryptographic assumptions remain separate executable/cryptographic obligations.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
LEAN MODEL != COMPLETE RUST IMPLEMENTATION VERIFICATION
```

## Named assumptions

The machine manifest names three scope assumptions rather than leaving them implicit:

- `MODEL_SCOPE`: the Lean definitions model the stated v0.11.0 contract semantics; full implementation correspondence is external to this theorem batch.
- `CANONICAL_BYTES_INPUT`: canonical identity determinism assumes equal canonical byte inputs and does not prove canonicalizer correctness or SHA-256 collision resistance.
- `REAL_WORLD_PRINCIPALS`: real-world identity uniqueness, operational hardening, credentials, and host isolation remain outside the theorem model unless explicitly represented.

These are scope assumptions, not Lean `axiom` declarations.

## MORIARTY source evidence

The theorem manifest is bound to the exact merged-main MORIARTY/1 run for the source release:

```text
workflow run  = 33069191846 (#413)
artifact ID   = 9645064099
artifact ZIP  = sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce
report SHA256 = sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c
families      = 15
probes        = 13
unresolved    = 0
graduated     = true
security proof = false
```

The exact report bytes are retained at `evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json` so Phase 10 does not depend on the temporary lifetime of a GitHub Actions artifact.

## Toolchain

The package is dependency-free beyond Lean core and uses:

```text
Lean     = v4.33.1
Lake     = 5.0.0-src+819816b
archive  = lean-4.33.1-linux.tar.zst
SHA-256  = 890afd185370f85666025b883914ab4f4b339136f8c96167b69cfb62aecaf235
```

CI downloads the archive directly, verifies the checksum, then builds the Lake package.

## Graduation checks

`tools/validate_phase10_gate.py` and `.github/workflows/phase10-lean.yml` require all of the following:

- `v0.11.0` is still reported immutable by GitHub.
- the tag is a direct commit reference to the exact source commit.
- the source commit resolves to the exact source tree.
- every named frozen input resolves to its recorded Git blob.
- the retained MORIARTY report matches its recorded SHA-256 and exact source identity.
- every theorem declaration in the manifest exists in `QSOLFed/Theorems.lean`.
- every theorem has source-contract and boundary traceability.
- `QSOLFed/TypeAudit.lean` ascribes all 47 fully elaborated theorem constants to their exact expected types, exposing any hidden or implicit parameters.
- no `sorry` or `admit` occurs in the Lean source.
- no custom `axiom` declaration occurs in the Lean source.
- all 47 graduation theorems compile.
- `#print axioms` reports **no kernel axiom dependencies** for the graduation theorem set.

A successful branch run establishes that the candidate formalization compiles under this gate. Phase 10 should be promoted to complete only after the reviewed formalization PR is merged and the exact merged `main` commit passes the same workflow.

## Local verification

With Lean 4.33.1 available on `PATH`:

```bash
python3 tools/validate_phase10_gate.py
lake build
lake env lean QSOLFed/TypeAudit.lean
lake env lean QSOLFed/AxiomAudit.lean
```

The frozen v0.11.0 tag must be present in the Git object database because the gate verifies the theorem source identity directly.
