#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_COMMIT = "c953463724cdf218802e66e16f582ae8d600ca47"
TARGET_TREE = "93f23cd7eda6dd92ae13b7bb96bee01935b80731"
REPORT_PATH = "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json"
REPORT_SHA = "sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


# Manifest: retain exact MORIARTY report bytes and mark the proof set as branch-verified.
manifest_path = ROOT / "machine/lean-phase10-manifest.json"
manifest = json.loads(manifest_path.read_text())
manifest["status"] = "LEAN_VERIFIED_ON_BRANCH"
manifest["moriarty_binding"]["report_path"] = REPORT_PATH
manifest["moriarty_binding"]["report_sha256"] = REPORT_SHA
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

# README4AI stays JSON and keeps the Phase 8 capability map as the current capability surface.
ai_path = ROOT / "README4AI.md"
ai = json.loads(ai_path.read_text())
ai["status"] = "phase10_lean_formalization_implemented_pending_merge"
ai["phase10_status"] = "lean_formalization_implemented_branch_verified_merge_pending"
ai["formalization_assurance_manifest"] = "claims/phase10.json"
ai["claim_boundary"] = (
    "Phase 8 remains the current runtime/protocol capability surface. Phase 9 adds provider-neutral "
    "MORIARTY/1 exact-commit adversarial graduation assurance. Phase 10 adds a post-tag Lean 4 formal "
    "model of selected invariants from immutable v0.11.0 without promoting runtime capability. The "
    "47 graduation theorems compile on pinned Lean 4.33.1 with no sorry/admit, no custom axioms, and "
    "no kernel axiom dependencies. LEAN THEOREM != DEPLOYMENT SECURITY PROOF."
)
ai["phase10_lean"] = {
    "contract": "state/phase10.json",
    "assurance_manifest": "claims/phase10.json",
    "documentation": "FORMALIZATION.md",
    "theorem_manifest": "machine/lean-phase10-manifest.json",
    "theorem_manifest_schema": "schemas/lean-phase10-manifest-v1.schema.json",
    "model": "QSOLFed/Model.lean",
    "theorems": "QSOLFed/Theorems.lean",
    "axiom_audit": "QSOLFed/AxiomAudit.lean",
    "gate_validator": "tools/validate_phase10_gate.py",
    "workflow": ".github/workflows/phase10-lean.yml",
    "source_release": "v0.11.0",
    "source_commit": TARGET_COMMIT,
    "source_tree": TARGET_TREE,
    "source_release_immutable": True,
    "retained_moriarty_report": REPORT_PATH,
    "retained_moriarty_report_sha256": REPORT_SHA,
    "lean_version": "4.33.1",
    "theorem_count": 47,
    "sorry_or_admit": False,
    "custom_axioms": False,
    "kernel_axiom_dependencies": False,
    "whole_implementation_verified": False,
    "deployment_security_proof": False,
    "source_release_rewritten": False,
}
precedence = ai.get("normative_precedence", [])
for item, after in (
    ("claims/phase10.json", "claims/phase9.json"),
    ("state/phase10.json", "state/phase9.json"),
    ("machine/lean-phase10-manifest.json", "state/phase10.json"),
    ("schemas/lean-phase10-manifest-v1.schema.json", "machine/lean-phase10-manifest.json"),
    ("FORMALIZATION.md", "MORIARTY.md"),
):
    if item not in precedence:
        idx = precedence.index(after) + 1
        precedence.insert(idx, item)
ai["normative_precedence"] = precedence
ai_path.write_text(json.dumps(ai, indent=2) + "\n")

# ROADMAP: current branch reflects implemented candidate status while the immutable tag remains historical source.
roadmap_path = ROOT / "ROADMAP.md"
roadmap = roadmap_path.read_text()
old_phase10 = '''## Phase 10 — Lean 4 formalization

**Status: planned. Begins only after an exact merged commit passes its own MORIARTY/1 workflow run.**

Bind the Lean package to the exact Moriarty-surviving merged commit, invariant IDs, contracts, schemas, phase gates, attack corpus and adversarial report. Initial theorem targets include Prime Directive admission, signature/trust/authority separation, peering/capability separation, import non-authority, lifecycle monotonicity, partition sovereignty, provenance preservation, canonical identity determinism, Holodeck separation/safeguards, adapter non-authority, SDK conformance boundaries, Assembly sovereignty, and transport identity/provenance independence.

No unresolved `sorry`/`admit` is permitted in the graduation theorem set; assumptions must be named and theorem-to-contract traceability complete.

### Phase 10 gate

The theorem manifest must compile from a clean checkout of the exact Moriarty-surviving lineage on a pinned Lean toolchain.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
```
'''
new_phase10 = '''## Phase 10 — Lean 4 formalization

**Status: implemented on the post-tag formalization layer; branch verification green, reviewed merge/main verification pending.**

The sole theorem source target is immutable release `v0.11.0`, exact commit `c953463724cdf218802e66e16f582ae8d600ca47`, exact tree `93f23cd7eda6dd92ae13b7bb96bee01935b80731`. The Lean files are later artifacts and do not rewrite that release.

- [x] Bind the theorem manifest to the immutable source release, invariant IDs, contracts, schemas, phase gates, attack corpus and exact merged-main MORIARTY report.
- [x] Retain the exact source MORIARTY report bytes after GitHub artifact verification.
- [x] Pin Lean 4.33.1 and the downloaded archive SHA-256.
- [x] Formalize all 13 initial theorem families named by the frozen roadmap.
- [x] Provide 47 theorem-to-contract-traceable graduation theorems.
- [x] Reject unresolved `sorry`/`admit` and custom `axiom` declarations.
- [x] Audit all 47 graduation theorems with `#print axioms`; current candidate has zero kernel axiom dependencies.
- [x] Preserve the Phase 8 capability surface and Phase 9 adversarial-assurance boundary unchanged.
- [ ] Merge the reviewed formalization PR and require the exact merged `main` commit to pass the same pinned Lean workflow before recording Phase 10 complete/`LEAN_VERIFIED` externally.

The formal model covers Prime Directive admission, signature/trust/authority separation, peering/capability separation, import non-authority, lifecycle monotonicity, partition sovereignty, provenance preservation, canonical identity determinism, Holodeck separation/safeguards, adapter non-authority, SDK conformance boundaries, Assembly sovereignty, and transport identity/provenance independence.

### Phase 10 gate

From a clean post-tag checkout, the gate must verify immutable `v0.11.0` source identity, frozen source blobs, retained MORIARTY report bytes, complete theorem-to-contract traceability and the pinned Lean archive; then compile all 47 graduation theorems with no unresolved placeholders, custom axioms or kernel axiom dependencies. Final completion additionally requires the reviewed formalization merge and exact merged-main workflow success.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER
```
'''
roadmap = replace_once(roadmap, old_phase10, new_phase10, "ROADMAP Phase 10")
roadmap_path.write_text(roadmap)

# AGENTS: make Phase 10 part of the machine contribution contract.
ag_path = ROOT / "AGENTS.md"
ag = ag_path.read_text()
ag = replace_once(
    ag,
    "`state/phase8.json`, `state/phase9.json`, `CANONICAL_JSON.md`",
    "`state/phase8.json`, `state/phase9.json`, `state/phase10.json`, `claims/phase10.json`, `machine/lean-phase10-manifest.json`, `schemas/lean-phase10-manifest-v1.schema.json`, `FORMALIZATION.md`, `QSOLFed/Model.lean`, `QSOLFed/Theorems.lean`, `QSOLFed/AxiomAudit.lean`, `tools/validate_phase10_gate.py`, `CANONICAL_JSON.md`",
    "AGENTS read-first Phase 10",
)
phase10_rules = '''### Current Phase 10 Lean 4 formalization rules

`state/phase10.json`, `claims/phase10.json`, `machine/lean-phase10-manifest.json`, `schemas/lean-phase10-manifest-v1.schema.json`, `FORMALIZATION.md`, `QSOLFed/*.lean`, `lean-toolchain`, `lakefile.toml`, `tools/validate_phase10_gate.py`, and `.github/workflows/phase10-lean.yml` define the post-tag formalization layer.

- The sole source target is immutable `v0.11.0` at commit `c953463724cdf218802e66e16f582ae8d600ca47` / tree `93f23cd7eda6dd92ae13b7bb96bee01935b80731`.
- Never move the source target to current `main`; formalization files are later artifacts and do not rewrite the source release.
- The retained Phase 9 MORIARTY report must match its recorded SHA-256 and exact source identity.
- `claims/phase10.json` must preserve the Phase 9/Phase 8 capability map exactly. Lean adds assurance only.
- Every graduation theorem must appear in the theorem manifest with frozen source refs and contract/boundary IDs.
- No unresolved `sorry`/`admit`, custom `axiom`, or kernel axiom dependency is permitted in the 47-theorem graduation set.
- Named scope assumptions live in the manifest; do not disguise implementation/deployment assumptions as theorems.
- `canonical_identity_deterministic` does not prove production canonicalizer correctness or SHA-256 collision resistance.
- Do not claim whole-Rust verification, deployment security proof, host-sandbox proof, or real-world principal uniqueness.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER
```

Run `python3 tools/validate_phase10_gate.py`, `lake build`, and `lake env lean QSOLFed/AxiomAudit.lean` after formalization/manifest/contract/claim/documentation changes.

'''
ag = replace_once(ag, "### Claim discipline\n", phase10_rules + "### Claim discipline\n", "AGENTS Phase 10 section")
ag = replace_once(
    ag,
    "Current adversarial-assurance manifest: `claims/phase9.json`.",
    "Current adversarial-assurance manifest: `claims/phase9.json`. Current formalization-assurance manifest: `claims/phase10.json`.",
    "AGENTS claim discipline",
)
ag = replace_once(
    ag,
    'python3 tools/validate_phase9_gate.py --target-commit "$(git rev-parse HEAD)"\n```',
    'python3 tools/validate_phase9_gate.py --target-commit "$(git rev-parse HEAD)"\npython3 tools/validate_phase10_gate.py\nlake build\nlake env lean QSOLFed/AxiomAudit.lean\n```',
    "AGENTS tests",
)
ag_path.write_text(ag)

# Validator: strengthen evidence/contract/schema/claim checks.
val_path = ROOT / "tools/validate_phase10_gate.py"
val = val_path.read_text()
val = replace_once(val, "import argparse\nimport json\n", "import argparse\nimport hashlib\nimport json\n", "validator hashlib import")
val = replace_once(
    val,
    'MANIFEST_PATH = ROOT / "machine/lean-phase10-manifest.json"\n',
    'MANIFEST_PATH = ROOT / "machine/lean-phase10-manifest.json"\nMANIFEST_SCHEMA_PATH = ROOT / "schemas/lean-phase10-manifest-v1.schema.json"\nSTATE_PATH = ROOT / "state/phase10.json"\nCLAIMS_PATH = ROOT / "claims/phase10.json"\nREPORT_PATH = ROOT / "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json"\nREPORT_SHA256 = "6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c"\n',
    "validator constants",
)
old_moriarty_tail = '''        "artifact_digest": "sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce",
        "target_commit": TARGET_COMMIT,
'''
new_moriarty_tail = '''        "artifact_digest": "sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce",
        "report_path": "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json",
        "report_sha256": "sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c",
        "target_commit": TARGET_COMMIT,
'''
val = replace_once(val, old_moriarty_tail, new_moriarty_tail, "validator MORIARTY expected fields")
old_moriarty_end = '    require({key: binding.get(key) for key in expected} == expected, "MORIARTY binding drift")\n\n\ndef verify_frozen_inputs'
new_moriarty_end = '''    require({key: binding.get(key) for key in expected} == expected, "MORIARTY binding drift")
    require(REPORT_PATH.is_file(), "retained MORIARTY report missing")
    report_bytes = REPORT_PATH.read_bytes()
    require(hashlib.sha256(report_bytes).hexdigest() == REPORT_SHA256, "retained MORIARTY report SHA-256 drift")
    report = json.loads(report_bytes.decode("utf-8"))
    report_expected = {
        "protocol": "MORIARTY/1",
        "schema": "moriarty-report/1",
        "target_commit": TARGET_COMMIT,
        "corpus_ref": expected["corpus_ref"],
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
        "no_counterexample_found_implies_none_exist": False,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "authority_effect": "none",
    }
    require({key: report.get(key) for key in report_expected} == report_expected, "retained MORIARTY report semantic drift")
    require(report.get("counterexamples") == [] and report.get("remediation_replays") == [], "retained MORIARTY report counterexample/replay drift")
    probes = report.get("probe_results")
    require(isinstance(probes, list) and len(probes) == 13, "retained MORIARTY probe inventory drift")
    expected_probe_ids = {"constitution", "phase0", "phase1", "phase2", "phase3", "phase4", "phase5a", "phase5", "phase5c", "phase6", "phase7", "phase8", "rust_all"}
    require({item.get("probe_id") for item in probes if isinstance(item, dict)} == expected_probe_ids, "retained MORIARTY probe ID drift")
    require(all(item.get("ok") is True and item.get("exit_code") == 0 and item.get("failure_kind") is None for item in probes), "retained MORIARTY probe failure")


def verify_frozen_inputs'''
val = replace_once(val, old_moriarty_end, new_moriarty_end, "validator retained MORIARTY report")
val = replace_once(
    val,
    '    require(manifest.get("status") == "IMPLEMENTED_PENDING_CI", "manifest must not pre-claim LEAN_VERIFIED")\n',
    '    require(manifest.get("status") in {"IMPLEMENTED_PENDING_CI", "LEAN_VERIFIED_ON_BRANCH", "LEAN_VERIFIED_ON_MERGED_MAIN"}, "manifest verification status drift")\n',
    "validator status",
)
phase10_contract_fn = '''

def verify_phase10_contracts(manifest: dict) -> None:
    state = load_json(STATE_PATH)
    claims = load_json(CLAIMS_PATH)
    phase9_claims = load_json(ROOT / "claims/phase9.json")
    phase8_claims = load_json(ROOT / "claims/phase8.json")
    schema = load_json(MANIFEST_SCHEMA_PATH)

    require(state.get("document_type") == "qsol-fed-phase10-lean-contract" and state.get("phase") == "10", "Phase 10 state contract identity drift")
    source = state.get("source_release", {})
    require(source.get("tag") == TARGET_TAG and source.get("commit") == TARGET_COMMIT and source.get("tree") == TARGET_TREE and source.get("immutable") is True, "Phase 10 state source release drift")
    scope = state.get("theorem_scope", {})
    require(scope.get("theorem_count") == EXPECTED_THEOREM_COUNT, "Phase 10 state theorem count drift")
    require(scope.get("no_sorry_or_admit") is True and scope.get("custom_axioms") == [] and scope.get("kernel_axiom_dependencies") == [], "Phase 10 state proof-discipline drift")
    evidence = state.get("moriarty_source_evidence", {})
    require(evidence.get("retained_report") == str(REPORT_PATH.relative_to(ROOT)) and evidence.get("retained_report_sha256") == "sha256:" + REPORT_SHA256, "Phase 10 state MORIARTY report binding drift")

    require(claims.get("document_type") == "qsol-fed-phase10-lean-claims" and claims.get("phase") == "10", "Phase 10 claim identity drift")
    require(claims.get("claim_surface_changed") is False, "Phase 10 must not change runtime capability claims")
    require(claims.get("capabilities") == phase9_claims.get("capabilities") == phase8_claims.get("capabilities"), "Phase 10 capability map differs from Phase 9/8 baseline")
    assurance = claims.get("formalization_assurance", {})
    require(assurance.get("theorem_count") == EXPECTED_THEOREM_COUNT, "Phase 10 formalization assurance theorem count drift")
    require(assurance.get("unresolved_sorry_or_admit") is False and assurance.get("custom_axioms") is False and assurance.get("graduation_theorem_kernel_axiom_dependencies") is False, "Phase 10 formalization assurance proof-discipline drift")
    require(assurance.get("whole_implementation_verified") is False and assurance.get("deployment_security_proof") is False and assurance.get("source_release_rewritten") is False, "Phase 10 formalization assurance overclaim")

    require(schema.get("$id") == "https://qsol.example/schemas/lean-phase10-manifest-v1.schema.json", "Phase 10 manifest schema ID drift")
    properties = schema.get("properties", {})
    require(properties.get("theorem_count", {}).get("const") == EXPECTED_THEOREM_COUNT, "Phase 10 manifest schema theorem count drift")
    require(manifest.get("status") in properties.get("status", {}).get("enum", []), "Phase 10 manifest status not admitted by schema")
    report_const = properties.get("moriarty_binding", {}).get("properties", {}).get("report_sha256", {}).get("const")
    require(report_const == "sha256:" + REPORT_SHA256, "Phase 10 manifest schema report digest drift")

    docs = (ROOT / "FORMALIZATION.md").read_text(encoding="utf-8")
    for text in (TARGET_TAG, TARGET_COMMIT, TARGET_TREE, "LEAN THEOREM != DEPLOYMENT SECURITY PROOF", "TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER"):
        require(text in docs, f"FORMALIZATION.md missing boundary/source text: {text}")
'''
val = replace_once(val, "\ndef validate() -> dict:\n", phase10_contract_fn + "\ndef validate() -> dict:\n", "validator phase10 contracts")
val = replace_once(
    val,
    "    verify_moriarty_binding(manifest)\n    frozen_inputs = verify_frozen_inputs(manifest)\n",
    "    verify_moriarty_binding(manifest)\n    verify_phase10_contracts(manifest)\n    frozen_inputs = verify_frozen_inputs(manifest)\n",
    "validator call phase10 contracts",
)
val_path.write_text(val)

# Workflow retains the evidence needed to audit a successful Phase 10 candidate.
wf_path = ROOT / ".github/workflows/phase10-lean.yml"
wf = wf_path.read_text()
wf = replace_once(
    wf,
    "            machine/lean-phase10-manifest.json\n            ${{ runner.temp }}/phase10-gate.json\n            ${{ runner.temp }}/phase10-axioms.txt\n",
    "            machine/lean-phase10-manifest.json\n            state/phase10.json\n            claims/phase10.json\n            schemas/lean-phase10-manifest-v1.schema.json\n            FORMALIZATION.md\n            lean-toolchain\n            lakefile.toml\n            evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json\n            ${{ runner.temp }}/phase10-gate.json\n            ${{ runner.temp }}/phase10-axioms.txt\n",
    "workflow evidence bundle",
)
wf_path.write_text(wf)

print("Phase 10 contracts synchronized")
