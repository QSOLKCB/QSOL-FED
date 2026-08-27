#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "machine/lean-phase10-manifest.json"
MANIFEST_SCHEMA_PATH = ROOT / "schemas/lean-phase10-manifest-v1.schema.json"
STATE_PATH = ROOT / "state/phase10.json"
CLAIMS_PATH = ROOT / "claims/phase10.json"
AXIOM_AUDIT_PATH = ROOT / "QSOLFed/AxiomAudit.lean"
REPORT_PATH = ROOT / "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json"
REPORT_SHA256 = "6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c"
TARGET_TAG = "v0.11.0"
TARGET_COMMIT = "c953463724cdf218802e66e16f582ae8d600ca47"
TARGET_TREE = "93f23cd7eda6dd92ae13b7bb96bee01935b80731"
LEAN_TOOLCHAIN = "leanprover/lean4:v4.33.1"
LEAN_ARCHIVE_SHA256 = "890afd185370f85666025b883914ab4f4b339136f8c96167b69cfb62aecaf235"
EXPECTED_THEOREM_COUNT = 47
PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b")
DECL_RE_TEMPLATE = r"\btheorem\s+{name}\b"
AXIOM_PRINT_RE = re.compile(r"(?m)^[ \t]*#print[ \t]+axioms[ \t]+QSOLFed\.([a-z][a-z0-9_]*)[ \t]*$")


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    return result.stdout.strip()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_frozen_target(manifest: dict) -> None:
    require(git("cat-file", "-t", TARGET_COMMIT) == "commit", "frozen target is not a commit object")
    require(git("rev-parse", f"{TARGET_TAG}^{{commit}}") == TARGET_COMMIT, "v0.11.0 does not resolve to frozen target commit")
    require(git("cat-file", "-t", TARGET_TAG) == "commit", "v0.11.0 is not a direct commit tag ref")
    require(git("rev-parse", f"{TARGET_COMMIT}^{{tree}}") == TARGET_TREE, "frozen target tree drift")

    release = manifest.get("source_release", {})
    expected = {
        "id": 377808649,
        "tag": TARGET_TAG,
        "immutable": True,
        "commit": TARGET_COMMIT,
        "tree": TARGET_TREE,
        "published_at": "2026-08-27T12:35:21Z",
    }
    require({key: release.get(key) for key in expected} == expected, "manifest frozen release identity drift")


def verify_moriarty_binding(manifest: dict) -> None:
    binding = manifest.get("moriarty_binding", {})
    expected = {
        "protocol": "MORIARTY/1",
        "workflow_run": 33069191846,
        "run_number": 413,
        "artifact_id": 9645064099,
        "artifact_digest": "sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce",
        "report_path": "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json",
        "report_sha256": "sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c",
        "target_commit": TARGET_COMMIT,
        "corpus_ref": "sha256:af50e8145a72a1a583ede29687535a59c0e17ac37fdd66e1ede51c453e8fd3e6",
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
    }
    require({key: binding.get(key) for key in expected} == expected, "MORIARTY binding drift")
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


def verify_frozen_inputs(manifest: dict) -> set[str]:
    items = manifest.get("frozen_inputs")
    require(isinstance(items, list) and items, "frozen_inputs must be a nonempty list")
    seen: set[str] = set()
    for item in items:
        require(set(item) == {"path", "git_blob_sha1"}, "frozen input field set drift")
        path = item["path"]
        blob = item["git_blob_sha1"]
        require(isinstance(path, str) and path and path not in seen, f"invalid/duplicate frozen input path: {path!r}")
        require(re.fullmatch(r"[0-9a-f]{40}", blob) is not None, f"invalid frozen input blob: {path}")
        actual = git("rev-parse", f"{TARGET_TAG}:{path}")
        require(actual == blob, f"frozen input blob drift: {path}: {actual} != {blob}")
        require(git("cat-file", "-t", actual) == "blob", f"frozen input is not a blob: {path}")
        seen.add(path)
    return seen


def verify_toolchain(manifest: dict) -> None:
    require((ROOT / "lean-toolchain").read_text(encoding="utf-8").strip() == LEAN_TOOLCHAIN, "lean-toolchain drift")
    toolchain = manifest.get("toolchain", {})
    require(toolchain.get("lean") == "v4.33.1", "manifest Lean version drift")
    require(toolchain.get("lean_toolchain") == LEAN_TOOLCHAIN, "manifest lean-toolchain drift")
    require(toolchain.get("archive_sha256") == LEAN_ARCHIVE_SHA256, "manifest Lean archive checksum drift")
    require(toolchain.get("external_dependencies") == [], "Phase 10 must remain dependency-free beyond Lean core")


def verify_theorems(manifest: dict, frozen_inputs: set[str]) -> None:
    theorems = manifest.get("theorems")
    require(isinstance(theorems, list), "theorems must be a list")
    require(manifest.get("theorem_count") == EXPECTED_THEOREM_COUNT == len(theorems), "theorem count drift")

    ids: set[str] = set()
    declarations: set[str] = set()
    file_cache: dict[str, str] = {}
    for index, theorem in enumerate(theorems, 1):
        required = {"id", "declaration", "module", "path", "source_refs", "contract_ids", "proof_status"}
        require(set(theorem) == required, f"theorem {index} field set drift")
        expected_id = f"FED-LEAN-{index:03d}"
        require(theorem["id"] == expected_id and expected_id not in ids, f"theorem ID drift/duplicate at {index}")
        ids.add(expected_id)
        declaration = theorem["declaration"]
        require(re.fullmatch(r"[a-z][a-z0-9_]*", declaration) is not None, f"invalid theorem declaration: {declaration}")
        require(declaration not in declarations, f"duplicate theorem declaration: {declaration}")
        declarations.add(declaration)
        require(theorem["module"] == "QSOLFed.Theorems", f"unexpected module for {declaration}")
        path = theorem["path"]
        require(path == "QSOLFed/Theorems.lean", f"unexpected theorem path for {declaration}")
        if path not in file_cache:
            file_cache[path] = (ROOT / path).read_text(encoding="utf-8")
        source = file_cache[path]
        require(re.search(DECL_RE_TEMPLATE.format(name=re.escape(declaration)), source) is not None, f"manifest declaration missing from Lean source: {declaration}")
        refs = theorem["source_refs"]
        require(isinstance(refs, list) and refs and len(refs) == len(set(refs)), f"invalid source_refs for {declaration}")
        for ref in refs:
            require(ref in frozen_inputs, f"theorem {declaration} references unbound frozen input {ref}")
        contract_ids = theorem["contract_ids"]
        require(isinstance(contract_ids, list) and contract_ids and all(isinstance(x, str) and x for x in contract_ids), f"missing contract traceability for {declaration}")
        require(theorem["proof_status"] == "IMPLEMENTED", f"unexpected proof status for {declaration}")


def verify_axiom_audit_coverage(manifest: dict) -> None:
    require(AXIOM_AUDIT_PATH.is_file(), "Phase 10 axiom audit source missing")
    audit_source = AXIOM_AUDIT_PATH.read_text(encoding="utf-8")
    audited = AXIOM_PRINT_RE.findall(audit_source)
    expected = [theorem["declaration"] for theorem in manifest.get("theorems", [])]
    require(len(audited) == EXPECTED_THEOREM_COUNT, "Phase 10 axiom audit theorem count drift")
    require(len(audited) == len(set(audited)), "Phase 10 axiom audit contains duplicate theorem entries")
    require(audited == expected, "Phase 10 axiom audit coverage/order differs from theorem manifest")


def verify_no_placeholders() -> None:
    lean_files = sorted(ROOT.glob("QSOLFed/**/*.lean")) + [ROOT / "QSOLFed.lean"]
    require(lean_files, "no Lean source files found")
    for path in lean_files:
        source = path.read_text(encoding="utf-8")
        match = PLACEHOLDER_RE.search(source)
        require(match is None, f"unresolved proof placeholder in {path.relative_to(ROOT)}")


def verify_manifest_policy(manifest: dict) -> None:
    require(manifest.get("schema") == "qsol-fed-lean-phase10-manifest/1", "manifest schema drift")
    require(manifest.get("protocol") == "qsol-fed/0" and manifest.get("phase") == 10, "manifest protocol/phase drift")
    require(manifest.get("status") in {"IMPLEMENTED_PENDING_CI", "LEAN_VERIFIED_ON_BRANCH", "LEAN_VERIFIED_ON_MERGED_MAIN"}, "manifest verification status drift")
    assumptions = manifest.get("assumptions")
    require(isinstance(assumptions, list) and {x.get("id") for x in assumptions} == {"MODEL_SCOPE", "CANONICAL_BYTES_INPUT", "REAL_WORLD_PRINCIPALS"}, "named assumptions drift")
    nonclaims = set(manifest.get("nonclaims", []))
    required_nonclaims = {
        "LEAN_THEOREM != DEPLOYMENT_SECURITY_PROOF",
        "FORMAL_MODEL != UNSTATED_REAL_WORLD_ASSUMPTION",
        "LEAN_MODEL != COMPLETE_RUST_IMPLEMENTATION_VERIFICATION",
        "MORIARTY_REPORT != SECURITY_PROOF",
        "TARGET_BOUND_SOURCE_RELEASE != POST_TAG_FORMALIZATION_LAYER",
    }
    require(required_nonclaims <= nonclaims, "formalization nonclaim boundary drift")
    graduation = manifest.get("graduation_requirements", {})
    require(graduation.get("no_unresolved_sorry_or_admit") is True, "placeholder prohibition missing")
    require(graduation.get("named_assumptions_required") is True, "named assumption requirement missing")
    require(graduation.get("theorem_to_contract_traceability_required") is True, "traceability requirement missing")
    require(graduation.get("clean_checkout_build_required") is True, "clean checkout build requirement missing")
    require(graduation.get("custom_axioms_allowed") == [], "custom axioms must not be admitted")


def verify_frozen_roadmap_contract() -> None:
    roadmap = git("show", f"{TARGET_TAG}:ROADMAP.md")
    required = [
        "Phase 10 — Lean 4 formalization",
        "Prime Directive admission",
        "signature/trust/authority separation",
        "transport identity/provenance independence",
        "No unresolved `sorry`/`admit` is permitted in the graduation theorem set",
        "assumptions must be named and theorem-to-contract traceability complete",
        "LEAN THEOREM != DEPLOYMENT SECURITY PROOF",
        "FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION",
    ]
    for text in required:
        require(text in roadmap, f"frozen Phase 10 ROADMAP contract missing: {text}")


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


def validate() -> dict:
    manifest = load_json(MANIFEST_PATH)
    verify_manifest_policy(manifest)
    verify_frozen_target(manifest)
    verify_moriarty_binding(manifest)
    verify_phase10_contracts(manifest)
    frozen_inputs = verify_frozen_inputs(manifest)
    verify_toolchain(manifest)
    verify_theorems(manifest, frozen_inputs)
    verify_axiom_audit_coverage(manifest)
    verify_no_placeholders()
    verify_frozen_roadmap_contract()
    return {
        "status": "ok",
        "target_tag": TARGET_TAG,
        "target_commit": TARGET_COMMIT,
        "target_tree": TARGET_TREE,
        "theorem_count": EXPECTED_THEOREM_COUNT,
        "manifest_status": manifest["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (GateError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"Phase 10 gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations bound to {TARGET_TAG})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
