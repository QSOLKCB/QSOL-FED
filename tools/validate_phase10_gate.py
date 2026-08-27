#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "machine/lean-phase10-manifest.json"
TARGET_TAG = "v0.11.0"
TARGET_COMMIT = "c953463724cdf218802e66e16f582ae8d600ca47"
TARGET_TREE = "93f23cd7eda6dd92ae13b7bb96bee01935b80731"
LEAN_TOOLCHAIN = "leanprover/lean4:v4.33.1"
LEAN_ARCHIVE_SHA256 = "890afd185370f85666025b883914ab4f4b339136f8c96167b69cfb62aecaf235"
EXPECTED_THEOREM_COUNT = 47
PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b")
DECL_RE_TEMPLATE = r"\btheorem\s+{name}\b"


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
        "target_commit": TARGET_COMMIT,
        "corpus_ref": "sha256:af50e8145a72a1a583ede29687535a59c0e17ac37fdd66e1ede51c453e8fd3e6",
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
    }
    require({key: binding.get(key) for key in expected} == expected, "MORIARTY binding drift")


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
    require(manifest.get("status") == "IMPLEMENTED_PENDING_CI", "manifest must not pre-claim LEAN_VERIFIED")
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


def validate() -> dict:
    manifest = load_json(MANIFEST_PATH)
    verify_manifest_policy(manifest)
    verify_frozen_target(manifest)
    verify_moriarty_binding(manifest)
    frozen_inputs = verify_frozen_inputs(manifest)
    verify_toolchain(manifest)
    verify_theorems(manifest, frozen_inputs)
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
