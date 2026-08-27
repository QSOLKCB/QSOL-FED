#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools/validate_phase10_gate.py"
THEOREMS = ROOT / "QSOLFed/Theorems.lean"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected one regex match, found {count}")
    return updated


validator = VALIDATOR.read_text(encoding="utf-8")
validator = replace_once(
    validator,
    "import json\nimport re\nimport subprocess\nfrom pathlib import Path\n",
    "import json\nimport os\nimport re\nimport subprocess\nimport tomllib\nfrom pathlib import Path\n",
    "imports",
)

expected_frozen = '''EXPECTED_FROZEN_INPUTS = {
    "ROADMAP.md": "42db05b1106e11cfb116920a5f4d8a2d92d60a66",
    "PRIME_DIRECTIVE.md": "ad6b5cdae5f8ada9b48f8066e3cb0f68ac9a6c93",
    "invariants/fed-v1.json": "97b62def1fd42cdc78cb178cddc9f269c98c620b",
    "wire/phase1.json": "1d34ac72d5d07c3f6b5bd28337eb6606cf44e782",
    "crypto/phase2.json": "042a850ccef4a058be595e955a87797d5e108e47",
    "state/phase4.json": "c9d7bcfcab9cd4581dc179a56071d7da1df97b13",
    "state/phase5a-holodeck.json": "bbb030469dcd66f4af37664c732820e6b6f0d760",
    "state/phase5.json": "5d2c22c46e9059668054a1dcb64facf071334505",
    "state/phase6.json": "c4eafb645c888d97f1d38e5eb1fe600e5aa49d0e",
    "state/phase7.json": "458c28c8ac075a6b3dcc2ea7189c3c77f0170a71",
    "state/phase8.json": "b855104b4fe4c97342b5bd48b248ca915e578703",
    "state/phase9.json": "c2bd1415cc86d27873a4432adb00d2306b87dbb0",
    "claims/phase9.json": "9ee94894169b0085c7282ac6c98a51b794eb0221",
    "fixtures/phase9/attack-corpus.json": "77d1a04e0912eec98613fc496478a04e6bae6cd6",
    "schemas/moriarty-report-v1.schema.json": "2c1992a796c48265309770653923effdb65b4f79",
}
'''
validator = replace_once(
    validator,
    "EXPECTED_THEOREM_COUNT = 47\n",
    "EXPECTED_THEOREM_COUNT = 47\n" + expected_frozen,
    "frozen inventory constant",
)

new_frozen_toolchain = '''def verify_frozen_inputs(manifest: dict) -> set[str]:
    items = manifest.get("frozen_inputs")
    require(isinstance(items, list), "frozen_inputs must be a list")
    require(len(items) == len(EXPECTED_FROZEN_INPUTS), "frozen input inventory count drift")
    observed: dict[str, str] = {}
    for item in items:
        require(isinstance(item, dict) and set(item) == {"path", "git_blob_sha1"}, "frozen input field set drift")
        path = item["path"]
        blob = item["git_blob_sha1"]
        require(isinstance(path, str) and path and path not in observed, f"invalid/duplicate frozen input path: {path!r}")
        require(re.fullmatch(r"[0-9a-f]{40}", blob) is not None, f"invalid frozen input blob: {path}")
        observed[path] = blob
    require(observed == EXPECTED_FROZEN_INPUTS, "frozen input inventory/path/blob drift")
    for path, blob in EXPECTED_FROZEN_INPUTS.items():
        actual = git("rev-parse", f"{TARGET_TAG}:{path}")
        require(actual == blob, f"frozen input blob drift: {path}: {actual} != {blob}")
        require(git("cat-file", "-t", actual) == "blob", f"frozen input is not a blob: {path}")
    return set(observed)


def verify_toolchain(manifest: dict) -> None:
    require((ROOT / "lean-toolchain").read_text(encoding="utf-8").strip() == LEAN_TOOLCHAIN, "lean-toolchain drift")
    toolchain = manifest.get("toolchain", {})
    require(toolchain.get("lean") == "v4.33.1", "manifest Lean version drift")
    require(toolchain.get("lean_toolchain") == LEAN_TOOLCHAIN, "manifest lean-toolchain drift")
    require(toolchain.get("archive_sha256") == LEAN_ARCHIVE_SHA256, "manifest Lean archive checksum drift")
    require(toolchain.get("external_dependencies") == [], "Phase 10 must remain dependency-free beyond Lean core")

    lakefile_path = ROOT / "lakefile.toml"
    require(lakefile_path.is_file(), "lakefile.toml missing")
    try:
        lakefile = tomllib.loads(lakefile_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"lakefile.toml invalid: {exc}") from exc
    expected_lakefile = {
        "name": "qsol-fed-formal",
        "version": "0.11.0",
        "defaultTargets": ["QSOLFed"],
        "lean_lib": [{"name": "QSOLFed"}],
    }
    require(_json_equal(lakefile, expected_lakefile), "lakefile dependency/configuration drift")

    resolved_path = ROOT / "lake-manifest.json"
    if resolved_path.exists():
        resolved = load_json(resolved_path)
        require(resolved.get("name") == "qsol-fed-formal", "resolved Lake package identity drift")
        require(resolved.get("packages") == [], "resolved Lake dependency graph is not empty")


def verify_theorems'''
validator = regex_once(
    validator,
    r"def verify_frozen_inputs\(manifest: dict\) -> set\[str\]:.*?\n\ndef verify_theorems",
    new_frozen_toolchain,
    "frozen inputs/toolchain",
)

status_old = '    require(manifest.get("status") in {"IMPLEMENTED_PENDING_CI", "LEAN_VERIFIED_ON_BRANCH", "LEAN_VERIFIED_ON_MERGED_MAIN"}, "manifest verification status drift")\n'
status_new = '''    status = manifest.get("status")
    require(status in {"IMPLEMENTED_PENDING_CI", "LEAN_VERIFIED_ON_BRANCH", "LEAN_VERIFIED_ON_MERGED_MAIN"}, "manifest verification status drift")
    if status == "LEAN_VERIFIED_ON_MERGED_MAIN":
        require(os.environ.get("GITHUB_EVENT_NAME") == "push", "merged-main status requires GitHub push context")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "merged-main status requires refs/heads/main")
        event_sha = os.environ.get("GITHUB_SHA", "")
        require(re.fullmatch(r"[0-9a-f]{40}", event_sha) is not None, "merged-main status requires exact GitHub SHA")
        require(git("rev-parse", "HEAD") == event_sha, "merged-main status SHA differs from checked-out commit")
'''
validator = replace_once(validator, status_old, status_new, "merged-main context")

baseline_old = '''    phase9_claims = load_json(ROOT / "claims/phase9.json")
    phase8_claims = load_json(ROOT / "claims/phase8.json")
'''
baseline_new = '''    phase9_claims = load_json(ROOT / "claims/phase9.json")
    phase8_claims = load_json(ROOT / "claims/phase8.json")
    try:
        frozen_phase9_claims = json.loads(git("show", f"{TARGET_TAG}:claims/phase9.json"))
    except json.JSONDecodeError as exc:
        raise GateError(f"frozen Phase 9 claims invalid JSON: {exc}") from exc
'''
validator = replace_once(validator, baseline_old, baseline_new, "frozen capability baseline load")

cap_old = '    require(claims.get("capabilities") == phase9_claims.get("capabilities") == phase8_claims.get("capabilities"), "Phase 10 capability map differs from Phase 9/8 baseline")\n'
cap_new = '''    frozen_capabilities = frozen_phase9_claims.get("capabilities")
    require(isinstance(frozen_capabilities, dict), "frozen Phase 9 capability baseline missing")
    require(claims.get("capabilities") == frozen_capabilities, "Phase 10 capability map differs from immutable v0.11.0 Phase 9 baseline")
    require(phase9_claims.get("capabilities") == frozen_capabilities, "working Phase 9 capability map differs from immutable v0.11.0 baseline")
    require(phase8_claims.get("capabilities") == frozen_capabilities, "working Phase 8 capability map differs from immutable v0.11.0 baseline")
'''
validator = replace_once(validator, cap_old, cap_new, "frozen capability comparison")

overclaim_old = '    require(assurance.get("whole_implementation_verified") is False and assurance.get("deployment_security_proof") is False and assurance.get("source_release_rewritten") is False, "Phase 10 formalization assurance overclaim")\n'
overclaim_new = '''    require(
        assurance.get("whole_implementation_verified") is False
        and assurance.get("deployment_security_proof") is False
        and assurance.get("source_release_rewritten") is False
        and assurance.get("formalization_creates_authority") is False,
        "Phase 10 formalization assurance overclaim",
    )
'''
validator = replace_once(validator, overclaim_old, overclaim_new, "authority nonclaim")

VALIDATOR.write_text(validator, encoding="utf-8")

theorems = THEOREMS.read_text(encoding="utf-8")
theorem_old = '''theorem valid_signature_does_not_bypass_local_rejection :
    (signedAdmission true .reject).localAuthorityGranted = false := rfl
'''
theorem_new = '''theorem valid_signature_does_not_bypass_local_rejection :
    (signedAdmission true .reject).localAdmission = .reject ∧
    (signedAdmission true .reject).localAuthorityGranted = false := by
  exact ⟨rfl, rfl⟩
'''
theorems = replace_once(theorems, theorem_old, theorem_new, "signed rejection theorem")
THEOREMS.write_text(theorems, encoding="utf-8")

print("Phase 10 Codex round-two fixes applied")
