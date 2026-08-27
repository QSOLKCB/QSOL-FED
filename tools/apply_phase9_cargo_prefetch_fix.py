#!/usr/bin/env python3
from pathlib import Path
import py_compile


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one marker, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Keep Cargo home on the quota filesystem while binding its config to the staged Rust sysroot.
replace_once(
    "tools/moriarty_isolation.py",
    '''def _owned_cargo_config(workspace: Path) -> bytes:\n    """Return harness-owned Cargo settings without importing user configuration.\n\n    The real runner stages Rust under `workspace/rust-runtime` before creating\n    per-probe homes. When that runtime is present, explicitly pass its sysroot so\n    rustc descendants do not need `/proc/self/exe` for toolchain discovery. The\n    validator also exercises this helper before staging Rust, so the sysroot\n    stanza is conditional while the offline policy remains unconditional.\n    """\n    lines = []\n    rust_runtime = workspace / "rust-runtime"\n    if rust_runtime.is_dir():\n        sysroot = rust_runtime.resolve(strict=True)\n''',
    '''def _owned_cargo_config(workspace: Path, rust_runtime: Path | None = None) -> bytes:\n    """Return harness-owned Cargo settings without importing user configuration.\n\n    Probe writable state may live on a separate quota filesystem, so the staged\n    Rust runtime is passed explicitly when available. The workspace-relative\n    fallback is retained for validator/helper tests that exercise this function\n    before a runtime is staged.\n    """\n    lines = []\n    runtime = rust_runtime if rust_runtime is not None else workspace / "rust-runtime"\n    if runtime.is_dir():\n        sysroot = runtime.resolve(strict=True)\n''',
)
replace_once(
    "tools/moriarty_isolation.py",
    '''def create_isolated_cargo_home(template: Path, workspace: Path, label: str) -> Path:\n''',
    '''def create_isolated_cargo_home(\n    template: Path,\n    workspace: Path,\n    label: str,\n    rust_runtime: Path | None = None,\n) -> Path:\n''',
)
replace_once(
    "tools/moriarty_isolation.py",
    '''    config = _owned_cargo_config(workspace)\n''',
    '''    config = _owned_cargo_config(workspace, rust_runtime)\n''',
)

# Bind cache preparation to an explicit, validator-forwarded Cargo cache root.
replace_once(
    "tools/run_moriarty.py",
    '''REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()\n_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None\n''',
    '''REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()\n_cache_value = os.environ.get("MORIARTY_CARGO_CACHE_ROOT")\nif _cache_value:\n    try:\n        CARGO_CACHE_HOME = Path(_cache_value).resolve(strict=True)\n    except OSError:\n        raise SystemExit("moriarty_cargo_cache_root_unavailable")\n    if not CARGO_CACHE_HOME.is_dir() or CARGO_CACHE_HOME == ROOT or ROOT in CARGO_CACHE_HOME.parents:\n        raise SystemExit("moriarty_cargo_cache_root_invalid")\nelse:\n    CARGO_CACHE_HOME = REAL_HOME / ".cargo"\n_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''def _fresh_cargo_home(probe_id: str, template: Path, workspace: Path, label: str) -> Path:\n    if probe_id == "rust_all":\n        return create_isolated_cargo_home(template, workspace, label)\n    return create_empty_cargo_home(workspace, label)\n''',
    '''def _fresh_cargo_home(\n    probe_id: str,\n    template: Path,\n    workspace: Path,\n    label: str,\n    rust_runtime: Path | None = None,\n) -> Path:\n    if probe_id == "rust_all":\n        return create_isolated_cargo_home(template, workspace, label, rust_runtime)\n    return create_empty_cargo_home(workspace, label)\n''',
)
# Both historical replay and current-target template must use the authenticated prefetch root.
text = Path("tools/run_moriarty.py").read_text(encoding="utf-8")
count = text.count('REAL_HOME / ".cargo"')
if count != 3:
    raise SystemExit(f"run_moriarty.py: expected three REAL_HOME Cargo references before cache rewrite, found {count}")
# Keep the rustup discovery environment's CARGO_HOME unchanged; replace only template construction references.
text = text.replace(
    'create_verified_cargo_template(\n            REAL_HOME / ".cargo",',
    'create_verified_cargo_template(\n            CARGO_CACHE_HOME,',
)
text = text.replace(
    'create_verified_cargo_template(\n            REAL_HOME / ".cargo", workspace, control_source / "Cargo.lock"',
    'create_verified_cargo_template(\n            CARGO_CACHE_HOME, workspace, control_source / "Cargo.lock"',
)
Path("tools/run_moriarty.py").write_text(text, encoding="utf-8")

# Pass the staged runtime into both current and historical Rust Cargo homes.
replace_once(
    "tools/run_moriarty.py",
    '''    cargo_home = _fresh_cargo_home(probe_id, template, writable_root, label)\n''',
    '''    cargo_home = _fresh_cargo_home(probe_id, template, writable_root, label, rust_runtime)\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, writable_root, label)\n''',
    '''            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, writable_root, label, rust_runtime)\n''',
)

# Forward/cache-bind the prepared Cargo home and require the prep step to precede MORIARTY.
replace_once(
    "tools/validate_phase9_gate.py",
    '''    "MORIARTY_EXPECTED_CARGO_VERSION",\n    "MORIARTY_PROBE_WRITABLE_ROOT",\n''',
    '''    "MORIARTY_EXPECTED_CARGO_VERSION",\n    "MORIARTY_CARGO_CACHE_ROOT",\n    "MORIARTY_PROBE_WRITABLE_ROOT",\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''        "MORIARTY_PROBE_WRITABLE_ROOT", "allow_abbrev=False",\n''',
    '''        "MORIARTY_CARGO_CACHE_ROOT", "MORIARTY_PROBE_WRITABLE_ROOT", "allow_abbrev=False",\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    snapshot_marker = "Snapshot trusted CI toolchains before repository execution"\n    phase9_marker = "Phase 9 MORIARTY/1 exact-commit graduation gate"\n    rust_test_marker = "Rust tests, state, Holodeck, adapters, SDKs, Assembly, transports, and fuzz smoke"\n    require(\n        snapshot_marker in workflow\n        and phase9_marker in workflow\n        and rust_test_marker in workflow\n        and workflow.index(snapshot_marker) < workflow.index(phase9_marker) < workflow.index(rust_test_marker),\n        "CI MORIARTY gate does not run immediately before target-controlled repository execution",\n    )\n''',
    '''    snapshot_marker = "Snapshot trusted CI toolchains before repository execution"\n    cache_marker = "Prepare authenticated Cargo archives without repository execution"\n    phase9_marker = "Phase 9 MORIARTY/1 exact-commit graduation gate"\n    rust_test_marker = "Rust tests, state, Holodeck, adapters, SDKs, Assembly, transports, and fuzz smoke"\n    require(\n        snapshot_marker in workflow\n        and cache_marker in workflow\n        and phase9_marker in workflow\n        and rust_test_marker in workflow\n        and workflow.index(snapshot_marker) < workflow.index(cache_marker) < workflow.index(phase9_marker) < workflow.index(rust_test_marker),\n        "CI authenticated cache/MORIARTY order does not precede target-controlled repository execution",\n    )\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    require("MORIARTY_PROBE_WRITABLE_ROOT: /mnt/qsol-moriarty-probe-writable" in workflow, "CI MORIARTY writable quota binding missing")\n''',
    '''    require("MORIARTY_CARGO_CACHE_ROOT: ${{ runner.temp }}/moriarty-cargo-source" in workflow, "CI MORIARTY authenticated Cargo cache binding missing")\n    require("MORIARTY_PROBE_WRITABLE_ROOT: /mnt/qsol-moriarty-probe-writable" in workflow, "CI MORIARTY writable quota binding missing")\n''',
)

for path in ("tools/moriarty_isolation.py", "tools/run_moriarty.py", "tools/validate_phase9_gate.py"):
    py_compile.compile(path, doraise=True)
print("cargo-prefetch-fix-ok")
