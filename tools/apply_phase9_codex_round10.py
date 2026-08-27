#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one marker, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# 1. Stream writable-tree enumeration and add a hard tmpfs quota-root verifier.
replace_once(
    "tools/moriarty_isolation.py",
    '''def probe_writable_tree_within_limits(paths: tuple[Path, ...]) -> bool:\n    total_bytes = 0\n    total_entries = 0\n    for supplied in paths:\n        try:\n            root = Path(supplied).resolve(strict=True)\n        except OSError:\n            return False\n        if not root.is_dir():\n            return False\n        stack: list[tuple[Path, int]] = [(root, 0)]\n        while stack:\n            current, depth = stack.pop()\n            if depth > MAX_PROBE_WRITABLE_DEPTH:\n                return False\n            try:\n                with os.scandir(current) as iterator:\n                    entries = list(iterator)\n            except OSError:\n                return False\n            for entry in entries:\n                total_entries += 1\n                if total_entries > MAX_PROBE_WRITABLE_ENTRIES:\n                    return False\n                try:\n                    info = entry.stat(follow_symlinks=False)\n                except OSError:\n                    return False\n                if stat.S_ISDIR(info.st_mode):\n                    stack.append((Path(entry.path), depth + 1))\n                elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):\n                    total_bytes += info.st_size\n                    if total_bytes > MAX_PROBE_WRITABLE_BYTES:\n                        return False\n                else:\n                    return False\n    return True\n\n\ndef probe_isolation_preexec(\n''',
    '''def probe_writable_tree_within_limits(paths: tuple[Path, ...]) -> bool:\n    total_bytes = 0\n    total_entries = 0\n    for supplied in paths:\n        try:\n            root = Path(supplied).resolve(strict=True)\n        except OSError:\n            return False\n        if not root.is_dir():\n            return False\n        stack: list[tuple[Path, int]] = [(root, 0)]\n        while stack:\n            current, depth = stack.pop()\n            if depth > MAX_PROBE_WRITABLE_DEPTH:\n                return False\n            try:\n                with os.scandir(current) as iterator:\n                    for entry in iterator:\n                        total_entries += 1\n                        if total_entries > MAX_PROBE_WRITABLE_ENTRIES:\n                            return False\n                        try:\n                            info = entry.stat(follow_symlinks=False)\n                        except OSError:\n                            return False\n                        if stat.S_ISDIR(info.st_mode):\n                            stack.append((Path(entry.path), depth + 1))\n                        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):\n                            total_bytes += info.st_size\n                            if total_bytes > MAX_PROBE_WRITABLE_BYTES:\n                                return False\n                        else:\n                            return False\n            except OSError:\n                return False\n    return True\n\n\ndef _mountinfo_unescape(value: str) -> str:\n    return (\n        value.replace("\\\\040", " ")\n        .replace("\\\\011", "\\t")\n        .replace("\\\\012", "\\n")\n        .replace("\\\\134", "\\\\")\n    )\n\n\ndef probe_quota_root(path: Path) -> Path:\n    \"\"\"Require an empty private tmpfs whose allocation ceiling is <= 2 GiB.\"\"\"\n    try:\n        root = Path(path).resolve(strict=True)\n        info = root.stat()\n    except OSError:\n        fail("moriarty_probe_quota_root_unavailable")\n    if not root.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:\n        fail("moriarty_probe_quota_root_not_private")\n    if not os.path.ismount(root):\n        fail("moriarty_probe_quota_root_not_mount")\n\n    fs_type: str | None = None\n    try:\n        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:\n            for line in handle:\n                fields = line.rstrip("\\n").split()\n                if "-" not in fields or len(fields) < 7:\n                    continue\n                separator = fields.index("-")\n                if separator + 1 >= len(fields):\n                    continue\n                mount_point = Path(_mountinfo_unescape(fields[4]))\n                try:\n                    resolved_mount = mount_point.resolve(strict=True)\n                except OSError:\n                    continue\n                if resolved_mount == root:\n                    fs_type = fields[separator + 1]\n                    break\n    except OSError:\n        fail("moriarty_probe_quota_mountinfo_unavailable")\n    if fs_type != "tmpfs":\n        fail("moriarty_probe_quota_root_not_tmpfs")\n\n    try:\n        filesystem = os.statvfs(root)\n    except OSError:\n        fail("moriarty_probe_quota_statvfs_failed")\n    capacity = filesystem.f_blocks * filesystem.f_frsize\n    if capacity <= 0 or capacity > MAX_PROBE_WRITABLE_BYTES:\n        fail("moriarty_probe_quota_capacity_invalid")\n    try:\n        with os.scandir(root) as iterator:\n            if next(iterator, None) is not None:\n                fail("moriarty_probe_quota_root_not_empty")\n    except OSError:\n        fail("moriarty_probe_quota_root_scan_failed")\n    return root\n\n\ndef probe_isolation_preexec(\n''',
)

# 2. Expose/require the hard quota root in the runner and place every probe-writable path there.
replace_once(
    "tools/run_moriarty.py",
    "probe_writable_tree_within_limits = _moriarty_isolation.probe_writable_tree_within_limits\n",
    "probe_writable_tree_within_limits = _moriarty_isolation.probe_writable_tree_within_limits\nprobe_quota_root = _moriarty_isolation.probe_quota_root\n",
)
replace_once(
    "tools/run_moriarty.py",
    "REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()\n\n\ndef fail(message: str) -> NoReturn:\n",
    "REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()\n_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None\n\n\ndef _probe_writable_root() -> Path:\n    if _ACTIVE_PROBE_WRITABLE_ROOT is None:\n        fail(\"moriarty_probe_quota_root_not_initialized\")\n    return _ACTIVE_PROBE_WRITABLE_ROOT\n\n\ndef fail(message: str) -> NoReturn:\n",
)
replace_once(
    "tools/run_moriarty.py",
    '''    cargo_home = _fresh_cargo_home(probe_id, template, workspace, label)\n    return run_probe(\n        probe_id,\n        workspace / f"{label}-home",\n        source,\n        cargo_home,\n        workspace / f"{label}-target",\n''',
    '''    writable_root = _probe_writable_root()\n    cargo_home = _fresh_cargo_home(probe_id, template, writable_root, label)\n    return run_probe(\n        probe_id,\n        writable_root / f"{label}-home",\n        source,\n        cargo_home,\n        writable_root / f"{label}-target",\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''    if not harness_files_match_target(target):\n        fail("moriarty_harness_worktree_bytes_do_not_match_target")\n\n    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:\n''',
    '''    if not harness_files_match_target(target):\n        fail("moriarty_harness_worktree_bytes_do_not_match_target")\n\n    quota_value = os.environ.get("MORIARTY_PROBE_WRITABLE_ROOT")\n    if not quota_value:\n        fail("moriarty_probe_quota_root_required")\n    global _ACTIVE_PROBE_WRITABLE_ROOT\n    _ACTIVE_PROBE_WRITABLE_ROOT = probe_quota_root(Path(quota_value))\n\n    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, workspace, label)\n            results[probe_id] = run_probe(\n                probe_id,\n                workspace / f"home-{probe_index}-{probe_id}",\n                probe_source,\n                probe_cargo_home,\n                workspace / f"target-{probe_index}-{probe_id}",\n''',
    '''            writable_root = _probe_writable_root()\n            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, writable_root, label)\n            results[probe_id] = run_probe(\n                probe_id,\n                writable_root / f"home-{probe_index}-{probe_id}",\n                probe_source,\n                probe_cargo_home,\n                writable_root / f"target-{probe_index}-{probe_id}",\n''',
)

# 3. Forward authenticated CI bindings to the runner, test fail-closed drift, and enforce CI order/quota markers.
replace_once(
    "tools/validate_phase9_gate.py",
    '''def execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:\n''',
    '''_RUNNER_BINDING_KEYS = (\n    "MORIARTY_RUST_TOOLCHAIN_ROOT",\n    "MORIARTY_EXPECTED_PYTHON_VERSION",\n    "MORIARTY_EXPECTED_RUSTC_VERSION",\n    "MORIARTY_EXPECTED_CARGO_VERSION",\n    "MORIARTY_PROBE_WRITABLE_ROOT",\n)\n\n\ndef _runner_environment(report_dir: Path) -> dict[str, str]:\n    env = {\n        "PATH": "/usr/bin:/bin",\n        "HOME": str(report_dir),\n        "PYTHONNOUSERSITE": "1",\n        "PYTHONDONTWRITEBYTECODE": "1",\n        "LANG": "C.UTF-8",\n        "LC_ALL": "C.UTF-8",\n    }\n    for key in _RUNNER_BINDING_KEYS:\n        value = os.environ.get(key)\n        require(value is not None and value != "", f"MORIARTY runner binding missing: {key}")\n        env[key] = value\n    return env\n\n\ndef validate_runner_toolchain_binding_negative(target: str) -> None:\n    with tempfile.TemporaryDirectory(prefix="moriarty-binding-negative-") as temp_dir:\n        root = Path(temp_dir)\n        cases = (\n            (\n                "snapshot path",\n                "MORIARTY_RUST_TOOLCHAIN_ROOT",\n                str(root / "missing-rust-snapshot"),\n                b"moriarty_ci_rust_snapshot_unavailable",\n            ),\n            (\n                "Cargo version",\n                "MORIARTY_EXPECTED_CARGO_VERSION",\n                "cargo 0.0.0 (intentional-negative)",\n                b"moriarty_toolchain_version_drift:cargo",\n            ),\n        )\n        for index, (label, key, value, marker) in enumerate(cases):\n            env = _runner_environment(root)\n            env[key] = value\n            output = root / f"negative-{index}.json"\n            completed = moriarty.trusted_run(\n                moriarty.PYTHON_TRUSTED,\n                ("-I", "tools/run_moriarty.py", "--target-commit", target, "--output", str(output)),\n                cwd=ROOT,\n                env=env,\n                stdout=subprocess.PIPE,\n                stderr=subprocess.PIPE,\n                check=False,\n            )\n            evidence = completed.stdout + completed.stderr\n            require(completed.returncode != 0 and marker in evidence, f"MORIARTY {label} negative binding test did not fail closed")\n            require(not output.exists(), f"MORIARTY {label} negative binding unexpectedly emitted a report")\n\n\ndef execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''        env={\n            "PATH": "/usr/bin:/bin",\n            "HOME": str(report_dir),\n            "PYTHONNOUSERSITE": "1",\n            "PYTHONDONTWRITEBYTECODE": "1",\n            "LANG": "C.UTF-8",\n            "LC_ALL": "C.UTF-8",\n        },\n''',
    '''        env=_runner_environment(report_dir),\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''        "probe_writable_tree_within_limits", "MORIARTY_RUST_TOOLCHAIN_ROOT", "allow_abbrev=False",\n''',
    '''        "probe_writable_tree_within_limits", "probe_quota_root", "MORIARTY_RUST_TOOLCHAIN_ROOT",\n        "MORIARTY_PROBE_WRITABLE_ROOT", "allow_abbrev=False",\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    snapshot_marker = "Snapshot trusted CI toolchains before repository execution"\n    rust_test_marker = "Rust tests, state, Holodeck, adapters, SDKs, Assembly, transports, and fuzz smoke"\n    require(snapshot_marker in workflow and workflow.index(snapshot_marker) < workflow.index(rust_test_marker), "CI toolchain snapshot does not precede repository execution")\n''',
    '''    snapshot_marker = "Snapshot trusted CI toolchains before repository execution"\n    phase9_marker = "Phase 9 MORIARTY/1 exact-commit graduation gate"\n    rust_test_marker = "Rust tests, state, Holodeck, adapters, SDKs, Assembly, transports, and fuzz smoke"\n    require(\n        snapshot_marker in workflow\n        and phase9_marker in workflow\n        and rust_test_marker in workflow\n        and workflow.index(snapshot_marker) < workflow.index(phase9_marker) < workflow.index(rust_test_marker),\n        "CI MORIARTY gate does not run immediately before target-controlled repository execution",\n    )\n    require("sudo mount -t tmpfs" in workflow and "size=2147483648" in workflow, "CI MORIARTY hard writable tmpfs quota missing")\n    require("MORIARTY_PROBE_WRITABLE_ROOT: /mnt/qsol-moriarty-probe-writable" in workflow, "CI MORIARTY writable quota binding missing")\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    validate_kernel_network_and_proc_denial()\n    execute_exact_commit_gate(target, Path(args.report_dir).resolve() if args.report_dir else None)\n''',
    '''    validate_kernel_network_and_proc_denial()\n    quota_value = os.environ.get("MORIARTY_PROBE_WRITABLE_ROOT")\n    require(quota_value is not None, "MORIARTY writable quota binding missing")\n    moriarty.probe_quota_root(Path(quota_value))\n    validate_runner_toolchain_binding_negative(target)\n    execute_exact_commit_gate(target, Path(args.report_dir).resolve() if args.report_dir else None)\n''',
)

# Compile source before allowing the applicator workflow to commit it.
import py_compile
for path in ("tools/moriarty_isolation.py", "tools/run_moriarty.py", "tools/validate_phase9_gate.py"):
    py_compile.compile(path, doraise=True)
print("round10-source-transform-ok")
