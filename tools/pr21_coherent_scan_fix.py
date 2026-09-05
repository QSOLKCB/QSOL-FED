#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement target, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# 1. Make live writable accounting observe one coherent, cgroup-complete snapshot.
isolation = "tools/moriarty_isolation.py"
replace_once(
    isolation,
    "import resource\nimport stat\n",
    "import resource\nimport signal\nimport stat\n",
)
replace_once(
    isolation,
    "PROBE_CGROUP_PIDS = 128\nMAX_TOOLCHAIN_STAGE_FILE_BYTES",
    "PROBE_CGROUP_PIDS = 128\nPROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS = 1.0\nMAX_TOOLCHAIN_STAGE_FILE_BYTES",
)
replace_once(
    isolation,
    "def probe_writable_tree_within_limits(paths: tuple[Path, ...]) -> bool:\n",
    "def _probe_writable_tree_scan(paths: tuple[Path, ...]) -> bool:\n",
)
replace_once(
    isolation,
    "    # Persistent mutation can otherwise keep producing incomplete\n"
    "    # snapshots. Bounded churn therefore fails closed.\n"
    "    return False\n\n\n"
    "def _mountinfo_unescape(value: str) -> str:\n",
    "    # Persistent mutation can otherwise keep producing incomplete\n"
    "    # snapshots. Bounded churn therefore fails closed.\n"
    "    return False\n\n\n"
    "def probe_writable_tree_within_limits(paths: tuple[Path, ...]) -> bool:\n"
    "    \"\"\"Account one coherent writable snapshot while live probe tasks are suspended.\"\"\"\n"
    "    cgroup_value = os.environ.get(\"MORIARTY_PROBE_CGROUP\")\n"
    "    if not cgroup_value:\n"
    "        return _probe_writable_tree_scan(paths)\n"
    "    try:\n"
    "        cgroup = probe_cgroup_root(Path(cgroup_value))\n"
    "        active = bool(probe_cgroup_pids(cgroup))\n"
    "    except SystemExit:\n"
    "        return False\n"
    "    if not active:\n"
    "        return _probe_writable_tree_scan(paths)\n"
    "    suspended = _suspend_probe_cgroup(cgroup)\n"
    "    if suspended is None:\n"
    "        _resume_probe_cgroup(cgroup)\n"
    "        return False\n"
    "    result = False\n"
    "    try:\n"
    "        result = _probe_writable_tree_scan(paths)\n"
    "    finally:\n"
    "        if not _resume_probe_cgroup(cgroup):\n"
    "            result = False\n"
    "    return result\n\n\n"
    "def _mountinfo_unescape(value: str) -> str:\n",
)
replace_once(
    isolation,
    'def probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n'
    '    try:\n'
    '        values = (root / "cgroup.procs").read_text(encoding="ascii").splitlines()\n'
    '        return tuple(sorted(int(value) for value in values if value))\n'
    '    except (OSError, UnicodeError, ValueError):\n'
    '        fail("moriarty_probe_cgroup_process_list_invalid")\n\n\n'
    'def kill_probe_cgroup(root: Path) -> None:\n',
    'def probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n'
    '    try:\n'
    '        values = (root / "cgroup.procs").read_text(encoding="ascii").splitlines()\n'
    '        return tuple(sorted(int(value) for value in values if value))\n'
    '    except (OSError, UnicodeError, ValueError):\n'
    '        fail("moriarty_probe_cgroup_process_list_invalid")\n\n\n'
    'def _probe_pid_stopped(pid: int) -> bool | None:\n'
    '    try:\n'
    '        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")\n'
    '    except FileNotFoundError:\n'
    '        return None\n'
    '    except (OSError, UnicodeError):\n'
    '        return False\n'
    '    for line in status.splitlines():\n'
    '        if line.startswith("State:"):\n'
    '            fields = line.split()\n'
    '            return len(fields) >= 2 and fields[1] in {"T", "t"}\n'
    '    return False\n\n\n'
    'def _suspend_probe_cgroup(root: Path) -> tuple[int, ...] | None:\n'
    '    \"\"\"SIGSTOP every task in the dedicated probe cgroup and prove quiescence.\"\"\"\n'
    '    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS\n'
    '    while True:\n'
    '        try:\n'
    '            pids = probe_cgroup_pids(root)\n'
    '        except SystemExit:\n'
    '            return None\n'
    '        if not pids:\n'
    '            return ()\n'
    '        for pid in pids:\n'
    '            try:\n'
    '                os.kill(pid, signal.SIGSTOP)\n'
    '            except ProcessLookupError:\n'
    '                pass\n'
    '            except OSError:\n'
    '                return None\n'
    '        time.sleep(0.001)\n'
    '        try:\n'
    '            current = probe_cgroup_pids(root)\n'
    '        except SystemExit:\n'
    '            return None\n'
    '        if not current:\n'
    '            return ()\n'
    '        if all(_probe_pid_stopped(pid) is True for pid in current):\n'
    '            try:\n'
    '                confirm = probe_cgroup_pids(root)\n'
    '            except SystemExit:\n'
    '                return None\n'
    '            if confirm == current and all(_probe_pid_stopped(pid) is True for pid in confirm):\n'
    '                return confirm\n'
    '        if time.monotonic() >= deadline:\n'
    '            return None\n\n\n'
    'def _resume_probe_cgroup(root: Path) -> bool:\n'
    '    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS\n'
    '    while True:\n'
    '        try:\n'
    '            pids = probe_cgroup_pids(root)\n'
    '        except SystemExit:\n'
    '            return False\n'
    '        if not pids:\n'
    '            return True\n'
    '        ok = True\n'
    '        for pid in pids:\n'
    '            try:\n'
    '                os.kill(pid, signal.SIGCONT)\n'
    '            except ProcessLookupError:\n'
    '                pass\n'
    '            except OSError:\n'
    '                ok = False\n'
    '        if not ok:\n'
    '            return False\n'
    '        time.sleep(0.001)\n'
    '        try:\n'
    '            current = probe_cgroup_pids(root)\n'
    '        except SystemExit:\n'
    '            return False\n'
    '        if all(_probe_pid_stopped(pid) is not True for pid in current):\n'
    '            return True\n'
    '        if time.monotonic() >= deadline:\n'
    '            return False\n\n\n'
    'def kill_probe_cgroup(root: Path) -> None:\n',
)

# 2. Strengthen the Phase 9 gate and add the exact cross-root regression.
validator = "tools/validate_phase9_gate.py"
replace_once(
    validator,
    "import tarfile\nimport tempfile\nfrom pathlib import Path\n",
    "import tarfile\nimport tempfile\nimport time\nfrom pathlib import Path\n",
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '        "production_credentials_used",',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '        "production_credentials_used",',
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '    ):\n',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '    ):\n',
)
replace_once(
    validator,
    "'probe_writable_scan_binds_queued_directory_identity', 'rust_toolchain_runtime_staged'}",
    "'probe_writable_scan_binds_queued_directory_identity', 'probe_writable_scan_cgroup_suspended', 'rust_toolchain_runtime_staged'}",
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity", "rust_toolchain_runtime_staged",\n',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "rust_toolchain_runtime_staged",\n',
)
replace_once(
    validator,
    '    require(isolation.PROBE_WRITABLE_SCAN_MAX_RESTARTS == 8, "MORIARTY writable-scan restart budget drift")\n',
    '    require(isolation.PROBE_WRITABLE_SCAN_MAX_RESTARTS == 8, "MORIARTY writable-scan restart budget drift")\n'
    '    require(isolation.PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS == 1.0, "MORIARTY cgroup-suspend timeout drift")\n',
)
replace_once(
    validator,
    '        "persistent writable-tree churn fails closed",\n',
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is suspended",\n',
)

cross_root_test = '''    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")
    require(cgroup_value is not None, "cross-root writable-scan regression requires probe cgroup")
    cgroup = isolation.probe_cgroup_root(Path(cgroup_value))
    require(not isolation.probe_cgroup_pids(cgroup), "cross-root regression requires an empty probe cgroup")
    with tempfile.TemporaryDirectory(prefix="moriarty-scan-cross-root-") as temp_dir:
        root = Path(temp_dir).resolve(strict=True)
        early = root / "early"
        late = root / "late"
        control = root / "control"
        early.mkdir()
        late.mkdir()
        control.mkdir()
        payload = late / "oversized"
        payload.write_bytes(b"")
        os.truncate(payload, isolation.MAX_PROBE_WRITABLE_BYTES + 1)
        trigger = control / "trigger"
        ack = control / "ack"
        ready = control / "ready"
        mover_program = r"""
import time
import sys
from pathlib import Path
early = Path(sys.argv[1])
late = Path(sys.argv[2])
trigger = Path(sys.argv[3])
ack = Path(sys.argv[4])
ready = Path(sys.argv[5])
ready.write_text("ready", encoding="ascii")
while not trigger.exists():
    time.sleep(0.001)
try:
    (late / "oversized").rename(early / "oversized")
except FileNotFoundError:
    pass
ack.write_text("moved", encoding="ascii")
while True:
    time.sleep(1)
"""
        mover = subprocess.Popen(
            [sys.executable, "-I", "-c", mover_program, str(early), str(late), str(trigger), str(ack), str(ready)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin", "HOME": str(control), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            preexec_fn=lambda: isolation._join_probe_cgroup(cgroup),
        )
        try:
            deadline = time.monotonic() + 1.0
            while not ready.exists() and mover.poll() is None and time.monotonic() < deadline:
                time.sleep(0.001)
            require(ready.exists() and mover.poll() is None, "cross-root mover did not become ready")
            original_open = isolation.os.open
            mover_was_suspended = False

            def trigger_cross_root_move(path, flags, *args, **kwargs):
                nonlocal mover_was_suspended
                if not isinstance(path, int) and os.fspath(path) == os.fspath(late) and not trigger.exists():
                    trigger.write_text("go", encoding="ascii")
                    wait_deadline = time.monotonic() + 0.05
                    while not ack.exists() and time.monotonic() < wait_deadline:
                        time.sleep(0.001)
                    mover_was_suspended = (
                        not ack.exists() and isolation._probe_pid_stopped(mover.pid) is True
                    )
                return original_open(path, flags, *args, **kwargs)

            try:
                isolation.os.open = trigger_cross_root_move
                require(
                    not isolation.probe_writable_tree_within_limits((early, late)),
                    "cross-root move hid an oversized payload from writable accounting",
                )
                require(mover_was_suspended, "live writable scan did not suspend the complete probe cgroup")
                require(
                    isolation._probe_pid_stopped(mover.pid) is not True,
                    "probe task remained suspended after writable scan",
                )
            finally:
                isolation.os.open = original_open
        finally:
            try:
                mover.kill()
            except ProcessLookupError:
                pass
            try:
                mover.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                isolation.kill_probe_cgroup(cgroup)
                mover.wait(timeout=1.0)
            require(not isolation.probe_cgroup_pids(cgroup), "cross-root mover leaked from probe cgroup")

'''
replace_once(
    validator,
    '    with tempfile.TemporaryDirectory(prefix="moriarty-scan-bound-") as temp_dir:\n',
    cross_root_test + '    with tempfile.TemporaryDirectory(prefix="moriarty-scan-bound-") as temp_dir:\n',
)

# 3. Synchronize assurance and machine-contract surfaces.
claims = "claims/phase9.json"
replace_once(
    claims,
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n',
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n'
    '    "probe_writable_scan_cgroup_suspended": true,\n',
)
state = "state/phase9.json"
replace_once(
    state,
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n',
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n'
    '    "probe_writable_scan_cgroup_suspended": true,\n',
)
replace_once(
    state,
    "Live writable-tree accounting binds queued directory device/inode identity, opens queued directories no-follow, restarts from the bound roots on transient child ENOENT or identity substitution, and rejects persistent churn after a bounded restart budget.",
    "Live writable-tree accounting suspends every task in the delegated probe cgroup and proves quiescence before binding roots and scanning all writable trees, then resumes the cgroup afterward; queued directories remain device/inode-bound and no-follow opened, transient child ENOENT or identity substitution restarts from the bound roots, and persistent churn is rejected after a bounded restart budget.",
)

# 4. Document the coherent-snapshot boundary.
docs = "MORIARTY.md"
replace_once(
    docs,
    "Runtime hardening notes: queued writable directories are bound to their discovered device/inode identity, opened with no-follow directory descriptors, and scanned through the opened descriptor.",
    "Runtime hardening notes: the delegated probe cgroup is suspended before each live writable-tree scan and resumed afterward, so all writable roots are accounted from one coherent probe snapshot, including descendants that created new sessions. Queued writable directories are bound to their discovered device/inode identity, opened with no-follow directory descriptors, and scanned through the opened descriptor.",
)

print("PR21 coherent writable-scan patch applied")
