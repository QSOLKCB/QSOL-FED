#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement target, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# 1. Make live writable accounting observe one coherent cgroup-frozen snapshot.
isolation = "tools/moriarty_isolation.py"
replace_once(
    isolation,
    "PROBE_CGROUP_PIDS = 128\nMAX_TOOLCHAIN_STAGE_FILE_BYTES",
    "PROBE_CGROUP_PIDS = 128\nPROBE_CGROUP_FREEZE_TIMEOUT_SECONDS = 1.0\nMAX_TOOLCHAIN_STAGE_FILE_BYTES",
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
    "    \"\"\"Account a coherent writable snapshot while any live probe tasks are frozen.\"\"\"\n"
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
    "    if not _set_probe_cgroup_frozen(cgroup, True):\n"
    "        return False\n"
    "    result = False\n"
    "    try:\n"
    "        result = _probe_writable_tree_scan(paths)\n"
    "    finally:\n"
    "        if not _set_probe_cgroup_frozen(cgroup, False):\n"
    "            result = False\n"
    "    return result\n\n\n"
    "def _mountinfo_unescape(value: str) -> str:\n",
)
replace_once(
    isolation,
    '    for name in ("cgroup.procs", "memory.max", "pids.max"):\n',
    '    for name in ("cgroup.procs", "cgroup.freeze", "cgroup.events", "memory.max", "pids.max"):\n',
)
replace_once(
    isolation,
    '    if not os.access(root / "cgroup.procs", os.W_OK):\n'
    '        fail("moriarty_probe_cgroup_not_delegated")\n'
    '    return root\n\n\n'
    'def probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n',
    '    if not os.access(root / "cgroup.procs", os.W_OK):\n'
    '        fail("moriarty_probe_cgroup_not_delegated")\n'
    '    if not os.access(root / "cgroup.freeze", os.W_OK):\n'
    '        fail("moriarty_probe_cgroup_freeze_not_delegated")\n'
    '    return root\n\n\n'
    'def _probe_cgroup_frozen_state(root: Path) -> bool | None:\n'
    '    try:\n'
    '        fields = dict(\n'
    '            line.split(None, 1)\n'
    '            for line in (root / "cgroup.events").read_text(encoding="ascii").splitlines()\n'
    '            if line.strip()\n'
    '        )\n'
    '    except (OSError, UnicodeError, ValueError):\n'
    '        return None\n'
    '    value = fields.get("frozen")\n'
    '    if value == "1":\n'
    '        return True\n'
    '    if value == "0":\n'
    '        return False\n'
    '    return None\n\n\n'
    'def _set_probe_cgroup_frozen(root: Path, frozen: bool) -> bool:\n'
    '    payload = b"1\\n" if frozen else b"0\\n"\n'
    '    try:\n'
    '        fd = os.open(root / "cgroup.freeze", os.O_WRONLY | os.O_CLOEXEC)\n'
    '        try:\n'
    '            if os.write(fd, payload) != len(payload):\n'
    '                return False\n'
    '        finally:\n'
    '            os.close(fd)\n'
    '    except OSError:\n'
    '        return False\n'
    '    deadline = time.monotonic() + PROBE_CGROUP_FREEZE_TIMEOUT_SECONDS\n'
    '    while True:\n'
    '        state = _probe_cgroup_frozen_state(root)\n'
    '        if state is frozen:\n'
    '            return True\n'
    '        if state is None or time.monotonic() >= deadline:\n'
    '            return False\n'
    '        time.sleep(0.001)\n\n\n'
    'def probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n',
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
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_frozen",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '        "production_credentials_used",',
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '    ):\n',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_frozen",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n'
    '    ):\n',
)
replace_once(
    validator,
    "'probe_writable_scan_binds_queued_directory_identity', 'rust_toolchain_runtime_staged'}",
    "'probe_writable_scan_binds_queued_directory_identity', 'probe_writable_scan_cgroup_frozen', 'rust_toolchain_runtime_staged'}",
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity", "rust_toolchain_runtime_staged",\n',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_frozen",\n'
    '        "rust_toolchain_runtime_staged",\n',
)
replace_once(
    validator,
    '    require(isolation.PROBE_WRITABLE_SCAN_MAX_RESTARTS == 8, "MORIARTY writable-scan restart budget drift")\n',
    '    require(isolation.PROBE_WRITABLE_SCAN_MAX_RESTARTS == 8, "MORIARTY writable-scan restart budget drift")\n'
    '    require(isolation.PROBE_CGROUP_FREEZE_TIMEOUT_SECONDS == 1.0, "MORIARTY cgroup-freeze timeout drift")\n',
)
replace_once(
    validator,
    '        "persistent writable-tree churn fails closed",\n',
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is frozen",\n',
)
replace_once(
    validator,
    '    require("memory.max" in workflow and "pids.max" in workflow and "MORIARTY_PROBE_CGROUP" in workflow, "CI MORIARTY cgroup aggregate resource envelope missing")\n',
    '    require("memory.max" in workflow and "pids.max" in workflow and "MORIARTY_PROBE_CGROUP" in workflow, "CI MORIARTY cgroup aggregate resource envelope missing")\n'
    '    require("cgroup.freeze" in workflow and \'test -w "$PROBE_CGROUP/cgroup.freeze"\' in workflow, "CI MORIARTY cgroup freeze delegation missing")\n',
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
            mover_was_frozen = False

            def trigger_cross_root_move(path, flags, *args, **kwargs):
                nonlocal mover_was_frozen
                if not isinstance(path, int) and os.fspath(path) == os.fspath(late) and not trigger.exists():
                    trigger.write_text("go", encoding="ascii")
                    wait_deadline = time.monotonic() + 0.05
                    while not ack.exists() and time.monotonic() < wait_deadline:
                        time.sleep(0.001)
                    mover_was_frozen = not ack.exists()
                return original_open(path, flags, *args, **kwargs)

            try:
                isolation.os.open = trigger_cross_root_move
                require(
                    not isolation.probe_writable_tree_within_limits((early, late)),
                    "cross-root move hid an oversized payload from writable accounting",
                )
                require(mover_was_frozen, "live writable scan did not freeze the probe cgroup")
                require(
                    isolation._probe_cgroup_frozen_state(cgroup) is False,
                    "probe cgroup remained frozen after writable scan",
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
    '    "probe_writable_scan_cgroup_frozen": true,\n',
)
state = "state/phase9.json"
replace_once(
    state,
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n',
    '    "probe_writable_scan_binds_queued_directory_identity": true,\n'
    '    "probe_writable_scan_cgroup_frozen": true,\n',
)
replace_once(
    state,
    "Live writable-tree accounting binds queued directory device/inode identity, opens queued directories no-follow, restarts from the bound roots on transient child ENOENT or identity substitution, and rejects persistent churn after a bounded restart budget.",
    "Live writable-tree accounting freezes the delegated probe cgroup before binding roots and scanning all writable trees, then thaws it afterward; queued directories remain device/inode-bound and no-follow opened, transient child ENOENT or identity substitution restarts from the bound roots, and persistent churn is rejected after a bounded restart budget.",
)

# 4. Synchronize documentation and CI delegation.
docs = "MORIARTY.md"
replace_once(
    docs,
    'sudo chown "$(id -u):$(id -g)" "$CGROUP/cgroup.procs"\n',
    'sudo chown "$(id -u):$(id -g)" "$CGROUP/cgroup.procs" "$CGROUP/cgroup.freeze"\n'
    'test -w "$CGROUP/cgroup.freeze"\n',
)
replace_once(
    docs,
    "Runtime hardening notes: queued writable directories are bound to their discovered device/inode identity, opened with no-follow directory descriptors, and scanned through the opened descriptor.",
    "Runtime hardening notes: the delegated probe cgroup is frozen before each live writable-tree scan and thawed afterward, so all writable roots are accounted from one coherent probe snapshot. Queued writable directories are bound to their discovered device/inode identity, opened with no-follow directory descriptors, and scanned through the opened descriptor.",
)

workflow = ".github/workflows/ci.yml"
replace_once(
    workflow,
    '          sudo chown "$(id -u):$(id -g)" "$PROBE_CGROUP/cgroup.procs"\n'
    '          test -w "$PROBE_CGROUP/cgroup.procs"\n',
    '          sudo chown "$(id -u):$(id -g)" "$PROBE_CGROUP/cgroup.procs" "$PROBE_CGROUP/cgroup.freeze"\n'
    '          test -w "$PROBE_CGROUP/cgroup.procs"\n'
    '          test -w "$PROBE_CGROUP/cgroup.freeze"\n',
)
replace_once(
    workflow,
    '            if test -d "$PROBE_CGROUP"; then\n'
    '              while read -r pid; do\n',
    '            if test -d "$PROBE_CGROUP"; then\n'
    '              test -w "$PROBE_CGROUP/cgroup.freeze" && echo 0 > "$PROBE_CGROUP/cgroup.freeze" 2>/dev/null || true\n'
    '              while read -r pid; do\n',
)

print("PR21 coherent writable-scan patch applied")
