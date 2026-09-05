#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement target, found {count}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# 1. Strengthen cgroup quiescence from TGID-only verification to every TID.
isolation = "tools/moriarty_isolation.py"
replace_once(
    isolation,
    '    for name in ("cgroup.procs", "memory.max", "pids.max"):\n',
    '    for name in ("cgroup.procs", "cgroup.threads", "memory.max", "pids.max"):\n',
)
old_block = '''def probe_cgroup_pids(root: Path) -> tuple[int, ...]:
    try:
        values = (root / "cgroup.procs").read_text(encoding="ascii").splitlines()
        return tuple(sorted(int(value) for value in values if value))
    except (OSError, UnicodeError, ValueError):
        fail("moriarty_probe_cgroup_process_list_invalid")


def _probe_pid_stopped(pid: int) -> bool | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError):
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            fields = line.split()
            return len(fields) >= 2 and fields[1] in {"T", "t"}
    return False


def _suspend_probe_cgroup(root: Path) -> tuple[int, ...] | None:
    """SIGSTOP every task in the dedicated probe cgroup and prove quiescence."""
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    while True:
        try:
            pids = probe_cgroup_pids(root)
        except SystemExit:
            return None
        if not pids:
            return ()
        for pid in pids:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
            except OSError:
                return None
        time.sleep(0.001)
        try:
            current = probe_cgroup_pids(root)
        except SystemExit:
            return None
        if not current:
            return ()
        if all(_probe_pid_stopped(pid) is True for pid in current):
            try:
                confirm = probe_cgroup_pids(root)
            except SystemExit:
                return None
            if confirm == current and all(_probe_pid_stopped(pid) is True for pid in confirm):
                return confirm
        if time.monotonic() >= deadline:
            return None


def _resume_probe_cgroup(root: Path) -> bool:
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    while True:
        try:
            pids = probe_cgroup_pids(root)
        except SystemExit:
            return False
        if not pids:
            return True
        ok = True
        for pid in pids:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            except OSError:
                ok = False
        if not ok:
            return False
        time.sleep(0.001)
        try:
            current = probe_cgroup_pids(root)
        except SystemExit:
            return False
        if all(_probe_pid_stopped(pid) is not True for pid in current):
            return True
        if time.monotonic() >= deadline:
            return False


'''
new_block = '''def probe_cgroup_pids(root: Path) -> tuple[int, ...]:
    try:
        values = (root / "cgroup.procs").read_text(encoding="ascii").splitlines()
        return tuple(sorted(int(value) for value in values if value))
    except (OSError, UnicodeError, ValueError):
        fail("moriarty_probe_cgroup_process_list_invalid")


def probe_cgroup_threads(root: Path) -> tuple[int, ...]:
    """Return every thread ID currently resident in the dedicated probe cgroup."""
    try:
        values = (root / "cgroup.threads").read_text(encoding="ascii").splitlines()
        tids = tuple(sorted(int(value) for value in values if value))
    except (OSError, UnicodeError, ValueError):
        fail("moriarty_probe_cgroup_thread_list_invalid")
    if len(tids) != len(set(tids)):
        fail("moriarty_probe_cgroup_thread_list_duplicate")
    return tids


def _probe_task_stopped(task_id: int) -> bool | None:
    try:
        status = Path(f"/proc/{task_id}/status").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError):
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            fields = line.split()
            return len(fields) >= 2 and fields[1] in {"T", "t"}
    return False


def _suspend_probe_cgroup(root: Path) -> tuple[int, ...] | None:
    """SIGSTOP each process, then prove every cgroup thread is quiescent."""
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    while True:
        try:
            pids = probe_cgroup_pids(root)
        except SystemExit:
            return None
        if not pids:
            return ()
        for pid in pids:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
            except OSError:
                return None
        time.sleep(0.001)
        try:
            threads = probe_cgroup_threads(root)
        except SystemExit:
            return None
        if not threads:
            return ()
        if all(_probe_task_stopped(tid) is True for tid in threads):
            try:
                confirm_threads = probe_cgroup_threads(root)
                confirm_pids = probe_cgroup_pids(root)
            except SystemExit:
                return None
            if (
                confirm_threads == threads
                and confirm_pids == pids
                and all(_probe_task_stopped(tid) is True for tid in confirm_threads)
            ):
                # Once every thread is stopped and the complete thread set is
                # stable, no task in this cgroup can create another thread or
                # move a payload until the harness explicitly resumes it.
                return confirm_threads
        if time.monotonic() >= deadline:
            return None


def _resume_probe_cgroup(root: Path) -> bool:
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    while True:
        try:
            pids = probe_cgroup_pids(root)
        except SystemExit:
            return False
        if not pids:
            return True
        ok = True
        for pid in pids:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            except OSError:
                ok = False
        if not ok:
            return False
        time.sleep(0.001)
        try:
            threads = probe_cgroup_threads(root)
        except SystemExit:
            return False
        if all(_probe_task_stopped(tid) is not True for tid in threads):
            try:
                confirm = probe_cgroup_threads(root)
            except SystemExit:
                return False
            if confirm == threads and all(_probe_task_stopped(tid) is not True for tid in confirm):
                return True
        if time.monotonic() >= deadline:
            return False


'''
replace_once(isolation, old_block, new_block)

# 2. Synchronize the closed assurance/contract surfaces.
validator = "tools/validate_phase9_gate.py"
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "per_probe_cargo_home",',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "probe_writable_scan_all_threads_verified", "per_probe_cargo_home",',
)
replace_once(
    validator,
    "'probe_writable_scan_binds_queued_directory_identity', 'probe_writable_scan_cgroup_suspended', 'rust_toolchain_runtime_staged'}",
    "'probe_writable_scan_binds_queued_directory_identity', 'probe_writable_scan_cgroup_suspended', 'probe_writable_scan_all_threads_verified', 'rust_toolchain_runtime_staged'}",
)
replace_once(
    validator,
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "rust_toolchain_runtime_staged",\n',
    '        "probe_writable_scan_binds_queued_directory_identity", "probe_writable_scan_cgroup_suspended",\n'
    '        "probe_writable_scan_all_threads_verified", "rust_toolchain_runtime_staged",\n',
)
replace_once(
    validator,
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is suspended",\n',
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is suspended",\n'
    '        "every cgroup thread is verified stopped",\n',
)

old_test = '''    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")
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
new_test = '''    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")
    require(cgroup_value is not None, "cross-root writable-scan regression requires probe cgroup")
    cgroup = isolation.probe_cgroup_root(Path(cgroup_value))
    require(not isolation.probe_cgroup_pids(cgroup), "cross-root regression requires an empty probe cgroup")
    require((cgroup / "cgroup.threads").is_file(), "probe cgroup thread enumeration unavailable")
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
import sys
import threading
import time
from pathlib import Path

early = Path(sys.argv[1])
late = Path(sys.argv[2])
trigger = Path(sys.argv[3])
ack = Path(sys.argv[4])
ready = Path(sys.argv[5])
worker_count = 120
barrier = threading.Barrier(worker_count + 1)


def worker():
    barrier.wait()
    while not trigger.exists():
        time.sleep(0.001)
    try:
        (late / "oversized").rename(early / "oversized")
    except FileNotFoundError:
        pass
    ack.touch(exist_ok=True)
    while True:
        time.sleep(1)


for _ in range(worker_count):
    threading.Thread(target=worker, daemon=True).start()
barrier.wait()
ready.write_text("ready", encoding="ascii")
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
            deadline = time.monotonic() + 2.0
            thread_ids: tuple[int, ...] = ()
            while mover.poll() is None and time.monotonic() < deadline:
                if ready.exists():
                    thread_ids = isolation.probe_cgroup_threads(cgroup)
                    if len(thread_ids) >= 121:
                        break
                time.sleep(0.001)
            require(ready.exists() and mover.poll() is None, "multithreaded cross-root mover did not become ready")
            require(121 <= len(thread_ids) <= isolation.PROBE_CGROUP_PIDS, "multithreaded cross-root mover task count drift")
            original_open = isolation.os.open
            every_thread_was_suspended = False

            def trigger_cross_root_move(path, flags, *args, **kwargs):
                nonlocal every_thread_was_suspended
                if not isinstance(path, int) and os.fspath(path) == os.fspath(late) and not trigger.exists():
                    trigger.write_text("go", encoding="ascii")
                    wait_deadline = time.monotonic() + 0.05
                    while not ack.exists() and time.monotonic() < wait_deadline:
                        time.sleep(0.001)
                    tids = isolation.probe_cgroup_threads(cgroup)
                    every_thread_was_suspended = (
                        len(tids) >= 121
                        and not ack.exists()
                        and all(isolation._probe_task_stopped(tid) is True for tid in tids)
                    )
                return original_open(path, flags, *args, **kwargs)

            try:
                isolation.os.open = trigger_cross_root_move
                require(
                    not isolation.probe_writable_tree_within_limits((early, late)),
                    "multithreaded cross-root move hid an oversized payload from writable accounting",
                )
                require(every_thread_was_suspended, "live writable scan did not verify every cgroup thread stopped")
                resumed_threads = isolation.probe_cgroup_threads(cgroup)
                require(
                    all(isolation._probe_task_stopped(tid) is not True for tid in resumed_threads),
                    "probe thread remained suspended after writable scan",
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
            require(not isolation.probe_cgroup_pids(cgroup), "multithreaded cross-root mover leaked from probe cgroup")

'''
replace_once(validator, old_test, new_test)

claims = "claims/phase9.json"
replace_once(
    claims,
    '    "probe_writable_scan_cgroup_suspended": true,\n',
    '    "probe_writable_scan_cgroup_suspended": true,\n'
    '    "probe_writable_scan_all_threads_verified": true,\n',
)

state = "state/phase9.json"
replace_once(
    state,
    '    "probe_writable_scan_cgroup_suspended": true,\n',
    '    "probe_writable_scan_cgroup_suspended": true,\n'
    '    "probe_writable_scan_all_threads_verified": true,\n',
)
replace_once(
    state,
    "Live writable-tree accounting suspends every task in the delegated probe cgroup and proves quiescence before binding roots and scanning all writable trees, then resumes the cgroup afterward;",
    "Live writable-tree accounting SIGSTOPs every process in the delegated probe cgroup and proves a stable cgroup.threads snapshot in which every thread is stopped before binding roots and scanning all writable trees, then resumes the cgroup afterward;",
)

docs = "MORIARTY.md"
replace_once(
    docs,
    "Runtime hardening notes: the delegated probe cgroup is suspended before each live writable-tree scan and resumed afterward, so all writable roots are accounted from one coherent probe snapshot, including descendants that created new sessions.",
    "Runtime hardening notes: the delegated probe cgroup is suspended before each live writable-tree scan and resumed afterward. MORIARTY SIGSTOPs each cgroup process, reads `cgroup.threads`, and accepts quiescence only after every thread ID is observed stopped in two stable thread snapshots; all writable roots are therefore accounted from one coherent probe snapshot, including multithreaded probes and descendants that created new sessions. In other words, every cgroup thread is verified stopped before scanning.",
)

print("PR21 thread-complete quiescence patch applied")
