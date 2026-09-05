#!/usr/bin/env python3
from pathlib import Path


def replace_n(path: str, old: str, new: str, expected: int = 1) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} matches, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(f"{path}: replacement boundary drift: {start!r} / {end!r}")
    begin = text.index(start)
    finish = text.index(end, begin)
    p.write_text(text[:begin] + replacement + text[finish:], encoding="utf-8")


# ---------------------------------------------------------------------------
# PID-identity-bound cgroup signaling.
# ---------------------------------------------------------------------------
isolation = "tools/moriarty_isolation.py"
replace_n(
    isolation,
    '    if not (cgroup_root / "cgroup.controllers").is_file():\n        fail("moriarty_probe_cgroup_v2_required")\n',
    '    if not (cgroup_root / "cgroup.controllers").is_file():\n        fail("moriarty_probe_cgroup_v2_required")\n'
    '    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):\n'
    '        fail("moriarty_probe_cgroup_pidfd_signaling_required")\n',
)

signal_block = r'''def probe_cgroup_pids(root: Path) -> tuple[int, ...]:
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


def _close_probe_pidfds(handles: tuple[tuple[int, int], ...]) -> None:
    for _pid, pidfd in handles:
        try:
            os.close(pidfd)
        except OSError:
            pass


def _open_probe_cgroup_pidfds(
    root: Path,
    pids: tuple[int, ...],
) -> tuple[tuple[int, int], ...] | None:
    """Bind candidate cgroup PIDs to stable task identities before signaling."""
    opened: list[tuple[int, int]] = []
    try:
        for pid in pids:
            try:
                pidfd = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                continue
            except OSError:
                return None
            opened.append((pid, pidfd))
        try:
            current = set(probe_cgroup_pids(root))
        except SystemExit:
            return None
        kept: list[tuple[int, int]] = []
        for pid, pidfd in opened:
            if pid in current:
                kept.append((pid, pidfd))
            else:
                try:
                    os.close(pidfd)
                except OSError:
                    pass
        opened = kept
        return tuple(opened)
    finally:
        # Ownership transfers only on a successful return.
        if opened and any(pid not in locals().get("current", set()) for pid, _fd in opened):
            _close_probe_pidfds(tuple(opened))


def _signal_probe_pidfds(handles: tuple[tuple[int, int], ...], sig: int) -> bool:
    for _pid, pidfd in handles:
        try:
            signal.pidfd_send_signal(pidfd, sig, None, 0)
        except ProcessLookupError:
            # The bound task exited; stable membership checks decide whether the
            # suspension snapshot must be retried.
            continue
        except OSError:
            return False
    return True


def _suspend_probe_cgroup(root: Path) -> tuple[tuple[int, int], ...] | None:
    """SIGSTOP pidfd-bound members, then prove every cgroup thread quiescent."""
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    while True:
        try:
            pids = probe_cgroup_pids(root)
        except SystemExit:
            return None
        if not pids:
            return ()
        handles = _open_probe_cgroup_pidfds(root, pids)
        if handles is None:
            return None
        handle_pids = tuple(pid for pid, _fd in handles)
        if handle_pids != pids:
            _close_probe_pidfds(handles)
            if time.monotonic() >= deadline:
                return None
            continue
        if not _signal_probe_pidfds(handles, signal.SIGSTOP):
            _signal_probe_pidfds(handles, signal.SIGCONT)
            _close_probe_pidfds(handles)
            return None
        time.sleep(0.001)
        try:
            threads = probe_cgroup_threads(root)
        except SystemExit:
            _signal_probe_pidfds(handles, signal.SIGCONT)
            _close_probe_pidfds(handles)
            return None
        if threads and all(_probe_task_stopped(tid) is True for tid in threads):
            try:
                confirm_threads = probe_cgroup_threads(root)
                confirm_pids = probe_cgroup_pids(root)
            except SystemExit:
                _signal_probe_pidfds(handles, signal.SIGCONT)
                _close_probe_pidfds(handles)
                return None
            if (
                confirm_threads == threads
                and confirm_pids == pids
                and all(_probe_task_stopped(tid) is True for tid in confirm_threads)
            ):
                # pidfds remain open across the scan, so resume is bound to the
                # exact identities that were stopped rather than reusable PID values.
                return handles
        _signal_probe_pidfds(handles, signal.SIGCONT)
        _close_probe_pidfds(handles)
        if time.monotonic() >= deadline:
            return None


def _resume_probe_cgroup(root: Path, handles: tuple[tuple[int, int], ...]) -> bool:
    deadline = time.monotonic() + PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS
    try:
        if not _signal_probe_pidfds(handles, signal.SIGCONT):
            return False
        while True:
            try:
                pids = probe_cgroup_pids(root)
            except SystemExit:
                return False
            if not pids:
                return True
            try:
                threads = probe_cgroup_threads(root)
            except SystemExit:
                return False
            if all(_probe_task_stopped(tid) is not True for tid in threads):
                try:
                    confirm_threads = probe_cgroup_threads(root)
                    confirm_pids = probe_cgroup_pids(root)
                except SystemExit:
                    return False
                if (
                    confirm_threads == threads
                    and confirm_pids == pids
                    and all(_probe_task_stopped(tid) is not True for tid in confirm_threads)
                ):
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.001)
    finally:
        _close_probe_pidfds(handles)


def kill_probe_cgroup(root: Path) -> None:
    """Kill every remaining task using pidfd-bound cgroup membership snapshots."""
    for _ in range(8):
        pids = probe_cgroup_pids(root)
        if not pids:
            return
        handles = _open_probe_cgroup_pidfds(root, pids)
        if handles is None:
            fail("moriarty_probe_cgroup_pidfd_open_failed")
        try:
            if not _signal_probe_pidfds(handles, signal.SIGKILL):
                fail("moriarty_probe_cgroup_pidfd_kill_failed")
        finally:
            _close_probe_pidfds(handles)
        time.sleep(0.01)
    if probe_cgroup_pids(root):
        fail("moriarty_probe_cgroup_descendants_survived")


'''
replace_between(
    isolation,
    "def probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n",
    "def _join_probe_cgroup(root: Path) -> None:\n",
    signal_block,
)

replace_n(
    isolation,
    '    suspended = _suspend_probe_cgroup(cgroup)\n'
    '    if suspended is None:\n'
    '        _resume_probe_cgroup(cgroup)\n'
    '        return False\n'
    '    result = False\n'
    '    try:\n'
    '        result = _probe_writable_tree_scan(paths)\n'
    '    finally:\n'
    '        if not _resume_probe_cgroup(cgroup):\n'
    '            result = False\n',
    '    suspended = _suspend_probe_cgroup(cgroup)\n'
    '    if suspended is None:\n'
    '        return False\n'
    '    result = False\n'
    '    try:\n'
    '        result = _probe_writable_tree_scan(paths)\n'
    '    finally:\n'
    '        if not _resume_probe_cgroup(cgroup, suspended):\n'
    '            result = False\n',
)

# ---------------------------------------------------------------------------
# Suspension-aware timeout/check scheduling in run_probe().
# ---------------------------------------------------------------------------
runner = "tools/run_moriarty.py"
timed_helper = r'''
def _timed_writable_check(
    paths: tuple[Path, ...],
    deadline: float,
    *,
    now_fn: Any = time.monotonic,
) -> tuple[bool, float, float, float]:
    """Run one live scan without charging harness suspension to probe runtime."""
    started = now_fn()
    within_limits = probe_writable_tree_within_limits(paths)
    finished = now_fn()
    if finished < started:
        fail("moriarty_writable_scan_monotonic_clock_regressed")
    suspended_seconds = finished - started
    adjusted_deadline = deadline + suspended_seconds
    next_check = finished + _moriarty_isolation.PROBE_WRITABLE_CHECK_INTERVAL_SECONDS
    return within_limits, adjusted_deadline, next_check, finished


'''
replace_n(runner, "def run_probe(\n", timed_helper + "def run_probe(\n")
replace_n(
    runner,
    '            if failure_kind is None and now >= next_writable_check:\n'
    '                if not probe_writable_tree_within_limits(tuple(private_writable_paths)):\n'
    '                    failure_kind = "tool_error"\n'
    '                    _kill_probe_tree(process)\n'
    '                    termination_deadline = now + TERMINATION_DRAIN_SECONDS\n'
    '                next_writable_check = now + _moriarty_isolation.PROBE_WRITABLE_CHECK_INTERVAL_SECONDS\n',
    '            if failure_kind is None and now >= next_writable_check:\n'
    '                within_limits, deadline, next_writable_check, now = _timed_writable_check(\n'
    '                    tuple(private_writable_paths), deadline\n'
    '                )\n'
    '                if not within_limits:\n'
    '                    failure_kind = "tool_error"\n'
    '                    _kill_probe_tree(process)\n'
    '                    termination_deadline = now + TERMINATION_DRAIN_SECONDS\n',
)

# ---------------------------------------------------------------------------
# Synchronize Phase 9 contracts/claims/docs.
# ---------------------------------------------------------------------------
for path in ("claims/phase9.json", "state/phase9.json"):
    replace_n(
        path,
        '    "probe_writable_scan_all_threads_verified": true,\n',
        '    "probe_writable_scan_all_threads_verified": true,\n'
        '    "probe_cgroup_signals_pidfd_bound": true,\n'
        '    "probe_writable_scan_suspension_not_charged_to_timeout": true,\n'
        '    "probe_writable_scan_next_check_from_completion": true,\n',
    )

state = "state/phase9.json"
replace_n(
    state,
    "Live writable-tree accounting SIGSTOPs every process in the delegated probe cgroup and proves a stable cgroup.threads snapshot in which every thread is stopped before binding roots and scanning all writable trees, then resumes the cgroup afterward; queued directories remain device/inode-bound and no-follow opened, transient child ENOENT or identity substitution restarts from the bound roots, and persistent churn is rejected after a bounded restart budget.",
    "Live writable-tree accounting opens pidfds for cgroup members, revalidates membership, SIGSTOPs only those bound task identities, and proves a stable cgroup.threads snapshot in which every thread is stopped before binding roots and scanning all writable trees; the same pidfds resume the exact stopped identities afterward. Suspension time is excluded from the probe execution deadline and the next periodic writable check is scheduled from scan completion, preventing slow allowed scans from starving probes. Queued directories remain device/inode-bound and no-follow opened, transient child ENOENT or identity substitution restarts from the bound roots, and persistent churn is rejected after a bounded restart budget.",
)

docs = "MORIARTY.md"
replace_n(
    docs,
    "Runtime hardening notes: the delegated probe cgroup is suspended before each live writable-tree scan and resumed afterward. MORIARTY SIGSTOPs each cgroup process, reads `cgroup.threads`, and accepts quiescence only after every thread ID is observed stopped in two stable thread snapshots; all writable roots are therefore accounted from one coherent probe snapshot, including multithreaded probes and descendants that created new sessions. In other words, every cgroup thread is verified stopped before scanning.",
    "Runtime hardening notes: the delegated probe cgroup is suspended before each live writable-tree scan and resumed afterward. MORIARTY opens pidfds for the enumerated cgroup processes, revalidates cgroup membership after the pidfds are open, and sends SIGSTOP/SIGCONT through those pidfds so signals remain bound to exact task identities rather than reusable numeric PIDs. It reads `cgroup.threads` and accepts quiescence only after every thread ID is observed stopped in two stable thread snapshots; all writable roots are therefore accounted from one coherent probe snapshot, including multithreaded probes and descendants that created new sessions. Every cgroup thread is verified stopped before scanning. Suspension time is excluded from the probe's 300-second execution budget, and the next writable check is scheduled from scan completion so a slow allowed scan cannot create an immediate stop-scan-stop starvation loop.",
)

# ---------------------------------------------------------------------------
# Closed validator surfaces and deterministic regressions.
# ---------------------------------------------------------------------------
validator = "tools/validate_phase9_gate.py"
replace_n(
    validator,
    '        "probe_writable_scan_all_threads_verified", "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n',
    '        "probe_writable_scan_all_threads_verified", "probe_cgroup_signals_pidfd_bound",\n'
    '        "probe_writable_scan_suspension_not_charged_to_timeout",\n'
    '        "probe_writable_scan_next_check_from_completion",\n'
    '        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",\n',
    expected=2,
)
replace_n(
    validator,
    "'probe_writable_scan_cgroup_suspended', 'probe_writable_scan_all_threads_verified', 'rust_toolchain_runtime_staged'}",
    "'probe_writable_scan_cgroup_suspended', 'probe_writable_scan_all_threads_verified', 'probe_cgroup_signals_pidfd_bound', 'probe_writable_scan_suspension_not_charged_to_timeout', 'probe_writable_scan_next_check_from_completion', 'rust_toolchain_runtime_staged'}",
)
replace_n(
    validator,
    '        "probe_writable_scan_all_threads_verified", "rust_toolchain_runtime_staged",\n',
    '        "probe_writable_scan_all_threads_verified", "probe_cgroup_signals_pidfd_bound",\n'
    '        "probe_writable_scan_suspension_not_charged_to_timeout",\n'
    '        "probe_writable_scan_next_check_from_completion", "rust_toolchain_runtime_staged",\n',
)
replace_n(
    validator,
    '        "probe_writable_tree_within_limits", "probe_quota_root", "MORIARTY_RUST_TOOLCHAIN_ROOT",\n',
    '        "probe_writable_tree_within_limits", "_timed_writable_check", "probe_quota_root", "MORIARTY_RUST_TOOLCHAIN_ROOT",\n',
)
replace_n(
    validator,
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is suspended",\n',
    '        "persistent writable-tree churn fails closed", "delegated probe cgroup is suspended",\n'
    '        "pidfds", "Suspension time is excluded",\n',
)

# Slow allowed scan: deterministically model a 1.5 s suspension without making CI sleep.
replace_n(
    validator,
    '    require(isolation.PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS == 1.0, "MORIARTY cgroup-suspend timeout drift")\n',
    '    require(isolation.PROBE_CGROUP_SUSPEND_TIMEOUT_SECONDS == 1.0, "MORIARTY cgroup-suspend timeout drift")\n'
    '    require(hasattr(isolation.os, "pidfd_open") and hasattr(isolation.signal, "pidfd_send_signal"), "MORIARTY pidfd signaling unavailable")\n'
    '    original_writable_check = moriarty.probe_writable_tree_within_limits\n'
    '    ticks = iter((100.0, 101.5))\n'
    '    try:\n'
    '        moriarty.probe_writable_tree_within_limits = lambda _paths: True\n'
    '        allowed, adjusted_deadline, scheduled, finished = moriarty._timed_writable_check(\n'
    '            (Path("/synthetic-slow-scan"),), 400.0, now_fn=lambda: next(ticks)\n'
    '        )\n'
    '    finally:\n'
    '        moriarty.probe_writable_tree_within_limits = original_writable_check\n'
    '    require(allowed, "synthetic slow allowed writable scan was rejected")\n'
    '    require(adjusted_deadline == 401.5, "writable-scan suspension time was charged to probe deadline")\n'
    '    require(finished == 101.5, "writable-scan completion timestamp drift")\n'
    '    require(\n'
    '        scheduled == 101.5 + isolation.PROBE_WRITABLE_CHECK_INTERVAL_SECONDS,\n'
    '        "next writable scan was not scheduled from scan completion",\n'
    '    )\n',
)

# Stale/recycled PID regression: the validator process is outside the probe cgroup.
replace_n(
    validator,
    '    require((cgroup / "cgroup.threads").is_file(), "probe cgroup thread enumeration unavailable")\n',
    '    require((cgroup / "cgroup.threads").is_file(), "probe cgroup thread enumeration unavailable")\n'
    '    stale_identity = isolation._open_probe_cgroup_pidfds(cgroup, (os.getpid(),))\n'
    '    require(stale_identity == (), "stale/recycled outside-cgroup PID identity was admitted for signaling")\n',
)

print("PR21 two-P2 hardening patch applied")
