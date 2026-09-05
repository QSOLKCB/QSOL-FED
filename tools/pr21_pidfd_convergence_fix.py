#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/moriarty_isolation.py")
text = path.read_text(encoding="utf-8")

start = text.index("def _open_probe_cgroup_pidfds(\n")
end = text.index("def _resume_probe_cgroup(\n", start)
replacement = r'''def _open_probe_cgroup_pidfds(
    root: Path,
    pids: tuple[int, ...],
) -> tuple[tuple[int, int], ...] | None:
    """Bind candidate cgroup PIDs to stable task identities before signaling."""
    opened: list[tuple[int, int]] = []
    for pid in pids:
        try:
            pidfd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            continue
        except OSError:
            _close_probe_pidfds(tuple(opened))
            return None
        opened.append((pid, pidfd))
    try:
        current = set(probe_cgroup_pids(root))
    except SystemExit:
        _close_probe_pidfds(tuple(opened))
        return None
    kept: list[tuple[int, int]] = []
    for pid, pidfd in opened:
        if pid not in current:
            try:
                os.close(pidfd)
            except OSError:
                pass
            continue
        try:
            # Signal 0 proves that the pidfd-bound identity still exists after
            # cgroup membership was revalidated. A recycled numeric PID cannot
            # redirect later signals away from this descriptor-bound identity.
            signal.pidfd_send_signal(pidfd, 0, None, 0)
        except ProcessLookupError:
            try:
                os.close(pidfd)
            except OSError:
                pass
            continue
        except OSError:
            try:
                os.close(pidfd)
            except OSError:
                pass
            _close_probe_pidfds(tuple(kept))
            for other_pid, other_fd in opened:
                if other_fd == pidfd or (other_pid, other_fd) in kept:
                    continue
                try:
                    os.close(other_fd)
                except OSError:
                    pass
            return None
        kept.append((pid, pidfd))
    return tuple(kept)


def _signal_probe_pidfds(
    handles: tuple[tuple[int, int], ...],
    sig: int,
    *,
    require_present: bool = False,
) -> bool:
    for _pid, pidfd in handles:
        try:
            signal.pidfd_send_signal(pidfd, sig, None, 0)
        except ProcessLookupError:
            # STOP requires every bound identity to still exist so the caller
            # can reacquire a coherent cgroup membership snapshot. CONT/KILL
            # may harmlessly encounter tasks that exited after the operation.
            if require_present:
                return False
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
        if not _signal_probe_pidfds(handles, signal.SIGSTOP, require_present=True):
            _signal_probe_pidfds(handles, signal.SIGCONT)
            _close_probe_pidfds(handles)
            if time.monotonic() >= deadline:
                return None
            continue

        # Do not resume merely because sibling threads have not all entered the
        # stopped state after the first scheduler tick. Keeping the pidfd-bound
        # process stopped allows a large thread group to converge. Only process
        # membership drift invalidates the identity set and requires reacquire.
        while True:
            try:
                current_pids = probe_cgroup_pids(root)
                threads = probe_cgroup_threads(root)
            except SystemExit:
                _signal_probe_pidfds(handles, signal.SIGCONT)
                _close_probe_pidfds(handles)
                return None
            if current_pids != pids:
                _signal_probe_pidfds(handles, signal.SIGCONT)
                _close_probe_pidfds(handles)
                break
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
                    # pidfds remain open across the scan, so resume is bound to
                    # the exact identities that were stopped, never reused PIDs.
                    return handles
            if time.monotonic() >= deadline:
                _signal_probe_pidfds(handles, signal.SIGCONT)
                _close_probe_pidfds(handles)
                return None
            # Reassert the process-directed group stop through the same stable
            # pidfds so sibling threads created during stop convergence cannot
            # remain runnable.
            if not _signal_probe_pidfds(handles, signal.SIGSTOP, require_present=True):
                _signal_probe_pidfds(handles, signal.SIGCONT)
                _close_probe_pidfds(handles)
                break
            time.sleep(0.001)


'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
print("pidfd quiescence convergence fix applied")
