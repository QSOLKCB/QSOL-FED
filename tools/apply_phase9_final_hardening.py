#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch_isolation() -> None:
    path = ROOT / "tools/moriarty_isolation.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '_SECCOMP_DATA_ARG0_OFFSET = 16\n_AF_UNIX = 1\n',
        '_SECCOMP_DATA_ARCH_OFFSET = 4\n_SECCOMP_DATA_ARG0_OFFSET = 16\n_AF_UNIX = 1\n_AUDIT_ARCH_X86_64 = 0xC000003E\n_AUDIT_ARCH_AARCH64 = 0xC00000B7\n',
        "seccomp constants",
    )
    old = '''def _socket_syscalls() -> tuple[int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (41, 53)
    if machine == "aarch64":
        return (198, 199)
    fail("moriarty_network_seccomp_arch_unsupported")


def apply_network_seccomp_policy() -> None:
    """Allow Unix-domain IPC while denying creation of every other socket family.

    The child receives no ambient network descriptors. By filtering both socket()
    and socketpair() on argument zero, descendants may use AF_UNIX for compiler
    and Cargo-local IPC, while AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, and every
    other non-local family fail at creation with EPERM. Socket I/O syscalls stay
    available only for descriptors that survived this creation boundary.
    """
    libc = _linux_libc()
    deny = _SECCOMP_RET_ERRNO | errno.EPERM
    allow = _SECCOMP_RET_ALLOW
    socket_nr, socketpair_nr = _socket_syscalls()
    instructions = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
        _SockFilter(_BPF_JMP_JEQ_K, 2, 0, socket_nr),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, socketpair_nr),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
    ]
    array_type = _SockFilter * len(instructions)
    array = array_type(*instructions)
    program = _SockFprog(len(instructions), array)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")
'''
    new = '''def _socket_syscalls() -> tuple[int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (41, 53, _AUDIT_ARCH_X86_64)
    if machine == "aarch64":
        return (198, 199, _AUDIT_ARCH_AARCH64)
    fail("moriarty_network_seccomp_arch_unsupported")


def _io_uring_syscalls() -> tuple[int, int, int]:
    # io_uring syscall numbers are shared by the supported Linux architectures.
    return (425, 426, 427)


def apply_network_seccomp_policy() -> None:
    """Allow AF_UNIX IPC while denying external socket creation and io_uring.

    The filter first binds itself to the expected Linux audit architecture. It
    denies io_uring entirely so IORING_OP_SOCKET/CONNECT/SEND cannot bypass the
    native syscall policy. Native socket()/socketpair() are then allowed only for
    AF_UNIX; every other family fails at creation with EPERM. The probe receives
    no ambient network descriptors, so later socket I/O can only operate on local
    Unix-domain IPC descriptors created inside the sandbox.
    """
    libc = _linux_libc()
    deny = _SECCOMP_RET_ERRNO | errno.EPERM
    allow = _SECCOMP_RET_ALLOW
    socket_nr, socketpair_nr, audit_arch = _socket_syscalls()
    instructions: list[_SockFilter] = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    for number in _io_uring_syscalls():
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    instructions.extend([
        _SockFilter(_BPF_JMP_JEQ_K, 2, 0, socket_nr),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, socketpair_nr),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
    ])
    array_type = _SockFilter * len(instructions)
    array = array_type(*instructions)
    program = _SockFprog(len(instructions), array)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")
'''
    text = replace_once(text, old, new, "seccomp policy")
    text = replace_once(
        text,
        'def create_verified_cargo_template(real_cargo_home: Path, workspace: Path, cargo_lock: Path) -> Path:\n',
        'def create_verified_cargo_template(\n    real_cargo_home: Path, workspace: Path, cargo_lock: Path, label: str = "cargo-template"\n) -> Path:\n',
        "cargo template signature",
    )
    text = replace_once(
        text,
        '    template = workspace / "cargo-template"\n',
        '    if not label or "/" in label or "\\\\" in label or label in {".", ".."}:\n        fail("moriarty_cargo_template_label_invalid")\n    template = workspace / label\n',
        "cargo template label",
    )
    path.write_text(text, encoding="utf-8")


def patch_runner() -> None:
    path = ROOT / "tools/run_moriarty.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(text, 'import hashlib\nimport json\n', 'import hashlib\nimport io\nimport json\n', "runner io import")
    text = replace_once(text, 'import sys\nimport tempfile\n', 'import sys\nimport tarfile\nimport tempfile\n', "runner tarfile import")

    anchor = '''    return subprocess.run(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=pass_fds,
        **kwargs,
    )


def _trusted_exact_path'''
    replacement = '''    return subprocess.run(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=pass_fds,
        **kwargs,
    )


def trusted_capture_bounded(
    trusted: TrustedExecutable,
    args: Sequence[str],
    *,
    limit: int,
    cwd: Path,
    env: dict[str, str],
    overflow_error: str,
    command_error: str,
) -> bytes:
    """Capture trusted stdout incrementally without exceeding `limit` bytes."""
    if limit < 0 or not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_capture_invalid:{trusted.name}")
    process = subprocess.Popen(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=(trusted.fd,),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    assert process.stdout is not None
    output = bytearray()
    try:
        while True:
            chunk = process.stdout.read(min(65_536, limit - len(output) + 1))
            if not chunk:
                break
            if len(output) + len(chunk) > limit:
                process.kill()
                process.wait()
                fail(overflow_error)
            output.extend(chunk)
        return_code = process.wait()
    finally:
        process.stdout.close()
    if return_code != 0:
        fail(command_error)
    if not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_executable_changed:{trusted.name}")
    return bytes(output)


def _trusted_exact_path'''
    text = replace_once(text, anchor, replacement, "bounded trusted capture")

    direct_anchor = '''def _rustup_which(rustup: TrustedExecutable, toolchain: str, component: str) -> TrustedExecutable:
    completed = trusted_run(
        rustup,
        ("which", "--toolchain", toolchain, component),
        cwd=REAL_HOME,
        env=_rustup_discovery_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"moriarty_rustup_component_unavailable:{component}")
    try:
        path = Path(completed.stdout.decode("utf-8", errors="strict").strip())
    except UnicodeError:
        fail(f"moriarty_rustup_component_path_invalid:{component}")
    toolchain_root = (REAL_HOME / ".rustup" / "toolchains").resolve(strict=True)
    resolved = path.resolve(strict=True)
    if toolchain_root not in resolved.parents:
        fail(f"moriarty_rustup_component_outside_toolchains:{component}")
    return _trusted_exact_path(component, resolved)


PYTHON_TRUSTED'''
    direct_replacement = direct_anchor.replace('\n\nPYTHON_TRUSTED', '''


def _direct_toolchain_root(cargo: TrustedExecutable, rustc: TrustedExecutable) -> Path:
    completed = trusted_run(
        rustc,
        ("--print", "sysroot"),
        cwd=REAL_HOME,
        env={"PATH": "/usr/bin:/bin", "HOME": str(REAL_HOME), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("moriarty_direct_rustc_sysroot_unavailable")
    try:
        root = Path(completed.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (UnicodeError, OSError):
        fail("moriarty_direct_rustc_sysroot_invalid")
    expected_bin = root / "bin"
    if (
        Path(cargo.executable).parent != expected_bin
        or Path(rustc.executable).parent != expected_bin
        or not (root / "lib").is_dir()
    ):
        fail("moriarty_direct_toolchain_not_self_contained")
    return root


PYTHON_TRUSTED''')
    text = replace_once(text, direct_anchor, direct_replacement, "direct toolchain root")

    text = replace_once(
        text,
        '        "GIT_CONFIG_GLOBAL": "/dev/null",\n        "GIT_NO_REPLACE_OBJECTS": "1",\n',
        '        "GIT_CONFIG_GLOBAL": "/dev/null",\n        "GIT_ATTR_NOSYSTEM": "1",\n        "GIT_NO_REPLACE_OBJECTS": "1",\n',
        "git attribute env",
    )

    old_archive = '''def git_archive_bytes(commit: str) -> bytes:
    completed = git("archive", "--format=tar", commit)
    if completed.returncode != 0:
        fail("moriarty_exact_export_git_archive_failed")
    if len(completed.stdout) > MAX_GIT_ARCHIVE_BYTES:
        fail("moriarty_exact_export_archive_too_large")
    return completed.stdout
'''
    new_archive = '''def git_archive_bytes(commit: str) -> bytes:
    """Build a bounded tar from commit tree/blob objects, bypassing archive attributes."""
    if not git_commit_exists(commit):
        fail("moriarty_exact_export_commit_missing")
    listing = trusted_capture_bounded(
        GIT_TRUSTED,
        ("ls-tree", "-rz", "--full-tree", commit),
        limit=MAX_GIT_ARCHIVE_BYTES,
        cwd=ROOT,
        env=_git_env(),
        overflow_error="moriarty_exact_export_tree_listing_too_large",
        command_error="moriarty_exact_export_ls_tree_failed",
    )
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        for raw_record in listing.split(b"\\0"):
            if not raw_record:
                continue
            try:
                metadata, raw_path = raw_record.split(b"\\t", 1)
                mode, object_type, object_id = metadata.decode("ascii", errors="strict").split(" ")
                relative = raw_path.decode("utf-8", errors="strict")
            except (ValueError, UnicodeError):
                fail("moriarty_exact_export_tree_record_invalid")
            if object_type != "blob" or mode not in {"100644", "100755"}:
                fail("moriarty_exact_export_nonregular_entry_forbidden")
            if not relative or relative.startswith("/") or any(part in {"", ".", ".."} for part in Path(relative).parts):
                fail("moriarty_exact_export_tree_path_invalid")
            remaining = MAX_GIT_ARCHIVE_BYTES - buffer.tell()
            if remaining <= 0:
                fail("moriarty_exact_export_archive_too_large")
            blob = trusted_capture_bounded(
                GIT_TRUSTED,
                ("cat-file", "blob", object_id),
                limit=remaining,
                cwd=ROOT,
                env=_git_env(),
                overflow_error="moriarty_exact_export_archive_too_large",
                command_error="moriarty_exact_export_blob_read_failed",
            )
            info = tarfile.TarInfo(relative)
            info.size = len(blob)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(blob))
            if buffer.tell() > MAX_GIT_ARCHIVE_BYTES:
                fail("moriarty_exact_export_archive_too_large")
    encoded = buffer.getvalue()
    if len(encoded) > MAX_GIT_ARCHIVE_BYTES:
        fail("moriarty_exact_export_archive_too_large")
    return encoded
'''
    text = replace_once(text, old_archive, new_archive, "direct commit export")

    text = text.replace('or not 0 <= item["stdout_bytes"] <= 9007199254740991', 'or not 0 <= item["stdout_bytes"] <= MAX_PROBE_OUTPUT_BYTES')
    text = text.replace('or not 0 <= item["stderr_bytes"] <= 9007199254740991', 'or not 0 <= item["stderr_bytes"] <= MAX_PROBE_OUTPUT_BYTES')
    if '9007199254740991' in text:
        raise SystemExit("counterexample byte ceiling replacement incomplete")

    old_verify_sig = '''def verify_resolved_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    cargo_template: Path,
    python_exec: Path,
'''
    new_verify_sig = '''def verify_resolved_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    python_exec: Path,
'''
    text = replace_once(text, old_verify_sig, new_verify_sig, "verify signature")

    old_before = '''        before_cargo = _fresh_cargo_home(
            probe_id, cargo_template, workspace, f"resolved-{index}-before"
        )
'''
    new_before = '''        if probe_id == "rust_all" and not (before_source / "Cargo.lock").is_file():
            fail("moriarty_resolution_target_cargo_lock_missing")
        before_template = (
            create_verified_cargo_template(
                REAL_HOME / ".cargo",
                workspace,
                before_source / "Cargo.lock",
                f"resolved-{index}-before-template",
            )
            if probe_id == "rust_all"
            else workspace
        )
        before_cargo = _fresh_cargo_home(
            probe_id, before_template, workspace, f"resolved-{index}-before"
        )
'''
    text = replace_once(text, old_before, new_before, "historical before cargo")

    old_after = '''        after_cargo = _fresh_cargo_home(
            probe_id, cargo_template, workspace, f"resolved-{index}-after"
        )
'''
    new_after = '''        if probe_id == "rust_all" and not (after_source / "Cargo.lock").is_file():
            fail("moriarty_resolution_commit_cargo_lock_missing")
        after_template = (
            create_verified_cargo_template(
                REAL_HOME / ".cargo",
                workspace,
                after_source / "Cargo.lock",
                f"resolved-{index}-after-template",
            )
            if probe_id == "rust_all"
            else workspace
        )
        after_cargo = _fresh_cargo_home(
            probe_id, after_template, workspace, f"resolved-{index}-after"
        )
'''
    text = replace_once(text, old_after, new_after, "historical after cargo")

    old_toolchain = '''        rust_runtime: Path | None = None
        if RUSTUP_DISCOVERY_USED:
            rust_source_root = Path(CARGO_TRUSTED.executable).parent.parent
            rust_runtime = stage_rust_toolchain_runtime(
                rust_source_root,
                workspace / "rust-runtime",
                CARGO_TRUSTED.fd,
                RUSTC_TRUSTED.fd,
            )
            cargo_exec = rust_runtime / "bin" / "cargo"
            rustc_exec = rust_runtime / "bin" / "rustc"
            rustdoc_candidate = rust_runtime / "bin" / "rustdoc"
            rustdoc_exec = rustdoc_candidate if rustdoc_candidate.is_file() else None
        else:
            cargo_exec = Path(CARGO_TRUSTED.executable)
            rustc_exec = Path(RUSTC_TRUSTED.executable)
            rustdoc_exec = None
'''
    new_toolchain = '''        rust_source_root = (
            Path(CARGO_TRUSTED.executable).parent.parent
            if RUSTUP_DISCOVERY_USED
            else _direct_toolchain_root(CARGO_TRUSTED, RUSTC_TRUSTED)
        )
        rust_runtime = stage_rust_toolchain_runtime(
            rust_source_root,
            workspace / "rust-runtime",
            CARGO_TRUSTED.fd,
            RUSTC_TRUSTED.fd,
        )
        cargo_exec = rust_runtime / "bin" / "cargo"
        rustc_exec = rust_runtime / "bin" / "rustc"
        rustdoc_candidate = rust_runtime / "bin" / "rustdoc"
        rustdoc_exec = rustdoc_candidate if rustdoc_candidate.is_file() else None
        if rustdoc_exec is None:
            fail("moriarty_staged_rustdoc_missing")
'''
    text = replace_once(text, old_toolchain, new_toolchain, "unified toolchain staging")

    text = replace_once(
        text,
        '''        verify_resolved_counterexamples(
            accepted,
            workspace,
            cargo_template,
            python_exec,
''',
        '''        verify_resolved_counterexamples(
            accepted,
            workspace,
            python_exec,
''',
        "verify call",
    )
    path.write_text(text, encoding="utf-8")


def patch_validator() -> None:
    path = ROOT / "tools/validate_phase9_gate.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '("tools/run_moriarty.py", "--target-commit", target, "--output", str(report_path)),',
        '("-I", "tools/run_moriarty.py", "--target-commit", target, "--output", str(report_path)),',
        "isolated runner bootstrap",
    )
    text = replace_once(
        text,
        'require("python3 tools/validate_phase9_gate.py --target-commit \\\"$MORIARTY_TARGET_COMMIT\\\" --report-dir \\\"$MORIARTY_REPORT_DIR\\\"" in workflow, "CI missing exact-commit Phase 9 gate")',
        'require("python3 -I tools/validate_phase9_gate.py --target-commit \\\"$MORIARTY_TARGET_COMMIT\\\" --report-dir \\\"$MORIARTY_REPORT_DIR\\\"" in workflow, "CI missing isolated exact-commit Phase 9 gate")',
        "CI bootstrap contract",
    )
    old_program = '''try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno == errno.EPERM:
        raise SystemExit(0)
    raise
raise SystemExit(4)
'''
    new_program = '''try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(4)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
result = libc.syscall(425, 1, ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(5)
raise SystemExit(0)
'''
    text = replace_once(text, old_program, new_program, "io_uring bypass regression")
    marker = '        "stage_rust_toolchain_runtime", "git_archive_bytes", "index_flags_clean",\n'
    text = replace_once(
        text,
        marker,
        '        "stage_rust_toolchain_runtime", "git_archive_bytes", "trusted_capture_bounded", "index_flags_clean",\n',
        "runner source markers",
    )
    path.write_text(text, encoding="utf-8")


def patch_ci() -> None:
    path = ROOT / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text = text.replace('permissions:\n  contents: write\n', 'permissions:\n  contents: read\n', 1)
    text = replace_once(
        text,
        '          python3 tools/validate_phase9_gate.py --target-commit "$MORIARTY_TARGET_COMMIT" --report-dir "$MORIARTY_REPORT_DIR"\n',
        '          python3 -I tools/validate_phase9_gate.py --target-commit "$MORIARTY_TARGET_COMMIT" --report-dir "$MORIARTY_REPORT_DIR"\n',
        "CI isolated Phase 9",
    )
    diagnostic = '''      - name: Stage-diagnose MORIARTY Rust failure
        if: failure()
        env:
          MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          MORIARTY_REPORT_DIR: ${{ runner.temp }}/moriarty-report
        run: |
          install -d -m 700 "$MORIARTY_REPORT_DIR"
          python3 tools/diagnose_moriarty_rust.py \\
            --target-commit "$MORIARTY_TARGET_COMMIT" \\
            --output "$MORIARTY_REPORT_DIR/moriarty-rust-stage-$MORIARTY_TARGET_COMMIT.json"
'''
    text = replace_once(text, diagnostic, '', "remove Rust diagnostic step")
    apply_step = '''      - name: Apply final Phase 9 hardening
        if: always()
        run: |
          python3 tools/apply_phase9_final_hardening.py
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add -A
          git commit -m "Close final Phase 9 assurance gaps"
          git push origin HEAD:agent/phase9-moriarty-graduation
'''
    text = replace_once(text, apply_step, '', "remove self patch step")
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_isolation()
    patch_runner()
    patch_validator()
    patch_ci()
    diagnostic = ROOT / "tools/diagnose_moriarty_rust.py"
    if diagnostic.exists():
        diagnostic.unlink()
    (ROOT / ".phase9-finalize-pending").write_text(
        "Delete this marker with the GitHub connector to produce the clean exact-head CI candidate.\n",
        encoding="utf-8",
    )
    Path(__file__).unlink()


if __name__ == "__main__":
    main()
