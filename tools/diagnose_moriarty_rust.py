#!/usr/bin/env python3
"""Closed, non-authoritative stage diagnostic for MORIARTY Rust isolation."""
from __future__ import annotations

import argparse
import ctypes
import errno
import os
import tempfile
from pathlib import Path
from typing import Callable

import moriarty_isolation as isolation
import run_moriarty as moriarty
from qsol_canonical import serialize


STAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("metadata", ("metadata", "--format-version", "1", "--no-deps", "--frozen")),
    ("check_lib", ("check", "--lib", "--frozen")),
    ("test_no_run", ("test", "--all-targets", "--no-run", "--frozen")),
    ("test_full", ("test", "--all-targets", "--frozen")),
)


def _record(stage_results: list[dict[str, object]], stage: str, result: dict[str, object]) -> bool:
    stage_results.append({
        "stage": stage,
        "ok": result["ok"],
        "exit_code": result["exit_code"],
        "failure_kind": result["failure_kind"],
    })
    return bool(result["ok"])


def _apply_local_ipc_seccomp() -> None:
    """Allow only AF_UNIX socketpair creation; deny external socket setup/I/O."""
    libc = isolation._linux_libc()
    machine = os.uname().machine
    socketpair_number = 53 if machine == "x86_64" else 199
    deny = isolation._SECCOMP_RET_ERRNO | errno.EPERM
    blocked = [number for number in isolation._network_syscalls() if number != socketpair_number]
    # Close alternate socket-creation / cross-process-fd avenues not needed by
    # this generated zero-dependency compiler control.
    blocked.extend([425, 434, 438])  # io_uring_setup, pidfd_open, pidfd_getfd
    instructions: list[isolation._SockFilter] = [
        isolation._SockFilter(isolation._BPF_LD_W_ABS, 0, 0, 0)
    ]
    for number in blocked:
        instructions.append(isolation._SockFilter(isolation._BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(isolation._SockFilter(isolation._BPF_RET_K, 0, 0, deny))
    # seccomp_data.args[0] begins at byte offset 16. Permit socketpair only
    # when its domain is AF_UNIX (=1); all other socketpair domains fail EPERM.
    instructions.append(isolation._SockFilter(isolation._BPF_JMP_JEQ_K, 0, 4, socketpair_number))
    instructions.append(isolation._SockFilter(isolation._BPF_LD_W_ABS, 0, 0, 16))
    instructions.append(isolation._SockFilter(isolation._BPF_JMP_JEQ_K, 0, 1, 1))
    instructions.append(isolation._SockFilter(isolation._BPF_RET_K, 0, 0, isolation._SECCOMP_RET_ALLOW))
    instructions.append(isolation._SockFilter(isolation._BPF_RET_K, 0, 0, deny))
    instructions.append(isolation._SockFilter(isolation._BPF_RET_K, 0, 0, isolation._SECCOMP_RET_ALLOW))
    array_type = isolation._SockFilter * len(instructions)
    array = array_type(*instructions)
    program = isolation._SockFprog(len(instructions), array)
    if libc.prctl(isolation._PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "diag_prctl_no_new_privs_seccomp")
    if libc.prctl(isolation._PR_SET_SECCOMP, isolation._SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "diag_prctl_seccomp_local_ipc_filter")


def _local_ipc_seccomp_preexec(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())
    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())
    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())

    def _apply() -> None:
        isolation.apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)
        _apply_local_ipc_seccomp()

    return _apply


def _write_only_seccomp_preexec(
    _read_exec_paths: tuple[Path, ...],
    _read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())

    def _apply() -> None:
        isolation.apply_landlock_write_policy(writable)
        isolation.apply_network_seccomp_policy()

    return _apply


def _full_landlock_no_seccomp_preexec(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())
    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())
    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())

    def _apply() -> None:
        isolation.apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)

    return _apply


def _no_policy_preexec(
    _read_exec_paths: tuple[Path, ...],
    _read_paths: tuple[Path, ...],
    _writable_paths: tuple[Path, ...],
):
    def _apply() -> None:
        return None

    return _apply


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    target = args.target_commit
    if moriarty.git_head() != target:
        raise SystemExit("moriarty_diag_target_mismatch")
    if not moriarty.tracked_tree_clean() or not moriarty.harness_files_match_target(target):
        raise SystemExit("moriarty_diag_dirty_or_unbound_harness")

    stage_results: list[dict[str, object]] = []
    first_failed: str | None = None
    original_argv = moriarty.PROBES["rust_all"]
    original_preexec = moriarty.probe_isolation_preexec

    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-rust-diag-") as work_dir:
        workspace = Path(work_dir)
        control = isolation.create_exact_export(target, workspace, moriarty.git_archive_bytes, "control")
        cargo_template = isolation.create_verified_cargo_template(
            moriarty.REAL_HOME / ".cargo", workspace, control / "Cargo.lock"
        )
        python_exec = isolation.stage_executable_from_fd(
            moriarty.PYTHON_TRUSTED.fd, workspace / "python-runtime" / "python3"
        )

        rust_runtime: Path | None = None
        if moriarty.RUSTUP_DISCOVERY_USED:
            rust_source_root = Path(moriarty.CARGO_TRUSTED.executable).parent.parent
            rust_runtime = isolation.stage_rust_toolchain_runtime(
                rust_source_root,
                workspace / "rust-runtime",
                moriarty.CARGO_TRUSTED.fd,
                moriarty.RUSTC_TRUSTED.fd,
            )
            cargo_exec = rust_runtime / "bin" / "cargo"
            rustc_exec = rust_runtime / "bin" / "rustc"
            rustdoc_candidate = rust_runtime / "bin" / "rustdoc"
            rustdoc_exec = rustdoc_candidate if rustdoc_candidate.is_file() else None
        else:
            cargo_exec = Path(moriarty.CARGO_TRUSTED.executable)
            rustc_exec = Path(moriarty.RUSTC_TRUSTED.executable)
            rustdoc_exec = None

        try:
            minimal = workspace / "minimal-src"
            (minimal / "src").mkdir(parents=True)
            (minimal / "Cargo.toml").write_text(
                '[package]\nname = "moriarty-diag"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n',
                encoding="utf-8",
            )
            (minimal / "Cargo.lock").write_text(
                '# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = "moriarty-diag"\nversion = "0.0.0"\n',
                encoding="utf-8",
            )
            (minimal / "src/lib.rs").write_text("pub fn diagnostic_value() -> u8 { 1 }\n", encoding="utf-8")
            isolation.seal_read_only_tree(minimal)
            moriarty.PROBES["rust_all"] = (original_argv[0], "check", "--lib", "--frozen")

            policy_matrix: tuple[tuple[str, Callable[..., object]], ...] = (
                ("minimal_full", original_preexec),
                ("minimal_local_ipc_seccomp", _local_ipc_seccomp_preexec),
                ("minimal_write_only_seccomp", _write_only_seccomp_preexec),
                ("minimal_full_landlock_no_seccomp", _full_landlock_no_seccomp_preexec),
                ("minimal_no_policy", _no_policy_preexec),
            )
            full_ok = False
            for index, (stage, preexec_factory) in enumerate(policy_matrix):
                moriarty.probe_isolation_preexec = preexec_factory
                label = f"policy-{index}-{stage}"
                cargo_home = isolation.create_isolated_cargo_home(cargo_template, workspace, label)
                result = moriarty.run_probe(
                    "rust_all",
                    workspace / f"home-{label}",
                    minimal,
                    cargo_home,
                    workspace / f"target-{label}",
                    python_exec,
                    cargo_exec,
                    rustc_exec,
                    rustdoc_exec,
                    rust_runtime,
                )
                ok = _record(stage_results, stage, result)
                if stage == "minimal_full":
                    full_ok = ok

            moriarty.probe_isolation_preexec = original_preexec
            if not full_ok:
                first_failed = "minimal_full"
            else:
                for index, (stage, tail) in enumerate(STAGES):
                    moriarty.PROBES["rust_all"] = (original_argv[0], *tail)
                    label = f"stage-{index}-{stage}"
                    source = isolation.create_exact_export(target, workspace, moriarty.git_archive_bytes, label)
                    cargo_home = isolation.create_isolated_cargo_home(cargo_template, workspace, label)
                    result = moriarty.run_probe(
                        "rust_all",
                        workspace / f"home-{label}",
                        source,
                        cargo_home,
                        workspace / f"target-{label}",
                        python_exec,
                        cargo_exec,
                        rustc_exec,
                        rustdoc_exec,
                        rust_runtime,
                    )
                    if not _record(stage_results, stage, result):
                        first_failed = stage
                        break
        finally:
            moriarty.PROBES["rust_all"] = original_argv
            moriarty.probe_isolation_preexec = original_preexec

    diagnostic = {
        "schema": "moriarty-rust-stage-diagnostic/1",
        "target_commit": target,
        "first_failed_stage": first_failed,
        "stages": stage_results,
        "raw_output_persisted": False,
        "authority_effect": "none",
    }
    output = Path(args.output).resolve()
    isolation.write_report_exclusive(output, serialize(diagnostic).encode("utf-8"), moriarty.ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
