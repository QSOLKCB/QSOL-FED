#!/usr/bin/env python3
"""Isolation primitives for the MORIARTY/1 exact-commit runner.

This module deliberately contains no operator-supplied command execution. It only
handles private filesystem staging, exact Git archive extraction, Cargo cache
projection, and exclusive report publication.
"""
from __future__ import annotations

import hashlib
import os
import stat
import tarfile
from pathlib import Path
from typing import Callable, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def proc_fd_path(fd: int) -> str:
    path = Path(f"/proc/self/fd/{fd}")
    if not path.exists():
        fail("moriarty_proc_fd_unavailable")
    return str(path)


def _relative_archive_name(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail("moriarty_archive_member_path_invalid")
    return path


def extract_exact_archive(archive_path: Path, destination: Path) -> None:
    """Extract a Git-created tar without admitting links or special files."""
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tarfile.open(archive_path, mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            _relative_archive_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                fail("moriarty_archive_special_member_forbidden")
            if not (member.isdir() or member.isfile()):
                fail("moriarty_archive_member_type_forbidden")
        for member in members:
            relative = _relative_archive_name(member.name)
            output = destination / relative
            if member.isdir():
                output.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                fail("moriarty_archive_file_unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(output, flags, 0o600)
            try:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
                source.close()
            if member.mode & 0o111:
                os.chmod(output, 0o500)
            else:
                os.chmod(output, 0o400)


def seal_read_only_tree(root: Path) -> None:
    """Remove write permission from every exported source entry."""
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            if path.is_symlink():
                fail("moriarty_export_symlink_forbidden")
            mode = path.stat().st_mode
            os.chmod(path, 0o500 if mode & 0o111 else 0o400)
        for name in dirs:
            path = current_path / name
            if path.is_symlink():
                fail("moriarty_export_symlink_forbidden")
            os.chmod(path, 0o500)
    os.chmod(root, 0o500)


def create_exact_export(
    target_commit: str,
    workspace: Path,
    run_git: Callable[..., int],
    label: str,
) -> Path:
    """Materialize only tracked bytes from an exact commit and seal them read-only."""
    archive_path = workspace / f"{label}.tar"
    source_root = workspace / f"{label}-src"
    if run_git("archive", "--format=tar", "--output", str(archive_path), target_commit) != 0:
        fail("moriarty_exact_export_git_archive_failed")
    extract_exact_archive(archive_path, source_root)
    try:
        archive_path.unlink()
    except OSError:
        fail("moriarty_exact_export_archive_cleanup_failed")
    seal_read_only_tree(source_root)
    return source_root


def _copy_regular_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        output_dir = destination / relative
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in list(dirs):
            path = current_path / directory
            if path.is_symlink():
                fail("moriarty_cargo_cache_symlink_forbidden")
        for name in files:
            source_file = current_path / name
            if source_file.is_symlink() or not source_file.is_file():
                fail("moriarty_cargo_cache_nonregular_file")
            destination_file = output_dir / name
            with source_file.open("rb") as input_handle:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(destination_file, flags, 0o600)
                try:
                    while True:
                        chunk = input_handle.read(65536)
                        if not chunk:
                            break
                        view = memoryview(chunk)
                        while view:
                            written = os.write(fd, view)
                            view = view[written:]
                finally:
                    os.close(fd)


def create_isolated_cargo_home(real_cargo_home: Path, workspace: Path) -> Path:
    """Project only Cargo registry cache material into a private home."""
    cargo_home = workspace / "cargo-home"
    cargo_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    _copy_regular_tree(real_cargo_home / "registry", cargo_home / "registry")
    return cargo_home


def stage_executable_from_fd(source_fd: int, destination: Path) -> Path:
    """Copy an already-open executable inode into a private immutable named path.

    This is used for Rustup multicall children: Cargo needs a path named ``rustc``
    so Rustup can dispatch by argv[0], while the bytes still originate from the
    descriptor that was pinned before any adversarial execution begins.
    """
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=False, exist_ok=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    output_fd = os.open(destination, flags, 0o700)
    source_hash = hashlib.sha256()
    output_hash = hashlib.sha256()
    try:
        source_copy = os.open(proc_fd_path(source_fd), os.O_RDONLY | os.O_CLOEXEC)
        try:
            while True:
                chunk = os.read(source_copy, 65536)
                if not chunk:
                    break
                source_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    output_hash.update(view[:written])
                    view = view[written:]
            os.fsync(output_fd)
        finally:
            os.close(source_copy)
    finally:
        os.close(output_fd)
    if source_hash.digest() != output_hash.digest():
        fail("moriarty_staged_executable_digest_mismatch")
    os.chmod(destination, 0o500)
    os.chmod(parent, 0o500)
    return destination


def private_directory(path: Path) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    return path.is_dir() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0


def write_report_exclusive(output: Path, encoded: bytes, repository_root: Path) -> None:
    """Publish one report outside the repository without following path aliases."""
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        fail("moriarty_report_output_must_be_absolute")
    try:
        repository = repository_root.resolve(strict=True)
        parent = output.parent.resolve(strict=True)
    except OSError:
        fail("moriarty_report_parent_unavailable")
    if parent == repository or repository in parent.parents:
        fail("moriarty_report_output_inside_repository")
    if not private_directory(parent):
        fail("moriarty_report_parent_not_private")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    directory_fd = os.open(parent, directory_flags)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            fail("moriarty_report_parent_changed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(output.name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            fail("moriarty_report_output_exists")
        except OSError:
            fail("moriarty_report_output_open_failed")
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
