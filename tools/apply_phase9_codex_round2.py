#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "tools/moriarty_isolation.py"
text = path.read_text(encoding="utf-8")
old = '''def _landlock_rights_for(path: Path, rights: int) -> int:\n    return rights if path.is_dir() else rights & ~_LANDLOCK_ACCESS_FS_READ_DIR\n'''
new = '''def _landlock_rights_for(path: Path, rights: int) -> int:\n    if path.is_dir():\n        return rights\n    file_rights = (\n        _LANDLOCK_ACCESS_FS_EXECUTE\n        | _LANDLOCK_ACCESS_FS_WRITE_FILE\n        | _LANDLOCK_ACCESS_FS_READ_FILE\n        | _LANDLOCK_ACCESS_FS_TRUNCATE\n    )\n    return rights & file_rights\n'''
if text.count(old) != 1:
    raise SystemExit(f"landlock file-right patch drift:{text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")

program = r'''
import errno
import socket
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import moriarty_isolation as iso
writable = Path(sys.argv[2])
parent_pid = sys.argv[3]
read_exec = tuple(path for path in (Path('/usr'), Path('/bin'), Path('/lib'), Path('/lib64')) if path.exists())
read_only = tuple(path for path in (Path('/etc'), Path('/dev/urandom'), Path('/dev/random')) if path.exists())
writable_paths = tuple(path for path in (writable, Path('/dev/null')) if path.exists())
try:
    iso.apply_landlock_policy(read_exec, read_only, writable_paths, allow_self_proc=True)
except BaseException as exc:
    print(f'LANDLOCK_FAIL:{type(exc).__name__}:{exc}', file=sys.stderr)
    raise SystemExit(11)
try:
    Path(f'/proc/{parent_pid}/environ').read_bytes()
except PermissionError:
    pass
else:
    print('PROC_PARENT_READ_ALLOWED', file=sys.stderr)
    raise SystemExit(12)
try:
    iso.apply_network_seccomp_policy()
except BaseException as exc:
    print(f'SECCOMP_FAIL:{type(exc).__name__}:{exc}', file=sys.stderr)
    raise SystemExit(13)
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno == errno.EPERM:
        raise SystemExit(0)
    print(f'SOCKET_WRONG_ERRNO:{exc.errno}', file=sys.stderr)
    raise SystemExit(14)
print('SOCKET_ALLOWED', file=sys.stderr)
raise SystemExit(15)
'''
import tempfile
with tempfile.TemporaryDirectory(prefix="moriarty-isolation-diag-") as temp_dir:
    writable = Path(temp_dir) / "writable"
    writable.mkdir(mode=0o700)
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program, str(ROOT / 'tools'), str(writable), str(__import__('os').getpid())],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"isolation diagnostic failed:{completed.returncode}:"
            + completed.stderr.decode('utf-8', errors='replace')[:1000]
        )
