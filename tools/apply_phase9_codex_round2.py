#!/usr/bin/env python3
"""Temporary diagnostic: expose runner stderr when it exits before report publication."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
target = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=root,
    check=True,
    stdout=subprocess.PIPE,
).stdout.decode("ascii").strip()
with tempfile.TemporaryDirectory(prefix="moriarty-runner-diag-") as temp_dir:
    parent = Path(temp_dir)
    os.chmod(parent, 0o700)
    output = parent / "report.json"
    completed = subprocess.run(
        [
            "python3",
            "tools/run_moriarty.py",
            "--target-commit",
            target,
            "--output",
            str(output),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    print(f"RUNNER_TARGET={target}")
    print(f"RUNNER_RC={completed.returncode}")
    print("RUNNER_STDOUT_BEGIN")
    print(completed.stdout.decode("utf-8", errors="replace")[:8000])
    print("RUNNER_STDOUT_END")
    print("RUNNER_STDERR_BEGIN")
    print(completed.stderr.decode("utf-8", errors="replace")[:16000])
    print("RUNNER_STDERR_END")
    print(f"REPORT_EXISTS={output.exists()}")
    if output.exists():
        print(f"REPORT_BYTES={output.stat().st_size}")
raise SystemExit(97)
