#!/usr/bin/env python3
"""Run the original one-shot Sol transformer with deterministic rewrite fixes."""
from __future__ import annotations

import subprocess
from pathlib import Path

ORIGINAL_TRANSFORMER_COMMIT = "07295c49a50e272006a5470b2d6b9f20b67fb975"
previous = subprocess.run(
    ["git", "show", f"{ORIGINAL_TRANSFORMER_COMMIT}:tools/apply_phase9_codex_round2.py"],
    check=True,
    stdout=subprocess.PIPE,
).stdout.decode("utf-8", errors="strict")

marker_old = '''validator = replace_once(\n    validator,\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\",\\n',\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\", \"stdout_truncated\", \"stderr_truncated\",\\n',\n    \"validator runner markers 3\",\n)\n'''
marker_new = '''runner_marker_start = validator.index(\"def validate_runner_source() -> None:\")\nrunner_marker_end = validator.index(\"def validate_docs_and_ci() -> None:\", runner_marker_start)\nrunner_marker_block = validator[runner_marker_start:runner_marker_end]\nrunner_marker_block = replace_once(\n    runner_marker_block,\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\",\\n',\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\", \"stdout_truncated\", \"stderr_truncated\",\\n',\n    \"validator runner markers 3\",\n)\nvalidator = validator[:runner_marker_start] + runner_marker_block + validator[runner_marker_end:]\n'''
if previous.count(marker_old) != 1:
    raise SystemExit(f"phase9 Sol wrapper marker replacement drift:{previous.count(marker_old)}")
patched = previous.replace(marker_old, marker_new, 1)

quote_old = """        program = r'''\nimport errno\nimport socket\nimport sys\nfrom pathlib import Path\nparent_pid = sys.argv[1]\ntry:\n    Path(f\"/proc/{parent_pid}/environ\").read_bytes()\nexcept PermissionError:\n    pass\nelse:\n    raise SystemExit(3)\ntry:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    if exc.errno == errno.EPERM:\n        raise SystemExit(0)\n    raise\nraise SystemExit(4)\n'''\n        preexec = moriarty.probe_isolation_preexec(\n"""
quote_new = '''        program = r"""\nimport errno\nimport socket\nimport sys\nfrom pathlib import Path\nparent_pid = sys.argv[1]\ntry:\n    Path(f"/proc/{parent_pid}/environ").read_bytes()\nexcept PermissionError:\n    pass\nelse:\n    raise SystemExit(3)\ntry:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    if exc.errno == errno.EPERM:\n        raise SystemExit(0)\n    raise\nraise SystemExit(4)\n"""\n        preexec = moriarty.probe_isolation_preexec(\n'''
if patched.count(quote_old) != 1:
    raise SystemExit(f"phase9 Sol wrapper quote replacement drift:{patched.count(quote_old)}")
patched = patched.replace(quote_old, quote_new, 1)

helper_path = str(Path(__file__).resolve())
exec(
    compile(patched, "<phase9-sol-transformer>", "exec"),
    {"__name__": "__main__", "__file__": helper_path},
)
