#!/usr/bin/env python3
"""Run the previous one-shot Sol transformer with one deterministic rewrite fix."""
from __future__ import annotations

import subprocess
from pathlib import Path

previous = subprocess.run(
    ["git", "show", "HEAD^:tools/apply_phase9_codex_round2.py"],
    check=True,
    stdout=subprocess.PIPE,
).stdout.decode("utf-8", errors="strict")
old = '''validator = replace_once(\n    validator,\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\",\\n',\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\", \"stdout_truncated\", \"stderr_truncated\",\\n',\n    \"validator runner markers 3\",\n)\n'''
new = '''runner_marker_start = validator.index(\"def validate_runner_source() -> None:\")\nrunner_marker_end = validator.index(\"def validate_docs_and_ci() -> None:\", runner_marker_start)\nrunner_marker_block = validator[runner_marker_start:runner_marker_end]\nrunner_marker_block = replace_once(\n    runner_marker_block,\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\",\\n',\n    '\"security_proof\", \"no_counterexample_found_implies_none_exist\", \"stdout_truncated\", \"stderr_truncated\",\\n',\n    \"validator runner markers 3\",\n)\nvalidator = validator[:runner_marker_start] + runner_marker_block + validator[runner_marker_end:]\n'''
if previous.count(old) != 1:
    raise SystemExit(f"phase9 Sol wrapper replacement drift:{previous.count(old)}")
patched = previous.replace(old, new, 1)
helper_path = str(Path(__file__).resolve())
exec(
    compile(patched, "<phase9-sol-transformer>", "exec"),
    {"__name__": "__main__", "__file__": helper_path},
)
