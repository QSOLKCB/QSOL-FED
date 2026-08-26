#!/usr/bin/env python3
"""Temporary one-shot patch: preserve runner stderr when report creation never begins."""
from __future__ import annotations

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "tools/validate_phase9_gate.py"
text = path.read_text(encoding="utf-8")
old = '''    require(report_path.exists(), "MORIARTY runner did not emit report")\n    raw = report_path.read_bytes()\n'''
new = '''    if not report_path.exists():\n        stderr = completed.stderr.decode("utf-8", errors="replace").strip()\n        stdout = completed.stdout.decode("utf-8", errors="replace").strip()\n        diagnostic = stderr or stdout or "no runner output"\n        raise SystemExit(\n            "MORIARTY runner did not emit report: "\n            + diagnostic[:2048]\n        )\n    raw = report_path.read_bytes()\n'''
if text.count(old) != 1:
    raise SystemExit(f"pre-report diagnostic patch drift:{text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
