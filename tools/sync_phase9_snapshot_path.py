#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/validate_phase9_gate.py")
text = path.read_text(encoding="utf-8")
old = "/opt/qsol-moriarty-rust-toolchain"
new = "/usr/local/qsol-moriarty-rust-toolchain"
count = text.count(old)
if count != 2:
    raise SystemExit(f"expected two validator snapshot markers, found {count}")
path.write_text(text.replace(old, new), encoding="utf-8")
