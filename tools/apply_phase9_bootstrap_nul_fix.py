#!/usr/bin/env python3
from pathlib import Path

for name in ("tools/run_moriarty.py", "tools/validate_phase9_gate.py"):
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    old = 'actual = hashlib.sha1(f"{kind} {len(payload)}\\\\0".encode("ascii") + payload).hexdigest()'
    new = 'actual = hashlib.sha1(f"{kind} {len(payload)}".encode("ascii") + b"\\x00" + payload).hexdigest()'
    if text.count(old) != 1:
        raise SystemExit(f"{name}: bootstrap NUL marker mismatch: {text.count(old)}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
