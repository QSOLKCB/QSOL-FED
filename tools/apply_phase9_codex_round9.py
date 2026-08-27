#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/validate_phase9_gate.py")
text = path.read_text(encoding="utf-8")
replacements = (
    (
        'require(\'$RUNNER_TEMP/moriarty-rust-toolchain/bin/cargo" test --all-targets --locked\' in workflow, "CI Rust suite does not use the pre-execution snapshot")',
        'require(\'/opt/qsol-moriarty-rust-toolchain/bin/cargo test --all-targets --locked\' in workflow, "CI Rust suite does not use the pre-execution snapshot")',
    ),
    (
        'require("MORIARTY_RUST_TOOLCHAIN_ROOT: ${{ runner.temp }}/moriarty-rust-toolchain" in workflow, "CI MORIARTY Rust snapshot binding missing")',
        'require("MORIARTY_RUST_TOOLCHAIN_ROOT: /opt/qsol-moriarty-rust-toolchain" in workflow, "CI MORIARTY Rust snapshot binding missing")',
    ),
)
for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"snapshot validator marker count={count}: {old}")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
