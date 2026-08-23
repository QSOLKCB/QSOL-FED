#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from qsol_fed_sdk import canonicalize, conformance_result


def main() -> None:
    fixture = json.loads((ROOT / "fixtures/phase6/conformance.json").read_text(encoding="utf-8"))
    result = conformance_result(fixture)
    sys.stdout.buffer.write(canonicalize(result) + b"\n")


if __name__ == "__main__":
    main()
