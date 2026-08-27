#!/usr/bin/env python3
"""Execute the prior review-6 patcher with its function-local indentation repaired."""
from __future__ import annotations

import re
import subprocess

source = subprocess.run(
    ["/usr/bin/git", "show", "HEAD^:.github/phase9_review6_repair.py"],
    check=True,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
).stdout.decode("utf-8")


def repair_assignment(name: str, indentation: str) -> None:
    global source
    pattern = re.compile(
        rf"(^\s*{re.escape(name)}\s*=\s*)dedent\((?P<body>'''\\\n.*?^\s*''')\)\n",
        re.MULTILINE | re.DOTALL,
    )
    source, count = pattern.subn(
        lambda match: f'{match.group(1)}indent(dedent({match.group("body")}), {indentation!r})\n',
        source,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"review6 patcher indentation repair failed:{name}:{count}")


repair_assignment("call_anchor", "    ")
repair_assignment("topology_tests", "        ")
repair_assignment("cleanup_test_anchor", "    ")
repair_assignment("cleanup_tests", "    ")
repair_assignment("read_test_anchor", "    ")
repair_assignment("read_tests", "    ")

code = compile(source, ".github/phase9_review6_repair.py<repaired>", "exec")
exec(code, {"__name__": "__main__", "__file__": ".github/phase9_review6_repair.py"})
