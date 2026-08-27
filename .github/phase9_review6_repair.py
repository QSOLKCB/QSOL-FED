#!/usr/bin/env python3
"""Execute the review-6 patcher with deterministic indentation repairs."""
from __future__ import annotations

import re
import subprocess

PATCHER_COMMIT = "941c9bc10ece7945a80eb677465f609bd31d78bf"
source = subprocess.run(
    ["/usr/bin/git", "show", f"{PATCHER_COMMIT}:.github/phase9_review6_repair.py"],
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


# Function-local Python anchors/replacements must retain their source indentation.
repair_assignment("call_anchor", "    ")
repair_assignment("topology_tests", "        ")
repair_assignment("cleanup_test_anchor", "    ")
repair_assignment("cleanup_tests", "    ")
repair_assignment("read_test_anchor", "    ")
repair_assignment("read_tests", "    ")

# The historical-prefetch template was a raw triple-quoted string beginning with
# a literal backslash line. That prevented dedent() from removing the four-space
# template indentation and produced an invalid nested workflow step. Remove that
# literal line, then strip the resulting leading newline before applying the
# canonical six-space GitHub Actions step indentation.
old_prefetch_start = "relative_prefetch = dedent(r'''\\\n    - name: Prepare authenticated Cargo archives without repository execution"
new_prefetch_start = "relative_prefetch = dedent(r'''\n    - name: Prepare authenticated Cargo archives without repository execution"
if source.count(old_prefetch_start) != 1:
    raise SystemExit("review6 historical-prefetch template anchor drift")
source = source.replace(old_prefetch_start, new_prefetch_start, 1)
old_prefetch_indent = '    prefetch = indent(relative_prefetch, "      ")'
new_prefetch_indent = '    prefetch = indent(relative_prefetch.lstrip("\\n"), "      ")'
if source.count(old_prefetch_indent) != 1:
    raise SystemExit("review6 historical-prefetch indentation anchor drift")
source = source.replace(old_prefetch_indent, new_prefetch_indent, 1)

# Add generator-level structural checks before the workflow is written. These
# catch the exact malformed-line failure that escaped Python compilation.
write_anchor = 'workflow_path.write_text(workflow.rstrip("\\n") + "\\n", encoding="utf-8")'
write_guard = '''if "      \\\\\\n" in workflow:\n    raise SystemExit("review6 generated workflow contains stray backslash step")\nif workflow.count("      - name: Prepare authenticated Cargo archives without repository execution") != 1:\n    raise SystemExit("review6 generated historical-prefetch step indentation invalid")\nif workflow.count("      - name: Phase 9 MORIARTY/1 exact-commit graduation gate") != 1:\n    raise SystemExit("review6 generated Phase 9 step indentation invalid")\nworkflow_path.write_text(workflow.rstrip("\\n") + "\\n", encoding="utf-8")'''
if source.count(write_anchor) != 1:
    raise SystemExit("review6 workflow-write anchor drift")
source = source.replace(write_anchor, write_guard, 1)

code = compile(source, ".github/phase9_review6_repair.py<repaired>", "exec")
exec(code, {"__name__": "__main__", "__file__": ".github/phase9_review6_repair.py"})
