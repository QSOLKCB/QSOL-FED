#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def replace_block(text: str, start: str, end: str, replacement: str, label: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{label}: start marker missing")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{label}: end marker missing")
    return text[:start_index] + replacement + text[end_index:]


def patch_runner() -> None:
    path = ROOT / "tools/run_moriarty.py"
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "MAX_GIT_ARCHIVE_BYTES = 64 * 1024 * 1024\n",
        "MAX_GIT_ARCHIVE_BYTES = 64 * 1024 * 1024\n"
        "MAX_GIT_TREE_METADATA_BYTES = 16 * 1024 * 1024\n"
        "MAX_GIT_TREE_ENTRIES = 32_768\n"
        "MAX_GIT_TREE_DEPTH = 64\n"
        "MAX_GIT_PATH_BYTES = 4096\n",
        "Git aggregate traversal bounds",
    )

    verified_commit_files = r'''def _verified_commit_files(commit: str) -> dict[str, tuple[str, str, bytes]]:
    global _VERIFIED_TREE_CACHE
    if _VERIFIED_TREE_CACHE is not None and _VERIFIED_TREE_CACHE[0] == commit:
        return _VERIFIED_TREE_CACHE[1]
    if not git_commit_exists(commit):
        fail("moriarty_exact_export_commit_missing")
    commit_payload = _verified_git_object("commit", commit, 1_048_576)
    first_line = commit_payload.split(b"\n", 1)[0]
    if not first_line.startswith(b"tree "):
        fail("moriarty_commit_tree_header_missing")
    try:
        root_tree = first_line[5:].decode("ascii", errors="strict")
    except UnicodeError:
        fail("moriarty_commit_tree_id_invalid")
    if not TARGET_RE.fullmatch(root_tree):
        fail("moriarty_commit_tree_id_invalid")

    files: dict[str, tuple[str, str, bytes]] = {}
    total_payload = 0
    total_tree_metadata = 0
    entry_count = 0
    # Iterative traversal avoids Python recursion exhaustion on adversarial trees.
    stack: list[tuple[str, str, int]] = [(root_tree, "", 0)]
    while stack:
        tree_id, prefix, depth = stack.pop()
        if depth > MAX_GIT_TREE_DEPTH:
            fail("moriarty_git_tree_depth_exceeded")
        remaining_metadata = MAX_GIT_TREE_METADATA_BYTES - total_tree_metadata
        if remaining_metadata <= 0:
            fail("moriarty_git_tree_metadata_exceeded")
        tree_payload = _verified_git_object("tree", tree_id, remaining_metadata)
        total_tree_metadata += len(tree_payload)
        if total_tree_metadata > MAX_GIT_TREE_METADATA_BYTES:
            fail("moriarty_git_tree_metadata_exceeded")
        cursor = 0
        child_trees: list[tuple[str, str, int]] = []
        while cursor < len(tree_payload):
            space = tree_payload.find(b" ", cursor)
            nul = tree_payload.find(b"\0", space + 1 if space >= 0 else cursor)
            if space <= cursor or nul <= space or nul + 21 > len(tree_payload):
                fail("moriarty_git_tree_object_malformed")
            mode_bytes = tree_payload[cursor:space]
            name_bytes = tree_payload[space + 1:nul]
            object_id = tree_payload[nul + 1:nul + 21].hex()
            cursor = nul + 21
            entry_count += 1
            if entry_count > MAX_GIT_TREE_ENTRIES:
                fail("moriarty_git_tree_entry_count_exceeded")
            try:
                mode = mode_bytes.decode("ascii", errors="strict")
                name = name_bytes.decode("utf-8", errors="strict")
            except UnicodeError:
                fail("moriarty_git_tree_entry_encoding_invalid")
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                fail("moriarty_git_tree_entry_name_invalid")
            relative = f"{prefix}/{name}" if prefix else name
            if len(relative.encode("utf-8")) > MAX_GIT_PATH_BYTES:
                fail("moriarty_git_tree_path_too_long")
            if relative in files:
                fail("moriarty_git_tree_duplicate_path")
            if mode == "40000":
                if depth >= MAX_GIT_TREE_DEPTH:
                    fail("moriarty_git_tree_depth_exceeded")
                child_trees.append((object_id, relative, depth + 1))
            elif mode in {"100644", "100755"}:
                remaining = MAX_GIT_ARCHIVE_BYTES - total_payload
                if remaining <= 0:
                    fail("moriarty_exact_export_archive_too_large")
                blob = _verified_git_object("blob", object_id, remaining)
                total_payload += len(blob)
                if total_payload > MAX_GIT_ARCHIVE_BYTES:
                    fail("moriarty_exact_export_archive_too_large")
                files[relative] = (mode, object_id, blob)
            else:
                fail("moriarty_exact_export_nonregular_entry_forbidden")
        if cursor != len(tree_payload):
            fail("moriarty_git_tree_object_malformed")
        # Reverse preserves Git tree order while keeping traversal iterative.
        stack.extend(reversed(child_trees))

    _VERIFIED_TREE_CACHE = (commit, files)
    return files


'''
    text = replace_block(
        text,
        "def _verified_commit_files(commit: str) -> dict[str, tuple[str, str, bytes]]:\n",
        "def _index_flags_output_clean(raw: bytes) -> bool:\n",
        verified_commit_files,
        "bounded iterative Git tree traversal",
    )

    normalize_block = r'''def _normalize_probe_output(
    data: bytes,
    *,
    source_root: Path,
    target_dir: Path,
    home: Path,
    cargo_home: Path,
    temp_dir: Path,
    workspace_root: Path,
) -> bytes:
    """Normalize private per-run paths to stable reproducibility placeholders."""
    replacements = [
        (source_root, b"<SOURCE>"),
        (target_dir, b"<TARGET>"),
        (home, b"<HOME>"),
        (cargo_home, b"<CARGO_HOME>"),
        (temp_dir, b"<TMP>"),
        (workspace_root, b"<WORK>"),
    ]
    encoded: list[tuple[bytes, bytes]] = []
    for candidate, marker in replacements:
        raw = os.fsencode(str(candidate.resolve()))
        if not raw:
            fail("moriarty_workspace_normalization_path_invalid")
        encoded.append((raw, marker))
    normalized = data
    # Most-specific paths first so a workspace replacement cannot hide a child path.
    for raw, marker in sorted(encoded, key=lambda item: len(item[0]), reverse=True):
        normalized = normalized.replace(raw, marker)
    return normalized


'''
    text = replace_block(
        text,
        "def _normalize_probe_output(data: bytes, workspace_root: Path) -> bytes:\n",
        "def _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:\n",
        normalize_block,
        "complete per-probe path normalization",
    )

    text = replace_once(
        text,
        '''    normalized = {\n        name: _normalize_probe_output(bytes(captured[name]), source_root.parent)\n        for name in ("stdout", "stderr")\n    }\n''',
        '''    normalized = {\n        name: _normalize_probe_output(\n            bytes(captured[name]),\n            source_root=source_root,\n            target_dir=target_dir,\n            home=home,\n            cargo_home=cargo_home,\n            temp_dir=temp_dir,\n            workspace_root=source_root.parent,\n        )\n        for name in ("stdout", "stderr")\n    }\n''',
        "run_probe normalization call",
    )

    replay_block = r'''def _run_counterexample_replay_probe(
    item: dict[str, Any],
    index: int,
    phase: str,
    commit: str,
    workspace: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> dict[str, Any]:
    probe_id = item["regression_probe_ids"][0]
    label = f"accepted-{index}-{phase}"
    source = create_exact_export(commit, workspace, git_archive_bytes, label)
    if probe_id == "rust_all" and not (source / "Cargo.lock").is_file():
        fail(f"moriarty_replay_{phase}_cargo_lock_missing")
    template = (
        create_verified_cargo_template(
            REAL_HOME / ".cargo",
            workspace,
            source / "Cargo.lock",
            f"{label}-template",
        )
        if probe_id == "rust_all"
        else workspace
    )
    cargo_home = _fresh_cargo_home(probe_id, template, workspace, label)
    return run_probe(
        probe_id,
        workspace / f"{label}-home",
        source,
        cargo_home,
        workspace / f"{label}-target",
        python_exec,
        cargo_exec,
        rustc_exec,
        rustdoc_exec,
        rust_runtime,
    )


def verify_accepted_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> list[dict[str, Any]]:
    """Replay every accepted finding and return reportable transition evidence.

    Every entry, including unresolved entries, must reproduce its recorded target
    failure. Only resolved entries additionally require the same probe to pass at
    resolution_commit. Replay mismatch is report data, not an early process exit.
    """
    records: list[dict[str, Any]] = []
    for index, item in enumerate(accepted):
        probe_id = item["regression_probe_ids"][0]
        record: dict[str, Any] = {
            "counterexample_id": item["counterexample_id"],
            "status": item["status"],
            "probe_id": probe_id,
            "ok": False,
            "target_reproduced": False,
            "resolution_green": None,
            "failure_kind": None,
            "failure_result": None,
        }
        try:
            before = _run_counterexample_replay_probe(
                item,
                index,
                "target",
                item["target_commit"],
                workspace,
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        except SystemExit:
            record["failure_kind"] = "replay_setup_error"
            records.append(record)
            continue

        target_reproduced = counterexample_failure_matches(item, before)
        record["target_reproduced"] = target_reproduced
        if not target_reproduced:
            record["failure_kind"] = "target_failure_not_reproduced"
            record["failure_result"] = report_probe_result(before)
            records.append(record)
            continue

        if item["status"] == "unresolved":
            record["ok"] = True
            records.append(record)
            continue

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        try:
            after = _run_counterexample_replay_probe(
                item,
                index,
                "resolution",
                resolution,
                workspace,
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        except SystemExit:
            record["resolution_green"] = False
            record["failure_kind"] = "replay_setup_error"
            records.append(record)
            continue

        resolution_green = after["ok"] is True and after["exit_code"] == 0
        record["resolution_green"] = resolution_green
        if not resolution_green:
            record["failure_kind"] = "resolution_probe_not_green"
            record["failure_result"] = report_probe_result(after)
            records.append(record)
            continue
        record["ok"] = True
        records.append(record)
    return records


'''
    text = replace_block(
        text,
        "def verify_resolved_counterexamples(\n",
        "def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:\n",
        replay_block,
        "accepted counterexample replay lifecycle",
    )

    text = replace_once(
        text,
        '''        verify_resolved_counterexamples(\n            accepted,\n            workspace,\n            python_exec,\n            cargo_exec,\n            rustc_exec,\n            rustdoc_exec,\n            rust_runtime,\n        )\n''',
        '''        remediation_replays = verify_accepted_counterexamples(\n            accepted,\n            workspace,\n            python_exec,\n            cargo_exec,\n            rustc_exec,\n            rustdoc_exec,\n            rust_runtime,\n        )\n''',
        "main accepted replay call",
    )

    text = replace_once(
        text,
        '''    all_probes_ok = all(result["ok"] for result in results.values())\n''',
        '''    all_probes_ok = all(result["ok"] for result in results.values())\n    all_replays_ok = all(item["ok"] for item in remediation_replays)\n''',
        "replay graduation aggregate",
    )
    text = replace_once(
        text,
        '''        "probe_results": [report_probe_result(results[probe_id]) for probe_id in ordered_probe_ids],\n        "counterexamples": accepted + generated,\n''',
        '''        "probe_results": [report_probe_result(results[probe_id]) for probe_id in ordered_probe_ids],\n        "remediation_replays": remediation_replays,\n        "counterexamples": accepted + generated,\n''',
        "report replay evidence",
    )
    text = replace_once(
        text,
        '''        "graduated": unresolved_count == 0 and all_probes_ok,\n''',
        '''        "graduated": unresolved_count == 0 and all_probes_ok and all_replays_ok,\n''',
        "graduation replay requirement",
    )
    text = replace_once(
        text,
        '''        f"{sum(not result['ok'] for result in results.values())} failed probe(s); report={output}",\n''',
        '''        f"{sum(not result['ok'] for result in results.values())} failed probe(s), "\n        f"{sum(not replay['ok'] for replay in remediation_replays)} failed remediation replay(s); report={output}",\n''',
        "blocked output replay count",
    )

    path.write_text(text, encoding="utf-8")


def patch_schema() -> None:
    path = ROOT / "schemas/moriarty-report-v1.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    required = schema["required"]
    if "remediation_replays" not in required:
        required.insert(required.index("counterexamples"), "remediation_replays")
    probe_item = copy.deepcopy(schema["properties"]["probe_results"]["items"])
    nullable_probe_item = copy.deepcopy(probe_item)
    nullable_probe_item["type"] = ["object", "null"]
    schema["properties"]["remediation_replays"] = {
        "type": "array",
        "maxItems": 32,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "counterexample_id",
                "status",
                "probe_id",
                "ok",
                "target_reproduced",
                "resolution_green",
                "failure_kind",
                "failure_result",
            ],
            "properties": {
                "counterexample_id": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "status": {"type": "string", "enum": ["unresolved", "resolved"]},
                "probe_id": {"type": "string", "pattern": "^[a-z0-9_]{1,64}$"},
                "ok": {"type": "boolean"},
                "target_reproduced": {"type": "boolean"},
                "resolution_green": {"type": ["boolean", "null"]},
                "failure_kind": {
                    "type": ["string", "null"],
                    "enum": [
                        None,
                        "target_failure_not_reproduced",
                        "resolution_probe_not_green",
                        "replay_setup_error",
                    ],
                },
                "failure_result": nullable_probe_item,
            },
        },
    }
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


def patch_validator() -> None:
    path = ROOT / "tools/validate_phase9_gate.py"
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''        "executed_probe_count", "probe_results", "counterexamples", "unresolved_counterexamples",\n''',
        '''        "executed_probe_count", "probe_results", "remediation_replays", "counterexamples", "unresolved_counterexamples",\n''',
        "schema report field set",
    )
    text = replace_once(
        text,
        '''    probe_result_fields = {\n        "probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256",\n        "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated",\n    }\n''',
        '''    probe_result_fields = {\n        "probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256",\n        "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated",\n    }\n    remediation_replay_fields = {\n        "counterexample_id", "status", "probe_id", "ok", "target_reproduced",\n        "resolution_green", "failure_kind", "failure_result",\n    }\n''',
        "remediation replay schema field set",
    )
    text = replace_once(
        text,
        '''    _require_closed_schema_fields(report_schema, report_fields, "report")\n    _require_closed_schema_fields(report_schema["properties"]["probe_results"]["items"], probe_result_fields, "probe result")\n''',
        '''    _require_closed_schema_fields(report_schema, report_fields, "report")\n    _require_closed_schema_fields(report_schema["properties"]["probe_results"]["items"], probe_result_fields, "probe result")\n    replay_item_schema = report_schema["properties"]["remediation_replays"]["items"]\n    _require_closed_schema_fields(replay_item_schema, remediation_replay_fields, "remediation replay")\n    _require_closed_schema_fields(replay_item_schema["properties"]["failure_result"], probe_result_fields, "remediation failure result")\n''',
        "remediation replay schema closure",
    )
    text = replace_once(
        text,
        '''    require(report_props["counterexamples"].get("maxItems") == moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY report counterexample bound drift")\n''',
        '''    require(report_props["counterexamples"].get("maxItems") == moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY report counterexample bound drift")\n    require(report_props["remediation_replays"].get("maxItems") == moriarty.MAX_ACCEPTED_COUNTEREXAMPLES, "MORIARTY remediation replay count bound drift")\n    replay_props = report_props["remediation_replays"]["items"]["properties"]\n    require(set(replay_props["failure_kind"].get("enum", [])) == {None, "target_failure_not_reproduced", "resolution_probe_not_green", "replay_setup_error"}, "MORIARTY remediation failure-kind schema drift")\n''',
        "remediation replay schema semantics",
    )

    old_norm_test = '''    require(moriarty._normalize_probe_output(b"x /tmp/private-run/a", Path("/tmp/private-run")) == b"x <WORK>/a", "MORIARTY workspace output normalization regression failed")\n'''
    new_norm_test = '''    norm_root = Path("/tmp/private-run")\n    normalized_paths = moriarty._normalize_probe_output(\n        b"/tmp/private-run/probe-12-rust_all-src /tmp/private-run/target-12-rust_all /tmp/private-run/home-12-rust_all /tmp/private-run/cargo-home-probe-12-rust_all /tmp/private-run/tmp-target-12-rust_all /tmp/private-run/other",\n        source_root=norm_root / "probe-12-rust_all-src",\n        target_dir=norm_root / "target-12-rust_all",\n        home=norm_root / "home-12-rust_all",\n        cargo_home=norm_root / "cargo-home-probe-12-rust_all",\n        temp_dir=norm_root / "tmp-target-12-rust_all",\n        workspace_root=norm_root,\n    )\n    require(\n        normalized_paths == b"<SOURCE> <TARGET> <HOME> <CARGO_HOME> <TMP> <WORK>/other",\n        "MORIARTY complete per-probe output normalization regression failed",\n    )\n    require(0 < moriarty.MAX_GIT_TREE_DEPTH <= 128, "MORIARTY Git tree depth bound invalid")\n    require(0 < moriarty.MAX_GIT_TREE_ENTRIES <= 65536, "MORIARTY Git tree entry bound invalid")\n    require(0 < moriarty.MAX_GIT_TREE_METADATA_BYTES <= moriarty.MAX_GIT_ARCHIVE_BYTES, "MORIARTY Git tree metadata bound invalid")\n    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")\n'''
    text = replace_once(text, old_norm_test, new_norm_test, "normalization and traversal validator regressions")

    text = replace_once(
        text,
        '        "counterexample_identity_projection", "verify_resolved_counterexamples",\n',
        '        "counterexample_identity_projection", "verify_accepted_counterexamples",\n',
        "runner replay source marker",
    )

    text = replace_once(
        text,
        '''        "executed_probe_count", "probe_results", "counterexamples", "unresolved_counterexamples",\n''',
        '''        "executed_probe_count", "probe_results", "remediation_replays", "counterexamples", "unresolved_counterexamples",\n''',
        "generated report field set",
    )

    insertion_marker = '''    counterexamples = report["counterexamples"]\n'''
    replay_validation = r'''    remediation_replays = report["remediation_replays"]
    replay_fields = {
        "counterexample_id", "status", "probe_id", "ok", "target_reproduced",
        "resolution_green", "failure_kind", "failure_result",
    }
    registry_entries = load("fixtures/phase9/accepted-counterexamples.json")["counterexamples"]
    registry_by_id = {item["counterexample_id"]: item for item in registry_entries}
    require(
        isinstance(remediation_replays, list)
        and len(remediation_replays) == len(registry_entries)
        and len(remediation_replays) <= moriarty.MAX_ACCEPTED_COUNTEREXAMPLES,
        "MORIARTY remediation replay count drift",
    )
    replay_ids: set[str] = set()
    for replay in remediation_replays:
        require(isinstance(replay, dict) and set(replay) == replay_fields, "MORIARTY remediation replay field-set drift")
        counterexample_id = replay["counterexample_id"]
        require(isinstance(counterexample_id, str) and counterexample_id in registry_by_id and counterexample_id not in replay_ids, "MORIARTY remediation replay identity invalid")
        replay_ids.add(counterexample_id)
        registry_item = registry_by_id[counterexample_id]
        require(replay["status"] == registry_item["status"], "MORIARTY remediation replay status drift")
        require(replay["probe_id"] == registry_item["regression_probe_ids"][0], "MORIARTY remediation replay probe drift")
        require(type(replay["ok"]) is bool and type(replay["target_reproduced"]) is bool, "MORIARTY remediation replay booleans invalid")
        require(replay["resolution_green"] is None or type(replay["resolution_green"]) is bool, "MORIARTY remediation resolution flag invalid")
        require(replay["failure_kind"] in {None, "target_failure_not_reproduced", "resolution_probe_not_green", "replay_setup_error"}, "MORIARTY remediation replay failure kind invalid")
        failure_result = replay["failure_result"]
        if failure_result is not None:
            require(isinstance(failure_result, dict) and set(failure_result) == result_fields, "MORIARTY remediation failure result schema drift")
            require(failure_result["probe_id"] == replay["probe_id"], "MORIARTY remediation failure result probe drift")
            require(type(failure_result["ok"]) is bool, "MORIARTY remediation failure result ok invalid")
            require(failure_result["exit_code"] is None or (type(failure_result["exit_code"]) is int and -2147483648 <= failure_result["exit_code"] <= 2147483647), "MORIARTY remediation failure result exit invalid")
            require(failure_result["failure_kind"] in {None, "exit_nonzero", "timeout", "tool_error"}, "MORIARTY remediation failure result kind invalid")
            for digest in ("stdout_sha256", "stderr_sha256"):
                require(isinstance(failure_result[digest], str) and moriarty.SHA256_REF_RE.fullmatch(failure_result[digest]) is not None, "MORIARTY remediation failure digest invalid")
            for size in ("stdout_bytes", "stderr_bytes"):
                require(type(failure_result[size]) is int and 0 <= failure_result[size] <= moriarty.MAX_PROBE_OUTPUT_BYTES, "MORIARTY remediation failure byte bound invalid")
            require(type(failure_result["stdout_truncated"]) is bool and type(failure_result["stderr_truncated"]) is bool, "MORIARTY remediation failure truncation invalid")
        if replay["ok"]:
            require(replay["failure_kind"] is None and failure_result is None and replay["target_reproduced"] is True, "MORIARTY successful remediation replay semantics invalid")
            if replay["status"] == "resolved":
                require(replay["resolution_green"] is True, "MORIARTY resolved remediation replay lacks green resolution")
            else:
                require(replay["resolution_green"] is None, "MORIARTY unresolved remediation replay gained resolution state")
        else:
            require(replay["failure_kind"] is not None, "MORIARTY failed remediation replay lacks failure kind")
            if replay["failure_kind"] in {"target_failure_not_reproduced", "resolution_probe_not_green"}:
                require(failure_result is not None, "MORIARTY failed remediation replay lost subprocess metadata")
    require(replay_ids == set(registry_by_id), "MORIARTY did not replay every accepted registry entry")

'''
    text = replace_once(text, insertion_marker, replay_validation + insertion_marker, "generated report replay validation")

    text = replace_once(
        text,
        '''    all_ok = all(item["ok"] for item in probe_results)\n    require(type(report["graduated"]) is bool and report["graduated"] == (all_ok and unresolved == 0), "MORIARTY graduation Boolean inconsistent with report evidence")\n''',
        '''    all_ok = all(item["ok"] for item in probe_results)\n    all_replays_ok = all(item["ok"] for item in remediation_replays)\n    require(type(report["graduated"]) is bool and report["graduated"] == (all_ok and all_replays_ok and unresolved == 0), "MORIARTY graduation Boolean inconsistent with report evidence")\n''',
        "graduation replay validation",
    )
    text = replace_once(
        text,
        '''    require(report["counterexamples"] == registry["counterexamples"], "MORIARTY successful report contains generated counterexample or registry drift")\n''',
        '''    require(report["counterexamples"] == registry["counterexamples"], "MORIARTY successful report contains generated counterexample or registry drift")\n    require(all(item.get("ok") is True for item in report["remediation_replays"]), "MORIARTY successful report contains failed remediation replay")\n''',
        "success report replay condition",
    )
    text = replace_once(
        text,
        '''        "counterexamples": counterexamples,\n        "unresolved_counterexamples": report["unresolved_counterexamples"],\n''',
        '''        "counterexamples": counterexamples,\n        "remediation_replay_failures": [\n            {\n                "counterexample_id": item["counterexample_id"],\n                "probe_id": item["probe_id"],\n                "failure_kind": item["failure_kind"],\n                "failure_result": item["failure_result"],\n            }\n            for item in report["remediation_replays"]\n            if not item["ok"]\n        ],\n        "unresolved_counterexamples": report["unresolved_counterexamples"],\n''',
        "failure diagnostic replay evidence",
    )

    path.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    path = ROOT / "MORIARTY.md"
    text = path.read_text(encoding="utf-8")
    addition = '''\n\n### Accepted-counterexample replay evidence\n\nEvery accepted registry entry, unresolved or resolved, is replayed at its recorded `target_commit` and must reproduce its stored failure metadata. Resolved entries additionally replay the same fixed probe at `resolution_commit` and require a green result. Per-run source, target, HOME, Cargo-home, and temporary paths are normalized to stable placeholders before digest comparison. Replay mismatch is persisted in `remediation_replays` in the canonical report before the runner exits nonzero; raw subprocess output is never stored.\n\nExact-export traversal is also aggregate-bounded: tree depth, entry count, cumulative tree metadata, path length, and blob payload all have independent fail-closed limits, and traversal is iterative rather than recursive.\n'''
    if "### Accepted-counterexample replay evidence" not in text:
        text += addition
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_runner()
    patch_schema()
    patch_validator()
    patch_docs()


if __name__ == "__main__":
    main()
