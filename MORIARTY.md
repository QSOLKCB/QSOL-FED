# MORIARTY/1 adversarial graduation

**Contract:** `state/phase9.json`  
**Assurance manifest:** `claims/phase9.json`  
**Attack corpus:** `fixtures/phase9/attack-corpus.json`  
**Accepted counterexamples:** `fixtures/phase9/accepted-counterexamples.json`  
**Reference runner:** `tools/run_moriarty.py`  
**Gate:** `tools/validate_phase9_gate.py`

MORIARTY/1 is the final executable-architecture adversarial graduation gate before formalization. It is **PROVIDER NEUTRAL** and binds every report to an **EXACT COMMIT**.

The reference operator may be Codex, another model, a human security reviewer, or a deterministic local harness. The operator is not an authority source. Candidate findings become meaningful only after they are reduced to a deterministic local failure of a source-owned fixed probe.

```text
COUNTEREXAMPLE != AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
ADVERSARIAL OPERATOR != CONSTITUTIONAL OVERRIDE
```

## Why Phase 9 does not add a product capability

Phase 9 does not turn on networking, execution, host isolation, synthetic evidence admission, or deployed interoperability. `claims/phase9.json` preserves the Phase 8 capability map exactly and adds assurance metadata only.

The current capability surface therefore remains `claims/phase8.json`. MORIARTY evaluates that executable architecture. It does not make it more authoritative by testing it.

## Threat boundary

The harness receives only the checked-out public repository, repository-owned disposable fixtures, and an exact Git commit identity. It receives no production credentials, production targets, private infrastructure addresses, arbitrary operator-selected commands, operator-selected URLs or sockets, secret-bearing semantic state, constitutional bypass, or runtime authority handle.

The attack corpus contains **probe IDs**, not command strings. `tools/run_moriarty.py` owns the fixed mapping from those IDs to reviewed repository commands. Unknown probe IDs fail closed.

The reference runner uses `subprocess.run` with an argv list and never invokes a shell. It does not execute semantic payload content, contact an operator-selected network target, or accept a command-line flag that supplies a command, URL, host, credential, or token.

## Exact-commit binding

A MORIARTY run must satisfy:

```text
git rev-parse HEAD == requested target_commit
```

The CI checkout explicitly selects the pull-request head SHA on pull requests and `github.sha` on pushes. The Phase 9 workflow then passes that same value to the gate. This avoids GitHub's synthetic PR merge commit when making an exact-commit assurance statement.

The report is ephemeral evidence for the commit that actually ran. For the Phase 10 handoff, the relevant target is the exact merged `main` commit whose own push workflow is green.

## Attack corpus

The Phase 9 corpus covers fifteen families:

1. canonical/parser differentials;
2. signature/domain/key-role confusion;
3. replay, downgrade and clock attacks;
4. HTTP rate/proxy/DDoS-shaped stress;
5. SSRF and decompression confusion;
6. crash/fsync/restart behavior;
7. lifecycle/partition/history attacks;
8. import/provenance authority laundering;
9. adapter confusion;
10. Holodeck escape attempts;
11. safeguard persuasion;
12. nested-world amplification;
13. Assembly capture and representation attacks;
14. transport/NAT/relay/store-forward/archive attacks;
15. cross-phase contradictions.

Each family names its owning phase or phases, boundary IDs, and one or more fixed regression probe IDs. The complete fixed probe set is:

```text
constitution
phase0
phase1
phase2
phase3
phase4
phase5a
phase5
phase5c
phase6
phase7
phase8
rust_all
```

The runner deduplicates probe IDs, so the exact commit executes the constitutional validator, every historical Phase 0-8 gate, and `cargo test --all-targets` once even though multiple attack families share regressions.

## Reproducible counterexamples

An accepted finding is represented as `moriarty-counterexample/1`. **Accepted means locally reproduced.** The accepted schema permits only local fixed-probe failure classes:

```text
exit_nonzero
timeout
tool_error
```

There is no `accepted_external` failure kind. An accepted record must contain the exact target commit, attack ID and family, owning phases, affected boundary IDs, fixed regression probe IDs, observed local failure class, exit semantics, output SHA-256 digests and byte counts, resolution state, and explicit non-authority/no-production-target/no-credential assertions.

The record is also semantically bound to `fixtures/phase9/attack-corpus.json`:

- `attack_id` must exist in the corpus;
- `family`, `owner_phases`, and `boundary_ids` must match the referenced attack exactly;
- `regression_probe_ids` must be a non-empty subset of that attack's source-owned probe IDs.

This prevents a structurally valid record from borrowing the name of one attack while pointing at an unrelated phase, boundary, or regression.

Raw command output is deliberately not embedded in the report. The reproduction primitive is the reviewed fixed probe ID, not a copied shell line supplied by an adversary.

A valid counterexample **reopens the owning phase**. The fix must add or strengthen a deterministic regression. When resolved, the counterexample remains in `fixtures/phase9/accepted-counterexamples.json`.

For a resolved record, `resolution_commit is the fix commit`. The runner verifies that:

1. the original finding target is a real Git commit reachable from the reviewed target;
2. `resolution_commit` is a real Git commit;
3. the fix commit descends from the vulnerable finding target;
4. the fix commit is itself an ancestor of the exact commit currently being reviewed.

A syntactically plausible but nonexistent SHA is therefore not remediation evidence. An unresolved accepted finding blocks graduation.

## External/model-assisted findings

**External observations are candidates only** until a deterministic local reproduction exists. A model review, human review, external scanner, or other observation cannot be inserted into the accepted counterexample registry merely by labelling it accepted.

Acceptance requires:

1. identify the exact vulnerable target commit;
2. reduce the observation to a deterministic local reproduction using disposable repository fixtures;
3. identify the owning attack-corpus entry and security boundary;
4. add a source-owned fixed probe or strengthen an existing probe in that attack family;
5. demonstrate that the fixed probe fails on the vulnerable state;
6. record the locally reproduced counterexample using `moriarty-counterexample/1`;
7. keep it unresolved until a real fix commit makes the regression pass;
8. preserve all older phase gates.

The Phase 9 gate includes negative contract tests that explicitly attempt to insert `accepted_external`, a corpus-mismatched record, an unrelated regression probe, and a nonexistent resolution commit. All must fail closed.

The operator never gets a mechanism to add an arbitrary runtime command merely because a model says it would be interesting.

## Report semantics

`moriarty-report/1` binds the exact target commit, canonical attack-corpus identity, provider-neutral operator profile, all executed fixed probe results, accepted and newly generated counterexamples, unresolved count, graduation Boolean, and explicit non-authority/non-proof fields.

A successful report requires every fixed probe to return zero and every accepted counterexample to be resolved.

```text
production_credentials_used                 = false
production_targets_used                     = false
constitutional_bypass_used                  = false
security_proof                              = false
no_counterexample_found_implies_none_exist  = false
authority_effect                            = none
```

## Graduation rule

For the exact checked-out commit:

> No unresolved reproducible counterexample may cross a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, adapter, Assembly, or resource-safety boundary.

This is an executable regression graduation claim, not a universal security theorem.

## Running locally

From a clean checkout, bind the run to the actual commit:

```bash
TARGET="$(git rev-parse HEAD)"
python3 tools/validate_phase9_gate.py --target-commit "$TARGET"
```

To emit the canonical report directly:

```bash
TARGET="$(git rev-parse HEAD)"
python3 tools/run_moriarty.py \
  --target-commit "$TARGET" \
  --output /tmp/moriarty-report.json
```

The report is intentionally ephemeral. Phase 11 may archive the report associated with the final frozen release, but repository source does not pre-claim that an unexecuted future commit has passed.
