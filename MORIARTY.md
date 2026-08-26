# MORIARTY/1 adversarial graduation

**Contract:** `state/phase9.json`  
**Assurance manifest:** `claims/phase9.json`  
**Attack corpus:** `fixtures/phase9/attack-corpus.json`  
**Accepted counterexamples:** `fixtures/phase9/accepted-counterexamples.json`  
**Reference runner:** `tools/run_moriarty.py`  
**Gate:** `tools/validate_phase9_gate.py`

MORIARTY/1 is the final executable-architecture adversarial graduation gate before formalization. It is **PROVIDER NEUTRAL** and binds every report to an **EXACT COMMIT**.

The reference operator may be Codex, another model, a human security reviewer, or a deterministic local harness. The operator is not an authority source. Candidate findings become meaningful only after they are reduced to a local reproducible counterexample and incorporated into the repository regression surface.

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

The harness receives only the checked-out public repository, repository-owned disposable fixtures, and an exact Git commit identity.

It receives no:

- production credentials;
- production targets;
- private infrastructure addresses;
- arbitrary operator-selected command;
- operator-selected URL or socket target;
- secret-bearing semantic state;
- constitutional bypass;
- runtime authority handle.

The attack corpus contains **probe IDs**, not command strings. `tools/run_moriarty.py` owns the fixed mapping from those IDs to reviewed repository commands. Unknown probe IDs fail closed.

The reference runner uses `subprocess.run` with an argv list and never invokes a shell. It does not execute semantic payload content, contact an operator-selected network target, or accept a command-line flag that supplies a command, URL, host, credential, or token.

## Exact-commit binding

A MORIARTY run must satisfy:

```text
git rev-parse HEAD == requested target_commit
```

The CI checkout explicitly selects the pull-request head SHA on pull requests and `github.sha` on pushes. The Phase 9 workflow then passes that same value to the gate.

This avoids a self-referential checked-in report. A commit does not contain a file claiming that its own future CI run passed. Instead, the workflow emits ephemeral `moriarty-report/1` evidence for the exact commit it actually executed.

For the merge handoff to Phase 10, the relevant target is the exact merged `main` commit whose own push workflow is green.

## Attack corpus

The frozen Phase 9 corpus covers fifteen families:

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

Each family names its owning phase or phases, the boundary IDs at risk, and one or more fixed regression probe IDs.

The complete fixed probe set is:

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

The runner deduplicates probe IDs, so the exact commit executes the constitutional validator, every historical Phase 0-8 gate, and `cargo test --all-targets` once even though multiple attack families share those regressions.

## Reproducible counterexamples

An accepted finding is represented as `moriarty-counterexample/1` and names:

- the exact target commit;
- attack ID and family;
- owning phase or phases;
- affected boundary IDs;
- fixed regression probe IDs;
- observed failure class and exit code;
- SHA-256 digests and byte counts for stdout/stderr rather than raw output;
- resolution state;
- explicit non-authority and no-production-target/credential assertions.

Raw command output is deliberately not embedded in the report. The reproduction primitive is the reviewed fixed probe ID, not a copied shell line supplied by an adversary.

A valid counterexample **reopens the owning phase**. The fix must add or strengthen a deterministic regression. When resolved, the counterexample remains in `fixtures/phase9/accepted-counterexamples.json` with a resolution commit and fixed regression probe reference. An unresolved accepted finding blocks graduation.

## External/model-assisted findings

A model-assisted or human adversarial review may propose a candidate finding outside the deterministic baseline. That proposal is not automatically accepted.

Acceptance requires:

1. identify the exact target commit;
2. reduce the claim to a deterministic local reproduction using disposable repository fixtures;
3. identify the owning phase and security boundary;
4. add a source-owned fixed probe or strengthen an existing one;
5. record the counterexample using `moriarty-counterexample/1`;
6. keep the finding unresolved until the regression fails on the vulnerable state and passes only after the fix;
7. preserve all older phase gates.

The operator never gets a mechanism to add an arbitrary runtime command merely because a model says it would be interesting.

## Report semantics

`moriarty-report/1` binds:

- exact target commit;
- canonical attack-corpus identity;
- provider-neutral operator profile;
- all executed fixed probe results;
- accepted and newly generated counterexamples;
- unresolved count;
- graduation Boolean;
- explicit non-authority/non-proof fields.

A successful report requires every fixed probe to return zero and every accepted counterexample to be resolved.

The report always carries:

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

To emit the raw canonical report directly:

```bash
TARGET="$(git rev-parse HEAD)"
python3 tools/run_moriarty.py \
  --target-commit "$TARGET" \
  --output /tmp/moriarty-report.json
```

The report is intentionally ephemeral. Phase 11 may archive the report associated with the final frozen release, but repository source does not pre-claim that an unexecuted future commit has passed.
