# Federation Assembly

**Contract:** `qsol-fed-assembly/1`  
**Charter Gate:** `qsol-fed-charter-gate/1`  
**Representation:** `one-member-one-vote/1`

The Federation Assembly is a **protocol-evolution governance plane**. It is not a sovereign controller for Federation members.

```text
ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP
ASSEMBLY CONSENSUS != TRUTH
ASSEMBLY VOTE != MEMBER-LOCAL COMMAND
ASSEMBLY ACCEPTANCE != SOURCE MERGE
ASSEMBLY ACCEPTANCE != DEPLOYMENT
NEXUS ADVICE != VOTE WEIGHT
```

## Membership

Federation network membership and Assembly membership are separate.

A node does not gain Assembly rights because it can speak `qsol-fed/1`, has an admitted peer relationship, possesses a valid signature, runs NEXUS, or is trusted locally by another member.

Assembly membership requires an explicit Assembly-local admission step with `local_opt_in = true`.

A member record may reference a Federation node ID, but that reference is optional:

```text
network_membership_required = false
qsol_governance_required    = false
representation_weight       = 1
authority_effect            = none
```

The v1 reference registry allows at most one active membership for the same NFC-normalized `representation_subject`.

### Anti-Sybil assumption

This does **not** prove that two different representation subjects are controlled by different real-world principals.

The protocol can deterministically enforce:

- one active record per normalized representation subject in its own registry;
- one vote per admitted Assembly member per proposal;
- a frozen electorate snapshot for each proposal.

It cannot, by wire syntax alone, prove human/institutional uniqueness or defeat coordinated identity creation in the real world. Real-world principal verification remains an explicit Assembly admission-policy assumption.

```text
REGISTRY UNIQUENESS != REAL-WORLD IDENTITY PROOF
```

## Proposal lifecycle

The reference model supports:

- `protocol_amendment`;
- `charter_amendment`;
- `advisory_resolution`;
- `fork_proposal`.

Active proposal states are:

```text
open
fork_required
withdrawn
```

Final outcomes (`accepted`, `rejected`, `withdrawn`, `fork_required`, `fork_endorsed`) live in immutable governance receipts rather than being written back into an indefinitely mutable proposal record.

When a proposal opens, the Assembly freezes the sorted active-member electorate. The member set remains Assembly-local for vote admission. The public proposal record carries only:

```text
electorate_ref  = sha256:<domain-separated snapshot digest>
electorate_size = N
```

The digest is computed incrementally from the ordered member IDs, so the advertised 1,024-member electorate does not have to fit all member IDs inside one 65,536-byte canonical proposal-identity projection. Later joins or withdrawals do not move quorum or voting eligibility for that already-open proposal.

Votes are append-only per member for the proposal. A second vote from the same member is rejected rather than silently replacing history.

`ProtocolAmendment` and `CharterAmendment` require an explicit compatibility classification. `not_applicable` is reserved for advisory resolutions; fork proposals are explicitly breaking.

Finalization is terminal. The deterministic receipt is derived first; only after that succeeds is the proposal removed from the active proposal/electorate set. This means a finalized `fork_required` proposal cannot accept another advisory, be withdrawn, or produce a second receipt, and finalized proposals reclaim the bounded active-proposal capacity.

### Quorum and approval

The Phase 7 reference model uses:

```text
quorum   = ceil(2/3 of electorate snapshot)
approval = ceil(2/3 of non-abstaining votes), with at least one yes
```

These are reference rules, not a claim of universal political optimality. A future governance-major may change them only through an explicit reviewed contract/version decision.

## Deterministic Charter Gate

Every submitted proposal receives a `qsol-fed-charter-gate/1` assessment before it can affect the current protocol lineage.

The gate maps declared requested effects onto the already-frozen constitutional invariant IDs in `invariants/fed-v1.json`.

Examples include:

- `remote_governance_mutation_forbidden`;
- `remote_evidence_promotion_forbidden`;
- `remote_vote_creation_forbidden`;
- `remote_capability_installation_forbidden`;
- `remote_history_rewrite_forbidden`;
- `remote_citizenship_mutation_forbidden`;
- `remote_arbitrary_execution_forbidden`;
- `remote_local_authority_claim_forbidden`;
- `secrets_in_semantic_state_forbidden`;
- `runtime_constitution_override_forbidden`;
- `import_is_not_authority`;
- `local_sovereignty_over_federation_convenience`.

A proposal with no constitutional conflict is `compatible`.

A proposal that conflicts with the current Charter is **not silently discarded** and is not permitted to rewrite the current lineage. It receives:

```text
disposition              = fork_required
current_lineage_eligible = false
member_local_authority_effect = none
```

That makes disagreement explicit and gives incompatible evolution a transparent fork path.

### Structural schema vs semantic validation

`schemas/assembly-proposal-v1.schema.json` is closed and validates the public shape, but schema validation alone is deliberately insufficient. Every proposal record MUST also pass `validate_proposal_record_semantics`, which:

- derives the Charter Gate from `draft.effects`;
- requires the stored assessment to match exactly;
- validates the active status against the derived assessment;
- validates proposal-kind compatibility rules; and
- recomputes the proposal identity from the bounded immutable projection.

This prevents a structurally valid record from declaring an authority-mutating effect while forging `disposition = compatible`.

## Fork and version path

Assembly outcomes are advisory-to-source, not self-executing runtime authority.

The reference mapping is:

| Proposal | Version path |
| --- | --- |
| advisory resolution | `no_protocol_change` |
| backward-compatible protocol amendment | `compatible_source_change_required` |
| breaking protocol amendment | `new_major_required` |
| charter amendment | `new_major_required` |
| constitutional conflict | `fork_required` |
| endorsed incompatible fork | `fork_required` |

An Assembly receipt never creates a tag, merges a branch, updates a binary, changes a running protocol, or upgrades a member.

Effective change still requires explicit source changes, compatibility analysis, tests, review, release/version decisions, and each member's own adoption decision.

```text
GOVERNANCE RECEIPT != SOURCE CHANGE
SOURCE CHANGE != MEMBER UPGRADE
```

## NEXUS advisory status

QSOL-NEXUS remains a Council service, not the Assembly sovereign.

A NEXUS Council report may be attached as an attributed advisory artifact. The Assembly record hard-codes:

```text
advisory_weight = 0
vote_weight     = 0
authority_effect = none
```

A NEXUS system may separately become an Assembly member only through the same explicit membership process as any other participant. Running NEXUS does not create voting rights.

## Governance receipts

Finalized proposals emit `qsol-fed-governance-receipt/1`.

Receipts deterministically bind:

- proposal identity;
- Charter Gate disposition and violated invariant IDs;
- electorate digest and size;
- yes/no/abstain tally;
- quorum and approval result;
- version/fork path;
- NEXUS advisory count;
- non-authority guarantees.

Every receipt carries:

```text
protocol_changed_automatically  = false
member_local_authority_mutated  = false
nexus_advisory_vote_weight      = 0
authority_effect                = none
```

## Member-local sovereignty

`src/assembly.rs` deliberately has an allowlisted dependency/import surface containing only deterministic collections/formatting, serialization, hashing, Unicode normalization, canonicalization, and wire grammar helpers. It has no handle to:

- `PeerRegistry`;
- `TrustRegistry`;
- local capability policy;
- the Federation object store;
- ORACLE evidence promotion;
- ARK authority;
- Holodeck runtime state;
- files or environment state;
- credentials;
- tools or process execution;
- network clients.

The strongest Assembly output is a governance receipt and an explicit source/version/fork obligation.

The Phase 7 gate is therefore:

> **No Assembly mechanism may directly mutate member-local authority.**
