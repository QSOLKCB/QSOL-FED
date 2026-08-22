# Governance

## 1. Principle

QSOL-FED governance exists to evolve the federation protocol, not to govern the internal state of member nodes.

A future Federation Assembly may decide what `qsol-fed/N` means. It does not thereby acquire authority to rewrite a member's local Council, evidence store, identity system, history or execution environment.

## 2. Current bootstrap governance

During the bootstrap phase, repository maintainers govern changes through reviewed source control. Constitutional invariants are duplicated intentionally across human, machine and executable surfaces so drift is visible.

The current sources of constitutional intent are:

1. `CHARTER.md`;
2. `PRIME_DIRECTIVE.md`;
3. `invariants/fed-v1.json`;
4. `src/invariants.rs`;
5. conformance tests and CI.

## 3. Future bodies

### Council of Minds

QSOL-NEXUS remains a deliberative Council service. It may reason about Federation questions and publish attributed reports. Its consensus does not automatically amend QSOL-FED.

### Federation Assembly

A future Assembly may represent participating member nodes or organizations in protocol governance. Its exact membership and voting rules are deliberately deferred until identity, peering and protocol mechanics exist.

### Charter Gate

The Charter Gate is deterministic policy enforcement, not a political chamber. It rejects actions that violate constitutional invariants.

Neither a Council majority nor an Assembly majority should be able to bypass the runtime gate merely by embedding an override request in Federation traffic.

## 4. Amendment classes

### Editorial

No semantic or wire change. Examples: spelling, diagrams, clarifying examples.

### Additive capability

Adds an optional capability without weakening existing invariants. Requires negotiation rules and default-deny behavior for peers that do not support it.

### Protocol semantic change

Changes message semantics, canonicalization, identity or required behavior. Requires compatibility analysis and likely protocol version movement.

### Constitutional amendment

Changes a sovereignty, authority or Prime Directive invariant. Requires:

- explicit rationale;
- threat-model analysis;
- updated human charter/directive;
- updated machine registry;
- updated executable policy;
- adversarial regression tests;
- migration/rejection semantics;
- explicit major-version decision.

A constitutional amendment must never hide inside a dependency bump or refactor.

## 5. No emergency peer bypass

An Assembly, Council or peer may recommend emergency local action. The Federation protocol itself must not define an unauthenticated or peer-controlled constitutional bypass.

A local sovereign operator can always alter their own node software. That action is local administration, not proof of Federation authority.

## 6. Forks

Protocol forks are preferable to pretending incompatible constitutional systems are identical. A fork that changes hard invariants should use a distinct protocol identity/version and must not masquerade as conformant `qsol-fed/1`.

## 7. NEXUS relationship

The architectural rule is permanent unless explicitly amended:

> QSOL-NEXUS is a Council within or alongside Federation members; QSOL-FED is not a mode of NEXUS and NEXUS is not the sovereign of QSOL-FED.

This allows third-party systems to federate without adopting NEXUS internals.
