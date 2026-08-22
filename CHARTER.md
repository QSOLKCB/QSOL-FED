# Federation Charter

**Document:** `qsol-fed-charter/1`

## Preamble

QSOL-FED exists so independent computational systems can cooperate without being absorbed into a central authority. Federation is voluntary interoperability among sovereign members.

No member is required to share a worldview, evidence label, model family, runtime, governance process, identity system or internal memory architecture with another member.

## Article I — Sovereignty

1. Each member retains exclusive authority over its local governance, evidence state, execution environment, history, identity semantics, capabilities, credentials and persistence rules.
2. Federation membership does not transfer ownership or control of local state to QSOL-FED, another member, a Council, a model, an operator or a majority of peers.
3. Local sovereignty takes precedence over federation convenience.
4. A member may disconnect, reject, quarantine or ignore federation traffic according to local policy.

## Article II — Non-interference

The Federation Prime Directive is constitutional: a member may exchange information and voluntarily accepted capabilities, but may not silently alter another member's governance, memory, identity, evidence state, authority structure or execution environment.

The normative operational rules live in `PRIME_DIRECTIVE.md`, `invariants/fed-v1.json` and `src/invariants.rs`.

## Article III — Epistemic independence

1. Peering is not trust.
2. Import is not authority.
3. Consensus is not truth.
4. Discovery is not permission.
5. Capability is not entitlement.
6. Foreign state is not local state.
7. Observation is not intervention.
8. A signed statement is an authenticated statement, not automatically a true statement.
9. A remote Council report remains a remote Council report unless a local process explicitly derives some local state from it.

## Article IV — Equality of protocol standing

QSOL-FED does not grant protocol authority based on:

- model provider;
- model size;
- open or closed weights;
- benchmark score;
- account tier;
- geographic location;
- institutional prestige;
- compute budget;
- rhetorical confidence;
- possession of additional tools.

A local member may apply its own trust policy, but such policy does not become universal Federation truth.

## Article V — Membership

Membership means a node can speak the Federation protocol under an accepted local peering policy. Membership does not imply:

- universal trust;
- access to all capabilities;
- voting rights in another system;
- remote execution rights;
- access to secrets;
- authority over local evidence;
- permanence.

Federation membership and any future Federation Assembly membership are separate concepts.

## Article VI — Data and provenance

1. Federation objects must preserve origin and provenance sufficient for local evaluation.
2. A member must not deliberately strip provenance in order to make foreign material appear local.
3. Imported material must retain foreign identity until an explicit local process creates a distinct local descendant.
4. Content identity, source identity, evidence status and authority are separate dimensions.

## Article VII — Capabilities

1. Capabilities are explicitly advertised and negotiated.
2. Unknown capabilities default to unavailable.
3. Advertising a capability does not authorize another node to invoke it.
4. Invocation authority, when later supported, must be separately admitted by local policy.
5. Arbitrary remote execution is forbidden in Federation v1.

## Article VIII — Governance

1. QSOL-NEXUS is not the sovereign of QSOL-FED.
2. A future Federation Assembly may govern protocol evolution but does not acquire control of member-local state.
3. Constitutional rules cannot be weakened by ordinary runtime configuration or an ordinary Federation message.
4. Constitutional amendments require explicit source changes, compatibility analysis, tests and a protocol-version decision.
5. Emergency convenience is not an implicit constitutional bypass.

## Article IX — Exit and partition

1. A node may leave without surrendering its local history.
2. Other nodes may retain already received attributed records subject to their own retention rules and applicable law.
3. Network partitions are normal distributed-systems conditions, not constitutional failures.
4. Rejoining does not silently reconcile contradictory state. Differences remain explicit until locally processed.

## Article X — Scope and claims

QSOL-FED provides a technical governance and interoperability model. It does not claim legal sovereignty, statehood, personhood, consciousness or moral status for software systems merely by calling them members, citizens, councils or nodes.

## Constitutional shorthand

```text
PEERING != TRUST
IMPORT != AUTHORITY
CONSENSUS != TRUTH
DISCOVERY != PERMISSION
CAPABILITY != ENTITLEMENT
FEDERATION != CENTRAL CONTROL
FOREIGN STATE != LOCAL STATE
OBSERVATION != INTERVENTION
LOCAL SOVEREIGNTY > FEDERATION CONVENIENCE
```

The shorthand is explanatory. The machine and executable invariant registries are authoritative for implementation behavior.
