# Contributing

QSOL-FED welcomes protocol, security, documentation, implementation and interoperability contributions.

## Before changing code

Read `AGENTS.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md` and `THREAT_MODEL.md`.

## Constitutional changes

Do not disguise a constitutional change as a refactor. If a change weakens or alters a sovereignty/authority invariant, say so explicitly and follow the amendment requirements in `GOVERNANCE.md`.

## Pull requests

A useful PR should state:

- what changes;
- what does not change;
- protocol compatibility impact;
- security/authority impact;
- tests added;
- claims that remain deferred.

Run:

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
```

## Interoperability work

Prefer language-neutral fixtures and exact byte-level vectors over prose-only compatibility claims.

## Security

Do not commit credentials, private keys or live secrets. Do not use public issues to publish active exploit secrets when private vulnerability reporting is available.

## Style

Keep human documentation readable and machine contracts explicit. Humor is welcome in explanatory text; security semantics should remain painfully literal.
