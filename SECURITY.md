# Security Policy

QSOL-FED treats federation boundaries as hostile-by-default network boundaries.

## Security principles

- fail closed on unknown authority semantics;
- separate identity, authenticity, trust, evidence and authority;
- keep foreign state foreign until explicit local admission;
- make constitutional security rules non-configurable at runtime;
- minimize remotely reachable capabilities;
- preserve provenance;
- avoid secret material in semantic objects;
- bound all parser and network inputs;
- do not claim stronger isolation than implemented and tested.

## Bootstrap security guarantees

PR #1 hard-codes admission rejection for attempts to:

- mutate local governance;
- promote local evidence status;
- create/reweight local votes;
- install capabilities;
- rewrite history;
- mutate citizenship/identity authority;
- execute arbitrary remote tools/code;
- claim local authority;
- import foreign state as authoritative local state;
- place secrets in semantic federation state;
- disable constitutional invariants at runtime.

The implementation currently provides policy logic and tests, not a production network service.

## Credentials

Credentials, private keys, tokens and secret material are operational security state. They must not intentionally enter:

- Federation payloads;
- Council reports;
- evidence objects;
- provenance narratives;
- logs intended for federation export;
- model prompts used to interpret Federation objects.

Future key storage must use an explicit secret boundary and should prefer OS-backed/key-agent mechanisms over plaintext configuration.

## Cryptography

No cryptographic suite is frozen by PR #1. Future work must specify:

- key type and parameters;
- node ID derivation;
- signing bytes and canonicalization;
- key rotation;
- revocation;
- multi-key transition;
- verification test vectors;
- algorithm agility and downgrade rules.

Do not equate a valid signature with truth or local authorization.

## Network policy

The first network implementation should default to:

- TLS for remote HTTP transport;
- no arbitrary URL fetch on behalf of peers;
- no ambient proxy surprises at sensitive boundaries;
- no redirects at signature/key-discovery boundaries unless explicitly reviewed;
- explicit DNS/SSRF defenses;
- strict request/body limits;
- replay and expiry checks;
- rate limiting;
- structured logging without secrets.

## Dependency policy

Security-sensitive dependencies should be minimal, pinned through Cargo.lock for applications, and reviewed for maintenance posture and unsafe-code implications where relevant.

## Vulnerability reporting

Until a dedicated private reporting channel is configured, avoid posting exploitable secret material, active credentials or private keys in public issues. Repository maintainers should enable GitHub private vulnerability reporting before production deployment.

## Scope discipline

Security documentation must distinguish:

- designed;
- implemented;
- tested;
- externally audited.

QSOL-FED currently claims the first three only where repository evidence exists, and claims no external audit.
