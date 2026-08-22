use std::collections::BTreeMap;
use std::fmt;

use chrono::DateTime;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, derive_message_id};
use crate::envelope::FederationEnvelope;
use crate::wire::is_wire_timestamp;

pub const SIGNED_ENVELOPE_SCHEMA_V1: &str = "qsol-fed-signed-envelope/1";
pub const NODE_IDENTITY_SCHEMA_V1: &str = "qsol-fed-node-identity/1";
pub const KEY_ROTATION_SCHEMA_V1: &str = "qsol-fed-key-rotation/1";
pub const KEY_STATUS_SCHEMA_V1: &str = "qsol-fed-key-status/1";
pub const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"qsol-fed-envelope-signature/1\0";
pub const NODE_ID_DOMAIN: &[u8] = b"qsol-fed-node-id/1\0";
pub const KEY_ID_DOMAIN: &[u8] = b"qsol-fed-key-id/1\0";
pub const NODE_IDENTITY_DOMAIN: &[u8] = b"qsol-fed-node-identity/1\0";
pub const KEY_ROTATION_DOMAIN: &[u8] = b"qsol-fed-key-rotation/1\0";
pub const KEY_STATUS_DOMAIN: &[u8] = b"qsol-fed-key-status/1\0";
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
pub const MAX_SIGNED_MESSAGE_LIFETIME_SECONDS: i64 = 3600;
pub const MAX_ROTATION_OVERLAP_SECONDS: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub String);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureValidity {
    Valid,
    Invalid,
    UnknownKey,
    Revoked,
    Compromised,
    NotYetValid,
    Retired,
    ClockRejected,
    NodeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDisposition {
    Unknown,
    LocallyTrusted,
    LocallyDistrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDisposition {
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationAssessment {
    pub signature: SignatureValidity,
    pub trust: TrustDisposition,
    pub authority: AuthorityDisposition,
}

impl AuthenticationAssessment {
    pub fn with_local_trust(mut self, trust: TrustDisposition) -> Self {
        self.trust = trust;
        self
    }
}

pub struct LocalSigningKey {
    inner: SigningKey,
}

impl LocalSigningKey {
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, CryptoError> {
        let seed = decode_fixed_hex::<32>(seed_hex)?;
        Ok(Self {
            inner: SigningKey::from_bytes(&seed),
        })
    }

    pub fn public_key_hex(&self) -> String {
        lowercase_hex(&self.inner.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> String {
        derive_key_id_from_bytes(&self.inner.verifying_key().to_bytes())
    }

    fn sign_domain(&self, domain: &[u8], payload: &[u8]) -> String {
        let mut preimage = Vec::with_capacity(domain.len() + payload.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(payload);
        lowercase_hex(&self.inner.sign(&preimage).to_bytes())
    }
}

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(CryptoError(format!("expected_{N}_byte_lowercase_hex")));
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| CryptoError("invalid_hex".into()))?;
    }
    Ok(out)
}

fn sha256_hex(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    lowercase_hex(&hasher.finalize())
}

fn derive_key_id_from_bytes(public_key: &[u8; 32]) -> String {
    format!("ed25519:{}", sha256_hex(KEY_ID_DOMAIN, public_key))
}

pub fn derive_key_id(public_key_hex: &str) -> Result<String, CryptoError> {
    let public_key = decode_fixed_hex::<32>(public_key_hex)?;
    Ok(derive_key_id_from_bytes(&public_key))
}

pub fn derive_node_id(root_public_key_hex: &str) -> Result<String, CryptoError> {
    let public_key = decode_fixed_hex::<32>(root_public_key_hex)?;
    Ok(format!(
        "fed:qsol:{}",
        sha256_hex(NODE_ID_DOMAIN, &public_key)
    ))
}

fn verify_signature(
    public_key_hex: &str,
    domain: &[u8],
    payload: &[u8],
    signature_hex: &str,
) -> Result<bool, CryptoError> {
    let public_key = decode_fixed_hex::<32>(public_key_hex)?;
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| CryptoError("invalid_ed25519_public_key".into()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    let mut preimage = Vec::with_capacity(domain.len() + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Ok(key.verify_strict(&preimage, &signature).is_ok())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let raw = serde_json::to_vec(value).map_err(|error| CryptoError(error.to_string()))?;
    canonicalize(&raw).map_err(|error| CryptoError(error.0))
}

fn parse_timestamp(value: &str) -> Result<i64, CryptoError> {
    if !is_wire_timestamp(value) {
        return Err(CryptoError("invalid_wire_timestamp".into()));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.timestamp())
        .map_err(|_| CryptoError("invalid_calendar_timestamp".into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPolicy {
    pub max_clock_skew_seconds: i64,
    pub max_signed_message_lifetime_seconds: i64,
}

pub const DEFAULT_CLOCK_POLICY: ClockPolicy = ClockPolicy {
    max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
    max_signed_message_lifetime_seconds: MAX_SIGNED_MESSAGE_LIFETIME_SECONDS,
};

impl ClockPolicy {
    pub fn validate_envelope(
        &self,
        envelope: &FederationEnvelope,
        now_unix: i64,
    ) -> Result<(), CryptoError> {
        let issued = parse_timestamp(&envelope.issued_at)?;
        let expires_text = envelope
            .expires_at
            .as_deref()
            .ok_or_else(|| CryptoError("signed_envelope_expiry_required".into()))?;
        let expires = parse_timestamp(expires_text)?;
        if expires <= issued {
            return Err(CryptoError("expiry_not_after_issue".into()));
        }
        if expires - issued > self.max_signed_message_lifetime_seconds {
            return Err(CryptoError("signed_message_lifetime_exceeded".into()));
        }
        if issued > now_unix + self.max_clock_skew_seconds {
            return Err(CryptoError("issued_too_far_in_future".into()));
        }
        if expires < now_unix - self.max_clock_skew_seconds {
            return Err(CryptoError("signed_message_expired".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentityDocument {
    pub schema: String,
    pub node_id: String,
    pub algorithm: SigningAlgorithm,
    pub root_key_id: String,
    pub root_public_key: String,
    pub operational_key_id: String,
    pub operational_public_key: String,
    pub created_at: String,
    pub root_signature: String,
}

#[derive(Serialize)]
struct NodeIdentityPayload<'a> {
    schema: &'a str,
    node_id: &'a str,
    algorithm: SigningAlgorithm,
    root_key_id: &'a str,
    root_public_key: &'a str,
    operational_key_id: &'a str,
    operational_public_key: &'a str,
    created_at: &'a str,
}

fn identity_payload(document: &NodeIdentityDocument) -> Result<Vec<u8>, CryptoError> {
    canonical_json(&NodeIdentityPayload {
        schema: &document.schema,
        node_id: &document.node_id,
        algorithm: document.algorithm,
        root_key_id: &document.root_key_id,
        root_public_key: &document.root_public_key,
        operational_key_id: &document.operational_key_id,
        operational_public_key: &document.operational_public_key,
        created_at: &document.created_at,
    })
}

pub fn create_identity_document(
    root: &LocalSigningKey,
    operational: &LocalSigningKey,
    created_at: &str,
) -> Result<NodeIdentityDocument, CryptoError> {
    parse_timestamp(created_at)?;
    if root.key_id() == operational.key_id() {
        return Err(CryptoError("root_and_operational_keys_must_be_distinct".into()));
    }
    let root_public_key = root.public_key_hex();
    let operational_public_key = operational.public_key_hex();
    let mut document = NodeIdentityDocument {
        schema: NODE_IDENTITY_SCHEMA_V1.into(),
        node_id: derive_node_id(&root_public_key)?,
        algorithm: SigningAlgorithm::Ed25519,
        root_key_id: root.key_id(),
        root_public_key,
        operational_key_id: operational.key_id(),
        operational_public_key,
        created_at: created_at.into(),
        root_signature: String::new(),
    };
    document.root_signature =
        root.sign_domain(NODE_IDENTITY_DOMAIN, &identity_payload(&document)?);
    Ok(document)
}

pub fn verify_identity_document(document: &NodeIdentityDocument) -> Result<bool, CryptoError> {
    if document.schema != NODE_IDENTITY_SCHEMA_V1
        || document.root_key_id == document.operational_key_id
        || document.node_id != derive_node_id(&document.root_public_key)?
        || document.root_key_id != derive_key_id(&document.root_public_key)?
        || document.operational_key_id != derive_key_id(&document.operational_public_key)?
    {
        return Ok(false);
    }
    parse_timestamp(&document.created_at)?;
    verify_signature(
        &document.root_public_key,
        NODE_IDENTITY_DOMAIN,
        &identity_payload(document)?,
        &document.root_signature,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationMode {
    Transition,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationRecord {
    pub schema: String,
    pub node_id: String,
    pub algorithm: SigningAlgorithm,
    pub sequence: u64,
    pub mode: RotationMode,
    pub previous_key_id: String,
    pub next_key_id: String,
    pub next_public_key: String,
    pub not_before: String,
    pub overlap_until: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub previous_signature: Option<String>,
    pub next_signature: String,
    pub root_signature: String,
}

#[derive(Serialize)]
struct RotationPayload<'a> {
    schema: &'a str,
    node_id: &'a str,
    algorithm: SigningAlgorithm,
    sequence: u64,
    mode: RotationMode,
    previous_key_id: &'a str,
    next_key_id: &'a str,
    next_public_key: &'a str,
    not_before: &'a str,
    overlap_until: &'a str,
}

fn rotation_payload(record: &KeyRotationRecord) -> Result<Vec<u8>, CryptoError> {
    canonical_json(&RotationPayload {
        schema: &record.schema,
        node_id: &record.node_id,
        algorithm: record.algorithm,
        sequence: record.sequence,
        mode: record.mode,
        previous_key_id: &record.previous_key_id,
        next_key_id: &record.next_key_id,
        next_public_key: &record.next_public_key,
        not_before: &record.not_before,
        overlap_until: &record.overlap_until,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatusKind {
    Revoked,
    Compromised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatusReason {
    OperatorRevocation,
    SuspectedCompromise,
    ConfirmedCompromise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyStatusRecord {
    pub schema: String,
    pub node_id: String,
    pub algorithm: SigningAlgorithm,
    pub sequence: u64,
    pub key_id: String,
    pub status: KeyStatusKind,
    pub effective_at: String,
    pub reason: KeyStatusReason,
    pub root_signature: String,
}

#[derive(Serialize)]
struct KeyStatusPayload<'a> {
    schema: &'a str,
    node_id: &'a str,
    algorithm: SigningAlgorithm,
    sequence: u64,
    key_id: &'a str,
    status: KeyStatusKind,
    effective_at: &'a str,
    reason: KeyStatusReason,
}

fn key_status_payload(record: &KeyStatusRecord) -> Result<Vec<u8>, CryptoError> {
    canonical_json(&KeyStatusPayload {
        schema: &record.schema,
        node_id: &record.node_id,
        algorithm: record.algorithm,
        sequence: record.sequence,
        key_id: &record.key_id,
        status: record.status,
        effective_at: &record.effective_at,
        reason: record.reason,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalKeyStatus {
    Active,
    Revoked,
    Compromised,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalKeyState {
    pub key_id: String,
    pub public_key: String,
    pub valid_from: i64,
    pub valid_until: Option<i64>,
    pub status: OperationalKeyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityState {
    pub node_id: String,
    pub root_key_id: String,
    pub root_public_key: String,
    pub current_key_id: String,
    pub sequence: u64,
    operational_keys: BTreeMap<String, OperationalKeyState>,
}

impl IdentityState {
    pub fn from_document(document: &NodeIdentityDocument) -> Result<Self, CryptoError> {
        if !verify_identity_document(document)? {
            return Err(CryptoError("identity_document_verification_failed".into()));
        }
        let created_at = parse_timestamp(&document.created_at)?;
        let initial = OperationalKeyState {
            key_id: document.operational_key_id.clone(),
            public_key: document.operational_public_key.clone(),
            valid_from: created_at,
            valid_until: None,
            status: OperationalKeyStatus::Active,
        };
        let mut operational_keys = BTreeMap::new();
        operational_keys.insert(initial.key_id.clone(), initial);
        Ok(Self {
            node_id: document.node_id.clone(),
            root_key_id: document.root_key_id.clone(),
            root_public_key: document.root_public_key.clone(),
            current_key_id: document.operational_key_id.clone(),
            sequence: 0,
            operational_keys,
        })
    }

    pub fn operational_key(&self, key_id: &str) -> Option<&OperationalKeyState> {
        self.operational_keys.get(key_id)
    }

    fn ensure_no_other_overlap(
        &self,
        current_key_id: &str,
        not_before: i64,
    ) -> Result<(), CryptoError> {
        if self.operational_keys.values().any(|key| {
            key.key_id != current_key_id
                && key.status == OperationalKeyStatus::Active
                && key.valid_until.is_some_and(|until| until > not_before)
        }) {
            return Err(CryptoError("overlapping_key_transitions_forbidden".into()));
        }
        Ok(())
    }

    pub fn create_transition_rotation(
        &self,
        root: &LocalSigningKey,
        previous: &LocalSigningKey,
        next: &LocalSigningKey,
        not_before: &str,
        overlap_until: &str,
    ) -> Result<KeyRotationRecord, CryptoError> {
        if root.key_id() != self.root_key_id || previous.key_id() != self.current_key_id {
            return Err(CryptoError("rotation_signing_key_mismatch".into()));
        }
        if next.key_id() == self.root_key_id || next.key_id() == self.current_key_id {
            return Err(CryptoError("rotation_next_key_role_invalid".into()));
        }
        let not_before_unix = parse_timestamp(not_before)?;
        let overlap_until_unix = parse_timestamp(overlap_until)?;
        if overlap_until_unix < not_before_unix
            || overlap_until_unix - not_before_unix > MAX_ROTATION_OVERLAP_SECONDS
        {
            return Err(CryptoError("rotation_overlap_invalid".into()));
        }
        self.ensure_no_other_overlap(&self.current_key_id, not_before_unix)?;
        let mut record = KeyRotationRecord {
            schema: KEY_ROTATION_SCHEMA_V1.into(),
            node_id: self.node_id.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            sequence: self.sequence + 1,
            mode: RotationMode::Transition,
            previous_key_id: previous.key_id(),
            next_key_id: next.key_id(),
            next_public_key: next.public_key_hex(),
            not_before: not_before.into(),
            overlap_until: overlap_until.into(),
            previous_signature: None,
            next_signature: String::new(),
            root_signature: String::new(),
        };
        let payload = rotation_payload(&record)?;
        record.previous_signature = Some(previous.sign_domain(KEY_ROTATION_DOMAIN, &payload));
        record.next_signature = next.sign_domain(KEY_ROTATION_DOMAIN, &payload);
        record.root_signature = root.sign_domain(KEY_ROTATION_DOMAIN, &payload);
        Ok(record)
    }

    pub fn create_recovery_rotation(
        &self,
        root: &LocalSigningKey,
        next: &LocalSigningKey,
        not_before: &str,
    ) -> Result<KeyRotationRecord, CryptoError> {
        if root.key_id() != self.root_key_id {
            return Err(CryptoError("root_key_mismatch".into()));
        }
        if next.key_id() == self.root_key_id || next.key_id() == self.current_key_id {
            return Err(CryptoError("rotation_next_key_role_invalid".into()));
        }
        let previous = self
            .operational_keys
            .get(&self.current_key_id)
            .ok_or_else(|| CryptoError("current_operational_key_missing".into()))?;
        if !matches!(
            previous.status,
            OperationalKeyStatus::Revoked | OperationalKeyStatus::Compromised
        ) {
            return Err(CryptoError(
                "recovery_requires_revoked_or_compromised_key".into(),
            ));
        }
        let not_before_unix = parse_timestamp(not_before)?;
        self.ensure_no_other_overlap(&self.current_key_id, not_before_unix)?;
        let mut record = KeyRotationRecord {
            schema: KEY_ROTATION_SCHEMA_V1.into(),
            node_id: self.node_id.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            sequence: self.sequence + 1,
            mode: RotationMode::Recovery,
            previous_key_id: self.current_key_id.clone(),
            next_key_id: next.key_id(),
            next_public_key: next.public_key_hex(),
            not_before: not_before.into(),
            overlap_until: not_before.into(),
            previous_signature: None,
            next_signature: String::new(),
            root_signature: String::new(),
        };
        let payload = rotation_payload(&record)?;
        record.next_signature = next.sign_domain(KEY_ROTATION_DOMAIN, &payload);
        record.root_signature = root.sign_domain(KEY_ROTATION_DOMAIN, &payload);
        Ok(record)
    }

    pub fn apply_rotation(&mut self, record: &KeyRotationRecord) -> Result<(), CryptoError> {
        if record.schema != KEY_ROTATION_SCHEMA_V1
            || record.node_id != self.node_id
            || record.sequence != self.sequence + 1
            || record.previous_key_id != self.current_key_id
            || record.next_key_id == self.root_key_id
            || record.next_key_id != derive_key_id(&record.next_public_key)?
            || self.operational_keys.contains_key(&record.next_key_id)
        {
            return Err(CryptoError("rotation_shape_or_sequence_invalid".into()));
        }
        let not_before = parse_timestamp(&record.not_before)?;
        let overlap_until = parse_timestamp(&record.overlap_until)?;
        if overlap_until < not_before
            || overlap_until - not_before > MAX_ROTATION_OVERLAP_SECONDS
        {
            return Err(CryptoError("rotation_overlap_invalid".into()));
        }
        self.ensure_no_other_overlap(&record.previous_key_id, not_before)?;
        let payload = rotation_payload(record)?;
        if !verify_signature(
            &self.root_public_key,
            KEY_ROTATION_DOMAIN,
            &payload,
            &record.root_signature,
        )? || !verify_signature(
            &record.next_public_key,
            KEY_ROTATION_DOMAIN,
            &payload,
            &record.next_signature,
        )? {
            return Err(CryptoError(
                "rotation_root_or_next_signature_invalid".into(),
            ));
        }

        let previous = self
            .operational_keys
            .get_mut(&record.previous_key_id)
            .ok_or_else(|| CryptoError("previous_operational_key_missing".into()))?;
        match record.mode {
            RotationMode::Transition => {
                if previous.status != OperationalKeyStatus::Active {
                    return Err(CryptoError(
                        "transition_requires_active_previous_key".into(),
                    ));
                }
                let previous_signature = record.previous_signature.as_deref().ok_or_else(|| {
                    CryptoError("transition_previous_signature_required".into())
                })?;
                if !verify_signature(
                    &previous.public_key,
                    KEY_ROTATION_DOMAIN,
                    &payload,
                    previous_signature,
                )? {
                    return Err(CryptoError(
                        "transition_previous_signature_invalid".into(),
                    ));
                }
            }
            RotationMode::Recovery => {
                if record.previous_signature.is_some()
                    || !matches!(
                        previous.status,
                        OperationalKeyStatus::Revoked | OperationalKeyStatus::Compromised
                    )
                    || overlap_until != not_before
                {
                    return Err(CryptoError("recovery_transition_invalid".into()));
                }
            }
        }
        if not_before < previous.valid_from {
            return Err(CryptoError("rotation_before_previous_activation".into()));
        }
        previous.valid_until = Some(overlap_until);
        let next = OperationalKeyState {
            key_id: record.next_key_id.clone(),
            public_key: record.next_public_key.clone(),
            valid_from: not_before,
            valid_until: None,
            status: OperationalKeyStatus::Active,
        };
        self.operational_keys.insert(next.key_id.clone(), next);
        self.current_key_id = record.next_key_id.clone();
        self.sequence = record.sequence;
        Ok(())
    }

    pub fn create_key_status_record(
        &self,
        root: &LocalSigningKey,
        key_id: &str,
        status: KeyStatusKind,
        effective_at: &str,
        reason: KeyStatusReason,
    ) -> Result<KeyStatusRecord, CryptoError> {
        if root.key_id() != self.root_key_id || key_id == self.root_key_id {
            return Err(CryptoError("status_root_or_target_invalid".into()));
        }
        let key = self
            .operational_keys
            .get(key_id)
            .ok_or_else(|| CryptoError("status_target_unknown".into()))?;
        let effective = parse_timestamp(effective_at)?;
        if effective < key.valid_from {
            return Err(CryptoError("status_before_key_activation".into()));
        }
        let mut record = KeyStatusRecord {
            schema: KEY_STATUS_SCHEMA_V1.into(),
            node_id: self.node_id.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            sequence: self.sequence + 1,
            key_id: key_id.into(),
            status,
            effective_at: effective_at.into(),
            reason,
            root_signature: String::new(),
        };
        record.root_signature = root.sign_domain(KEY_STATUS_DOMAIN, &key_status_payload(&record)?);
        Ok(record)
    }

    pub fn apply_key_status(&mut self, record: &KeyStatusRecord) -> Result<(), CryptoError> {
        if record.schema != KEY_STATUS_SCHEMA_V1
            || record.node_id != self.node_id
            || record.sequence != self.sequence + 1
            || record.key_id == self.root_key_id
        {
            return Err(CryptoError("key_status_shape_or_sequence_invalid".into()));
        }
        let effective_at = parse_timestamp(&record.effective_at)?;
        let payload = key_status_payload(record)?;
        if !verify_signature(
            &self.root_public_key,
            KEY_STATUS_DOMAIN,
            &payload,
            &record.root_signature,
        )? {
            return Err(CryptoError("key_status_root_signature_invalid".into()));
        }
        let key = self
            .operational_keys
            .get_mut(&record.key_id)
            .ok_or_else(|| CryptoError("key_status_target_unknown".into()))?;
        if effective_at < key.valid_from {
            return Err(CryptoError("status_before_key_activation".into()));
        }
        key.status = match record.status {
            KeyStatusKind::Revoked => OperationalKeyStatus::Revoked,
            KeyStatusKind::Compromised => OperationalKeyStatus::Compromised,
        };
        key.valid_until = Some(
            key.valid_until
                .map_or(effective_at, |old| old.min(effective_at)),
        );
        self.sequence = record.sequence;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub schema: String,
    pub algorithm: SigningAlgorithm,
    pub node_id: String,
    pub key_id: String,
    pub envelope: FederationEnvelope,
    pub signature: String,
}

fn canonical_envelope_bytes(envelope: &FederationEnvelope) -> Result<Vec<u8>, CryptoError> {
    if !envelope.validate_shape() {
        return Err(CryptoError("envelope_shape_invalid".into()));
    }
    let canonical = canonical_json(envelope)?;
    let derived = derive_message_id(&canonical).map_err(|error| CryptoError(error.0))?;
    if derived != envelope.message_id {
        return Err(CryptoError("message_id_mismatch".into()));
    }
    Ok(canonical)
}

pub fn sign_envelope(
    identity: &IdentityState,
    signing_key: &LocalSigningKey,
    envelope: FederationEnvelope,
) -> Result<SignedEnvelope, CryptoError> {
    let key_id = signing_key.key_id();
    let operational = identity
        .operational_keys
        .get(&key_id)
        .ok_or_else(|| CryptoError("root_or_unregistered_key_cannot_sign_envelope".into()))?;
    if operational.status != OperationalKeyStatus::Active
        || envelope.sender != identity.node_id
        || key_id == identity.root_key_id
    {
        return Err(CryptoError("operational_signing_key_not_admitted".into()));
    }
    let canonical = canonical_envelope_bytes(&envelope)?;
    Ok(SignedEnvelope {
        schema: SIGNED_ENVELOPE_SCHEMA_V1.into(),
        algorithm: SigningAlgorithm::Ed25519,
        node_id: identity.node_id.clone(),
        key_id,
        envelope,
        signature: signing_key.sign_domain(ENVELOPE_SIGNATURE_DOMAIN, &canonical),
    })
}

impl SignedEnvelope {
    pub fn to_wire(&self) -> Result<Vec<u8>, CryptoError> {
        canonical_json(self)
    }

    pub fn from_wire(raw: &[u8]) -> Result<Self, CryptoError> {
        let canonical = canonicalize(raw).map_err(|error| CryptoError(error.0))?;
        if canonical != raw {
            return Err(CryptoError("signed_envelope_bytes_not_canonical".into()));
        }
        let signed: Self = serde_json::from_slice(raw)
            .map_err(|error| CryptoError(format!("signed_envelope_schema:{error}")))?;
        if signed.schema != SIGNED_ENVELOPE_SCHEMA_V1
            || signed.node_id != signed.envelope.sender
            || validate_key_id_and_signature_shape(&signed.key_id, &signed.signature).is_err()
        {
            return Err(CryptoError("signed_envelope_shape_invalid".into()));
        }
        canonical_envelope_bytes(&signed.envelope)?;
        Ok(signed)
    }
}

fn validate_key_id_and_signature_shape(key_id: &str, signature: &str) -> Result<(), CryptoError> {
    if !key_id.starts_with("ed25519:") || key_id.len() != 72 {
        return Err(CryptoError("invalid_key_id".into()));
    }
    let _ = decode_fixed_hex::<32>(&key_id[8..])?;
    let _ = decode_fixed_hex::<64>(signature)?;
    Ok(())
}

pub fn verify_signed_envelope(
    signed: &SignedEnvelope,
    identity: &IdentityState,
    now_unix: i64,
    clock: ClockPolicy,
) -> Result<AuthenticationAssessment, CryptoError> {
    let base = AuthenticationAssessment {
        signature: SignatureValidity::Invalid,
        trust: TrustDisposition::Unknown,
        authority: AuthorityDisposition::None,
    };
    if signed.schema != SIGNED_ENVELOPE_SCHEMA_V1
        || signed.node_id != identity.node_id
        || signed.envelope.sender != identity.node_id
    {
        return Ok(AuthenticationAssessment {
            signature: SignatureValidity::NodeMismatch,
            ..base
        });
    }
    if clock.validate_envelope(&signed.envelope, now_unix).is_err() {
        return Ok(AuthenticationAssessment {
            signature: SignatureValidity::ClockRejected,
            ..base
        });
    }
    let issued = parse_timestamp(&signed.envelope.issued_at)?;
    let Some(key) = identity.operational_keys.get(&signed.key_id) else {
        return Ok(AuthenticationAssessment {
            signature: SignatureValidity::UnknownKey,
            ..base
        });
    };
    match key.status {
        OperationalKeyStatus::Revoked => {
            return Ok(AuthenticationAssessment {
                signature: SignatureValidity::Revoked,
                ..base
            });
        }
        OperationalKeyStatus::Compromised => {
            return Ok(AuthenticationAssessment {
                signature: SignatureValidity::Compromised,
                ..base
            });
        }
        OperationalKeyStatus::Active => {}
    }
    if issued < key.valid_from {
        return Ok(AuthenticationAssessment {
            signature: SignatureValidity::NotYetValid,
            ..base
        });
    }
    if key.valid_until.is_some_and(|until| issued > until) {
        return Ok(AuthenticationAssessment {
            signature: SignatureValidity::Retired,
            ..base
        });
    }
    let canonical = canonical_envelope_bytes(&signed.envelope)?;
    let valid = verify_signature(
        &key.public_key,
        ENVELOPE_SIGNATURE_DOMAIN,
        &canonical,
        &signed.signature,
    )?;
    Ok(AuthenticationAssessment {
        signature: if valid {
            SignatureValidity::Valid
        } else {
            SignatureValidity::Invalid
        },
        ..base
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{AuthorityClaim, MessageClass};
    use crate::invariants::{admit_effect, AdmissionDecision, FederationEffect};

    const ROOT_SEED: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const OP_SEED: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const NEXT_SEED: &str =
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    const VALID_NOW: i64 = 1_787_443_320;

    fn identity() -> (LocalSigningKey, LocalSigningKey, IdentityState) {
        let root = LocalSigningKey::from_seed_hex(ROOT_SEED).unwrap();
        let operational = LocalSigningKey::from_seed_hex(OP_SEED).unwrap();
        let document =
            create_identity_document(&root, &operational, "2026-08-23T00:00:00Z").unwrap();
        assert!(verify_identity_document(&document).unwrap());
        let state = IdentityState::from_document(&document).unwrap();
        (root, operational, state)
    }

    fn envelope(state: &IdentityState, issued: &str, expires: &str) -> FederationEnvelope {
        let mut envelope = FederationEnvelope {
            protocol: "qsol-fed/1".into(),
            message_id: format!("sha256:{}", "0".repeat(64)),
            sender: state.node_id.clone(),
            recipient: state.node_id.clone(),
            message_class: MessageClass::Challenge,
            payload_ref: format!("sha256:{}", "b".repeat(64)),
            provenance_ref: None,
            issued_at: issued.into(),
            expires_at: Some(expires.into()),
            authority_claim: AuthorityClaim::None,
            signature: (),
        };
        let canonical = canonical_json(&envelope).unwrap();
        envelope.message_id = derive_message_id(&canonical).unwrap();
        envelope
    }

    #[test]
    fn rfc8032_empty_message_vector_matches() {
        let key = LocalSigningKey::from_seed_hex(ROOT_SEED).unwrap();
        assert_eq!(
            key.public_key_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let signature = key.inner.sign(b"");
        assert_eq!(
            lowercase_hex(&signature.to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn node_and_key_derivation_are_stable() {
        let (root, operational, state) = identity();
        assert_eq!(
            state.node_id,
            "fed:qsol:8fbf311d9bd830509a22b40926970621fd31ee14ef238c552517f6a567fbc69d"
        );
        assert_eq!(
            root.key_id(),
            "ed25519:bf8c7661e1c89dad9cc90c6d831f39cc86828af665c8181b19b15cd21d8c6a97"
        );
        assert_eq!(
            operational.key_id(),
            "ed25519:a69898edb88628faa92ffbd47b4b5eec1ffb4a8855540c55037d28c4ba6dfaf3"
        );
    }

    #[test]
    fn root_and_operational_roles_must_remain_distinct() {
        let root = LocalSigningKey::from_seed_hex(ROOT_SEED).unwrap();
        assert!(create_identity_document(&root, &root, "2026-08-23T00:00:00Z").is_err());
        let (root, operational, state) = identity();
        assert!(state
            .create_transition_rotation(
                &root,
                &operational,
                &root,
                "2026-08-23T01:00:00Z",
                "2026-08-23T01:00:00Z"
            )
            .is_err());
    }

    #[test]
    fn root_key_cannot_sign_federation_envelope() {
        let (root, _operational, state) = identity();
        let env = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        assert!(sign_envelope(&state, &root, env).is_err());
    }

    #[test]
    fn signed_envelope_matches_frozen_vector() {
        let (_root, operational, state) = identity();
        let env = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        assert_eq!(
            env.message_id,
            "sha256:180b4d750d683daed2c56f226b277ac8e5eb96b0b85d60c726a27a205ffc998e"
        );
        let signed = sign_envelope(&state, &operational, env).unwrap();
        assert_eq!(
            signed.signature,
            "8f2df33a560b3911ea903255e8c7501901fb9af4655afcd2671d17d0d919ef52b97deddda0160bd3e3800897410bb2f8b2a8b0fa71d1afa43fd6037dd319450e"
        );
    }

    #[test]
    fn valid_signature_is_not_trust_or_authority() {
        let (_root, operational, state) = identity();
        let env = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        let signed = sign_envelope(&state, &operational, env).unwrap();
        let assessment =
            verify_signed_envelope(&signed, &state, VALID_NOW, DEFAULT_CLOCK_POLICY).unwrap();
        assert_eq!(assessment.signature, SignatureValidity::Valid);
        assert_eq!(assessment.trust, TrustDisposition::Unknown);
        assert_eq!(assessment.authority, AuthorityDisposition::None);
        let trusted = assessment.with_local_trust(TrustDisposition::LocallyTrusted);
        assert_eq!(trusted.authority, AuthorityDisposition::None);
        assert!(matches!(
            admit_effect(FederationEffect::MutateLocalGovernance),
            AdmissionDecision::Reject { .. }
        ));
    }

    #[test]
    fn transition_rotation_requires_three_signatures_and_preserves_overlap() {
        let (root, operational, mut state) = identity();
        let next = LocalSigningKey::from_seed_hex(NEXT_SEED).unwrap();
        let rotation = state
            .create_transition_rotation(
                &root,
                &operational,
                &next,
                "2026-08-23T01:00:00Z",
                "2026-08-23T02:00:00Z",
            )
            .unwrap();
        assert!(rotation.previous_signature.is_some());
        state.apply_rotation(&rotation).unwrap();
        assert_eq!(state.current_key_id, next.key_id());
        assert_eq!(
            state.operational_key(&operational.key_id()).unwrap().valid_until,
            Some(1_787_450_400)
        );
        assert_eq!(
            state.operational_key(&next.key_id()).unwrap().valid_from,
            1_787_446_800
        );
    }

    #[test]
    fn second_transition_cannot_overlap_an_existing_transition() {
        let (root, operational, mut state) = identity();
        let next = LocalSigningKey::from_seed_hex(NEXT_SEED).unwrap();
        let first = state
            .create_transition_rotation(
                &root,
                &operational,
                &next,
                "2026-08-23T01:00:00Z",
                "2026-08-23T02:00:00Z",
            )
            .unwrap();
        state.apply_rotation(&first).unwrap();
        let third = LocalSigningKey::from_seed_hex(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        )
        .unwrap();
        assert!(state
            .create_transition_rotation(
                &root,
                &next,
                &third,
                "2026-08-23T01:30:00Z",
                "2026-08-23T02:30:00Z"
            )
            .is_err());
    }

    #[test]
    fn compromised_key_can_recover_only_through_root_and_new_key() {
        let (root, operational, mut state) = identity();
        let status = state
            .create_key_status_record(
                &root,
                &operational.key_id(),
                KeyStatusKind::Compromised,
                "2026-08-23T00:30:00Z",
                KeyStatusReason::ConfirmedCompromise,
            )
            .unwrap();
        state.apply_key_status(&status).unwrap();
        let next = LocalSigningKey::from_seed_hex(NEXT_SEED).unwrap();
        let recovery = state
            .create_recovery_rotation(&root, &next, "2026-08-23T00:31:00Z")
            .unwrap();
        assert!(recovery.previous_signature.is_none());
        state.apply_rotation(&recovery).unwrap();
        assert_eq!(state.current_key_id, next.key_id());
    }

    #[test]
    fn compromised_peer_never_bypasses_prime_directive() {
        let (root, operational, mut state) = identity();
        let env = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        let signed = sign_envelope(&state, &operational, env).unwrap();
        assert_eq!(
            verify_signed_envelope(&signed, &state, VALID_NOW, DEFAULT_CLOCK_POLICY)
                .unwrap()
                .signature,
            SignatureValidity::Valid
        );
        let status = state
            .create_key_status_record(
                &root,
                &operational.key_id(),
                KeyStatusKind::Compromised,
                "2026-08-23T00:01:00Z",
                KeyStatusReason::ConfirmedCompromise,
            )
            .unwrap();
        state.apply_key_status(&status).unwrap();
        assert_eq!(
            verify_signed_envelope(&signed, &state, VALID_NOW, DEFAULT_CLOCK_POLICY)
                .unwrap()
                .signature,
            SignatureValidity::Compromised
        );
        assert!(matches!(
            admit_effect(FederationEffect::MutateLocalGovernance),
            AdmissionDecision::Reject { .. }
        ));
    }

    #[test]
    fn signed_envelope_rejects_algorithm_confusion_and_tampering() {
        let (_root, operational, state) = identity();
        let env = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        let signed = sign_envelope(&state, &operational, env).unwrap();
        let wire = String::from_utf8(signed.to_wire().unwrap()).unwrap();
        assert!(serde_json::from_str::<SignedEnvelope>(
            &wire.replace("\"ed25519\"", "\"ed25519ph\"")
        )
        .is_err());
        let mut tampered = signed.clone();
        tampered.signature.replace_range(0..2, "00");
        assert_eq!(
            verify_signed_envelope(&tampered, &state, VALID_NOW, DEFAULT_CLOCK_POLICY)
                .unwrap()
                .signature,
            SignatureValidity::Invalid
        );
    }

    #[test]
    fn clock_policy_rejects_missing_expiry_and_excessive_lifetime() {
        let (_root, operational, state) = identity();
        let mut missing = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:05:00Z",
        );
        missing.expires_at = None;
        let canonical = canonical_json(&missing).unwrap();
        missing.message_id = derive_message_id(&canonical).unwrap();
        let signed = sign_envelope(&state, &operational, missing).unwrap();
        assert_eq!(
            verify_signed_envelope(&signed, &state, VALID_NOW, DEFAULT_CLOCK_POLICY)
                .unwrap()
                .signature,
            SignatureValidity::ClockRejected
        );
        let long = envelope(
            &state,
            "2026-08-23T00:00:00Z",
            "2026-08-23T02:00:00Z",
        );
        let signed = sign_envelope(&state, &operational, long).unwrap();
        assert_eq!(
            verify_signed_envelope(&signed, &state, VALID_NOW, DEFAULT_CLOCK_POLICY)
                .unwrap()
                .signature,
            SignatureValidity::ClockRejected
        );
    }

    #[test]
    fn rotation_previous_signature_is_required_nullable() {
        let (root, operational, state) = identity();
        let next = LocalSigningKey::from_seed_hex(NEXT_SEED).unwrap();
        let rotation = state
            .create_transition_rotation(
                &root,
                &operational,
                &next,
                "2026-08-23T01:00:00Z",
                "2026-08-23T02:00:00Z",
            )
            .unwrap();
        let mut value = serde_json::to_value(rotation).unwrap();
        value.as_object_mut().unwrap().remove("previous_signature");
        assert!(serde_json::from_value::<KeyRotationRecord>(value).is_err());
    }
}
