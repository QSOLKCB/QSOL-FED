use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::{derive_message_id, CanonicalError};
use crate::wire::{
    is_node_id, is_sha256_ref, is_wire_timestamp, require_canonical_wire, PROTOCOL_V1,
};

/// Federation v1 authority claim. There is intentionally only one representable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClaim {
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageClass {
    #[serde(rename = "hello")]
    Hello,
    #[serde(rename = "capabilities")]
    Capabilities,
    #[serde(rename = "evidence.offer")]
    EvidenceOffer,
    #[serde(rename = "evidence.request")]
    EvidenceRequest,
    #[serde(rename = "hypothesis")]
    Hypothesis,
    #[serde(rename = "challenge")]
    Challenge,
    #[serde(rename = "response")]
    Response,
    #[serde(rename = "council.report")]
    CouncilReport,
    #[serde(rename = "minority.report")]
    MinorityReport,
    #[serde(rename = "experiment.receipt")]
    ExperimentReceipt,
    #[serde(rename = "citation")]
    Citation,
    #[serde(rename = "publication")]
    Publication,
}

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// Exact Phase 1 envelope shape. `signature` is required to be JSON null until Phase 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEnvelope {
    pub protocol: String,
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub message_class: MessageClass,
    pub payload_ref: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provenance_ref: Option<String>,
    pub issued_at: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub expires_at: Option<String>,
    pub authority_claim: AuthorityClaim,
    pub signature: (),
}

impl FederationEnvelope {
    pub fn has_supported_wire_protocol(&self) -> bool {
        self.protocol == PROTOCOL_V1
    }

    pub fn validate_shape(&self) -> bool {
        self.has_supported_wire_protocol()
            && is_sha256_ref(&self.message_id)
            && is_node_id(&self.sender)
            && is_node_id(&self.recipient)
            && is_sha256_ref(&self.payload_ref)
            && self.provenance_ref.as_deref().is_none_or(is_sha256_ref)
            && is_wire_timestamp(&self.issued_at)
            && self.expires_at.as_deref().is_none_or(is_wire_timestamp)
    }

    /// Require already-canonical wire bytes, validate the exact v1 shape, and
    /// verify the deterministic message identifier. This does not authenticate
    /// a sender and does not claim cryptographic identity.
    pub fn from_wire(raw: &[u8]) -> Result<Self, CanonicalError> {
        let canonical = require_canonical_wire(raw)?;
        let envelope: Self = serde_json::from_slice(&canonical)
            .map_err(|error| CanonicalError(format!("envelope_schema:{error}")))?;
        if !envelope.validate_shape() {
            return Err(CanonicalError("envelope_shape_invalid".into()));
        }
        let derived = derive_message_id(&canonical)?;
        if envelope.message_id != derived {
            return Err(CanonicalError("message_id_mismatch".into()));
        }
        Ok(envelope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeManifest {
    pub protocol: String,
    pub node_id: String,
    pub capabilities: Vec<String>,
    pub authority_claim: AuthorityClaim,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope_json() -> &'static str {
        r#"{"authority_claim":"none","expires_at":null,"issued_at":"2026-08-23T00:00:00Z","message_class":"council.report","message_id":"sha256:b577289b47aeb89de80d1c1253474e9eee4ef9c49743149f9ca5c5b27a9de2da","payload_ref":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocol":"qsol-fed/1","provenance_ref":null,"recipient":"fed:qsol:bob","sender":"fed:qsol:alice","signature":null}"#
    }

    #[test]
    fn exact_v1_envelope_parses_and_verifies_message_id() {
        let envelope = FederationEnvelope::from_wire(sample_envelope_json().as_bytes()).unwrap();
        assert!(envelope.has_supported_wire_protocol());
        assert_eq!(envelope.authority_claim, AuthorityClaim::None);
        assert_eq!(envelope.message_class, MessageClass::CouncilReport);
    }

    #[test]
    fn non_canonical_wire_bytes_are_rejected() {
        let pretty: serde_json::Value = serde_json::from_str(sample_envelope_json()).unwrap();
        let noncanonical = serde_json::to_string_pretty(&pretty).unwrap();
        assert!(FederationEnvelope::from_wire(noncanonical.as_bytes()).is_err());

        let unsorted = r#"{"protocol":"qsol-fed/1","authority_claim":"none","expires_at":null,"issued_at":"2026-08-23T00:00:00Z","message_class":"council.report","message_id":"sha256:b577289b47aeb89de80d1c1253474e9eee4ef9c49743149f9ca5c5b27a9de2da","payload_ref":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provenance_ref":null,"recipient":"fed:qsol:bob","sender":"fed:qsol:alice","signature":null}"#;
        assert!(FederationEnvelope::from_wire(unsorted.as_bytes()).is_err());
    }

    #[test]
    fn required_nullable_fields_must_be_present() {
        for field in ["provenance_ref", "expires_at"] {
            let mut value: serde_json::Value = serde_json::from_str(sample_envelope_json()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            let omitted = serde_json::to_vec(&value).unwrap();
            assert!(FederationEnvelope::from_wire(&omitted).is_err());
        }
    }

    #[test]
    fn signature_must_remain_null_before_phase2() {
        let hostile = sample_envelope_json().replace("\"signature\":null", "\"signature\":\"fake\"");
        assert!(FederationEnvelope::from_wire(hostile.as_bytes()).is_err());
    }

    #[test]
    fn unsupported_major_fails_closed() {
        let hostile = sample_envelope_json().replace("qsol-fed/1", "qsol-fed/2");
        assert!(FederationEnvelope::from_wire(hostile.as_bytes()).is_err());
    }

    #[test]
    fn hostile_authority_and_unknown_fields_fail_closed() {
        let authority = sample_envelope_json().replace("\"authority_claim\":\"none\"", "\"authority_claim\":\"local_root\"");
        assert!(FederationEnvelope::from_wire(authority.as_bytes()).is_err());

        let unknown = sample_envelope_json().replace("\"signature\":null", "\"signature\":null,\"force\":true");
        assert!(FederationEnvelope::from_wire(unknown.as_bytes()).is_err());
    }
}
