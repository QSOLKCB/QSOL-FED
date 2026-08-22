use serde::{Deserialize, Serialize};

use crate::invariants::PROTOCOL_ID;

/// Bootstrap authority claim. There is intentionally only one representable value.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEnvelope {
    pub protocol: String,
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub message_class: MessageClass,
    pub payload_ref: String,
    pub provenance_ref: Option<String>,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub authority_claim: AuthorityClaim,
    pub signature: Option<String>,
}

impl FederationEnvelope {
    pub fn has_bootstrap_protocol(&self) -> bool {
        self.protocol == PROTOCOL_ID
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
        r#"{
            "protocol":"qsol-fed/0",
            "message_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sender":"fed:qsol:alice",
            "recipient":"fed:qsol:bob",
            "message_class":"council.report",
            "payload_ref":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "provenance_ref":null,
            "issued_at":"2026-08-22T00:00:00Z",
            "expires_at":null,
            "authority_claim":"none",
            "signature":null
        }"#
    }

    #[test]
    fn bootstrap_envelope_parses() {
        let envelope: FederationEnvelope = serde_json::from_str(sample_envelope_json()).unwrap();
        assert!(envelope.has_bootstrap_protocol());
        assert_eq!(envelope.authority_claim, AuthorityClaim::None);
        assert_eq!(envelope.message_class, MessageClass::CouncilReport);
    }

    #[test]
    fn remote_authority_claim_is_unrepresentable() {
        let hostile = sample_envelope_json().replace(
            "\"authority_claim\":\"none\"",
            "\"authority_claim\":\"local_root\"",
        );
        assert!(serde_json::from_str::<FederationEnvelope>(&hostile).is_err());
    }

    #[test]
    fn unknown_message_class_fails_closed() {
        let hostile = sample_envelope_json().replace(
            "\"message_class\":\"council.report\"",
            "\"message_class\":\"governance.override\"",
        );
        assert!(serde_json::from_str::<FederationEnvelope>(&hostile).is_err());
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let hostile = sample_envelope_json().replace(
            "\"signature\":null",
            "\"signature\":null,\"force\":true",
        );
        assert!(serde_json::from_str::<FederationEnvelope>(&hostile).is_err());
    }
}
