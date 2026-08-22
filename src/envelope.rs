use serde::{Deserialize, Deserializer, Serialize};

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

/// Deserialize an explicitly present nullable string.
///
/// `Option<T>` fields normally treat an omitted key as `None`. The Federation
/// schema deliberately distinguishes omission from an explicit JSON `null`, so
/// applying this deserializer without `#[serde(default)]` makes absence an error
/// while preserving `null -> None`.
fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
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
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provenance_ref: Option<String>,
    pub issued_at: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub expires_at: Option<String>,
    pub authority_claim: AuthorityClaim,
    #[serde(deserialize_with = "deserialize_required_nullable")]
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
        assert_eq!(envelope.provenance_ref, None);
        assert_eq!(envelope.expires_at, None);
        assert_eq!(envelope.signature, None);
    }

    #[test]
    fn schema_required_nullable_fields_must_be_present() {
        for field in ["provenance_ref", "expires_at", "signature"] {
            let mut value: serde_json::Value =
                serde_json::from_str(sample_envelope_json()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            let omitted = serde_json::to_string(&value).unwrap();

            assert!(
                serde_json::from_str::<FederationEnvelope>(&omitted).is_err(),
                "omitted required nullable field unexpectedly accepted: {field}"
            );
        }
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
