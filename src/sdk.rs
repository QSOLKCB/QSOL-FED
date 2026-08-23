//! Phase 6 minimal governance-neutral federation SDK.
//!
//! This module deliberately exposes protocol construction and validation only.
//! It does not expose QSOL governance, NEXUS Council semantics, ORACLE authority,
//! ARK archival semantics, Holodeck state, trust mutation, or capability installation.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{canonicalize, derive_message_id, object_id, CanonicalError};
use crate::envelope::FederationEnvelope;
use crate::wire::{
    classify_protocol, is_capability_id, is_node_id, is_sha256_ref, is_wire_timestamp,
    ProtocolDisposition, ProvenanceObject,
};

pub const SDK_CONTRACT_V1: &str = "qsol-fed-sdk/1";
pub const THIRD_PARTY_PROFILE_V1: &str = "third-party-node-profile/1";
pub const BOOTSTRAP_PROTOCOL: &str = "qsol-fed/0";
pub const WIRE_PROTOCOL: &str = "qsol-fed/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkError(pub String);

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SdkError {}

impl From<CanonicalError> for SdkError {
    fn from(value: CanonicalError) -> Self {
        Self(value.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SdkNodeManifest {
    pub protocol: String,
    pub node_id: String,
    pub capabilities: Vec<String>,
    pub authority_claim: String,
}

impl SdkNodeManifest {
    pub fn validate(&self) -> Result<(), SdkError> {
        let mut capabilities = HashSet::new();
        if self.protocol != BOOTSTRAP_PROTOCOL
            || !is_node_id(&self.node_id)
            || self.capabilities.len() > 64
            || self.authority_claim != "none"
            || !self
                .capabilities
                .iter()
                .all(|capability| is_capability_id(capability) && capabilities.insert(capability))
        {
            return Err(SdkError("sdk_node_manifest_invalid".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyNodeProfile {
    pub schema: String,
    pub implementation: String,
    pub governance_model: String,
    pub qsol_governance_adopted: bool,
    pub nexus_required: bool,
    pub council_required: bool,
}

impl ThirdPartyNodeProfile {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.schema != THIRD_PARTY_PROFILE_V1
            || self.implementation.is_empty()
            || self.implementation.len() > 128
            || self.governance_model != "local"
            || self.qsol_governance_adopted
            || self.nexus_required
            || self.council_required
        {
            return Err(SdkError("third_party_profile_invalid".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SdkEnvelopeInput {
    pub sender: String,
    pub recipient: String,
    pub message_class: String,
    pub payload_ref: String,
    pub provenance_ref: Option<String>,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

impl SdkEnvelopeInput {
    pub fn validate(&self) -> Result<(), SdkError> {
        const CLASSES: &[&str] = &[
            "hello",
            "capabilities",
            "evidence.offer",
            "evidence.request",
            "hypothesis",
            "challenge",
            "response",
            "council.report",
            "minority.report",
            "experiment.receipt",
            "citation",
            "publication",
        ];
        if !is_node_id(&self.sender)
            || !is_node_id(&self.recipient)
            || !CLASSES.contains(&self.message_class.as_str())
            || !is_sha256_ref(&self.payload_ref)
            || self.provenance_ref.as_deref().is_some_and(|value| !is_sha256_ref(value))
            || !is_wire_timestamp(&self.issued_at)
            || self.expires_at.as_deref().is_some_and(|value| !is_wire_timestamp(value))
        {
            return Err(SdkError("sdk_envelope_input_invalid".into()));
        }
        Ok(())
    }
}

pub fn sdk_canonicalize<T: Serialize>(value: &T) -> Result<String, SdkError> {
    let raw = serde_json::to_vec(value).map_err(|_| SdkError("sdk_serialize_failed".into()))?;
    let canonical = canonicalize(&raw)?;
    String::from_utf8(canonical).map_err(|_| SdkError("sdk_canonical_utf8_invalid".into()))
}

pub fn sdk_object_id<T: Serialize>(value: &T) -> Result<String, SdkError> {
    let raw = serde_json::to_vec(value).map_err(|_| SdkError("sdk_serialize_failed".into()))?;
    Ok(object_id(&raw)?)
}

pub fn sdk_classify_protocol(protocol: &str) -> ProtocolDisposition {
    classify_protocol(protocol)
}

pub fn sdk_validate_capability_id(capability: &str) -> bool {
    is_capability_id(capability)
}

pub fn sdk_build_node_manifest(
    node_id: impl Into<String>,
    capabilities: Vec<String>,
) -> Result<SdkNodeManifest, SdkError> {
    let manifest = SdkNodeManifest {
        protocol: BOOTSTRAP_PROTOCOL.into(),
        node_id: node_id.into(),
        capabilities,
        authority_claim: "none".into(),
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn sdk_build_provenance(provenance: ProvenanceObject) -> Result<ProvenanceObject, SdkError> {
    if !provenance.validate() {
        return Err(SdkError("sdk_provenance_invalid".into()));
    }
    Ok(provenance)
}

pub fn sdk_build_unsigned_envelope(input: &SdkEnvelopeInput) -> Result<Vec<u8>, SdkError> {
    input.validate()?;
    let mut value = json!({
        "protocol": WIRE_PROTOCOL,
        "message_id": format!("sha256:{}", "0".repeat(64)),
        "sender": input.sender,
        "recipient": input.recipient,
        "message_class": input.message_class,
        "payload_ref": input.payload_ref,
        "provenance_ref": input.provenance_ref,
        "issued_at": input.issued_at,
        "expires_at": input.expires_at,
        "authority_claim": "none",
        "signature": null
    });
    let provisional = canonicalize(
        &serde_json::to_vec(&value).map_err(|_| SdkError("sdk_serialize_failed".into()))?,
    )?;
    let message_id = derive_message_id(&provisional)?;
    value["message_id"] = Value::String(message_id);
    let canonical = canonicalize(
        &serde_json::to_vec(&value).map_err(|_| SdkError("sdk_serialize_failed".into()))?,
    )?;
    FederationEnvelope::from_wire(&canonical)?;
    Ok(canonical)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Phase6Fixture {
    schema: String,
    wire_protocol: String,
    node_manifest: SdkNodeManifest,
    third_party_profile: ThirdPartyNodeProfile,
    payload: Value,
    provenance: ProvenanceObject,
    hello: SdkEnvelopeInput,
    evidence_offer: SdkEnvelopeInput,
    expected: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Phase6ConformanceResult {
    pub schema: String,
    pub implementation: String,
    pub node_manifest_canonical: String,
    pub node_manifest_object_id: String,
    pub profile_canonical: String,
    pub profile_object_id: String,
    pub payload_canonical: String,
    pub payload_object_id: String,
    pub provenance_canonical: String,
    pub provenance_object_id: String,
    pub hello_canonical: String,
    pub hello_message_id: String,
    pub evidence_canonical: String,
    pub evidence_message_id: String,
    pub qsol_governance_adopted: bool,
    pub nexus_required: bool,
    pub council_required: bool,
    pub authority_effect: String,
}

pub fn phase6_conformance_from_fixture(
    fixture_json: &str,
    implementation: &str,
) -> Result<Phase6ConformanceResult, SdkError> {
    let fixture: Phase6Fixture = serde_json::from_str(fixture_json)
        .map_err(|_| SdkError("phase6_fixture_invalid".into()))?;
    if fixture.schema != "qsol-fed-sdk-conformance/1" || fixture.wire_protocol != WIRE_PROTOCOL {
        return Err(SdkError("phase6_fixture_contract_invalid".into()));
    }
    fixture.node_manifest.validate()?;
    fixture.third_party_profile.validate()?;
    if sdk_classify_protocol(&fixture.wire_protocol) != ProtocolDisposition::Supported {
        return Err(SdkError("phase6_protocol_not_supported".into()));
    }
    let node_manifest_canonical = sdk_canonicalize(&fixture.node_manifest)?;
    let node_manifest_object_id = sdk_object_id(&fixture.node_manifest)?;
    let profile_canonical = sdk_canonicalize(&fixture.third_party_profile)?;
    let profile_object_id = sdk_object_id(&fixture.third_party_profile)?;
    let payload_canonical = sdk_canonicalize(&fixture.payload)?;
    let payload_object_id = sdk_object_id(&fixture.payload)?;
    let provenance = sdk_build_provenance(fixture.provenance)?;
    let provenance_canonical = sdk_canonicalize(&provenance)?;
    let provenance_object_id = sdk_object_id(&provenance)?;
    let hello = sdk_build_unsigned_envelope(&fixture.hello)?;
    let evidence = sdk_build_unsigned_envelope(&fixture.evidence_offer)?;
    let hello_envelope = FederationEnvelope::from_wire(&hello)?;
    let evidence_envelope = FederationEnvelope::from_wire(&evidence)?;

    let result = Phase6ConformanceResult {
        schema: "qsol-fed-sdk-conformance-result/1".into(),
        implementation: implementation.into(),
        node_manifest_canonical,
        node_manifest_object_id,
        profile_canonical,
        profile_object_id,
        payload_canonical,
        payload_object_id,
        provenance_canonical,
        provenance_object_id,
        hello_canonical: String::from_utf8(hello).map_err(|_| SdkError("sdk_utf8".into()))?,
        hello_message_id: hello_envelope.message_id,
        evidence_canonical: String::from_utf8(evidence)
            .map_err(|_| SdkError("sdk_utf8".into()))?,
        evidence_message_id: evidence_envelope.message_id,
        qsol_governance_adopted: fixture.third_party_profile.qsol_governance_adopted,
        nexus_required: fixture.third_party_profile.nexus_required,
        council_required: fixture.third_party_profile.council_required,
        authority_effect: "none".into(),
    };

    let expected = fixture
        .expected
        .as_object()
        .ok_or_else(|| SdkError("phase6_expected_invalid".into()))?;
    for (key, actual) in [
        ("node_manifest_canonical", &result.node_manifest_canonical),
        ("node_manifest_object_id", &result.node_manifest_object_id),
        ("profile_canonical", &result.profile_canonical),
        ("profile_object_id", &result.profile_object_id),
        ("payload_canonical", &result.payload_canonical),
        ("payload_object_id", &result.payload_object_id),
        ("provenance_canonical", &result.provenance_canonical),
        ("provenance_object_id", &result.provenance_object_id),
        ("hello_canonical", &result.hello_canonical),
        ("hello_message_id", &result.hello_message_id),
        ("evidence_canonical", &result.evidence_canonical),
        ("evidence_message_id", &result.evidence_message_id),
    ] {
        if expected.get(key).and_then(Value::as_str) != Some(actual.as_str()) {
            return Err(SdkError(format!("phase6_expected_mismatch:{key}")));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_node_fixture_matches_frozen_phase6_vectors() {
        let result = phase6_conformance_from_fixture(
            include_str!("../fixtures/phase6/conformance.json"),
            "rust",
        )
        .unwrap();
        assert_eq!(result.authority_effect, "none");
        assert!(!result.qsol_governance_adopted);
        assert!(!result.nexus_required);
        assert!(!result.council_required);
    }

    #[test]
    fn sdk_rejects_governance_adoption_as_third_party_fixture() {
        let profile = ThirdPartyNodeProfile {
            schema: THIRD_PARTY_PROFILE_V1.into(),
            implementation: "neutral".into(),
            governance_model: "local".into(),
            qsol_governance_adopted: true,
            nexus_required: false,
            council_required: false,
        };
        assert!(profile.validate().is_err());
    }

    #[test]
    fn sdk_does_not_reclassify_protocol_conformance_as_deployment() {
        assert_eq!(sdk_classify_protocol("qsol-fed/1"), ProtocolDisposition::Supported);
        assert_eq!(sdk_classify_protocol("qsol-fed/2"), ProtocolDisposition::UnsupportedMajor);
        assert!(sdk_validate_capability_id("federation.sdk/1"));
        assert!(!sdk_validate_capability_id("Council/Admin/1"));
    }
}
