//! Phase 5C live-local QSOL-ORACLE transport consumer.
//!
//! The adapter runs only the reviewed donor `tools/fed_transport.py serve` entrypoint
//! from a release-fingerprint-attested local QSOL-ORACLE tree. It accepts no caller-
//! supplied command, URL, socket, tool, or shell fragment.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::canonical::canonicalize;
#[cfg(test)]
use crate::canonical::MAX_INPUT_BYTES;
use crate::qsol_adapters::OracleEvidenceObservation;
#[cfg(test)]
use crate::qsol_adapters::OracleEvidenceState;

pub const ORACLE_PINNED_REPOSITORY: &str = "QSOLKCB/QSOL-ORACLE";
pub const ORACLE_PINNED_COMMIT: &str = "043e864b3c25dfeca3ce1752b3110479479071b1";
pub const ORACLE_RELEASE_FINGERPRINT_SHA256: &str =
    "7b0eff4dfa9b0caa84f14920d21f6a5446114535d82706cb62e34773c39818d2";
pub const ORACLE_TRANSPORT_PROTOCOL: &str = "QSOL-ORACLE-FED/1";
pub const ORACLE_REQUEST_KIND: &str = "evidence.export";
pub const ORACLE_RESPONSE_KIND: &str = "evidence.export.result";
pub const ORACLE_TRANSPORT_MAX_LINE_BYTES: usize = 65_536;

const ORACLE_TRANSPORT_SCRIPT_SHA256: &str =
    "d05ef2904dff775e70fcc0ee97780d69eac10d56f3cbb50c23dc4ecf6affb77d";
const ORACLE_MEMBRANE_SHA256: &str =
    "fd74c8fdfcf53882a920432d7bb8be2cedc8e00a6283f7f73af7847f6dc5454a";
const ORACLE_REQUEST_SCHEMA_SHA256: &str =
    "6e64bbb883d293e41c2bba07ba6bf84c4f431fd361c2fa4ebe6fe3b28f4395a4";
const ORACLE_RESPONSE_SCHEMA_SHA256: &str =
    "16c07a3bb8767bb4d08294d12d1f1367ae04d6bd3c9205b70d504da971c3e747";
const ORACLE_OBSERVATION_SCHEMA_SHA256: &str =
    "9f7a3c40d73d9c1f39f869831f250f483eaf1137c2169ff65b5f29d4108bb497";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleLiveError(pub String);

impl std::fmt::Display for OracleLiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OracleLiveError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct OracleTransportQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleResearchRequirementKind {
    PrimarySource,
    CurrentState,
    Identity,
    Provenance,
    ConflictResolution,
    Execution,
    Scope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleResearchRequirement {
    pub id: String,
    pub kind: OracleResearchRequirementKind,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleResearchRequest {
    pub subject: String,
    pub question: String,
    pub requirements: Vec<OracleResearchRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleTransportRequest {
    pub protocol: String,
    pub kind: String,
    pub request_id: String,
    pub query: OracleTransportQuery,
    pub research: Option<OracleResearchRequest>,
    pub synthetic_input: bool,
    pub evidence_promotion_requested: bool,
    pub authority_requested: bool,
    pub remote_execution_requested: bool,
}

impl OracleTransportRequest {
    pub fn new(request_id: impl Into<String>, query: OracleTransportQuery) -> Self {
        Self {
            protocol: ORACLE_TRANSPORT_PROTOCOL.into(),
            kind: ORACLE_REQUEST_KIND.into(),
            request_id: request_id.into(),
            query,
            research: None,
            synthetic_input: false,
            evidence_promotion_requested: false,
            authority_requested: false,
            remote_execution_requested: false,
        }
    }

    pub fn validate(&self) -> Result<(), OracleLiveError> {
        if self.protocol != ORACLE_TRANSPORT_PROTOCOL
            || self.kind != ORACLE_REQUEST_KIND
            || !bounded_chars(&self.request_id, 256)
            || self.synthetic_input
            || self.evidence_promotion_requested
            || self.authority_requested
            || self.remote_execution_requested
        {
            return Err(OracleLiveError("oracle_transport_request_boundary_invalid".into()));
        }
        for value in [
            self.query.subject.as_deref(),
            self.query.event_type.as_deref(),
            self.query.provenance_kind.as_deref(),
            self.query.evidence_state.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !bounded_chars(value, 512) {
                return Err(OracleLiveError("oracle_transport_query_text_invalid".into()));
            }
        }
        if let Some(hash) = &self.query.event_hash {
            if !is_lower_sha256(hash) {
                return Err(OracleLiveError("oracle_transport_event_hash_invalid".into()));
            }
        }
        if let Some(limit) = self.query.limit {
            if !(1..=256).contains(&limit) {
                return Err(OracleLiveError("oracle_transport_query_limit_invalid".into()));
            }
        }
        if let Some(research) = &self.research {
            if !bounded_chars(&research.subject, 4_096)
                || !bounded_chars(&research.question, 4_096)
                || research.requirements.is_empty()
                || research.requirements.len() > 64
                || !research.requirements.iter().any(|requirement| !requirement.satisfied)
            {
                return Err(OracleLiveError("oracle_transport_research_invalid".into()));
            }
            let mut ids = HashSet::new();
            for requirement in &research.requirements {
                let id: String = requirement.id.nfc().collect();
                if !bounded_chars(&id, 256)
                    || !bounded_chars(&requirement.detail, 4_096)
                    || !ids.insert(id)
                {
                    return Err(OracleLiveError(
                        "oracle_transport_research_requirement_invalid".into(),
                    ));
                }
            }
        }
        let _ = canonical_struct(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleTransportResponse {
    pub protocol: String,
    pub kind: String,
    pub request_id: String,
    pub observation: OracleEvidenceObservation,
    pub total_matches: u64,
    pub returned: u16,
    pub truncated: bool,
    pub source_events_sha256: String,
    pub ledger_mutated: bool,
    pub transport_authority: String,
    pub response_sha256: String,
}

impl OracleTransportResponse {
    pub fn validate_for_request(&self, request_id: &str) -> Result<(), OracleLiveError> {
        if self.protocol != ORACLE_TRANSPORT_PROTOCOL
            || self.kind != ORACLE_RESPONSE_KIND
            || self.request_id != request_id
            || !bounded_chars(&self.request_id, 256)
            || self.returned > 256
            || u64::from(self.returned) > self.total_matches
            || self.truncated != (self.total_matches > u64::from(self.returned))
            || !is_lower_sha256(&self.source_events_sha256)
            || self.ledger_mutated
            || self.transport_authority != "none"
            || !is_lower_sha256(&self.response_sha256)
        {
            return Err(OracleLiveError("oracle_transport_response_boundary_invalid".into()));
        }
        self.observation
            .validate()
            .map_err(|error| OracleLiveError(error.0))?;
        if self.observation.evidence_refs.len() != usize::from(self.returned) {
            return Err(OracleLiveError("oracle_transport_reference_count_mismatch".into()));
        }
        for reference in &self.observation.evidence_refs {
            let Some(hash) = reference.reference.strip_prefix("oracle-event:") else {
                return Err(OracleLiveError("oracle_transport_evidence_ref_invalid".into()));
            };
            if !is_lower_sha256(hash) {
                return Err(OracleLiveError("oracle_transport_evidence_ref_invalid".into()));
            }
        }
        let mut payload = serde_json::to_value(self)
            .map_err(|_| OracleLiveError("oracle_transport_response_serialize_failed".into()))?;
        let object = payload
            .as_object_mut()
            .ok_or_else(|| OracleLiveError("oracle_transport_response_not_object".into()))?;
        object.remove("response_sha256");
        let digest = sha256_hex(&canonical_json_value(&payload)?);
        if digest != self.response_sha256 {
            return Err(OracleLiveError("oracle_transport_response_digest_mismatch".into()));
        }
        let _ = canonical_struct(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseFileRecord {
    bytes: u64,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OracleReleaseFingerprint {
    authority: String,
    files: Vec<ReleaseFileRecord>,
    release_fingerprint_sha256: String,
    protocol: String,
    truth_claim: bool,
}

#[derive(Debug, Clone)]
pub struct OracleLiveAdapter {
    oracle_root: PathBuf,
}

impl OracleLiveAdapter {
    pub fn open(oracle_root: impl AsRef<Path>) -> Result<Self, OracleLiveError> {
        let oracle_root = oracle_root.as_ref().to_path_buf();
        attest_oracle_release(&oracle_root)?;
        Ok(Self { oracle_root })
    }

    pub fn request(
        &self,
        request: &OracleTransportRequest,
    ) -> Result<OracleTransportResponse, OracleLiveError> {
        request.validate()?;
        let request_bytes = canonical_struct(request)?;
        if request_bytes.len() > ORACLE_TRANSPORT_MAX_LINE_BYTES {
            return Err(OracleLiveError("oracle_transport_request_too_large".into()));
        }

        let mut child = Command::new("python3")
            .arg("tools/fed_transport.py")
            .arg("serve")
            .current_dir(&self.oracle_root)
            .env_remove("PYTHONPATH")
            .env_remove("PYTHONHOME")
            .env("PYTHONNOUSERSITE", "1")
            .env("PYTHONSAFEPATH", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| OracleLiveError("oracle_transport_spawn_failed".into()))?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| OracleLiveError("oracle_transport_stdin_unavailable".into()))?;
            stdin
                .write_all(&request_bytes)
                .and_then(|_| stdin.write_all(b"\n"))
                .map_err(|_| OracleLiveError("oracle_transport_stdin_write_failed".into()))?;
        }
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|_| OracleLiveError("oracle_transport_wait_failed".into()))?;
        if !output.status.success() {
            return Err(OracleLiveError("oracle_transport_process_rejected_request".into()));
        }
        if output.stdout.is_empty()
            || output.stdout.len() > ORACLE_TRANSPORT_MAX_LINE_BYTES + 1
            || !output.stdout.ends_with(b"\n")
        {
            return Err(OracleLiveError("oracle_transport_stdout_framing_invalid".into()));
        }
        let raw = &output.stdout[..output.stdout.len() - 1];
        if raw.contains(&b'\n')
            || canonicalize(raw)
                .map_err(|_| OracleLiveError("oracle_transport_noncanonical_response".into()))?
                != raw
        {
            return Err(OracleLiveError("oracle_transport_noncanonical_response".into()));
        }
        let response: OracleTransportResponse = serde_json::from_slice(raw)
            .map_err(|_| OracleLiveError("oracle_transport_response_parse_failed".into()))?;
        response.validate_for_request(&request.request_id)?;
        Ok(response)
    }
}

pub fn attest_oracle_release(root: &Path) -> Result<(), OracleLiveError> {
    let fingerprint_path = root.join("release/fingerprint.json");
    let raw = fs::read(&fingerprint_path)
        .map_err(|_| OracleLiveError("oracle_release_fingerprint_missing".into()))?;
    let fingerprint: OracleReleaseFingerprint = serde_json::from_slice(&raw)
        .map_err(|_| OracleLiveError("oracle_release_fingerprint_invalid".into()))?;
    if fingerprint.protocol != "QSOL-ORACLE-RELEASE/1"
        || fingerprint.authority != "integrity-only"
        || fingerprint.truth_claim
        || fingerprint.release_fingerprint_sha256 != ORACLE_RELEASE_FINGERPRINT_SHA256
    {
        return Err(OracleLiveError("oracle_release_fingerprint_identity_drift".into()));
    }
    if fingerprint.files.is_empty() {
        return Err(OracleLiveError("oracle_release_fingerprint_empty".into()));
    }

    let mut critical = HashSet::new();
    for record in &fingerprint.files {
        let relative = Path::new(&record.path);
        if !safe_relative_path(relative) || !is_lower_sha256(&record.sha256) {
            return Err(OracleLiveError("oracle_release_fingerprint_path_invalid".into()));
        }
        let bytes = fs::read(root.join(relative))
            .map_err(|_| OracleLiveError("oracle_release_fingerprint_file_missing".into()))?;
        if bytes.len() as u64 != record.bytes || sha256_hex(&bytes) != record.sha256 {
            return Err(OracleLiveError("oracle_release_fingerprint_file_mismatch".into()));
        }
        match record.path.as_str() {
            "tools/fed_transport.py" if record.sha256 == ORACLE_TRANSPORT_SCRIPT_SHA256 => {
                critical.insert("transport");
            }
            "contracts/fed-membrane.json" if record.sha256 == ORACLE_MEMBRANE_SHA256 => {
                critical.insert("contract");
            }
            "schema/fed-transport-request.schema.json"
                if record.sha256 == ORACLE_REQUEST_SCHEMA_SHA256 =>
            {
                critical.insert("request_schema");
            }
            "schema/fed-transport-response.schema.json"
                if record.sha256 == ORACLE_RESPONSE_SCHEMA_SHA256 =>
            {
                critical.insert("response_schema");
            }
            "schema/fed-oracle-observation.schema.json"
                if record.sha256 == ORACLE_OBSERVATION_SCHEMA_SHA256 =>
            {
                critical.insert("observation_schema");
            }
            _ => {}
        }
    }
    if critical.len() != 5 {
        return Err(OracleLiveError("oracle_release_critical_pin_missing".into()));
    }

    let contract: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("contracts/fed-membrane.json"))
            .map_err(|_| OracleLiveError("oracle_membrane_contract_missing".into()))?,
    )
    .map_err(|_| OracleLiveError("oracle_membrane_contract_invalid".into()))?;
    if contract.pointer("/protocol").and_then(|value| value.as_str())
        != Some(ORACLE_TRANSPORT_PROTOCOL)
        || contract
            .pointer("/consumer_pin/repository")
            .and_then(|value| value.as_str())
            != Some("QSOLKCB/QSOL-FED")
        || contract
            .pointer("/consumer_pin/commit")
            .and_then(|value| value.as_str())
            != Some("407d0ed75c7d8a76bd49b3c30e74a0ae2c59f1e6")
        || contract
            .pointer("/observation/synthetic_input")
            .and_then(|value| value.as_bool())
            != Some(false)
        || contract
            .pointer("/observation/evidence_promotion")
            .and_then(|value| value.as_bool())
            != Some(false)
        || contract
            .pointer("/observation/authority_effect")
            .and_then(|value| value.as_str())
            != Some("none")
    {
        return Err(OracleLiveError("oracle_membrane_contract_boundary_drift".into()));
    }
    Ok(())
}

fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, OracleLiveError> {
    let raw = serde_json::to_vec(value)
        .map_err(|_| OracleLiveError("oracle_transport_serialize_failed".into()))?;
    canonicalize(&raw).map_err(|_| OracleLiveError("oracle_transport_canonicalization_failed".into()))
}

fn canonical_json_value(value: &serde_json::Value) -> Result<Vec<u8>, OracleLiveError> {
    let raw = serde_json::to_vec(value)
        .map_err(|_| OracleLiveError("oracle_transport_serialize_failed".into()))?;
    canonicalize(&raw).map_err(|_| OracleLiveError("oracle_transport_canonicalization_failed".into()))
}

fn bounded_chars(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.chars().count() <= maximum
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_requests_keep_authority_flags_false_and_canonical() {
        let request = OracleTransportRequest::new(
            "oracle-live-test",
            OracleTransportQuery {
                event_hash: Some(
                    "80468db2bf709982ce4eead9de02ba088306fd365dc999f860139e51987ed8ad"
                        .into(),
                ),
                limit: Some(1),
                ..OracleTransportQuery::default()
            },
        );
        request.validate().unwrap();
        let bytes = canonical_struct(&request).unwrap();
        assert!(bytes.len() <= MAX_INPUT_BYTES);
        assert!(!request.synthetic_input);
        assert!(!request.evidence_promotion_requested);
        assert!(!request.authority_requested);
        assert!(!request.remote_execution_requested);
    }

    #[test]
    fn research_missing_evidence_is_explicit_and_bounded() {
        let mut request = OracleTransportRequest::new("research", OracleTransportQuery::default());
        request.research = Some(OracleResearchRequest {
            subject: "subject".into(),
            question: "question".into(),
            requirements: vec![OracleResearchRequirement {
                id: "primary".into(),
                kind: OracleResearchRequirementKind::PrimarySource,
                satisfied: false,
                detail: "primary source has not been observed".into(),
            }],
        });
        request.validate().unwrap();
    }

    #[test]
    fn live_response_rejects_non_oracle_event_reference() {
        let response = OracleTransportResponse {
            protocol: ORACLE_TRANSPORT_PROTOCOL.into(),
            kind: ORACLE_RESPONSE_KIND.into(),
            request_id: "x".into(),
            observation: OracleEvidenceObservation {
                schema: "qsol-fed-oracle-observation/1".into(),
                state: OracleEvidenceState::Known,
                evidence_refs: vec![crate::qsol_adapters::OracleEvidenceReference {
                    reference: format!("sha256:{}", "1".repeat(64)),
                    is_evidence: true,
                }],
                suggested_searches: vec![],
                synthetic_input: false,
                truth_claim: false,
                evidence_promotion: false,
                authority_effect: "none".into(),
            },
            total_matches: 1,
            returned: 1,
            truncated: false,
            source_events_sha256: "2".repeat(64),
            ledger_mutated: false,
            transport_authority: "none".into(),
            response_sha256: "3".repeat(64),
        };
        assert!(matches!(
            response.validate_for_request("x"),
            Err(OracleLiveError(message)) if message == "oracle_transport_evidence_ref_invalid"
        ));
    }
}
