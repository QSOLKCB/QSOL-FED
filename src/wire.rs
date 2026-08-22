use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, derive_message_id, CanonicalError};

pub const PROTOCOL_V1: &str = "qsol-fed/1";
pub const PROVENANCE_SCHEMA_V1: &str = "qsol-fed-provenance/1";
pub const ERROR_SCHEMA_V1: &str = "qsol-fed-error/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolDisposition {
    Supported,
    UnsupportedMajor,
}

pub fn classify_protocol(protocol: &str) -> ProtocolDisposition {
    if protocol == PROTOCOL_V1 {
        ProtocolDisposition::Supported
    } else {
        ProtocolDisposition::UnsupportedMajor
    }
}

pub fn is_sha256_ref(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn is_node_id(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("fed:qsol:") else {
        return false;
    };
    if tail.is_empty() || tail.len() > 128 {
        return false;
    }
    let bytes = tail.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(*byte, b'.' | b'_' | b'-')
    })
}

pub fn is_capability_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 96 {
        return false;
    }
    let Some((name, version)) = value.rsplit_once('/') else {
        return false;
    };
    if version.is_empty() || version.starts_with('0') || !version.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut segments = name.split(['.', '-']);
    let Some(first) = segments.next() else {
        return false;
    };
    fn valid_segment(segment: &str, first: bool) -> bool {
        if segment.is_empty() {
            return false;
        }
        let mut bytes = segment.bytes();
        let Some(head) = bytes.next() else {
            return false;
        };
        if first && !head.is_ascii_lowercase() {
            return false;
        }
        if !head.is_ascii_lowercase() && !head.is_ascii_digit() {
            return false;
        }
        bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }
    if !valid_segment(first, true) {
        return false;
    }
    segments.all(|segment| valid_segment(segment, false))
}

pub fn is_wire_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16 | 19) {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRelation {
    Observed,
    Derived,
    Quoted,
    Transported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceObject {
    pub schema: String,
    pub source_node: String,
    pub source_object: String,
    pub relation: ProvenanceRelation,
    pub parents: Vec<String>,
    pub created_at: String,
}

impl ProvenanceObject {
    pub fn validate(&self) -> bool {
        self.schema == PROVENANCE_SCHEMA_V1
            && is_node_id(&self.source_node)
            && is_sha256_ref(&self.source_object)
            && self.parents.len() <= 64
            && self.parents.iter().all(|value| is_sha256_ref(value))
            && is_wire_timestamp(&self.created_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    Malformed,
    UnsupportedProtocol,
    UnsupportedCapability,
    AuthenticationFailed,
    Expired,
    Replay,
    PrimeDirectiveRejected,
    Quarantined,
    LocalPolicyRejected,
    NotFound,
    RateLimited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolErrorEnvelope {
    pub protocol: String,
    pub error_code: ProtocolErrorCode,
    pub request_message_id: Option<String>,
    pub invariant_id: Option<String>,
    pub message: String,
    pub retryable: bool,
}

impl ProtocolErrorEnvelope {
    pub fn validate(&self) -> bool {
        self.protocol == PROTOCOL_V1
            && self
                .request_message_id
                .as_deref()
                .is_none_or(is_sha256_ref)
            && self.message.chars().count() <= 512
            && self.invariant_id.as_deref().is_none_or(|value| {
                !value.is_empty()
                    && value.len() <= 96
                    && value.as_bytes()[0].is_ascii_lowercase()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            })
    }
}

pub fn validate_message_id(raw: &[u8], claimed: &str) -> Result<(), CanonicalError> {
    let derived = derive_message_id(raw)?;
    if derived == claimed {
        Ok(())
    } else {
        Err(CanonicalError("message_id_mismatch".into()))
    }
}

pub fn require_canonical_wire(raw: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let canonical = canonicalize(raw)?;
    if canonical == raw {
        Ok(canonical)
    } else {
        Err(CanonicalError("wire_bytes_not_canonical".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_grammar_is_frozen() {
        for value in ["evidence.exchange/1", "council.report/1", "x/12", "a-b.c9/3"] {
            assert!(is_capability_id(value), "expected valid: {value}");
        }
        for value in ["Evidence/1", "evidence_exchange/1", "evidence/01", "evidence/0", "/1", "evidence/"] {
            assert!(!is_capability_id(value), "expected invalid: {value}");
        }
    }

    #[test]
    fn unsupported_protocol_major_fails_closed() {
        assert_eq!(classify_protocol("qsol-fed/1"), ProtocolDisposition::Supported);
        for value in ["qsol-fed/0", "qsol-fed/2", "qsol-fed/99", "other/1"] {
            assert_eq!(classify_protocol(value), ProtocolDisposition::UnsupportedMajor);
        }
    }
}
