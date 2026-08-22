use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Write as _};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const CANONICAL_PROFILE: &str = "qsol-fed-canonical-json/1";
pub const MESSAGE_ID_DOMAIN: &[u8] = b"qsol-fed-message-id/1\0";
pub const SAFE_INTEGER_MIN: i64 = -9_007_199_254_740_991;
pub const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;
pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_DEPTH: usize = 32;
pub const MAX_STRING_UTF8: usize = 8_192;
pub const MAX_ARRAY_ITEMS: usize = 1_024;
pub const MAX_OBJECT_MEMBERS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError(pub String);

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

fn normalize_string<E: serde::de::Error>(value: String) -> Result<String, E> {
    let normalized: String = value.nfc().collect();
    if normalized.len() > MAX_STRING_UTF8 {
        return Err(E::custom("string_too_large"));
    }
    Ok(normalized)
}

struct CanonicalVisitor;

impl<'de> Visitor<'de> for CanonicalVisitor {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a qsol-fed-canonical-json/1 value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CanonicalValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CanonicalValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CanonicalValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(SAFE_INTEGER_MIN..=SAFE_INTEGER_MAX).contains(&value) {
            return Err(E::custom("integer_out_of_range"));
        }
        Ok(CanonicalValue::Integer(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > SAFE_INTEGER_MAX as u64 {
            return Err(E::custom("integer_out_of_range"));
        }
        Ok(CanonicalValue::Integer(value as i64))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("non_integer_number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CanonicalValue::String(normalize_string::<E>(value)?))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<CanonicalValue>()? {
            if values.len() >= MAX_ARRAY_ITEMS {
                return Err(serde::de::Error::custom("too_many_array_items"));
            }
            values.push(value);
        }
        Ok(CanonicalValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = BTreeMap::new();
        let mut raw_seen = HashSet::new();
        let mut normalized_seen = HashSet::new();
        while let Some(raw_key) = map.next_key::<String>()? {
            if result.len() >= MAX_OBJECT_MEMBERS {
                return Err(serde::de::Error::custom("too_many_object_members"));
            }
            if !raw_seen.insert(raw_key.clone()) {
                return Err(serde::de::Error::custom("duplicate_key"));
            }
            let key = normalize_string::<A::Error>(raw_key)?;
            if !normalized_seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("normalized_duplicate_key"));
            }
            let value = map.next_value::<CanonicalValue>()?;
            result.insert(key, value);
        }
        Ok(CanonicalValue::Object(result))
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(CanonicalVisitor)
    }
}

impl CanonicalValue {
    fn validate_depth(&self, depth: usize) -> Result<(), CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError("max_depth_exceeded".into()));
        }
        match self {
            CanonicalValue::Array(values) => {
                for value in values {
                    value.validate_depth(depth + 1)?;
                }
            }
            CanonicalValue::Object(values) => {
                for value in values.values() {
                    value.validate_depth(depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn parse_canonical_value(raw: &[u8]) -> Result<CanonicalValue, CanonicalError> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(CanonicalError("input_too_large".into()));
    }
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(CanonicalError("utf8_bom_forbidden".into()));
    }
    let text = std::str::from_utf8(raw).map_err(|_| CanonicalError("invalid_utf8".into()))?;
    let value: CanonicalValue =
        serde_json::from_str(text).map_err(|error| CanonicalError(error.to_string()))?;
    value.validate_depth(1)?;
    Ok(value)
}

fn escape_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

pub fn serialize_canonical(value: &CanonicalValue) -> String {
    let mut output = String::new();
    serialize_into(value, &mut output);
    output
}

fn serialize_into(value: &CanonicalValue, output: &mut String) {
    match value {
        CanonicalValue::Null => output.push_str("null"),
        CanonicalValue::Bool(true) => output.push_str("true"),
        CanonicalValue::Bool(false) => output.push_str("false"),
        CanonicalValue::Integer(value) => {
            let _ = write!(output, "{value}");
        }
        CanonicalValue::String(value) => escape_string(value, output),
        CanonicalValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                serialize_into(value, output);
            }
            output.push(']');
        }
        CanonicalValue::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                escape_string(key, output);
                output.push(':');
                serialize_into(value, output);
            }
            output.push('}');
        }
    }
}

pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    Ok(serialize_canonical(&parse_canonical_value(raw)?).into_bytes())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn sha256_ref(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", lowercase_hex(&digest))
}

pub fn object_id(raw: &[u8]) -> Result<String, CanonicalError> {
    Ok(sha256_ref(&canonicalize(raw)?))
}

pub fn derive_message_id(raw_envelope: &[u8]) -> Result<String, CanonicalError> {
    let value = parse_canonical_value(raw_envelope)?;
    let CanonicalValue::Object(mut object) = value else {
        return Err(CanonicalError("envelope_must_be_object".into()));
    };
    if object.remove("message_id").is_none() || object.remove("signature").is_none() {
        return Err(CanonicalError("envelope_projection_fields_missing".into()));
    }
    let projection = serialize_canonical(&CanonicalValue::Object(object));
    let mut preimage = Vec::with_capacity(MESSAGE_ID_DOMAIN.len() + projection.len());
    preimage.extend_from_slice(MESSAGE_ID_DOMAIN);
    preimage.extend_from_slice(projection.as_bytes());
    Ok(sha256_ref(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct GoldenManifest {
        vectors: Vec<GoldenVector>,
    }

    #[derive(Deserialize)]
    struct GoldenVector {
        input: String,
        canonical: String,
        canonical_utf8_hex: String,
        object_id: String,
        message_id: Option<String>,
    }

    #[test]
    fn rust_matches_language_neutral_golden_vectors() {
        let manifest: GoldenManifest = serde_json::from_str(include_str!(
            "../fixtures/phase1/golden-vectors.json"
        ))
        .unwrap();
        for vector in manifest.vectors {
            let canonical = canonicalize(vector.input.as_bytes()).unwrap();
            assert_eq!(String::from_utf8(canonical.clone()).unwrap(), vector.canonical);
            assert_eq!(lowercase_hex(&canonical), vector.canonical_utf8_hex);
            assert_eq!(object_id(vector.input.as_bytes()).unwrap(), vector.object_id);
            if let Some(expected) = vector.message_id {
                assert_eq!(derive_message_id(vector.input.as_bytes()).unwrap(), expected);
            }
        }
    }

    #[test]
    fn rust_rejects_adversarial_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/phase1/adversarial.json"
        ))
        .unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let raw = case["raw"].as_str().unwrap();
            assert!(canonicalize(raw.as_bytes()).is_err(), "accepted {}", case["id"]);
        }
    }

    #[test]
    fn rust_enforces_oversized_corpus_recipes() {
        let too_large = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_STRING_UTF8 + 1));
        assert!(canonicalize(too_large.as_bytes()).is_err());

        let too_many = format!("[{}]", vec!["0"; MAX_ARRAY_ITEMS + 1].join(","));
        assert!(canonicalize(too_many.as_bytes()).is_err());

        let mut too_deep = "0".to_string();
        for _ in 0..MAX_DEPTH {
            too_deep = format!("[{too_deep}]");
        }
        assert!(canonicalize(too_deep.as_bytes()).is_err());

        let oversized_input = format!("\"{}\"", "a".repeat(MAX_INPUT_BYTES));
        assert!(canonicalize(oversized_input.as_bytes()).is_err());
    }
}
