//! Phase 4 portable federation bundle export/import and offline verification.

use std::collections::HashSet;

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, object_id};
use crate::peering::{
    rebuild_peer_identity, verify_capability_advertisement_signature, CapabilityAdvertisement,
    PeerLifecycleRecord, PeerLifecycleState, PeerRegistry,
};
use crate::store::{FederationObjectStore, ForeignNamespace};
use crate::wire::{is_node_id, is_sha256_ref, is_wire_timestamp, ProvenanceObject, PROTOCOL_V1};
use crate::NodeIdentityDocument;

pub const FEDERATION_BUNDLE_SCHEMA_V1: &str = "qsol-fed-bundle/1";
pub const MAX_BUNDLE_PEERS: usize = 256;
pub const MAX_BUNDLE_OBJECTS: usize = 1_024;
pub const MAX_BUNDLE_BYTES: usize = 65_536;
pub const MAX_BUNDLE_EMBEDDED_HEX_CHARS: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(pub String);

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BundleError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundlePeer {
    pub node_id: String,
    pub identity_hex: String,
    pub lifecycle_hex: Vec<String>,
    pub capability_advertisement_hex: Option<String>,
    pub exported_state: PeerLifecycleState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleObject {
    pub object_id: String,
    pub source_node: String,
    pub exported_namespace: ForeignNamespace,
    pub object_hex: String,
    pub provenance_id: Option<String>,
    pub provenance_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableFederationBundle {
    pub schema: String,
    pub protocol: String,
    pub exporter_node: String,
    pub created_at: String,
    pub peers: Vec<BundlePeer>,
    pub objects: Vec<BundleObject>,
    pub authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerificationReport {
    pub bundle_id: String,
    pub peer_count: usize,
    pub object_count: usize,
    pub authority: &'static str,
    pub network_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleImportReceipt {
    pub bundle_id: String,
    pub peers_imported: usize,
    pub objects_imported: usize,
    pub placement: &'static str,
    pub authority: &'static str,
    pub trust_changed: bool,
}

pub fn export_bundle(
    store: &FederationObjectStore,
    peers: &PeerRegistry,
    exporter_node: &str,
    created_at: &str,
    peer_ids: &[String],
    object_ids: &[String],
) -> Result<Vec<u8>, BundleError> {
    if !is_node_id(exporter_node) || !valid_timestamp(created_at) {
        return Err(BundleError("bundle_exporter_or_time_invalid".into()));
    }
    if peer_ids.len() > MAX_BUNDLE_PEERS || object_ids.len() > MAX_BUNDLE_OBJECTS {
        return Err(BundleError("bundle_selection_too_large".into()));
    }

    let mut peer_seen = HashSet::new();
    let mut peer_entries = Vec::new();
    for node_id in peer_ids {
        if !peer_seen.insert(node_id.as_str()) {
            return Err(BundleError("bundle_duplicate_peer_selection".into()));
        }
        let record = peers
            .get(node_id)
            .map_err(|error| BundleError(error.0))?
            .ok_or_else(|| BundleError("bundle_peer_not_found".into()))?;
        let identity_hex = encode_hex(&canonical_struct(&record.identity)?)?;
        let lifecycle_hex = record
            .lifecycle
            .iter()
            .map(|value| canonical_struct(value).and_then(|bytes| encode_hex(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let capability_advertisement_hex = record
            .capability_advertisement
            .as_ref()
            .map(|value| canonical_struct(value).and_then(|bytes| encode_hex(&bytes)))
            .transpose()?;
        peer_entries.push(BundlePeer {
            node_id: record.node_id,
            identity_hex,
            lifecycle_hex,
            capability_advertisement_hex,
            exported_state: record.state,
        });
    }
    peer_entries.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let mut selected = HashSet::new();
    let mut object_entries = Vec::new();
    for object_ref in object_ids {
        if !selected.insert(object_ref.as_str()) {
            return Err(BundleError("bundle_duplicate_object_selection".into()));
        }
        let records = store
            .foreign_records(object_ref)
            .map_err(|error| BundleError(error.0))?;
        if records.is_empty() {
            return Err(BundleError("bundle_foreign_object_not_found".into()));
        }
        let object_bytes = store
            .object_bytes(object_ref)
            .map_err(|error| BundleError(error.0))?
            .ok_or_else(|| BundleError("bundle_object_bytes_missing".into()))?;
        let object_hex = encode_hex(&object_bytes)?;
        for (namespace, record) in records {
            let (provenance_id, provenance_hex) =
                if let Some(provenance_id) = &record.provenance_id {
                    let bytes = store
                        .provenance_bytes(provenance_id)
                        .map_err(|error| BundleError(error.0))?
                        .ok_or_else(|| BundleError("bundle_provenance_bytes_missing".into()))?;
                    (Some(provenance_id.clone()), Some(encode_hex(&bytes)?))
                } else {
                    (None, None)
                };
            object_entries.push(BundleObject {
                object_id: record.object_id,
                source_node: record.source_node,
                exported_namespace: namespace,
                object_hex: object_hex.clone(),
                provenance_id,
                provenance_hex,
            });
            if object_entries.len() > MAX_BUNDLE_OBJECTS {
                return Err(BundleError("bundle_expanded_object_limit".into()));
            }
        }
    }
    object_entries.sort_by(|a, b| {
        a.object_id
            .cmp(&b.object_id)
            .then(a.source_node.cmp(&b.source_node))
            .then(a.provenance_id.cmp(&b.provenance_id))
    });

    let bundle = PortableFederationBundle {
        schema: FEDERATION_BUNDLE_SCHEMA_V1.into(),
        protocol: PROTOCOL_V1.into(),
        exporter_node: exporter_node.into(),
        created_at: created_at.into(),
        peers: peer_entries,
        objects: object_entries,
        authority: "none".into(),
    };
    let bytes = canonical_struct(&bundle)?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError("bundle_too_large".into()));
    }
    verify_bundle(&bytes)?;
    Ok(bytes)
}

pub fn verify_bundle(raw: &[u8]) -> Result<BundleVerificationReport, BundleError> {
    if raw.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError("bundle_too_large".into()));
    }
    require_exact_canonical(raw)?;
    let bundle: PortableFederationBundle = serde_json::from_slice(raw)
        .map_err(|error| BundleError(format!("bundle_schema:{error}")))?;
    if bundle.schema != FEDERATION_BUNDLE_SCHEMA_V1
        || bundle.protocol != PROTOCOL_V1
        || !is_node_id(&bundle.exporter_node)
        || !valid_timestamp(&bundle.created_at)
        || bundle.authority != "none"
        || bundle.peers.len() > MAX_BUNDLE_PEERS
        || bundle.objects.len() > MAX_BUNDLE_OBJECTS
    {
        return Err(BundleError("bundle_shape_invalid".into()));
    }

    let mut peers_seen = HashSet::new();
    for peer in &bundle.peers {
        if !is_node_id(&peer.node_id) || !peers_seen.insert(peer.node_id.as_str()) {
            return Err(BundleError("bundle_peer_identity_invalid_or_duplicate".into()));
        }
        let identity_bytes = decode_hex(&peer.identity_hex)?;
        require_exact_canonical(&identity_bytes)?;
        let identity: NodeIdentityDocument = serde_json::from_slice(&identity_bytes)
            .map_err(|error| BundleError(format!("bundle_identity_schema:{error}")))?;
        if identity.node_id != peer.node_id {
            return Err(BundleError("bundle_identity_node_mismatch".into()));
        }
        if peer.lifecycle_hex.len() > crate::peering::MAX_PEER_LIFECYCLE_RECORDS {
            return Err(BundleError("bundle_lifecycle_too_large".into()));
        }
        let mut lifecycle = Vec::new();
        for encoded in &peer.lifecycle_hex {
            let bytes = decode_hex(encoded)?;
            require_exact_canonical(&bytes)?;
            let record: PeerLifecycleRecord = serde_json::from_slice(&bytes)
                .map_err(|error| BundleError(format!("bundle_lifecycle_schema:{error}")))?;
            lifecycle.push(record);
        }
        let identity_state = rebuild_peer_identity(&identity, &lifecycle)
            .map_err(|error| BundleError(error.0))?;
        if let Some(encoded) = &peer.capability_advertisement_hex {
            let bytes = decode_hex(encoded)?;
            require_exact_canonical(&bytes)?;
            let advertisement: CapabilityAdvertisement = serde_json::from_slice(&bytes)
                .map_err(|error| BundleError(format!("bundle_capability_schema:{error}")))?;
            verify_capability_advertisement_signature(&advertisement, &identity_state)
                .map_err(|error| BundleError(error.0))?;
        }
    }

    let mut attributions_seen: HashSet<(String, String, Option<String>)> = HashSet::new();
    for object in &bundle.objects {
        let attribution_key = (
            object.object_id.clone(),
            object.source_node.clone(),
            object.provenance_id.clone(),
        );
        if !is_sha256_ref(&object.object_id)
            || !is_node_id(&object.source_node)
            || !attributions_seen.insert(attribution_key)
            || object.provenance_id.is_some() != object.provenance_hex.is_some()
        {
            return Err(BundleError(
                "bundle_object_attribution_invalid_or_duplicate".into(),
            ));
        }
        let object_bytes = decode_hex(&object.object_hex)?;
        require_exact_canonical(&object_bytes)?;
        if object_id(&object_bytes).map_err(|error| BundleError(error.0))? != object.object_id {
            return Err(BundleError("bundle_object_hash_mismatch".into()));
        }
        if let (Some(provenance_id), Some(encoded)) =
            (&object.provenance_id, &object.provenance_hex)
        {
            if !is_sha256_ref(provenance_id) {
                return Err(BundleError("bundle_provenance_id_invalid".into()));
            }
            let provenance_bytes = decode_hex(encoded)?;
            require_exact_canonical(&provenance_bytes)?;
            if object_id(&provenance_bytes).map_err(|error| BundleError(error.0))?
                != *provenance_id
            {
                return Err(BundleError("bundle_provenance_hash_mismatch".into()));
            }
            let provenance: ProvenanceObject = serde_json::from_slice(&provenance_bytes)
                .map_err(|error| BundleError(format!("bundle_provenance_schema:{error}")))?;
            if !provenance.validate()
                || provenance.source_node != object.source_node
                || provenance.source_object != object.object_id
            {
                return Err(BundleError("bundle_provenance_identity_mismatch".into()));
            }
        }
    }

    let bundle_id = object_id(raw).map_err(|error| BundleError(error.0))?;
    Ok(BundleVerificationReport {
        bundle_id,
        peer_count: bundle.peers.len(),
        object_count: bundle.objects.len(),
        authority: "none",
        network_required: false,
    })
}

pub fn import_bundle(
    store: &FederationObjectStore,
    peers: &PeerRegistry,
    raw: &[u8],
    imported_at: &str,
) -> Result<BundleImportReceipt, BundleError> {
    if !valid_timestamp(imported_at) {
        return Err(BundleError("bundle_import_time_invalid".into()));
    }
    let report = verify_bundle(raw)?;
    let bundle: PortableFederationBundle = serde_json::from_slice(raw)
        .map_err(|error| BundleError(format!("bundle_schema:{error}")))?;

    for peer in &bundle.peers {
        let identity_bytes = decode_hex(&peer.identity_hex)?;
        let identity: NodeIdentityDocument = serde_json::from_slice(&identity_bytes)
            .map_err(|error| BundleError(format!("bundle_identity_schema:{error}")))?;
        let lifecycle = peer
            .lifecycle_hex
            .iter()
            .map(|encoded| {
                let bytes = decode_hex(encoded)?;
                serde_json::from_slice::<PeerLifecycleRecord>(&bytes)
                    .map_err(|error| BundleError(format!("bundle_lifecycle_schema:{error}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let existed = peers
            .get(&identity.node_id)
            .map_err(|error| BundleError(error.0))?
            .is_some();
        peers
            .import_quarantined(identity.clone(), lifecycle, imported_at)
            .map_err(|error| BundleError(error.0))?;
        if !existed {
            if let Some(encoded) = &peer.capability_advertisement_hex {
                let bytes = decode_hex(encoded)?;
                let advertisement: CapabilityAdvertisement = serde_json::from_slice(&bytes)
                    .map_err(|error| BundleError(format!("bundle_capability_schema:{error}")))?;
                peers
                    .attach_archival_capability_advertisement(
                        &identity.node_id,
                        advertisement,
                        imported_at,
                    )
                    .map_err(|error| BundleError(error.0))?;
            }
        }
    }

    for object in &bundle.objects {
        let object_bytes = decode_hex(&object.object_hex)?;
        let provenance_bytes = object
            .provenance_hex
            .as_ref()
            .map(|encoded| decode_hex(encoded))
            .transpose()?;
        store
            .put_foreign(
                &object.source_node,
                &object_bytes,
                provenance_bytes.as_deref(),
                ForeignNamespace::Quarantine,
                imported_at,
            )
            .map_err(|error| BundleError(error.0))?;
    }

    Ok(BundleImportReceipt {
        bundle_id: report.bundle_id,
        peers_imported: report.peer_count,
        objects_imported: report.object_count,
        placement: "new_material_quarantined_existing_state_preserved",
        authority: "none",
        trust_changed: false,
    })
}

fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, BundleError> {
    let raw = serde_json::to_vec(value).map_err(|error| BundleError(format!("bundle_encode:{error}")))?;
    canonicalize(&raw).map_err(|error| BundleError(error.0))
}

fn require_exact_canonical(raw: &[u8]) -> Result<(), BundleError> {
    let canonical = canonicalize(raw).map_err(|error| BundleError(error.0))?;
    if canonical == raw {
        Ok(())
    } else {
        Err(BundleError("bundle_embedded_bytes_not_canonical".into()))
    }
}

fn valid_timestamp(value: &str) -> bool {
    is_wire_timestamp(value) && DateTime::parse_from_rfc3339(value).is_ok()
}

fn encode_hex(bytes: &[u8]) -> Result<String, BundleError> {
    if bytes.len().saturating_mul(2) > MAX_BUNDLE_EMBEDDED_HEX_CHARS {
        return Err(BundleError("bundle_embedded_value_too_large".into()));
    }
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    Ok(value)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, BundleError> {
    if value.is_empty()
        || value.len() > MAX_BUNDLE_EMBEDDED_HEX_CHARS
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BundleError("bundle_hex_invalid_or_oversized".into()));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        output.push(
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| BundleError("bundle_hex_invalid".into()))?,
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peering::{create_capability_advertisement, PeerLifecycleState};
    use crate::{create_identity_document, LocalSigningKey};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ROOT: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const OP: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "qsol-fed-bundle-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn provenance(source: &str, object_ref: &str, created_at: &str) -> Vec<u8> {
        format!(
            "{{\"created_at\":\"{created_at}\",\"parents\":[],\"relation\":\"transported\",\"schema\":\"qsol-fed-provenance/1\",\"source_node\":\"{source}\",\"source_object\":\"{object_ref}\"}}"
        )
        .into_bytes()
    }

    #[test]
    fn round_trip_preserves_foreign_identity_and_provenance_exactly() {
        let root = temp_root("roundtrip");
        let source_store = FederationObjectStore::open(root.join("source-store")).unwrap();
        let source_peers = PeerRegistry::open(root.join("source-peers")).unwrap();
        let root_key = LocalSigningKey::from_seed_hex(ROOT).unwrap();
        let op = LocalSigningKey::from_seed_hex(OP).unwrap();
        let identity =
            create_identity_document(&root_key, &op, "2026-08-23T00:00:00Z").unwrap();
        let identity_state = crate::IdentityState::from_document(&identity).unwrap();
        source_peers
            .introduce(identity.clone(), vec![], None, "2026-08-23T00:00:01Z")
            .unwrap();
        source_peers
            .transition(
                &identity.node_id,
                PeerLifecycleState::Admitted,
                "2026-08-23T00:00:02Z",
            )
            .unwrap();
        let advertisement = create_capability_advertisement(
            &identity_state,
            &op,
            1,
            "2026-08-23T00:00:00Z",
            "2026-08-23T01:00:00Z",
            vec!["evidence.exchange/1".into()],
        )
        .unwrap();
        source_peers
            .record_capability_advertisement(
                advertisement,
                1_787_443_320,
                "2026-08-23T00:00:03Z",
            )
            .unwrap();

        let object = br#"{"foreign":"payload"}"#;
        let object_ref = object_id(object).unwrap();
        let first = provenance(&identity.node_id, &object_ref, "2026-08-23T00:00:00Z");
        let second = provenance("fed:qsol:second", &object_ref, "2026-08-23T00:00:01Z");
        source_store
            .put_foreign(
                &identity.node_id,
                object,
                Some(&first),
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:04Z",
            )
            .unwrap();
        source_store
            .put_foreign(
                "fed:qsol:second",
                object,
                Some(&second),
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:05Z",
            )
            .unwrap();

        let bundle = export_bundle(
            &source_store,
            &source_peers,
            "fed:qsol:exporter",
            "2026-08-23T00:01:00Z",
            &[identity.node_id.clone()],
            &[object_ref.clone()],
        )
        .unwrap();
        let before: PortableFederationBundle = serde_json::from_slice(&bundle).unwrap();
        assert_eq!(before.objects.len(), 2);
        let report = verify_bundle(&bundle).unwrap();
        assert!(!report.network_required);
        assert_eq!(report.authority, "none");

        let target_store = FederationObjectStore::open(root.join("target-store")).unwrap();
        let target_peers = PeerRegistry::open(root.join("target-peers")).unwrap();
        let receipt = import_bundle(
            &target_store,
            &target_peers,
            &bundle,
            "2026-08-23T00:02:00Z",
        )
        .unwrap();
        assert_eq!(
            receipt.placement,
            "new_material_quarantined_existing_state_preserved"
        );
        assert_eq!(receipt.authority, "none");
        assert!(!receipt.trust_changed);
        assert_eq!(
            target_peers.state(&identity.node_id).unwrap(),
            crate::peering::PeerStateView::Quarantined
        );

        let reexport = export_bundle(
            &target_store,
            &target_peers,
            "fed:qsol:exporter",
            "2026-08-23T00:01:00Z",
            &[identity.node_id.clone()],
            &[object_ref],
        )
        .unwrap();
        let after: PortableFederationBundle = serde_json::from_slice(&reexport).unwrap();
        assert_eq!(before.peers[0].identity_hex, after.peers[0].identity_hex);
        assert_eq!(before.peers[0].lifecycle_hex, after.peers[0].lifecycle_hex);
        assert_eq!(
            before.peers[0].capability_advertisement_hex,
            after.peers[0].capability_advertisement_hex
        );
        assert_eq!(before.objects, after.objects);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn import_preserves_existing_admitted_peer() {
        let root = temp_root("existing-peer");
        let source_store = FederationObjectStore::open(root.join("source-store")).unwrap();
        let source_peers = PeerRegistry::open(root.join("source-peers")).unwrap();
        let root_key = LocalSigningKey::from_seed_hex(ROOT).unwrap();
        let op = LocalSigningKey::from_seed_hex(OP).unwrap();
        let identity =
            create_identity_document(&root_key, &op, "2026-08-23T00:00:00Z").unwrap();
        source_peers
            .introduce(identity.clone(), vec![], None, "2026-08-23T00:00:01Z")
            .unwrap();
        let bundle = export_bundle(
            &source_store,
            &source_peers,
            "fed:qsol:exporter",
            "2026-08-23T00:01:00Z",
            &[identity.node_id.clone()],
            &[],
        )
        .unwrap();

        let target_store = FederationObjectStore::open(root.join("target-store")).unwrap();
        let target_peers = PeerRegistry::open(root.join("target-peers")).unwrap();
        target_peers
            .introduce(identity.clone(), vec![], None, "2026-08-23T00:00:02Z")
            .unwrap();
        target_peers
            .transition(
                &identity.node_id,
                PeerLifecycleState::Admitted,
                "2026-08-23T00:00:03Z",
            )
            .unwrap();
        import_bundle(
            &target_store,
            &target_peers,
            &bundle,
            "2026-08-23T00:02:00Z",
        )
        .unwrap();
        assert_eq!(
            target_peers.state(&identity.node_id).unwrap(),
            crate::peering::PeerStateView::Admitted
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn embedded_hex_and_total_bundle_bounds_match_phase1_profile() {
        assert_eq!(MAX_BUNDLE_BYTES, 65_536);
        assert_eq!(MAX_BUNDLE_EMBEDDED_HEX_CHARS, 8_192);
        assert_eq!(MAX_BUNDLE_OBJECTS, 1_024);
        assert!(encode_hex(&vec![0u8; 4_096]).is_ok());
        assert!(encode_hex(&vec![0u8; 4_097]).is_err());
    }
}
