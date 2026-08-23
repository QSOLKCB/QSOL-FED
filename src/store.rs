//! Phase 4 content-addressed Federation object storage.
//!
//! Content identity and foreign attribution are deliberately separate. Identical
//! canonical bytes may have multiple independent source/provenance observations.
//! Foreign bytes remain foreign, and namespace placement never creates authority.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, object_id};
use crate::wire::{
    is_node_id, is_sha256_ref, is_wire_timestamp, ProvenanceObject, ProvenanceRelation,
    PROVENANCE_SCHEMA_V1,
};

pub const FOREIGN_RECORD_SCHEMA_V1: &str = "qsol-fed-foreign-object/1";
pub const LOCAL_DESCENDANT_SCHEMA_V1: &str = "qsol-fed-local-descendant/1";
const NAMESPACE_MOVE_SCHEMA_V1: &str = "qsol-fed-namespace-move/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignNamespace {
    Foreign,
    Quarantine,
}

impl ForeignNamespace {
    fn directory(self) -> &'static str {
        match self {
            Self::Foreign => "foreign",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignObjectRecord {
    pub schema: String,
    pub object_id: String,
    pub source_node: String,
    pub provenance_id: Option<String>,
    pub namespace: ForeignNamespace,
    pub received_at: String,
    pub authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDescendantRecord {
    pub schema: String,
    pub object_id: String,
    pub local_node: String,
    pub parent_foreign_object: String,
    pub provenance_id: String,
    pub created_at: String,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceMoveTransaction {
    schema: String,
    object_id: String,
    target: ForeignNamespace,
    changed_at: String,
}

#[derive(Serialize)]
struct AttributionKey<'a> {
    source_node: &'a str,
    provenance_id: &'a Option<String>,
}

pub struct FederationObjectStore {
    root: PathBuf,
}

impl FederationObjectStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        fs::create_dir_all(root)
            .map_err(|error| StoreError(format!("store_root_create:{error}")))?;
        let root = fs::canonicalize(root)
            .map_err(|error| StoreError(format!("store_root_canonicalize:{error}")))?;
        for directory in [
            "objects",
            "provenance",
            "foreign",
            "quarantine",
            "descendants",
            "transactions",
        ] {
            fs::create_dir_all(root.join(directory)).map_err(|error| {
                StoreError(format!("store_namespace_create:{directory}:{error}"))
            })?;
        }
        let store = Self { root };
        store.recover_namespace_moves()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put_foreign(
        &self,
        source_node: &str,
        object_bytes: &[u8],
        provenance_bytes: Option<&[u8]>,
        namespace: ForeignNamespace,
        received_at: &str,
    ) -> Result<ForeignObjectRecord, StoreError> {
        if !is_node_id(source_node) || !valid_timestamp(received_at) {
            return Err(StoreError("foreign_record_identity_or_time_invalid".into()));
        }
        require_exact_canonical(object_bytes)?;
        let object_ref = object_id(object_bytes).map_err(|error| StoreError(error.0))?;
        let provenance_id = if let Some(raw) = provenance_bytes {
            require_exact_canonical(raw)?;
            let provenance: ProvenanceObject = serde_json::from_slice(raw)
                .map_err(|error| StoreError(format!("foreign_provenance_schema:{error}")))?;
            if !provenance.validate()
                || provenance.source_node != source_node
                || provenance.source_object != object_ref
            {
                return Err(StoreError("foreign_provenance_identity_mismatch".into()));
            }
            let id = object_id(raw).map_err(|error| StoreError(error.0))?;
            write_content_addressed(&self.root.join("provenance"), &id, raw)?;
            Some(id)
        } else {
            None
        };

        write_content_addressed(&self.root.join("objects"), &object_ref, object_bytes)?;
        let record = ForeignObjectRecord {
            schema: FOREIGN_RECORD_SCHEMA_V1.into(),
            object_id: object_ref.clone(),
            source_node: source_node.into(),
            provenance_id,
            namespace,
            received_at: received_at.into(),
            authority: "none".into(),
        };
        validate_foreign_record(&record, namespace, &object_ref, None)?;
        let attribution = attribution_id(&record)?;

        for candidate_namespace in [ForeignNamespace::Foreign, ForeignNamespace::Quarantine] {
            let path = attribution_record_path(
                &self.root,
                candidate_namespace,
                &object_ref,
                &attribution,
            )?;
            if let Some(existing) = read_record_file(
                &path,
                candidate_namespace,
                &object_ref,
                &attribution,
            )? {
                return Ok(existing);
            }
        }

        let path = attribution_record_path(&self.root, namespace, &object_ref, &attribution)?;
        write_exact_or_same(&path, &canonical_struct(&record)?)?;
        Ok(record)
    }

    pub fn foreign_records(
        &self,
        object_ref: &str,
    ) -> Result<Vec<(ForeignNamespace, ForeignObjectRecord)>, StoreError> {
        if !is_sha256_ref(object_ref) {
            return Err(StoreError("foreign_record_id_invalid".into()));
        }
        let mut records = Vec::new();
        for namespace in [ForeignNamespace::Foreign, ForeignNamespace::Quarantine] {
            let directory = attribution_directory(&self.root, namespace, object_ref)?;
            if !directory.exists() {
                continue;
            }
            for entry in fs::read_dir(&directory)
                .map_err(|error| StoreError(format!("foreign_record_dir_read:{error}")))?
            {
                let entry = entry
                    .map_err(|error| StoreError(format!("foreign_record_dir_entry:{error}")))?;
                if !entry
                    .file_type()
                    .map_err(|error| StoreError(format!("foreign_record_type:{error}")))?
                    .is_file()
                {
                    return Err(StoreError("foreign_record_layout_corrupt".into()));
                }
                let attribution = attribution_from_filename(&entry.path())?;
                let record = read_record_file(
                    &entry.path(),
                    namespace,
                    object_ref,
                    &attribution,
                )?
                .ok_or_else(|| StoreError("foreign_record_disappeared".into()))?;
                records.push((namespace, record));
            }
        }
        records.sort_by(|left, right| {
            let left_id = attribution_id(&left.1).unwrap_or_default();
            let right_id = attribution_id(&right.1).unwrap_or_default();
            left.0
                .directory()
                .cmp(right.0.directory())
                .then(left_id.cmp(&right_id))
        });
        Ok(records)
    }

    pub fn foreign_record(
        &self,
        object_ref: &str,
    ) -> Result<Option<(ForeignNamespace, ForeignObjectRecord)>, StoreError> {
        let mut records = self.foreign_records(object_ref)?;
        match records.len() {
            0 => Ok(None),
            1 => Ok(records.pop()),
            _ => Err(StoreError(
                "foreign_record_ambiguous_multiple_attributions".into(),
            )),
        }
    }

    pub fn move_namespace(
        &self,
        object_ref: &str,
        target: ForeignNamespace,
        changed_at: &str,
    ) -> Result<Vec<ForeignObjectRecord>, StoreError> {
        if !is_sha256_ref(object_ref) || !valid_timestamp(changed_at) {
            return Err(StoreError("namespace_move_invalid".into()));
        }
        let records = self.foreign_records(object_ref)?;
        if records.is_empty() {
            return Err(StoreError("foreign_record_not_found".into()));
        }
        if records.iter().all(|(namespace, _)| *namespace == target) {
            return Ok(records.into_iter().map(|(_, record)| record).collect());
        }
        let transaction = NamespaceMoveTransaction {
            schema: NAMESPACE_MOVE_SCHEMA_V1.into(),
            object_id: object_ref.into(),
            target,
            changed_at: changed_at.into(),
        };
        write_exact_or_same(
            &move_transaction_path(&self.root, object_ref)?,
            &canonical_struct(&transaction)?,
        )?;
        self.finish_namespace_move(&transaction)
    }

    pub fn create_local_descendant(
        &self,
        local_node: &str,
        parent_foreign_object: &str,
        local_object_bytes: &[u8],
        created_at: &str,
    ) -> Result<LocalDescendantRecord, StoreError> {
        if !is_node_id(local_node)
            || !is_sha256_ref(parent_foreign_object)
            || !valid_timestamp(created_at)
        {
            return Err(StoreError("local_descendant_identity_or_time_invalid".into()));
        }
        if self.foreign_records(parent_foreign_object)?.is_empty() {
            return Err(StoreError("local_descendant_parent_not_foreign".into()));
        }
        require_exact_canonical(local_object_bytes)?;
        let descendant_id = object_id(local_object_bytes).map_err(|error| StoreError(error.0))?;
        if descendant_id == parent_foreign_object {
            return Err(StoreError("local_descendant_self_parent_forbidden".into()));
        }
        write_content_addressed(&self.root.join("objects"), &descendant_id, local_object_bytes)?;

        let provenance = ProvenanceObject {
            schema: PROVENANCE_SCHEMA_V1.into(),
            source_node: local_node.into(),
            source_object: descendant_id.clone(),
            relation: ProvenanceRelation::Derived,
            parents: vec![parent_foreign_object.into()],
            created_at: created_at.into(),
        };
        if !provenance.validate() {
            return Err(StoreError("local_descendant_provenance_invalid".into()));
        }
        let provenance_bytes = canonical_struct(&provenance)?;
        let provenance_id = object_id(&provenance_bytes).map_err(|error| StoreError(error.0))?;
        write_content_addressed(
            &self.root.join("provenance"),
            &provenance_id,
            &provenance_bytes,
        )?;

        let record = LocalDescendantRecord {
            schema: LOCAL_DESCENDANT_SCHEMA_V1.into(),
            object_id: descendant_id.clone(),
            local_node: local_node.into(),
            parent_foreign_object: parent_foreign_object.into(),
            provenance_id,
            created_at: created_at.into(),
            authority: "none".into(),
        };
        write_exact_or_same(
            &record_path_named(&self.root.join("descendants"), &descendant_id)?,
            &canonical_struct(&record)?,
        )?;
        Ok(record)
    }

    pub fn object_bytes(&self, object_ref: &str) -> Result<Option<Vec<u8>>, StoreError> {
        read_content_addressed(&self.root.join("objects"), object_ref)
    }

    pub fn provenance_bytes(&self, provenance_ref: &str) -> Result<Option<Vec<u8>>, StoreError> {
        read_content_addressed(&self.root.join("provenance"), provenance_ref)
    }

    pub fn list_foreign_records(
        &self,
        namespace: ForeignNamespace,
    ) -> Result<Vec<ForeignObjectRecord>, StoreError> {
        let mut records = Vec::new();
        let namespace_root = self.root.join(namespace.directory());
        for object_entry in fs::read_dir(&namespace_root)
            .map_err(|error| StoreError(format!("foreign_list:{error}")))?
        {
            let object_entry =
                object_entry.map_err(|error| StoreError(format!("foreign_list_entry:{error}")))?;
            if !object_entry
                .file_type()
                .map_err(|error| StoreError(format!("foreign_list_type:{error}")))?
                .is_dir()
            {
                return Err(StoreError("foreign_namespace_layout_corrupt".into()));
            }
            let object_ref = object_ref_from_directory(&object_entry.path())?;
            for entry in fs::read_dir(object_entry.path())
                .map_err(|error| StoreError(format!("foreign_list_object:{error}")))?
            {
                let entry = entry
                    .map_err(|error| StoreError(format!("foreign_list_object_entry:{error}")))?;
                if !entry
                    .file_type()
                    .map_err(|error| StoreError(format!("foreign_list_object_type:{error}")))?
                    .is_file()
                {
                    return Err(StoreError("foreign_record_layout_corrupt".into()));
                }
                let attribution = attribution_from_filename(&entry.path())?;
                let record = read_record_file(
                    &entry.path(),
                    namespace,
                    &object_ref,
                    &attribution,
                )?
                .ok_or_else(|| StoreError("foreign_record_disappeared".into()))?;
                records.push(record);
            }
        }
        records.sort_by(|a, b| {
            a.object_id
                .cmp(&b.object_id)
                .then(a.source_node.cmp(&b.source_node))
                .then(a.provenance_id.cmp(&b.provenance_id))
        });
        Ok(records)
    }

    fn recover_namespace_moves(&self) -> Result<(), StoreError> {
        let transactions = self.root.join("transactions");
        for entry in fs::read_dir(&transactions)
            .map_err(|error| StoreError(format!("namespace_tx_list:{error}")))?
        {
            let entry = entry
                .map_err(|error| StoreError(format!("namespace_tx_entry:{error}")))?;
            if !entry
                .file_type()
                .map_err(|error| StoreError(format!("namespace_tx_type:{error}")))?
                .is_file()
            {
                return Err(StoreError("namespace_tx_layout_corrupt".into()));
            }
            let raw = fs::read(entry.path())
                .map_err(|error| StoreError(format!("namespace_tx_read:{error}")))?;
            require_exact_canonical(&raw)?;
            let transaction: NamespaceMoveTransaction = serde_json::from_slice(&raw)
                .map_err(|error| StoreError(format!("namespace_tx_schema:{error}")))?;
            validate_namespace_transaction(&transaction)?;
            if entry.path() != move_transaction_path(&self.root, &transaction.object_id)? {
                return Err(StoreError("namespace_tx_filename_mismatch".into()));
            }
            self.finish_namespace_move(&transaction)?;
        }
        Ok(())
    }

    fn finish_namespace_move(
        &self,
        transaction: &NamespaceMoveTransaction,
    ) -> Result<Vec<ForeignObjectRecord>, StoreError> {
        validate_namespace_transaction(transaction)?;
        let records = self.foreign_records(&transaction.object_id)?;
        if records.is_empty() {
            return Err(StoreError("namespace_move_lost_all_attributions".into()));
        }

        let mut moved = Vec::new();
        for (source_namespace, mut record) in records {
            let attribution = attribution_id(&record)?;
            if source_namespace != transaction.target {
                record.namespace = transaction.target;
                record.received_at = transaction.changed_at.clone();
                let target_path = attribution_record_path(
                    &self.root,
                    transaction.target,
                    &transaction.object_id,
                    &attribution,
                )?;
                write_exact_or_same(&target_path, &canonical_struct(&record)?)?;
                let source_path = attribution_record_path(
                    &self.root,
                    source_namespace,
                    &transaction.object_id,
                    &attribution,
                )?;
                if source_path.exists() {
                    fs::remove_file(&source_path)
                        .map_err(|error| StoreError(format!("namespace_remove_old:{error}")))?;
                    sync_parent(&source_path)?;
                    remove_empty_parent_directory(&source_path)?;
                }
            }
            moved.push(record);
        }

        let marker = move_transaction_path(&self.root, &transaction.object_id)?;
        if marker.exists() {
            fs::remove_file(&marker)
                .map_err(|error| StoreError(format!("namespace_tx_remove:{error}")))?;
            sync_parent(&marker)?;
        }
        moved.sort_by(|a, b| {
            a.source_node
                .cmp(&b.source_node)
                .then(a.provenance_id.cmp(&b.provenance_id))
        });
        Ok(moved)
    }
}

fn valid_timestamp(value: &str) -> bool {
    is_wire_timestamp(value) && DateTime::parse_from_rfc3339(value).is_ok()
}

fn validate_namespace_transaction(transaction: &NamespaceMoveTransaction) -> Result<(), StoreError> {
    if transaction.schema != NAMESPACE_MOVE_SCHEMA_V1
        || !is_sha256_ref(&transaction.object_id)
        || !valid_timestamp(&transaction.changed_at)
    {
        return Err(StoreError("namespace_tx_corrupt".into()));
    }
    Ok(())
}

fn validate_foreign_record(
    record: &ForeignObjectRecord,
    expected_namespace: ForeignNamespace,
    expected_object: &str,
    expected_attribution: Option<&str>,
) -> Result<(), StoreError> {
    if record.schema != FOREIGN_RECORD_SCHEMA_V1
        || record.object_id != expected_object
        || record.namespace != expected_namespace
        || record.authority != "none"
        || !is_node_id(&record.source_node)
        || !valid_timestamp(&record.received_at)
        || record
            .provenance_id
            .as_deref()
            .is_some_and(|id| !is_sha256_ref(id))
    {
        return Err(StoreError("foreign_record_corrupt".into()));
    }
    if let Some(expected) = expected_attribution {
        if attribution_id(record)? != expected {
            return Err(StoreError("foreign_attribution_filename_mismatch".into()));
        }
    }
    Ok(())
}

fn read_record_file(
    path: &Path,
    namespace: ForeignNamespace,
    object_ref: &str,
    attribution: &str,
) -> Result<Option<ForeignObjectRecord>, StoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path).map_err(|error| StoreError(format!("foreign_record_read:{error}")))?;
    require_exact_canonical(&raw)?;
    let record: ForeignObjectRecord = serde_json::from_slice(&raw)
        .map_err(|error| StoreError(format!("foreign_record_schema:{error}")))?;
    validate_foreign_record(&record, namespace, object_ref, Some(attribution))?;
    Ok(Some(record))
}

fn attribution_id(record: &ForeignObjectRecord) -> Result<String, StoreError> {
    object_id(&canonical_struct(&AttributionKey {
        source_node: &record.source_node,
        provenance_id: &record.provenance_id,
    })?)
    .map_err(|error| StoreError(error.0))
}

fn require_exact_canonical(raw: &[u8]) -> Result<(), StoreError> {
    let canonical = canonicalize(raw).map_err(|error| StoreError(error.0))?;
    if canonical != raw {
        return Err(StoreError("stored_object_bytes_not_canonical".into()));
    }
    Ok(())
}

fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let raw = serde_json::to_vec(value).map_err(|error| StoreError(format!("store_encode:{error}")))?;
    canonicalize(&raw).map_err(|error| StoreError(error.0))
}

fn digest_from_ref(reference: &str) -> Result<&str, StoreError> {
    if !is_sha256_ref(reference) {
        return Err(StoreError("content_reference_invalid".into()));
    }
    Ok(&reference[7..])
}

fn content_path(directory: &Path, reference: &str) -> Result<PathBuf, StoreError> {
    Ok(directory.join(format!("{}.json", digest_from_ref(reference)?)))
}

fn attribution_directory(
    root: &Path,
    namespace: ForeignNamespace,
    object_ref: &str,
) -> Result<PathBuf, StoreError> {
    Ok(root
        .join(namespace.directory())
        .join(digest_from_ref(object_ref)?))
}

fn attribution_record_path(
    root: &Path,
    namespace: ForeignNamespace,
    object_ref: &str,
    attribution_ref: &str,
) -> Result<PathBuf, StoreError> {
    Ok(attribution_directory(root, namespace, object_ref)?
        .join(format!("{}.record.json", digest_from_ref(attribution_ref)?)))
}

fn attribution_from_filename(path: &Path) -> Result<String, StoreError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StoreError("foreign_record_filename_invalid".into()))?;
    let digest = name
        .strip_suffix(".record.json")
        .ok_or_else(|| StoreError("foreign_record_filename_invalid".into()))?;
    let reference = format!("sha256:{digest}");
    if !is_sha256_ref(&reference) {
        return Err(StoreError("foreign_record_filename_invalid".into()));
    }
    Ok(reference)
}

fn object_ref_from_directory(path: &Path) -> Result<String, StoreError> {
    let digest = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StoreError("foreign_object_directory_invalid".into()))?;
    let reference = format!("sha256:{digest}");
    if !is_sha256_ref(&reference) {
        return Err(StoreError("foreign_object_directory_invalid".into()));
    }
    Ok(reference)
}

fn move_transaction_path(root: &Path, object_ref: &str) -> Result<PathBuf, StoreError> {
    Ok(root
        .join("transactions")
        .join(format!("{}.move.json", digest_from_ref(object_ref)?)))
}

fn record_path_named(directory: &Path, reference: &str) -> Result<PathBuf, StoreError> {
    Ok(directory.join(format!("{}.record.json", digest_from_ref(reference)?)))
}

fn write_content_addressed(directory: &Path, reference: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let derived = object_id(bytes).map_err(|error| StoreError(error.0))?;
    if derived != reference {
        return Err(StoreError("content_address_mismatch".into()));
    }
    write_exact_or_same(&content_path(directory, reference)?, bytes)
}

fn read_content_addressed(directory: &Path, reference: &str) -> Result<Option<Vec<u8>>, StoreError> {
    let path = content_path(directory, reference)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(&path).map_err(|error| StoreError(format!("content_read:{error}")))?;
    require_exact_canonical(&raw)?;
    if object_id(&raw).map_err(|error| StoreError(error.0))? != reference {
        return Err(StoreError("content_store_hash_corrupt".into()));
    }
    Ok(Some(raw))
}

fn write_exact_or_same(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError("store_parent_missing".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| StoreError(format!("store_parent_create:{error}")))?;
    if path.exists() {
        let existing = fs::read(path)
            .map_err(|error| StoreError(format!("store_existing_read:{error}")))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(StoreError("content_address_collision_or_metadata_conflict".into()));
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StoreError("store_filename_invalid".into()))?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| StoreError(format!("store_temp_open:{error}")))?;
    file.write_all(bytes)
        .map_err(|error| StoreError(format!("store_write:{error}")))?;
    file.flush()
        .map_err(|error| StoreError(format!("store_flush:{error}")))?;
    file.sync_all()
        .map_err(|error| StoreError(format!("store_fsync:{error}")))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| StoreError(format!("store_rename:{error}")))?;
    sync_parent(path)
}

fn remove_empty_parent_directory(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if fs::read_dir(parent)
        .map_err(|error| StoreError(format!("store_parent_read:{error}")))?
        .next()
        .is_none()
    {
        fs::remove_dir(parent)
            .map_err(|error| StoreError(format!("store_empty_parent_remove:{error}")))?;
        sync_parent(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), StoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)
        .map_err(|error| StoreError(format!("store_parent_open:{error}")))?;
    directory
        .sync_all()
        .map_err(|error| StoreError(format!("store_parent_fsync:{error}")))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError(
        "store_parent_fsync_unsupported_platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "qsol-fed-store-{label}-{}-{nonce}",
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
    fn foreign_bytes_and_provenance_are_preserved_exactly() {
        let root = temp_root("foreign");
        let store = FederationObjectStore::open(&root).unwrap();
        let object = br#"{"kind":"observation","value":7}"#;
        let id = object_id(object).unwrap();
        let provenance = provenance("fed:qsol:peer", &id, "2026-08-23T00:00:00Z");
        let record = store
            .put_foreign(
                "fed:qsol:peer",
                object,
                Some(&provenance),
                ForeignNamespace::Quarantine,
                "2026-08-23T00:00:01Z",
            )
            .unwrap();
        assert_eq!(record.authority, "none");
        assert_eq!(store.object_bytes(&id).unwrap().unwrap(), object);
        assert_eq!(
            store
                .provenance_bytes(record.provenance_id.as_ref().unwrap())
                .unwrap()
                .unwrap(),
            provenance
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identical_bytes_preserve_multiple_foreign_attributions() {
        let root = temp_root("attributions");
        let store = FederationObjectStore::open(&root).unwrap();
        let object = br#"{"same":"bytes"}"#;
        let id = object_id(object).unwrap();
        let first = provenance("fed:qsol:peer-a", &id, "2026-08-23T00:00:00Z");
        let second = provenance("fed:qsol:peer-b", &id, "2026-08-23T00:00:01Z");
        store
            .put_foreign(
                "fed:qsol:peer-a",
                object,
                Some(&first),
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:02Z",
            )
            .unwrap();
        store
            .put_foreign(
                "fed:qsol:peer-b",
                object,
                Some(&second),
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:03Z",
            )
            .unwrap();
        let records = store.foreign_records(&id).unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].1.provenance_id, records[1].1.provenance_id);
        assert!(store.foreign_record(&id).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn local_descendant_points_back_to_foreign_parent() {
        let root = temp_root("descendant");
        let store = FederationObjectStore::open(&root).unwrap();
        let foreign = br#"{"foreign":true}"#;
        let parent = object_id(foreign).unwrap();
        store
            .put_foreign(
                "fed:qsol:peer",
                foreign,
                None,
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:00Z",
            )
            .unwrap();
        let descendant = br#"{"local":"interpretation"}"#;
        let record = store
            .create_local_descendant(
                "fed:qsol:local",
                &parent,
                descendant,
                "2026-08-23T00:01:00Z",
            )
            .unwrap();
        let provenance: ProvenanceObject = serde_json::from_slice(
            &store
                .provenance_bytes(&record.provenance_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(provenance.parents, vec![parent]);
        assert_eq!(record.authority, "none");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn descendant_cannot_be_its_own_foreign_parent() {
        let root = temp_root("self-parent");
        let store = FederationObjectStore::open(&root).unwrap();
        let foreign = br#"{"same":true}"#;
        let parent = object_id(foreign).unwrap();
        store
            .put_foreign(
                "fed:qsol:peer",
                foreign,
                None,
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:00Z",
            )
            .unwrap();
        let error = store
            .create_local_descendant(
                "fed:qsol:local",
                &parent,
                foreign,
                "2026-08-23T00:01:00Z",
            )
            .unwrap_err();
        assert_eq!(error.0, "local_descendant_self_parent_forbidden");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn listed_records_are_validated_fail_closed() {
        let root = temp_root("list-corrupt");
        let store = FederationObjectStore::open(&root).unwrap();
        let object = br#"{"x":1}"#;
        let record = store
            .put_foreign(
                "fed:qsol:peer",
                object,
                None,
                ForeignNamespace::Foreign,
                "2026-08-23T00:00:00Z",
            )
            .unwrap();
        let attribution = attribution_id(&record).unwrap();
        let path = attribution_record_path(
            &store.root,
            ForeignNamespace::Foreign,
            &record.object_id,
            &attribution,
        )
        .unwrap();
        let mut corrupt = record.clone();
        corrupt.authority = "root".into();
        fs::write(&path, canonical_struct(&corrupt).unwrap()).unwrap();
        assert!(store.list_foreign_records(ForeignNamespace::Foreign).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_namespace_move_is_recovered_on_open() {
        let root = temp_root("move-recovery");
        let store = FederationObjectStore::open(&root).unwrap();
        let object = br#"{"move":true}"#;
        let record = store
            .put_foreign(
                "fed:qsol:peer",
                object,
                None,
                ForeignNamespace::Quarantine,
                "2026-08-23T00:00:00Z",
            )
            .unwrap();
        let attribution = attribution_id(&record).unwrap();
        let transaction = NamespaceMoveTransaction {
            schema: NAMESPACE_MOVE_SCHEMA_V1.into(),
            object_id: record.object_id.clone(),
            target: ForeignNamespace::Foreign,
            changed_at: "2026-08-23T00:01:00Z".into(),
        };
        write_exact_or_same(
            &move_transaction_path(&store.root, &record.object_id).unwrap(),
            &canonical_struct(&transaction).unwrap(),
        )
        .unwrap();
        let mut target = record.clone();
        target.namespace = ForeignNamespace::Foreign;
        target.received_at = transaction.changed_at.clone();
        write_exact_or_same(
            &attribution_record_path(
                &store.root,
                ForeignNamespace::Foreign,
                &record.object_id,
                &attribution,
            )
            .unwrap(),
            &canonical_struct(&target).unwrap(),
        )
        .unwrap();
        drop(store);

        let reopened = FederationObjectStore::open(&root).unwrap();
        let records = reopened.foreign_records(&record.object_id).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, ForeignNamespace::Foreign);
        assert!(!move_transaction_path(&reopened.root, &record.object_id)
            .unwrap()
            .exists());
        let _ = fs::remove_dir_all(root);
    }
}
