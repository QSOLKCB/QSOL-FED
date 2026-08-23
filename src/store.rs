//! Phase 4 content-addressed Federation object storage.
//!
//! Foreign bytes remain foreign. Storage location, import, and local derivation
//! never create local authority.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, object_id};
use crate::wire::{is_node_id, is_sha256_ref, is_wire_timestamp, ProvenanceObject, ProvenanceRelation, PROVENANCE_SCHEMA_V1};

pub const FOREIGN_RECORD_SCHEMA_V1: &str = "qsol-fed-foreign-object/1";
pub const LOCAL_DESCENDANT_SCHEMA_V1: &str = "qsol-fed-local-descendant/1";

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

pub struct FederationObjectStore {
    root: PathBuf,
}

impl FederationObjectStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|error| StoreError(format!("store_root_create:{error}")))?;
        let root = fs::canonicalize(root).map_err(|error| StoreError(format!("store_root_canonicalize:{error}")))?;
        for directory in ["objects", "provenance", "foreign", "quarantine", "descendants"] {
            fs::create_dir_all(root.join(directory))
                .map_err(|error| StoreError(format!("store_namespace_create:{directory}:{error}")))?;
        }
        Ok(Self { root })
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
        let record_bytes = canonical_struct(&record)?;
        let path = record_path(&self.root, namespace, &object_ref)?;
        write_exact_or_same(&path, &record_bytes)?;
        Ok(record)
    }

    pub fn move_namespace(
        &self,
        object_ref: &str,
        target: ForeignNamespace,
        changed_at: &str,
    ) -> Result<ForeignObjectRecord, StoreError> {
        if !is_sha256_ref(object_ref) || !valid_timestamp(changed_at) {
            return Err(StoreError("namespace_move_invalid".into()));
        }
        let (source_namespace, mut record) = self
            .foreign_record(object_ref)?
            .ok_or_else(|| StoreError("foreign_record_not_found".into()))?;
        if source_namespace == target {
            return Ok(record);
        }
        record.namespace = target;
        record.received_at = changed_at.into();
        let target_path = record_path(&self.root, target, object_ref)?;
        write_exact_or_same(&target_path, &canonical_struct(&record)?)?;
        let source_path = record_path(&self.root, source_namespace, object_ref)?;
        fs::remove_file(&source_path).map_err(|error| StoreError(format!("namespace_remove_old:{error}")))?;
        sync_parent(&source_path)?;
        Ok(record)
    }

    pub fn create_local_descendant(
        &self,
        local_node: &str,
        parent_foreign_object: &str,
        local_object_bytes: &[u8],
        created_at: &str,
    ) -> Result<LocalDescendantRecord, StoreError> {
        if !is_node_id(local_node) || !is_sha256_ref(parent_foreign_object) || !valid_timestamp(created_at) {
            return Err(StoreError("local_descendant_identity_or_time_invalid".into()));
        }
        self.foreign_record(parent_foreign_object)?
            .ok_or_else(|| StoreError("local_descendant_parent_not_foreign".into()))?;
        require_exact_canonical(local_object_bytes)?;
        let descendant_id = object_id(local_object_bytes).map_err(|error| StoreError(error.0))?;
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
        write_content_addressed(&self.root.join("provenance"), &provenance_id, &provenance_bytes)?;

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

    pub fn foreign_record(
        &self,
        object_ref: &str,
    ) -> Result<Option<(ForeignNamespace, ForeignObjectRecord)>, StoreError> {
        if !is_sha256_ref(object_ref) {
            return Err(StoreError("foreign_record_id_invalid".into()));
        }
        let mut found = None;
        for namespace in [ForeignNamespace::Foreign, ForeignNamespace::Quarantine] {
            let path = record_path(&self.root, namespace, object_ref)?;
            if !path.exists() {
                continue;
            }
            let raw = fs::read(&path).map_err(|error| StoreError(format!("foreign_record_read:{error}")))?;
            require_exact_canonical(&raw)?;
            let record: ForeignObjectRecord = serde_json::from_slice(&raw)
                .map_err(|error| StoreError(format!("foreign_record_schema:{error}")))?;
            if record.schema != FOREIGN_RECORD_SCHEMA_V1
                || record.object_id != object_ref
                || record.namespace != namespace
                || record.authority != "none"
                || !is_node_id(&record.source_node)
                || !valid_timestamp(&record.received_at)
                || record.provenance_id.as_deref().is_some_and(|id| !is_sha256_ref(id))
            {
                return Err(StoreError("foreign_record_corrupt".into()));
            }
            if found.is_some() {
                return Err(StoreError("foreign_record_in_multiple_namespaces".into()));
            }
            found = Some((namespace, record));
        }
        Ok(found)
    }

    pub fn list_foreign_records(
        &self,
        namespace: ForeignNamespace,
    ) -> Result<Vec<ForeignObjectRecord>, StoreError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.root.join(namespace.directory()))
            .map_err(|error| StoreError(format!("foreign_list:{error}")))?
        {
            let entry = entry.map_err(|error| StoreError(format!("foreign_list_entry:{error}")))?;
            if !entry.file_type().map_err(|error| StoreError(format!("foreign_list_type:{error}")))?.is_file() {
                continue;
            }
            let raw = fs::read(entry.path()).map_err(|error| StoreError(format!("foreign_list_read:{error}")))?;
            require_exact_canonical(&raw)?;
            let record: ForeignObjectRecord = serde_json::from_slice(&raw)
                .map_err(|error| StoreError(format!("foreign_list_schema:{error}")))?;
            records.push(record);
        }
        records.sort_by(|a, b| a.object_id.cmp(&b.object_id));
        Ok(records)
    }
}

fn valid_timestamp(value: &str) -> bool {
    is_wire_timestamp(value) && DateTime::parse_from_rfc3339(value).is_ok()
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

fn record_path(root: &Path, namespace: ForeignNamespace, reference: &str) -> Result<PathBuf, StoreError> {
    record_path_named(&root.join(namespace.directory()), reference)
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
    if path.exists() {
        let existing = fs::read(path).map_err(|error| StoreError(format!("store_existing_read:{error}")))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(StoreError("content_address_collision_or_metadata_conflict".into()));
    }
    let file_name = path.file_name().and_then(|value| value.to_str())
        .ok_or_else(|| StoreError("store_filename_invalid".into()))?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary)
        .map_err(|error| StoreError(format!("store_temp_open:{error}")))?;
    file.write_all(bytes).map_err(|error| StoreError(format!("store_write:{error}")))?;
    file.flush().map_err(|error| StoreError(format!("store_flush:{error}")))?;
    file.sync_all().map_err(|error| StoreError(format!("store_fsync:{error}")))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| StoreError(format!("store_rename:{error}")))?;
    sync_parent(path)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), StoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent).map_err(|error| StoreError(format!("store_parent_open:{error}")))?;
    directory.sync_all().map_err(|error| StoreError(format!("store_parent_fsync:{error}")))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError("store_parent_fsync_unsupported_platform".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("qsol-fed-store-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn foreign_bytes_and_provenance_are_preserved_exactly() {
        let root = temp_root("foreign");
        let store = FederationObjectStore::open(&root).unwrap();
        let object = br#"{"kind":"observation","value":7}"#;
        let id = object_id(object).unwrap();
        let provenance = format!("{{\"created_at\":\"2026-08-23T00:00:00Z\",\"parents\":[],\"relation\":\"transported\",\"schema\":\"qsol-fed-provenance/1\",\"source_node\":\"fed:qsol:peer\",\"source_object\":\"{id}\"}}");
        let record = store.put_foreign("fed:qsol:peer", object, Some(provenance.as_bytes()), ForeignNamespace::Quarantine, "2026-08-23T00:00:01Z").unwrap();
        assert_eq!(record.authority, "none");
        assert_eq!(store.object_bytes(&id).unwrap().unwrap(), object);
        assert_eq!(store.provenance_bytes(record.provenance_id.as_ref().unwrap()).unwrap().unwrap(), provenance.as_bytes());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn local_descendant_points_back_to_foreign_parent() {
        let root = temp_root("descendant");
        let store = FederationObjectStore::open(&root).unwrap();
        let foreign = br#"{"foreign":true}"#;
        let parent = object_id(foreign).unwrap();
        store.put_foreign("fed:qsol:peer", foreign, None, ForeignNamespace::Foreign, "2026-08-23T00:00:00Z").unwrap();
        let descendant = br#"{"local":"interpretation"}"#;
        let record = store.create_local_descendant("fed:qsol:local", &parent, descendant, "2026-08-23T00:01:00Z").unwrap();
        let provenance: ProvenanceObject = serde_json::from_slice(&store.provenance_bytes(&record.provenance_id).unwrap().unwrap()).unwrap();
        assert_eq!(provenance.parents, vec![parent]);
        assert_eq!(record.authority, "none");
        let _ = fs::remove_dir_all(root);
    }
}
