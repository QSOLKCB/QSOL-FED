use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};

use crate::wire::{is_sha256_ref, is_wire_timestamp};
use crate::{MAX_CLOCK_SKEW_SECONDS, MAX_SIGNED_MESSAGE_LIFETIME_SECONDS};

pub const MAX_REPLAY_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const REPLAY_COMPACTION_THRESHOLD_BYTES: u64 = 1024 * 1024;
pub const REPLAY_RETENTION_SECONDS: i64 =
    MAX_SIGNED_MESSAGE_LIFETIME_SECONDS + (2 * MAX_CLOCK_SKEW_SECONDS);

static OPEN_REPLAY_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayError(pub String);

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReplayError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    FreshRecorded,
    Replay,
}

#[derive(Debug, Clone)]
struct SeenRecord {
    seen_at: String,
    unix: i64,
}

struct ReplayPathClaim {
    key: PathBuf,
}

impl ReplayPathClaim {
    fn acquire(path: &Path) -> Result<Self, ReplayError> {
        let key = replay_path_key(path)?;
        let registry = OPEN_REPLAY_PATHS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut open_paths = registry
            .lock()
            .map_err(|_| ReplayError("replay_path_registry_poisoned".into()))?;
        if !open_paths.insert(key.clone()) {
            return Err(ReplayError("replay_store_already_open".into()));
        }
        Ok(Self { key })
    }
}

impl Drop for ReplayPathClaim {
    fn drop(&mut self) {
        if let Some(registry) = OPEN_REPLAY_PATHS.get() {
            if let Ok(mut open_paths) = registry.lock() {
                open_paths.remove(&self.key);
            }
        }
    }
}

fn replay_path_key(path: &Path) -> Result<PathBuf, ReplayError> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|error| ReplayError(format!("replay_path_canonicalize:{error}")));
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| ReplayError(format!("replay_parent_canonicalize:{error}")))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ReplayError("replay_path_missing_filename".into()))?;
    Ok(canonical_parent.join(file_name))
}

fn parse_replay_timestamp(value: &str) -> Result<i64, ReplayError> {
    if !is_wire_timestamp(value) {
        return Err(ReplayError("replay_timestamp_invalid_syntax".into()));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.timestamp())
        .map_err(|_| ReplayError("replay_timestamp_invalid_calendar".into()))
}

fn format_replay_timestamp(timestamp: i64) -> Result<String, ReplayError> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .ok_or_else(|| ReplayError("replay_timestamp_out_of_range".into()))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ReplayError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)
        .map_err(|error| ReplayError(format!("replay_parent_open:{error}")))?;
    directory
        .sync_all()
        .map_err(|error| ReplayError(format!("replay_parent_fsync:{error}")))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), ReplayError> {
    Err(ReplayError(
        "replay_parent_directory_fsync_unsupported_platform".into(),
    ))
}

/// Single-process durable replay store.
///
/// Records are retained for the complete interval in which a signed Phase 2
/// message could still pass the frozen lifetime/skew policy. Older records are
/// safely pruned because authentication rejects those messages before replay
/// admission. The append log is atomically compacted and fsynced before it can
/// approach the hard 64 MiB ceiling.
pub struct DurableReplayStore {
    path: PathBuf,
    file: File,
    seen: HashMap<String, SeenRecord>,
    _path_claim: ReplayPathClaim,
}

impl DurableReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayError> {
        let path = path.as_ref().to_path_buf();
        let path_claim = ReplayPathClaim::acquire(&path)?;
        let existed_before_open = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|error| ReplayError(format!("replay_open:{error}")))?;
        if !existed_before_open {
            sync_parent_directory(&path)?;
        }
        let metadata = file
            .metadata()
            .map_err(|error| ReplayError(format!("replay_metadata:{error}")))?;
        if metadata.len() > MAX_REPLAY_LOG_BYTES {
            return Err(ReplayError("replay_log_too_large".into()));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| ReplayError(format!("replay_read:{error}")))?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(ReplayError("replay_log_partial_tail".into()));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ReplayError("replay_log_invalid_utf8".into()))?;
        let mut seen = HashMap::new();
        for (index, line) in text.lines().enumerate() {
            let Some((message_id, seen_at)) = line.split_once('\t') else {
                return Err(ReplayError(format!(
                    "replay_log_malformed_line:{}",
                    index + 1
                )));
            };
            if message_id.contains('\t') || seen_at.contains('\t') || !is_sha256_ref(message_id) {
                return Err(ReplayError(format!(
                    "replay_log_invalid_line:{}",
                    index + 1
                )));
            }
            let unix = parse_replay_timestamp(seen_at)
                .map_err(|_| ReplayError(format!("replay_log_invalid_line:{}", index + 1)))?;
            if seen
                .insert(
                    message_id.to_owned(),
                    SeenRecord {
                        seen_at: seen_at.to_owned(),
                        unix,
                    },
                )
                .is_some()
            {
                return Err(ReplayError(format!("replay_log_duplicate:{}", index + 1)));
            }
        }
        Ok(Self {
            path,
            file,
            seen,
            _path_claim: path_claim,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn contains(&self, message_id: &str) -> bool {
        self.seen.contains_key(message_id)
    }

    fn prune_memory(&mut self, now_unix: i64) {
        let cutoff = now_unix.saturating_sub(REPLAY_RETENTION_SECONDS);
        self.seen.retain(|_, record| record.unix >= cutoff);
    }

    fn compact(&mut self, now_unix: i64) -> Result<(), ReplayError> {
        self.prune_memory(now_unix);
        let mut entries: Vec<_> = self.seen.iter().collect();
        entries.sort_by(|left, right| left.0.cmp(right.0));

        let file_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ReplayError("replay_compaction_filename_invalid".into()))?;
        let temporary = self.path.with_file_name(format!(".{file_name}.compact.tmp"));
        let _ = fs::remove_file(&temporary);
        let mut compacted = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| ReplayError(format!("replay_compaction_open:{error}")))?;
        for (message_id, record) in entries {
            compacted
                .write_all(format!("{message_id}\t{}\n", record.seen_at).as_bytes())
                .map_err(|error| ReplayError(format!("replay_compaction_write:{error}")))?;
        }
        compacted
            .flush()
            .map_err(|error| ReplayError(format!("replay_compaction_flush:{error}")))?;
        compacted
            .sync_all()
            .map_err(|error| ReplayError(format!("replay_compaction_fsync:{error}")))?;
        drop(compacted);

        fs::rename(&temporary, &self.path)
            .map_err(|error| ReplayError(format!("replay_compaction_rename:{error}")))?;
        sync_parent_directory(&self.path)?;
        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| ReplayError(format!("replay_compaction_reopen:{error}")))?;
        Ok(())
    }

    pub fn check_and_record(
        &mut self,
        message_id: &str,
        seen_at: &str,
    ) -> Result<ReplayDecision, ReplayError> {
        if !is_sha256_ref(message_id) {
            return Err(ReplayError("replay_record_invalid".into()));
        }
        let now_unix = parse_replay_timestamp(seen_at)?;
        self.prune_memory(now_unix);
        if self.seen.contains_key(message_id) {
            return Ok(ReplayDecision::Replay);
        }

        let record = format!("{message_id}\t{seen_at}\n");
        let mut current = self
            .file
            .metadata()
            .map_err(|error| ReplayError(format!("replay_metadata:{error}")))?
            .len();
        if current >= REPLAY_COMPACTION_THRESHOLD_BYTES
            || current.saturating_add(record.len() as u64) > MAX_REPLAY_LOG_BYTES
        {
            self.compact(now_unix)?;
            current = self
                .file
                .metadata()
                .map_err(|error| ReplayError(format!("replay_metadata:{error}")))?
                .len();
        }
        if current.saturating_add(record.len() as u64) > MAX_REPLAY_LOG_BYTES {
            return Err(ReplayError("replay_active_window_too_large".into()));
        }

        self.file
            .write_all(record.as_bytes())
            .map_err(|error| ReplayError(format!("replay_write:{error}")))?;
        self.file
            .flush()
            .map_err(|error| ReplayError(format!("replay_flush:{error}")))?;
        self.file
            .sync_all()
            .map_err(|error| ReplayError(format!("replay_fsync:{error}")))?;
        self.seen.insert(
            message_id.to_owned(),
            SeenRecord {
                seen_at: format_replay_timestamp(now_unix)?,
                unix: now_unix,
            },
        );
        Ok(ReplayDecision::FreshRecorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "qsol-fed-{label}-{}-{nonce}.log",
            std::process::id()
        ))
    }

    #[test]
    fn replay_survives_restart() {
        let path = temp_path("replay");
        let message_id = format!("sha256:{}", "a".repeat(64));
        {
            let mut store = DurableReplayStore::open(&path).unwrap();
            assert_eq!(
                store
                    .check_and_record(&message_id, "2026-08-23T00:00:00Z")
                    .unwrap(),
                ReplayDecision::FreshRecorded
            );
            assert_eq!(
                store
                    .check_and_record(&message_id, "2026-08-23T00:00:01Z")
                    .unwrap(),
                ReplayDecision::Replay
            );
        }
        let mut reopened = DurableReplayStore::open(&path).unwrap();
        assert!(reopened.contains(&message_id));
        assert_eq!(
            reopened
                .check_and_record(&message_id, "2026-08-23T00:00:02Z")
                .unwrap(),
            ReplayDecision::Replay
        );
        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn partial_duplicate_and_impossible_timestamps_fail_closed() {
        let partial = temp_path("partial");
        fs::write(
            &partial,
            format!("sha256:{}\t2026-08-23T00:00:00Z", "b".repeat(64)),
        )
        .unwrap();
        assert!(DurableReplayStore::open(&partial).is_err());
        let _ = fs::remove_file(partial);

        let duplicate = temp_path("duplicate");
        let line = format!("sha256:{}\t2026-08-23T00:00:00Z\n", "c".repeat(64));
        fs::write(&duplicate, format!("{line}{line}")).unwrap();
        assert!(DurableReplayStore::open(&duplicate).is_err());
        let _ = fs::remove_file(duplicate);

        let calendar = temp_path("calendar");
        fs::write(
            &calendar,
            format!("sha256:{}\t2026-99-99T99:99:99Z\n", "d".repeat(64)),
        )
        .unwrap();
        assert!(DurableReplayStore::open(&calendar).is_err());
        let _ = fs::remove_file(calendar);
    }

    #[test]
    fn only_one_store_handle_per_path_is_allowed() {
        let path = temp_path("single-handle");
        let first = DurableReplayStore::open(&path).unwrap();
        let second = DurableReplayStore::open(&path).err().unwrap();
        assert_eq!(second.0, "replay_store_already_open");
        drop(first);
        let reopened = DurableReplayStore::open(&path).unwrap();
        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_replay_records_are_pruned_and_compacted_durably() {
        let path = temp_path("compaction");
        let old_id = format!("sha256:{}", "e".repeat(64));
        let fresh_id = format!("sha256:{}", "f".repeat(64));
        let filler = format!("sha256:{}\t2026-08-22T20:00:00Z\n", "1".repeat(64));
        let mut contents = String::new();
        contents.push_str(&format!("{old_id}\t2026-08-22T20:00:00Z\n"));
        while contents.len() < REPLAY_COMPACTION_THRESHOLD_BYTES as usize {
            let index = contents.len() / filler.len();
            let digest = format!("{index:064x}");
            contents.push_str(&format!("sha256:{digest}\t2026-08-22T20:00:00Z\n"));
        }
        fs::write(&path, contents).unwrap();
        {
            let mut store = DurableReplayStore::open(&path).unwrap();
            assert_eq!(
                store
                    .check_and_record(&fresh_id, "2026-08-23T00:00:00Z")
                    .unwrap(),
                ReplayDecision::FreshRecorded
            );
            assert!(!store.contains(&old_id));
        }
        let compacted = fs::read_to_string(&path).unwrap();
        assert!(compacted.contains(&fresh_id));
        assert!(!compacted.contains(&old_id));
        assert!(compacted.len() < REPLAY_COMPACTION_THRESHOLD_BYTES as usize);
        let _ = fs::remove_file(path);
    }
}
