use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::DateTime;

use crate::wire::{is_sha256_ref, is_wire_timestamp};

pub const MAX_REPLAY_LOG_BYTES: u64 = 64 * 1024 * 1024;

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
        if let Some(registry) = OPEN_REPLAY_PATHS.get()
            && let Ok(mut open_paths) = registry.lock()
        {
            open_paths.remove(&self.key);
        }
    }
}

fn replay_path_key(path: &Path) -> Result<PathBuf, ReplayError> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|error| ReplayError(format!("replay_path_canonicalize:{error}")));
    }
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| ReplayError(format!("replay_parent_canonicalize:{error}")))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ReplayError("replay_path_missing_filename".into()))?;
    Ok(canonical_parent.join(file_name))
}

fn valid_replay_timestamp(value: &str) -> bool {
    is_wire_timestamp(value) && DateTime::parse_from_rfc3339(value).is_ok()
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ReplayError> {
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
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

/// Single-process durable replay store for Phase 2.
///
/// Each accepted message is appended as `<message_id>\t<seen_at>\n`, flushed,
/// and fsynced before `FreshRecorded` is returned. New replay-log directory
/// entries are fsynced before the store can report freshness. A malformed,
/// duplicate, or partial existing log fails closed on open. Exactly one live
/// store handle per canonical path is allowed in a process. This type deliberately
/// makes no multi-process locking claim; network-service concurrency belongs to Phase 3.
pub struct DurableReplayStore {
    path: PathBuf,
    file: File,
    seen: HashSet<String>,
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
        let mut seen = HashSet::new();
        for (index, line) in text.lines().enumerate() {
            let Some((message_id, seen_at)) = line.split_once('\t') else {
                return Err(ReplayError(format!(
                    "replay_log_malformed_line:{}",
                    index + 1
                )));
            };
            if message_id.contains('\t')
                || seen_at.contains('\t')
                || !is_sha256_ref(message_id)
                || !valid_replay_timestamp(seen_at)
            {
                return Err(ReplayError(format!(
                    "replay_log_invalid_line:{}",
                    index + 1
                )));
            }
            if !seen.insert(message_id.to_owned()) {
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
        self.seen.contains(message_id)
    }

    pub fn check_and_record(
        &mut self,
        message_id: &str,
        seen_at: &str,
    ) -> Result<ReplayDecision, ReplayError> {
        if !is_sha256_ref(message_id) || !valid_replay_timestamp(seen_at) {
            return Err(ReplayError("replay_record_invalid".into()));
        }
        if self.seen.contains(message_id) {
            return Ok(ReplayDecision::Replay);
        }
        let record = format!("{message_id}\t{seen_at}\n");
        let current = self
            .file
            .metadata()
            .map_err(|error| ReplayError(format!("replay_metadata:{error}")))?
            .len();
        if current.saturating_add(record.len() as u64) > MAX_REPLAY_LOG_BYTES {
            return Err(ReplayError("replay_log_too_large".into()));
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
        self.seen.insert(message_id.to_owned());
        Ok(ReplayDecision::FreshRecorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
    fn partial_or_duplicate_log_fails_closed() {
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
    }

    #[test]
    fn impossible_calendar_timestamps_fail_closed() {
        let path = temp_path("calendar");
        let message_id = format!("sha256:{}", "d".repeat(64));
        {
            let mut store = DurableReplayStore::open(&path).unwrap();
            assert!(store
                .check_and_record(&message_id, "2026-99-99T99:99:99Z")
                .is_err());
        }
        fs::write(
            &path,
            format!("{message_id}\t2026-99-99T99:99:99Z\n"),
        )
        .unwrap();
        assert!(DurableReplayStore::open(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn only_one_store_handle_per_path_is_allowed() {
        let path = temp_path("single-handle");
        let first = DurableReplayStore::open(&path).unwrap();
        let second = DurableReplayStore::open(&path).unwrap_err();
        assert_eq!(second.0, "replay_store_already_open");
        drop(first);
        let reopened = DurableReplayStore::open(&path).unwrap();
        drop(reopened);
        let _ = fs::remove_file(path);
    }
}
