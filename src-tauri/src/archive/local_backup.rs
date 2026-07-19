use super::database::ArchiveDatabase;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_PREFIX: &str = "archive-";
const DATABASE_FILE: &str = "conversation-archive.db";
const KEY_FILE: &str = "conversation-archive.key";
const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_KEY_BYTES: u64 = 512;
const MAX_RETENTION: usize = 10_000;
const RESTORE_JOURNAL_VERSION: u32 = 1;
const RESTORE_PREPARED_FILE: &str = ".conversation-archive.restore-journal.json";
const RESTORE_COMMITTED_FILE: &str = ".conversation-archive.restore-committed.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalArchiveSnapshotSummary {
    pub(crate) id: String,
    /// UTC Unix timestamp in milliseconds.
    pub(crate) created_at: i64,
    pub(crate) database_size_bytes: u64,
    pub(crate) total_size_bytes: u64,
    pub(crate) includes_key: bool,
    pub(crate) directory: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifest {
    schema_version: u32,
    snapshot_id: String,
    created_at: i64,
    database: SnapshotArtifact,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<SnapshotArtifact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotArtifact {
    file_name: String,
    size_bytes: u64,
    sha256: String,
}

struct InspectedSnapshot {
    summary: LocalArchiveSnapshotSummary,
    database_path: PathBuf,
    bundled_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveRestoreRecovery {
    None,
    RolledBack,
    CommittedCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestoreJournalState {
    Prepared,
    Committed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    schema_version: u32,
    transaction_id: String,
    state: RestoreJournalState,
    includes_managed_key: bool,
    database_had_existing: bool,
    key_had_existing: bool,
    wal_had_existing: bool,
    shm_had_existing: bool,
}

/// Create and atomically publish a transactionally consistent SQLCipher
/// recovery bundle. `include_key` intentionally applies equally to managed and
/// environment-provided keys: an included key makes this directory equivalent
/// to plaintext access and therefore requires restrictive permissions.
pub(crate) fn create_local_archive_snapshot(
    root: &Path,
    retention: usize,
    include_key: bool,
    database: &ArchiveDatabase,
    key: &[u8; 32],
) -> Result<LocalArchiveSnapshotSummary, String> {
    validate_retention(retention)?;
    let root = ensure_snapshot_root(root)?;
    let created_at = chrono::Utc::now().timestamp_millis();
    let snapshot_id = format!("{SNAPSHOT_PREFIX}{created_at}-{}", Uuid::new_v4());
    validate_snapshot_id(&snapshot_id)?;
    let target = root.join(&snapshot_id);

    let temporary = tempfile::Builder::new()
        .prefix(".archive-snapshot-")
        .tempdir_in(&root)
        .map_err(|error| format!("创建本地归档快照临时目录失败: {error}"))?;
    set_directory_permissions(temporary.path())?;

    let snapshot_database_path = temporary.path().join(DATABASE_FILE);
    database.encrypted_snapshot_to_path_with_key(&snapshot_database_path, key)?;
    let (database_size, database_sha256) = hash_secure_file(&snapshot_database_path)?;
    let database_artifact = SnapshotArtifact {
        file_name: DATABASE_FILE.to_string(),
        size_bytes: database_size,
        sha256: database_sha256,
    };
    // Validate before publishing. A failure leaves only the auto-cleaned
    // temporary directory and never exposes a partial snapshot in the list.
    ArchiveDatabase::validate_encrypted_file(&snapshot_database_path, key)?;

    let key_artifact = if include_key {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        Some(write_artifact(
            &temporary.path().join(KEY_FILE),
            KEY_FILE,
            encoded.as_bytes(),
        )?)
    } else {
        None
    };
    let manifest = SnapshotManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        snapshot_id: snapshot_id.clone(),
        created_at,
        database: database_artifact,
        key: key_artifact,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("序列化本地归档快照清单失败: {error}"))?;
    write_secure_file(&temporary.path().join(MANIFEST_FILE), &manifest_bytes)?;
    sync_directory(temporary.path())?;

    let temporary_path = temporary.keep();
    if let Err(error) = std::fs::rename(&temporary_path, &target) {
        let _ = std::fs::remove_dir_all(&temporary_path);
        return Err(format!("发布本地归档快照失败: {error}"));
    }
    sync_directory(&root)?;

    let inspected = inspect_snapshot_directory(&target, &snapshot_id, Some(key), true)?;
    let summary = inspected.summary;
    prune_local_archive_snapshots(&root, retention)?;
    Ok(summary)
}

/// List only complete, recognized bundles. Unrelated directories and damaged
/// bundles are intentionally ignored so retention cleanup can never infer that
/// they are safe to delete.
pub(crate) fn list_local_archive_snapshots(
    root: &Path,
) -> Result<Vec<LocalArchiveSnapshotSummary>, String> {
    let Some(root) = open_snapshot_root(root)? else {
        return Ok(Vec::new());
    };
    let mut snapshots = Vec::new();
    let entries =
        std::fs::read_dir(&root).map_err(|error| format!("读取本地归档快照目录失败: {error}"))?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(snapshot_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_snapshot_id(&snapshot_id).is_err() {
            continue;
        }
        let path = entry.path();
        if let Ok(inspected) = inspect_snapshot_directory(&path, &snapshot_id, None, false) {
            snapshots.push(inspected.summary);
        }
    }
    snapshots.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    Ok(snapshots)
}

/// List snapshot summaries using manifests and file metadata only. This is
/// suitable for UI rendering; any destructive or restore operation still uses
/// the strict SHA-256 validator above immediately before acting.
pub(crate) fn list_local_archive_snapshot_metadata(
    root: &Path,
) -> Result<Vec<LocalArchiveSnapshotSummary>, String> {
    let Some(root) = open_snapshot_root(root)? else {
        return Ok(Vec::new());
    };
    let mut snapshots = Vec::new();
    for entry in
        std::fs::read_dir(&root).map_err(|error| format!("读取本地归档快照目录失败: {error}"))?
    {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(snapshot_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_snapshot_id(&snapshot_id).is_err() {
            continue;
        }
        if let Ok(summary) = inspect_snapshot_metadata(&entry.path(), &snapshot_id) {
            snapshots.push(summary);
        }
    }
    snapshots.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    Ok(snapshots)
}

/// Cheap status probe used by the regular health endpoint. Full artifact
/// hashing and SQLCipher validation remain mandatory for list/delete/restore,
/// but must not turn each UI health refresh into 30 full database reads.
pub(crate) fn latest_local_archive_snapshot_timestamp(root: &Path) -> Result<Option<i64>, String> {
    Ok(list_local_archive_snapshot_metadata(root)?
        .into_iter()
        .map(|snapshot| snapshot.created_at)
        .max())
}

/// Verify the manifest, artifact hashes, bundled/fallback key and SQLCipher
/// integrity without changing the live archive.
pub(crate) fn validate_local_archive_snapshot(
    root: &Path,
    snapshot_id: &str,
    fallback_key: Option<&[u8; 32]>,
) -> Result<LocalArchiveSnapshotSummary, String> {
    let path = resolve_snapshot_directory(root, snapshot_id)?;
    inspect_snapshot_directory(&path, snapshot_id, fallback_key, true)
        .map(|snapshot| snapshot.summary)
}

/// Permanently remove one complete recognized bundle. The directory is first
/// renamed within its root, preventing a concurrent replacement at the public
/// snapshot ID from being recursively removed.
pub(crate) fn delete_local_archive_snapshot(root: &Path, snapshot_id: &str) -> Result<(), String> {
    let root = open_snapshot_root(root)?.ok_or_else(|| "本地归档快照目录不存在".to_string())?;
    let path = resolve_snapshot_directory_in_root(&root, snapshot_id)?;
    inspect_snapshot_directory(&path, snapshot_id, None, false)?;

    let quarantine = root.join(format!(".deleted-{}", Uuid::new_v4()));
    std::fs::rename(&path, &quarantine)
        .map_err(|error| format!("隔离待删除本地归档快照失败: {error}"))?;
    let metadata = std::fs::symlink_metadata(&quarantine)
        .map_err(|error| format!("校验待删除本地归档快照失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        let _ = std::fs::rename(&quarantine, &path);
        return Err("待删除本地归档快照在删除前被替换".to_string());
    }
    std::fs::remove_dir_all(&quarantine)
        .map_err(|error| format!("删除本地归档快照失败: {error}"))?;
    sync_directory(&root)
}

/// Enforce retention using only snapshots accepted by the strict manifest and
/// hash validator. Foreign and damaged directories are never deleted.
pub(crate) fn prune_local_archive_snapshots(
    root: &Path,
    retention: usize,
) -> Result<Vec<String>, String> {
    validate_retention(retention)?;
    let snapshots = list_local_archive_snapshots(root)?;
    let mut deleted = Vec::new();
    for snapshot in snapshots.into_iter().skip(retention) {
        delete_local_archive_snapshot(root, &snapshot.id)?;
        deleted.push(snapshot.id);
    }
    Ok(deleted)
}

/// Restore a validated snapshot to explicit live paths. When
/// `target_managed_key` is `None`, the caller is using an external/environment
/// key and a bundled different key is rejected. With a managed target, a
/// bundled key and database are replaced as one rollback-capable transaction.
/// The caller must ensure no live database connection or capture stream exists.
pub(crate) fn restore_local_archive_snapshot(
    root: &Path,
    snapshot_id: &str,
    target_database: &Path,
    target_managed_key: Option<&Path>,
    current_key: &[u8; 32],
) -> Result<LocalArchiveSnapshotSummary, String> {
    let snapshot_path = resolve_snapshot_directory(root, snapshot_id)?;
    let inspected =
        inspect_snapshot_directory(&snapshot_path, snapshot_id, Some(current_key), true)?;
    let restore_key = inspected.bundled_key.unwrap_or(*current_key);
    if target_managed_key.is_none()
        && inspected
            .bundled_key
            .is_some_and(|bundled| bundled != *current_key)
    {
        return Err("快照密钥与当前环境变量密钥不一致；环境变量模式下不会覆盖部署密钥".to_string());
    }

    let target_database = normalize_absolute_path(target_database)?;
    let target_managed_key = target_managed_key
        .map(normalize_absolute_path)
        .transpose()?;
    if target_database.starts_with(&snapshot_path)
        || target_managed_key
            .as_ref()
            .is_some_and(|path| path.starts_with(&snapshot_path))
    {
        return Err("归档恢复目标不得位于待恢复快照目录内".to_string());
    }
    if target_managed_key.as_ref() == Some(&target_database) {
        return Err("归档数据库与托管密钥恢复目标不得相同".to_string());
    }

    let database_parent = prepare_target_parent(&target_database, false)?;
    validate_replace_target(&target_database)?;
    let staged_database = stage_copy(
        &inspected.database_path,
        &database_parent,
        ".conversation-archive.restore-db-",
    )?;
    if let Err(error) = ArchiveDatabase::validate_encrypted_file(&staged_database, &restore_key) {
        let _ = std::fs::remove_file(&staged_database);
        return Err(error);
    }

    let staged_key =
        if let (Some(key_target), Some(_)) = (target_managed_key.as_ref(), inspected.bundled_key) {
            let result = (|| {
                let key_parent = prepare_target_parent(key_target, true)?;
                validate_replace_target(key_target)?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(restore_key);
                let staged = stage_bytes(
                    &encoded.into_bytes(),
                    &key_parent,
                    ".conversation-archive.restore-key-",
                )?;
                Ok::<_, String>(Some((key_target.clone(), staged)))
            })();
            match result {
                Ok(staged) => staged,
                Err(error) => {
                    let _ = std::fs::remove_file(&staged_database);
                    return Err(error);
                }
            }
        } else {
            None
        };

    let recovery_managed_key = target_managed_key.clone().unwrap_or_else(|| {
        target_database
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("secrets")
            .join(KEY_FILE)
    });
    let staged_key_path = staged_key.as_ref().map(|(_, staged)| staged.as_path());
    let result = install_restore_files_durably(
        &staged_database,
        staged_key_path,
        &target_database,
        &recovery_managed_key,
    );
    if result.is_err() {
        let _ = std::fs::remove_file(&staged_database);
        if let Some((_, staged)) = staged_key.as_ref() {
            let _ = std::fs::remove_file(staged);
        }
    }
    result?;
    Ok(inspected.summary)
}

fn auxiliary_database_path(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

struct DurableReplacement {
    target: PathBuf,
    staged: Option<PathBuf>,
    backup: PathBuf,
    had_existing: bool,
}

/// Recover an interrupted local or remote archive restore before opening the
/// SQLCipher database. Journal data never supplies paths: every path is derived
/// from these two fixed application targets and a canonical UUID.
pub(crate) fn recover_interrupted_archive_restore(
    target_database: &Path,
    managed_key_path: &Path,
) -> Result<ArchiveRestoreRecovery, String> {
    let (target_database, managed_key_path) =
        validate_durable_targets(target_database, managed_key_path, false)?;
    let prepared_path = restore_marker_path(&target_database, RESTORE_PREPARED_FILE)?;
    let committed_path = restore_marker_path(&target_database, RESTORE_COMMITTED_FILE)?;
    let prepared = read_restore_journal(&prepared_path)?;
    let committed = read_restore_journal(&committed_path)?;
    if prepared.is_none() && committed.is_none() {
        return Ok(ArchiveRestoreRecovery::None);
    }

    let journal = match (prepared.as_ref(), committed.as_ref()) {
        (Some(prepared), Some(committed)) => {
            validate_restore_journal(prepared, RestoreJournalState::Prepared)?;
            validate_restore_journal(committed, RestoreJournalState::Committed)?;
            let mut expected = prepared.clone();
            expected.state = RestoreJournalState::Committed;
            if &expected != committed {
                return Err("归档恢复 prepared 与 committed 日志不匹配".to_string());
            }
            committed
        }
        (None, Some(committed)) => {
            validate_restore_journal(committed, RestoreJournalState::Committed)?;
            committed
        }
        (Some(prepared), None) => {
            validate_restore_journal(prepared, RestoreJournalState::Prepared)?;
            prepared
        }
        (None, None) => unreachable!(),
    };
    let replacements = replacements_from_journal(journal, &target_database, &managed_key_path)?;
    if journal.state == RestoreJournalState::Committed {
        cleanup_committed_restore(&replacements, &prepared_path, &committed_path)?;
        Ok(ArchiveRestoreRecovery::CommittedCleanup)
    } else {
        rollback_prepared_restore(&replacements, &prepared_path, &committed_path)?;
        Ok(ArchiveRestoreRecovery::RolledBack)
    }
}

/// Install one already validated encrypted database through the same durable
/// journal used by local snapshot restores. This closes the crash gap in the
/// legacy S3/WebDAV single-database restore path.
pub(crate) fn install_archive_database_durably(
    staged_database: &Path,
    target_database: &Path,
    managed_key_path: &Path,
) -> Result<(), String> {
    install_restore_files_durably(staged_database, None, target_database, managed_key_path)
}

fn install_restore_files_durably(
    input_database: &Path,
    input_key: Option<&Path>,
    target_database: &Path,
    managed_key_path: &Path,
) -> Result<(), String> {
    let includes_key = input_key.is_some();
    let (target_database, managed_key_path) =
        validate_durable_targets(target_database, managed_key_path, includes_key)?;
    recover_interrupted_archive_restore(&target_database, &managed_key_path)?;
    let transaction_id = Uuid::new_v4().to_string();
    let journal = RestoreJournal {
        schema_version: RESTORE_JOURNAL_VERSION,
        transaction_id,
        state: RestoreJournalState::Prepared,
        includes_managed_key: includes_key,
        database_had_existing: path_exists(&target_database)?,
        key_had_existing: includes_key && path_exists(&managed_key_path)?,
        wal_had_existing: path_exists(&auxiliary_database_path(&target_database, "-wal"))?,
        shm_had_existing: path_exists(&auxiliary_database_path(&target_database, "-shm"))?,
    };
    let replacements = replacements_from_journal(&journal, &target_database, &managed_key_path)?;
    for replacement in &replacements {
        validate_replace_target(&replacement.target)?;
        if path_exists(&replacement.backup)?
            || replacement
                .staged
                .as_ref()
                .map(|path| path_exists(path))
                .transpose()?
                .unwrap_or(false)
        {
            return Err("归档恢复事务 UUID 对应的暂存或回滚文件已存在".to_string());
        }
    }
    let prepared_path = restore_marker_path(&target_database, RESTORE_PREPARED_FILE)?;
    let committed_path = restore_marker_path(&target_database, RESTORE_COMMITTED_FILE)?;
    persist_restore_journal(&prepared_path, &journal)?;

    let transaction = (|| {
        adopt_staged_file(input_database, replacements[0].staged.as_ref().unwrap())?;
        if includes_key {
            let key_input = input_key.ok_or_else(|| "归档恢复缺少密钥暂存文件".to_string())?;
            let key_entry = replacements
                .iter()
                .find(|entry| entry.target == managed_key_path)
                .ok_or_else(|| "归档恢复密钥事务条目缺失".to_string())?;
            adopt_staged_file(key_input, key_entry.staged.as_ref().unwrap())?;
        }
        for replacement in &replacements {
            if replacement.had_existing {
                std::fs::rename(&replacement.target, &replacement.backup)
                    .map_err(|error| format!("暂存现有归档恢复目标失败: {error}"))?;
            }
        }
        for replacement in &replacements {
            if let Some(staged) = replacement.staged.as_ref() {
                std::fs::rename(staged, &replacement.target)
                    .map_err(|error| format!("安装归档恢复目标失败: {error}"))?;
                set_file_permissions(&replacement.target)?;
            }
        }
        sync_replacement_parents(&replacements)?;
        let mut committed = journal.clone();
        committed.state = RestoreJournalState::Committed;
        persist_restore_journal(&committed_path, &committed)?;
        cleanup_committed_restore(&replacements, &prepared_path, &committed_path)
    })();
    if let Err(error) = transaction {
        let recovery = recover_interrupted_archive_restore(&target_database, &managed_key_path);
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(format!("{error}；自动恢复失败: {recovery_error}")),
        };
    }
    Ok(())
}

fn validate_durable_targets(
    target_database: &Path,
    managed_key_path: &Path,
    require_key_parent: bool,
) -> Result<(PathBuf, PathBuf), String> {
    let target_database = normalize_absolute_path(target_database)?;
    let managed_key_path = normalize_absolute_path(managed_key_path)?;
    if target_database.file_name().and_then(|name| name.to_str()) != Some(DATABASE_FILE)
        || managed_key_path.file_name().and_then(|name| name.to_str()) != Some(KEY_FILE)
    {
        return Err("持久化归档恢复仅允许固定数据库与密钥文件名".to_string());
    }
    if target_database == managed_key_path {
        return Err("归档数据库与密钥恢复目标不得相同".to_string());
    }
    prepare_target_parent(&target_database, false)?;
    if require_key_parent {
        prepare_target_parent(&managed_key_path, true)?;
    } else if let Some(parent) = managed_key_path.parent() {
        if parent.exists() {
            reject_symlink_components(parent)?;
        }
    }
    validate_replace_target(&target_database)?;
    validate_replace_target(&managed_key_path)?;
    Ok((target_database, managed_key_path))
}

fn replacements_from_journal(
    journal: &RestoreJournal,
    target_database: &Path,
    managed_key_path: &Path,
) -> Result<Vec<DurableReplacement>, String> {
    validate_restore_journal(journal, journal.state)?;
    let id = &journal.transaction_id;
    let mut replacements = vec![durable_replacement(
        target_database,
        true,
        journal.database_had_existing,
        id,
    )?];
    if journal.includes_managed_key {
        replacements.push(durable_replacement(
            managed_key_path,
            true,
            journal.key_had_existing,
            id,
        )?);
    }
    replacements.push(durable_replacement(
        &auxiliary_database_path(target_database, "-wal"),
        false,
        journal.wal_had_existing,
        id,
    )?);
    replacements.push(durable_replacement(
        &auxiliary_database_path(target_database, "-shm"),
        false,
        journal.shm_had_existing,
        id,
    )?);
    Ok(replacements)
}

fn durable_replacement(
    target: &Path,
    has_staged: bool,
    had_existing: bool,
    transaction_id: &str,
) -> Result<DurableReplacement, String> {
    let parent = target
        .parent()
        .ok_or_else(|| "归档恢复目标缺少父目录".to_string())?;
    let name = target
        .file_name()
        .ok_or_else(|| "归档恢复目标缺少文件名".to_string())?;
    let mut base = std::ffi::OsString::from(".");
    base.push(name);
    base.push(".restore-");
    base.push(transaction_id);
    let mut staged_name = base.clone();
    staged_name.push(".new");
    let mut backup_name = base;
    backup_name.push(".bak");
    Ok(DurableReplacement {
        target: target.to_path_buf(),
        staged: has_staged.then(|| parent.join(staged_name)),
        backup: parent.join(backup_name),
        had_existing,
    })
}

fn validate_restore_journal(
    journal: &RestoreJournal,
    expected_state: RestoreJournalState,
) -> Result<(), String> {
    if journal.schema_version != RESTORE_JOURNAL_VERSION || journal.state != expected_state {
        return Err("归档恢复日志版本或状态无效".to_string());
    }
    let id = Uuid::parse_str(&journal.transaction_id)
        .map_err(|_| "归档恢复日志事务 ID 无效".to_string())?;
    if id.to_string() != journal.transaction_id {
        return Err("归档恢复日志事务 ID 不规范".to_string());
    }
    if !journal.includes_managed_key && journal.key_had_existing {
        return Err("归档恢复日志密钥状态无效".to_string());
    }
    Ok(())
}

fn restore_marker_path(target_database: &Path, name: &str) -> Result<PathBuf, String> {
    target_database
        .parent()
        .map(|parent| parent.join(name))
        .ok_or_else(|| "归档恢复数据库目标缺少父目录".to_string())
}

fn read_restore_journal(path: &Path) -> Result<Option<RestoreJournal>, String> {
    if !path_exists(path)? {
        return Ok(None);
    }
    let bytes = read_small_secure_file(path, MAX_MANIFEST_BYTES)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("归档恢复日志格式无效: {error}"))
}

fn persist_restore_journal(path: &Path, journal: &RestoreJournal) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "归档恢复日志缺少父目录".to_string())?;
    let bytes =
        serde_json::to_vec(journal).map_err(|error| format!("序列化归档恢复日志失败: {error}"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".archive-restore-journal-")
        .tempfile_in(parent)
        .map_err(|error| format!("创建归档恢复日志临时文件失败: {error}"))?;
    set_open_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(&bytes)
        .map_err(|error| format!("写入归档恢复日志失败: {error}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("同步归档恢复日志失败: {error}"))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| format!("发布归档恢复日志失败: {}", error.error))?;
    sync_directory(parent)
}

fn adopt_staged_file(source: &Path, destination: &Path) -> Result<(), String> {
    validate_secure_file(source, "归档恢复暂存文件")?;
    let source_parent = normalize_absolute_path(
        source
            .parent()
            .ok_or_else(|| "归档恢复暂存文件缺少父目录".to_string())?,
    )?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| "归档恢复事务暂存目标缺少父目录".to_string())?;
    if source_parent != destination_parent {
        return Err("归档恢复暂存文件必须与目标位于同一目录".to_string());
    }
    if path_exists(destination)? {
        return Err("归档恢复事务暂存目标已存在".to_string());
    }
    std::fs::rename(source, destination)
        .map_err(|error| format!("发布归档恢复事务暂存文件失败: {error}"))?;
    sync_directory(destination_parent)
}

fn rollback_prepared_restore(
    replacements: &[DurableReplacement],
    prepared_path: &Path,
    committed_path: &Path,
) -> Result<(), String> {
    for replacement in replacements.iter().rev() {
        let backup_exists = path_exists(&replacement.backup)?;
        let target_exists = path_exists(&replacement.target)?;
        if replacement.had_existing && backup_exists {
            if target_exists {
                remove_regular_file(&replacement.target)?;
            }
            std::fs::rename(&replacement.backup, &replacement.target)
                .map_err(|error| format!("回滚归档恢复目标失败: {error}"))?;
        } else if replacement.had_existing {
            // The prepared journal is durable before staging begins. A
            // missing backup with an existing target therefore means either
            // no rename happened yet or a previous recovery already restored
            // the old target. Both are safe and must be idempotent.
            if !target_exists {
                return Err("归档恢复回滚文件和原目标均缺失，拒绝继续".to_string());
            }
        } else if replacement.staged.is_some() && target_exists {
            remove_regular_file(&replacement.target)?;
        }
        if let Some(staged) = replacement.staged.as_ref() {
            if path_exists(staged)? {
                remove_regular_file(staged)?;
            }
        }
    }
    sync_replacement_parents(replacements)?;
    remove_marker_if_present(committed_path)?;
    remove_marker_if_present(prepared_path)?;
    sync_directory(
        prepared_path
            .parent()
            .ok_or_else(|| "归档恢复日志缺少父目录".to_string())?,
    )
}

fn inspect_snapshot_metadata(
    directory: &Path,
    snapshot_id: &str,
) -> Result<LocalArchiveSnapshotSummary, String> {
    validate_snapshot_id(snapshot_id)?;
    validate_secure_directory(directory, "本地归档快照目录")?;
    let manifest_path = directory.join(MANIFEST_FILE);
    let manifest_bytes = read_small_secure_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("本地归档快照清单格式无效: {error}"))?;
    validate_manifest(&manifest, snapshot_id)?;

    let mut expected_files = BTreeSet::from([MANIFEST_FILE.to_string(), DATABASE_FILE.to_string()]);
    if manifest.key.is_some() {
        expected_files.insert(KEY_FILE.to_string());
    }
    validate_exact_directory_contents(directory, &expected_files)?;
    validate_artifact_size_only(
        &directory.join(DATABASE_FILE),
        &manifest.database,
        DATABASE_FILE,
    )?;
    if let Some(key) = manifest.key.as_ref() {
        validate_artifact_size_only(&directory.join(KEY_FILE), key, KEY_FILE)?;
    }
    let total_size_bytes = manifest
        .database
        .size_bytes
        .checked_add(manifest.key.as_ref().map_or(0, |key| key.size_bytes))
        .and_then(|size| size.checked_add(manifest_bytes.len() as u64))
        .ok_or_else(|| "本地归档快照大小溢出".to_string())?;
    Ok(LocalArchiveSnapshotSummary {
        id: snapshot_id.to_string(),
        created_at: manifest.created_at,
        database_size_bytes: manifest.database.size_bytes,
        total_size_bytes,
        includes_key: manifest.key.is_some(),
        directory: directory.to_string_lossy().into_owned(),
    })
}

fn cleanup_committed_restore(
    replacements: &[DurableReplacement],
    prepared_path: &Path,
    committed_path: &Path,
) -> Result<(), String> {
    for replacement in replacements {
        if replacement.staged.is_some() && !path_exists(&replacement.target)? {
            return Err("已提交的归档恢复目标缺失".to_string());
        }
        if let Some(staged) = replacement.staged.as_ref() {
            if path_exists(staged)? {
                remove_regular_file(staged)?;
            }
        }
        if path_exists(&replacement.backup)? {
            remove_regular_file(&replacement.backup)?;
        }
    }
    sync_replacement_parents(replacements)?;
    // Keep the committed record until the prepared record is gone. A crash at
    // either deletion point can therefore only resume forward cleanup.
    remove_marker_if_present(prepared_path)?;
    sync_directory(
        prepared_path
            .parent()
            .ok_or_else(|| "归档恢复日志缺少父目录".to_string())?,
    )?;
    remove_marker_if_present(committed_path)?;
    sync_directory(
        committed_path
            .parent()
            .ok_or_else(|| "归档恢复日志缺少父目录".to_string())?,
    )
}

fn sync_replacement_parents(replacements: &[DurableReplacement]) -> Result<(), String> {
    let parents: BTreeSet<PathBuf> = replacements
        .iter()
        .filter_map(|replacement| replacement.target.parent().map(Path::to_path_buf))
        .collect();
    for parent in parents {
        sync_directory(&parent)?;
    }
    Ok(())
}

fn remove_regular_file(path: &Path) -> Result<(), String> {
    validate_replace_target(path)?;
    std::fs::remove_file(path).map_err(|error| format!("清理归档恢复事务文件失败: {error}"))
}

fn remove_marker_if_present(path: &Path) -> Result<(), String> {
    if path_exists(path)? {
        remove_regular_file(path)?;
    }
    Ok(())
}

fn inspect_snapshot_directory(
    directory: &Path,
    snapshot_id: &str,
    fallback_key: Option<&[u8; 32]>,
    verify_cipher: bool,
) -> Result<InspectedSnapshot, String> {
    validate_snapshot_id(snapshot_id)?;
    validate_secure_directory(directory, "本地归档快照目录")?;

    let manifest_path = directory.join(MANIFEST_FILE);
    let manifest_bytes = read_small_secure_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("本地归档快照清单格式无效: {error}"))?;
    validate_manifest(&manifest, snapshot_id)?;

    let mut expected_files = BTreeSet::from([MANIFEST_FILE.to_string(), DATABASE_FILE.to_string()]);
    if manifest.key.is_some() {
        expected_files.insert(KEY_FILE.to_string());
    }
    validate_exact_directory_contents(directory, &expected_files)?;

    let database_path = directory.join(DATABASE_FILE);
    validate_artifact(&database_path, &manifest.database, DATABASE_FILE)?;
    let bundled_key = if let Some(key_artifact) = manifest.key.as_ref() {
        let key_path = directory.join(KEY_FILE);
        validate_artifact(&key_path, key_artifact, KEY_FILE)?;
        Some(read_snapshot_key(&key_path)?)
    } else {
        None
    };

    if verify_cipher {
        let effective_key = bundled_key
            .as_ref()
            .or(fallback_key)
            .ok_or_else(|| "该本地归档快照未包含密钥，必须提供当前归档密钥才能校验".to_string())?;
        ArchiveDatabase::validate_encrypted_file(&database_path, effective_key)?;
    }

    let manifest_size = manifest_bytes.len() as u64;
    let total_size_bytes = manifest
        .database
        .size_bytes
        .checked_add(
            manifest
                .key
                .as_ref()
                .map_or(0, |artifact| artifact.size_bytes),
        )
        .and_then(|size| size.checked_add(manifest_size))
        .ok_or_else(|| "本地归档快照大小溢出".to_string())?;
    Ok(InspectedSnapshot {
        summary: LocalArchiveSnapshotSummary {
            id: snapshot_id.to_string(),
            created_at: manifest.created_at,
            database_size_bytes: manifest.database.size_bytes,
            total_size_bytes,
            includes_key: manifest.key.is_some(),
            directory: directory.to_string_lossy().into_owned(),
        },
        database_path,
        bundled_key,
    })
}

fn validate_manifest(manifest: &SnapshotManifest, snapshot_id: &str) -> Result<(), String> {
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "不支持的本地归档快照版本 {}",
            manifest.schema_version
        ));
    }
    if manifest.snapshot_id != snapshot_id {
        return Err("本地归档快照目录名与清单 ID 不一致".to_string());
    }
    let id_created_at = validate_snapshot_id(snapshot_id)?;
    if manifest.created_at != id_created_at {
        return Err("本地归档快照 ID 与清单时间不一致".to_string());
    }
    validate_artifact_metadata(&manifest.database, DATABASE_FILE)?;
    if let Some(key) = manifest.key.as_ref() {
        validate_artifact_metadata(key, KEY_FILE)?;
        if key.size_bytes > MAX_KEY_BYTES {
            return Err("本地归档快照密钥文件过大".to_string());
        }
    }
    Ok(())
}

fn validate_artifact_metadata(
    artifact: &SnapshotArtifact,
    expected_file_name: &str,
) -> Result<(), String> {
    if artifact.file_name != expected_file_name {
        return Err(format!("本地归档快照清单文件名必须为 {expected_file_name}"));
    }
    if artifact.size_bytes == 0 {
        return Err(format!("本地归档快照文件 {expected_file_name} 为空"));
    }
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "本地归档快照文件 {expected_file_name} 的 SHA-256 无效"
        ));
    }
    Ok(())
}

fn validate_artifact(
    path: &Path,
    artifact: &SnapshotArtifact,
    expected_file_name: &str,
) -> Result<(), String> {
    validate_artifact_metadata(artifact, expected_file_name)?;
    let (size, digest) = hash_secure_file(path)?;
    if size != artifact.size_bytes || digest != artifact.sha256 {
        return Err(format!(
            "本地归档快照文件 {expected_file_name} 校验和不匹配"
        ));
    }
    Ok(())
}

fn validate_artifact_size_only(
    path: &Path,
    artifact: &SnapshotArtifact,
    expected_file_name: &str,
) -> Result<(), String> {
    validate_artifact_metadata(artifact, expected_file_name)?;
    let metadata = validate_secure_file(path, "本地归档快照文件")?;
    if metadata.len() != artifact.size_bytes {
        return Err(format!(
            "本地归档快照文件 {expected_file_name} 大小与清单不匹配"
        ));
    }
    Ok(())
}

fn write_artifact(path: &Path, file_name: &str, bytes: &[u8]) -> Result<SnapshotArtifact, String> {
    write_secure_file(path, bytes)?;
    Ok(SnapshotArtifact {
        file_name: file_name.to_string(),
        size_bytes: bytes.len() as u64,
        sha256: sha256_bytes(bytes),
    })
}

fn write_secure_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("创建本地归档快照文件失败: {error}"))?;
    set_open_file_permissions(&file, path)?;
    file.write_all(bytes)
        .map_err(|error| format!("写入本地归档快照文件失败: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步本地归档快照文件失败: {error}"))
}

fn read_small_secure_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = validate_secure_file(path, "本地归档快照文件")?;
    if metadata.len() > max_bytes {
        return Err(format!("本地归档快照文件 {} 过大", path.display()));
    }
    let mut file =
        File::open(path).map_err(|error| format!("打开本地归档快照文件失败: {error}"))?;
    let mut bytes = Vec::new();
    Read::take(&mut file, max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("读取本地归档快照文件失败: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("本地归档快照文件 {} 过大", path.display()));
    }
    Ok(bytes)
}

fn read_snapshot_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = read_small_secure_file(path, MAX_KEY_BYTES)?;
    let encoded = std::str::from_utf8(&bytes)
        .map_err(|_| "本地归档快照密钥必须是 UTF-8 Base64".to_string())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim().as_bytes())
        .map_err(|_| "本地归档快照密钥不是有效 Base64".to_string())?;
    decoded
        .try_into()
        .map_err(|_| "本地归档快照密钥解码后必须恰好为 32 字节".to_string())
}

fn hash_secure_file(path: &Path) -> Result<(u64, String), String> {
    validate_secure_file(path, "本地归档快照文件")?;
    let mut file =
        File::open(path).map_err(|error| format!("打开本地归档快照文件失败: {error}"))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("读取本地归档快照文件失败: {error}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| "本地归档快照文件大小溢出".to_string())?;
        digest.update(&buffer[..read]);
    }
    Ok((size, hex::encode(digest.finalize())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_exact_directory_contents(
    directory: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("读取本地归档快照内容失败: {error}"))?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("读取本地归档快照内容失败: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "本地归档快照包含非 UTF-8 文件名".to_string())?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| format!("读取本地归档快照文件元数据失败: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("本地归档快照只能包含普通文件且不得包含符号链接".to_string());
        }
        actual.insert(name);
    }
    if &actual != expected {
        return Err("本地归档快照包含缺失或未识别的文件".to_string());
    }
    Ok(())
}

fn validate_snapshot_id(snapshot_id: &str) -> Result<i64, String> {
    if snapshot_id.len() > 96 || !snapshot_id.starts_with(SNAPSHOT_PREFIX) {
        return Err("本地归档快照 ID 无效".to_string());
    }
    let remainder = &snapshot_id[SNAPSHOT_PREFIX.len()..];
    let (timestamp, uuid) = remainder
        .split_once('-')
        .ok_or_else(|| "本地归档快照 ID 无效".to_string())?;
    if !(13..=19).contains(&timestamp.len()) || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("本地归档快照 ID 时间无效".to_string());
    }
    let created_at = timestamp
        .parse::<i64>()
        .map_err(|_| "本地归档快照 ID 时间无效".to_string())?;
    let parsed_uuid = Uuid::parse_str(uuid).map_err(|_| "本地归档快照 ID 无效".to_string())?;
    if parsed_uuid.to_string() != uuid {
        return Err("本地归档快照 ID 必须使用规范 UUID".to_string());
    }
    Ok(created_at)
}

fn validate_retention(retention: usize) -> Result<(), String> {
    if retention == 0 || retention > MAX_RETENTION {
        return Err(format!(
            "本地归档快照保留数量必须在 1 到 {MAX_RETENTION} 之间"
        ));
    }
    Ok(())
}

fn resolve_snapshot_directory(root: &Path, snapshot_id: &str) -> Result<PathBuf, String> {
    let root = open_snapshot_root(root)?.ok_or_else(|| "本地归档快照目录不存在".to_string())?;
    resolve_snapshot_directory_in_root(&root, snapshot_id)
}

fn resolve_snapshot_directory_in_root(root: &Path, snapshot_id: &str) -> Result<PathBuf, String> {
    validate_snapshot_id(snapshot_id)?;
    let candidate = root.join(snapshot_id);
    let metadata = std::fs::symlink_metadata(&candidate)
        .map_err(|error| format!("读取本地归档快照元数据失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("本地归档快照路径不是普通目录或为符号链接".to_string());
    }
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| format!("解析本地归档快照根目录失败: {error}"))?;
    let canonical_candidate = std::fs::canonicalize(&candidate)
        .map_err(|error| format!("解析本地归档快照目录失败: {error}"))?;
    if canonical_candidate.parent() != Some(canonical_root.as_path()) {
        return Err("本地归档快照路径超出配置目录".to_string());
    }
    Ok(candidate)
}

fn ensure_snapshot_root(root: &Path) -> Result<PathBuf, String> {
    let root = normalize_absolute_path(root)?;
    reject_symlink_components(&root)?;
    let existed = match std::fs::symlink_metadata(&root) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("读取本地归档快照目录元数据失败: {error}")),
    };
    if !existed {
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("创建本地归档快照目录失败: {error}"))?;
    }
    reject_symlink_components(&root)?;
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| format!("读取本地归档快照目录元数据失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("本地归档快照路径必须是普通目录且不得为符号链接".to_string());
    }
    if !existed {
        set_directory_permissions(&root)?;
    }
    validate_secure_directory(&root, "本地归档快照根目录")?;
    Ok(root)
}

fn open_snapshot_root(root: &Path) -> Result<Option<PathBuf>, String> {
    let root = normalize_absolute_path(root)?;
    reject_symlink_components(&root)?;
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取本地归档快照目录元数据失败: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("本地归档快照路径必须是普通目录且不得为符号链接".to_string());
    }
    validate_directory_permissions(&root, &metadata)?;
    Ok(Some(root))
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("本地归档快照目录不能为空".to_string());
    }
    let path_text = path.to_string_lossy();
    if path_text.contains("://") || path_text.starts_with("\\\\") || path_text.starts_with("//") {
        return Err("本地归档快照目录必须是本机文件路径，不能是 URL".to_string());
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("读取当前目录失败: {error}"))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => return Err("本地归档快照目录不得包含父目录跳转".to_string()),
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str())
            }
        }
    }
    Ok(normalized)
}

fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "本地归档快照路径组件 {} 不得是符号链接",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "读取本地归档快照路径组件 {} 失败: {error}",
                    current.display()
                ))
            }
        }
    }
    Ok(())
}

fn validate_secure_directory(path: &Path, label: &str) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("读取{label}元数据失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label}必须是普通目录且不得为符号链接"));
    }
    validate_directory_permissions(path, &metadata)?;
    Ok(metadata)
}

fn validate_secure_file(path: &Path, label: &str) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("读取{label}元数据失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label}必须是普通文件且不得为符号链接"));
    }
    validate_file_permissions(path, &metadata)?;
    Ok(metadata)
}

fn prepare_target_parent(target: &Path, key_directory: bool) -> Result<PathBuf, String> {
    let target = normalize_absolute_path(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| "归档恢复目标路径无效".to_string())?
        .to_path_buf();
    reject_symlink_components(&parent)?;
    std::fs::create_dir_all(&parent)
        .map_err(|error| format!("创建归档恢复目标目录失败: {error}"))?;
    reject_symlink_components(&parent)?;
    let metadata = std::fs::symlink_metadata(&parent)
        .map_err(|error| format!("读取归档恢复目标目录失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("归档恢复目标父路径必须是普通目录且不得为符号链接".to_string());
    }
    if key_directory {
        set_directory_permissions(&parent)?;
    }
    Ok(parent)
}

fn validate_replace_target(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("归档恢复目标 {} 不得是符号链接", path.display()))
        }
        Ok(metadata) if !metadata.is_file() => {
            Err(format!("归档恢复目标 {} 必须是普通文件", path.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("读取归档恢复目标元数据失败: {error}")),
    }
}

fn stage_copy(source: &Path, parent: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut source_file =
        File::open(source).map_err(|error| format!("打开本地归档快照恢复源失败: {error}"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .map_err(|error| format!("创建归档恢复临时文件失败: {error}"))?;
    set_open_file_permissions(temporary.as_file(), temporary.path())?;
    std::io::copy(&mut source_file, temporary.as_file_mut())
        .map_err(|error| format!("复制本地归档快照失败: {error}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("同步归档恢复临时文件失败: {error}"))?;
    temporary
        .keep()
        .map(|(_, path)| path)
        .map_err(|error| format!("保留归档恢复临时文件失败: {}", error.error))
}

fn stage_bytes(bytes: &[u8], parent: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut temporary = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .map_err(|error| format!("创建归档恢复临时文件失败: {error}"))?;
    set_open_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(bytes)
        .map_err(|error| format!("写入归档恢复临时文件失败: {error}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("同步归档恢复临时文件失败: {error}"))?;
    temporary
        .keep()
        .map(|(_, path)| path)
        .map_err(|error| format!("保留归档恢复临时文件失败: {}", error.error))
}

fn path_exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("读取归档恢复目标元数据失败: {error}")),
    }
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置本地归档快照目录权限失败: {error}"))
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_open_file_permissions(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置本地归档快照文件 {} 权限失败: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_open_file_permissions(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置归档恢复文件权限失败: {error}"))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_directory_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "本地归档快照目录 {} 权限必须为 0700，当前为 {mode:04o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_permissions(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_file_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "本地归档快照文件 {} 权限必须为 0600，当前为 {mode:04o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_permissions(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("同步本地归档快照目录失败: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn database(path: &Path, key: &[u8; 32]) -> ArchiveDatabase {
        ArchiveDatabase::open(path, key).unwrap()
    }

    #[test]
    fn creates_lists_and_validates_keyed_bundle_with_restrictive_permissions() {
        let temporary = tempdir().unwrap();
        let key = [7_u8; 32];
        let database = database(&temporary.path().join("live.db"), &key);
        let root = temporary.path().join("backups");

        let created = create_local_archive_snapshot(&root, 30, true, &database, &key).unwrap();
        assert!(created.includes_key);
        assert!(created.total_size_bytes > created.database_size_bytes);
        assert_eq!(
            list_local_archive_snapshots(&root).unwrap(),
            vec![created.clone()]
        );
        assert_eq!(
            list_local_archive_snapshot_metadata(&root).unwrap(),
            vec![created.clone()]
        );
        assert_eq!(
            validate_local_archive_snapshot(&root, &created.id, None).unwrap(),
            created
        );
        let bytes = std::fs::read(root.join(&created.id).join(DATABASE_FILE)).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for name in [DATABASE_FILE, KEY_FILE, MANIFEST_FILE] {
                assert_eq!(
                    std::fs::metadata(root.join(&created.id).join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn keyless_bundle_requires_matching_fallback_key() {
        let temporary = tempdir().unwrap();
        let key = [11_u8; 32];
        let database = database(&temporary.path().join("live.db"), &key);
        let root = temporary.path().join("backups");
        let snapshot = create_local_archive_snapshot(&root, 30, false, &database, &key).unwrap();

        assert!(!snapshot.includes_key);
        assert!(validate_local_archive_snapshot(&root, &snapshot.id, None).is_err());
        assert!(validate_local_archive_snapshot(&root, &snapshot.id, Some(&[12; 32])).is_err());
        validate_local_archive_snapshot(&root, &snapshot.id, Some(&key)).unwrap();
    }

    #[test]
    fn retention_and_delete_touch_only_recognized_snapshots() {
        let temporary = tempdir().unwrap();
        let key = [13_u8; 32];
        let database = database(&temporary.path().join("live.db"), &key);
        let root = temporary.path().join("backups");
        let first = create_local_archive_snapshot(&root, 30, true, &database, &key).unwrap();
        let foreign = root.join("personal-files");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("keep.txt"), b"keep").unwrap();
        let damaged = root.join(format!(
            "{SNAPSHOT_PREFIX}{}-{}",
            chrono::Utc::now().timestamp_millis(),
            Uuid::new_v4()
        ));
        std::fs::create_dir(&damaged).unwrap();
        set_directory_permissions(&damaged).unwrap();
        std::fs::write(damaged.join("unknown"), b"keep").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = create_local_archive_snapshot(&root, 1, true, &database, &key).unwrap();
        assert_ne!(first.id, second.id);
        assert!(!root.join(first.id).exists());
        assert!(foreign.join("keep.txt").exists());
        assert!(damaged.join("unknown").exists());
        assert!(delete_local_archive_snapshot(&root, "../personal-files").is_err());
        delete_local_archive_snapshot(&root, &second.id).unwrap();
        assert!(foreign.exists());
        assert!(damaged.exists());
    }

    #[test]
    fn tampering_prevents_validation_deletion_and_pruning() {
        let temporary = tempdir().unwrap();
        let key = [17_u8; 32];
        let database = database(&temporary.path().join("live.db"), &key);
        let root = temporary.path().join("backups");
        let snapshot = create_local_archive_snapshot(&root, 30, true, &database, &key).unwrap();
        let database_path = root.join(&snapshot.id).join(DATABASE_FILE);
        let mut options = OpenOptions::new();
        options.append(true);
        options
            .open(&database_path)
            .unwrap()
            .write_all(b"tamper")
            .unwrap();

        assert!(validate_local_archive_snapshot(&root, &snapshot.id, None).is_err());
        assert!(delete_local_archive_snapshot(&root, &snapshot.id).is_err());
        assert!(prune_local_archive_snapshots(&root, 1).unwrap().is_empty());
        assert!(root.join(snapshot.id).exists());
    }

    #[test]
    fn restores_managed_database_and_key_and_rejects_environment_mismatch() {
        let temporary = tempdir().unwrap();
        let source_key = [21_u8; 32];
        let source = database(&temporary.path().join("source.db"), &source_key);
        let root = temporary.path().join("backups");
        let snapshot =
            create_local_archive_snapshot(&root, 30, true, &source, &source_key).unwrap();

        let target_key = [22_u8; 32];
        let target_path = temporary.path().join("live").join(DATABASE_FILE);
        let target = database(&target_path, &target_key);
        drop(target);
        let key_path = temporary.path().join("live-secrets").join(KEY_FILE);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        set_directory_permissions(key_path.parent().unwrap()).unwrap();
        write_secure_file(
            &key_path,
            base64::engine::general_purpose::STANDARD
                .encode(target_key)
                .as_bytes(),
        )
        .unwrap();

        restore_local_archive_snapshot(
            &root,
            &snapshot.id,
            &target_path,
            Some(&key_path),
            &target_key,
        )
        .unwrap();
        ArchiveDatabase::validate_encrypted_file(&target_path, &source_key).unwrap();
        assert_eq!(read_snapshot_key(&key_path).unwrap(), source_key);

        let environment_target = temporary.path().join("environment.db");
        let environment = database(&environment_target, &target_key);
        drop(environment);
        let before = std::fs::read(&environment_target).unwrap();
        assert!(restore_local_archive_snapshot(
            &root,
            &snapshot.id,
            &environment_target,
            None,
            &target_key,
        )
        .is_err());
        assert_eq!(std::fs::read(&environment_target).unwrap(), before);
    }

    fn simulate_crashed_restore(
        root: &Path,
        committed: bool,
    ) -> (PathBuf, PathBuf, Vec<DurableReplacement>) {
        let live = root.join("live");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        set_directory_permissions(&secrets).unwrap();
        let database_target = live.join(DATABASE_FILE);
        let key_target = secrets.join(KEY_FILE);
        write_secure_file(&database_target, b"old-database").unwrap();
        write_secure_file(&key_target, b"old-key").unwrap();
        let journal = RestoreJournal {
            schema_version: RESTORE_JOURNAL_VERSION,
            transaction_id: Uuid::new_v4().to_string(),
            state: RestoreJournalState::Prepared,
            includes_managed_key: true,
            database_had_existing: true,
            key_had_existing: true,
            wal_had_existing: false,
            shm_had_existing: false,
        };
        let replacements =
            replacements_from_journal(&journal, &database_target, &key_target).unwrap();
        let prepared_path = restore_marker_path(&database_target, RESTORE_PREPARED_FILE).unwrap();
        persist_restore_journal(&prepared_path, &journal).unwrap();
        for replacement in &replacements {
            if let Some(staged) = replacement.staged.as_ref() {
                let bytes = if replacement.target == database_target {
                    b"new-database".as_slice()
                } else {
                    b"new-key".as_slice()
                };
                write_secure_file(staged, bytes).unwrap();
            }
            if replacement.had_existing {
                std::fs::rename(&replacement.target, &replacement.backup).unwrap();
            }
        }
        for replacement in &replacements {
            if let Some(staged) = replacement.staged.as_ref() {
                std::fs::rename(staged, &replacement.target).unwrap();
            }
        }
        sync_replacement_parents(&replacements).unwrap();
        if committed {
            let mut marker = journal;
            marker.state = RestoreJournalState::Committed;
            persist_restore_journal(
                &restore_marker_path(&database_target, RESTORE_COMMITTED_FILE).unwrap(),
                &marker,
            )
            .unwrap();
        }
        (database_target, key_target, replacements)
    }

    #[test]
    fn prepared_crash_recovery_rolls_back_database_and_key() {
        let temporary = tempdir().unwrap();
        let (database_target, key_target, replacements) =
            simulate_crashed_restore(temporary.path(), false);

        assert_eq!(
            recover_interrupted_archive_restore(&database_target, &key_target).unwrap(),
            ArchiveRestoreRecovery::RolledBack
        );
        assert_eq!(std::fs::read(&database_target).unwrap(), b"old-database");
        assert_eq!(std::fs::read(&key_target).unwrap(), b"old-key");
        assert!(replacements.iter().all(|entry| !entry.backup.exists()
            && entry.staged.as_ref().is_none_or(|path| !path.exists())));
        assert_eq!(
            recover_interrupted_archive_restore(&database_target, &key_target).unwrap(),
            ArchiveRestoreRecovery::None
        );
    }

    #[test]
    fn prepared_journal_before_staging_is_safely_rolled_back() {
        let temporary = tempdir().unwrap();
        let live = temporary.path().join("live");
        let secrets = temporary.path().join("secrets");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        set_directory_permissions(&secrets).unwrap();
        let database_target = live.join(DATABASE_FILE);
        let key_target = secrets.join(KEY_FILE);
        write_secure_file(&database_target, b"old-database").unwrap();
        write_secure_file(&key_target, b"old-key").unwrap();
        let journal = RestoreJournal {
            schema_version: RESTORE_JOURNAL_VERSION,
            transaction_id: Uuid::new_v4().to_string(),
            state: RestoreJournalState::Prepared,
            includes_managed_key: true,
            database_had_existing: true,
            key_had_existing: true,
            wal_had_existing: false,
            shm_had_existing: false,
        };
        persist_restore_journal(
            &restore_marker_path(&database_target, RESTORE_PREPARED_FILE).unwrap(),
            &journal,
        )
        .unwrap();

        assert_eq!(
            recover_interrupted_archive_restore(&database_target, &key_target).unwrap(),
            ArchiveRestoreRecovery::RolledBack
        );
        assert_eq!(std::fs::read(database_target).unwrap(), b"old-database");
        assert_eq!(std::fs::read(key_target).unwrap(), b"old-key");
    }

    #[test]
    fn prepared_recovery_is_idempotent_after_backups_already_restored() {
        let temporary = tempdir().unwrap();
        let (database_target, key_target, replacements) =
            simulate_crashed_restore(temporary.path(), false);
        for replacement in replacements.iter().rev() {
            if replacement.had_existing {
                remove_regular_file(&replacement.target).unwrap();
                std::fs::rename(&replacement.backup, &replacement.target).unwrap();
            }
        }
        sync_replacement_parents(&replacements).unwrap();

        assert_eq!(
            recover_interrupted_archive_restore(&database_target, &key_target).unwrap(),
            ArchiveRestoreRecovery::RolledBack
        );
        assert_eq!(std::fs::read(database_target).unwrap(), b"old-database");
        assert_eq!(std::fs::read(key_target).unwrap(), b"old-key");
    }

    #[test]
    fn committed_crash_recovery_keeps_new_targets_and_finishes_cleanup() {
        let temporary = tempdir().unwrap();
        let (database_target, key_target, replacements) =
            simulate_crashed_restore(temporary.path(), true);

        assert_eq!(
            recover_interrupted_archive_restore(&database_target, &key_target).unwrap(),
            ArchiveRestoreRecovery::CommittedCleanup
        );
        assert_eq!(std::fs::read(&database_target).unwrap(), b"new-database");
        assert_eq!(std::fs::read(&key_target).unwrap(), b"new-key");
        assert!(replacements.iter().all(|entry| !entry.backup.exists()
            && entry.staged.as_ref().is_none_or(|path| !path.exists())));
    }

    #[cfg(unix)]
    #[test]
    fn existing_insecure_snapshot_root_is_rejected_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempdir().unwrap();
        let root = temporary.path().join("existing-backups");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(ensure_snapshot_root(&root).is_err());
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_roots_and_snapshot_directories() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let real_root = temporary.path().join("real");
        std::fs::create_dir(&real_root).unwrap();
        set_directory_permissions(&real_root).unwrap();
        let linked_root = temporary.path().join("linked");
        symlink(&real_root, &linked_root).unwrap();
        assert!(list_local_archive_snapshots(&linked_root).is_err());

        let id = format!(
            "{SNAPSHOT_PREFIX}{}-{}",
            chrono::Utc::now().timestamp_millis(),
            Uuid::new_v4()
        );
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, real_root.join(&id)).unwrap();
        assert!(validate_local_archive_snapshot(&real_root, &id, None).is_err());
        assert!(delete_local_archive_snapshot(&real_root, &id).is_err());
    }
}
