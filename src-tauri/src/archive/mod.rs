mod auth;
mod database;
mod key;
pub mod local_api;
pub(crate) mod local_backup;
mod middleware;
mod normalize;
mod redaction;
pub mod types;

pub use middleware::{local_archive_middleware, team_archive_middleware};
pub use types::*;

use auth::ArchiveAuthService;
use database::ArchiveDatabase;
use key::load_archive_key;
pub(crate) use key::{
    archive_key_configured, archive_key_source, initialize_archive_key, ArchiveKeySource,
};
use redaction::{sha256_hex, Redactor};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone)]
pub struct ArchiveService {
    inner: Arc<ArchiveServiceInner>,
}

struct ArchiveServiceInner {
    database: Mutex<Option<CachedDatabase>>,
    restore_lock: Mutex<()>,
    local_backup_operation_lock: Mutex<()>,
    auth: ArchiveAuthService,
    local_backup_status: Mutex<LocalBackupRuntimeStatus>,
}

#[derive(Default)]
struct LocalBackupRuntimeStatus {
    last_error: Option<String>,
    snapshot_directory: Option<String>,
    last_success_at: Option<i64>,
    last_attempt_at: Option<i64>,
}

struct CachedDatabase {
    key_fingerprint: String,
    database: Arc<ArchiveDatabase>,
}

static ARCHIVE_SERVICE_INNER: OnceLock<Arc<ArchiveServiceInner>> = OnceLock::new();
static ARCHIVE_INITIALIZATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static LOCAL_BACKUP_SIGNAL: OnceLock<tokio::sync::mpsc::Sender<()>> = OnceLock::new();
static LOCAL_HISTORY_SIGNAL: OnceLock<tokio::sync::mpsc::Sender<()>> = OnceLock::new();
static LOCAL_HISTORY_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static LOCAL_HISTORY_STATUS: OnceLock<Mutex<LocalHistoryRuntimeStatus>> = OnceLock::new();
static LOCAL_MEMORY_STATUS: OnceLock<Mutex<LocalMemoryRuntimeStatus>> = OnceLock::new();

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalHistoryRuntimeStatus {
    pub running: bool,
    pub last_started_at: Option<i64>,
    pub last_completed_at: Option<i64>,
    pub last_imported: usize,
    pub last_skipped: usize,
    pub last_failed: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMemoryRuntimeStatus {
    pub running: bool,
    pub last_started_at: Option<i64>,
    pub last_completed_at: Option<i64>,
    pub last_imported: usize,
    pub last_skipped: usize,
    pub last_deleted: usize,
    pub last_failed: usize,
    pub last_error: Option<String>,
    pub providers: Vec<AgentMemoryProviderStatus>,
}

fn local_history_status_store() -> &'static Mutex<LocalHistoryRuntimeStatus> {
    LOCAL_HISTORY_STATUS.get_or_init(|| Mutex::new(LocalHistoryRuntimeStatus::default()))
}

fn local_memory_status_store() -> &'static Mutex<LocalMemoryRuntimeStatus> {
    LOCAL_MEMORY_STATUS.get_or_init(|| Mutex::new(LocalMemoryRuntimeStatus::default()))
}

fn archive_initialization_lock() -> &'static tokio::sync::Mutex<()> {
    ARCHIVE_INITIALIZATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl ArchiveService {
    pub fn new() -> Self {
        Self {
            inner: ARCHIVE_SERVICE_INNER
                .get_or_init(|| {
                    Arc::new(ArchiveServiceInner {
                        database: Mutex::new(None),
                        restore_lock: Mutex::new(()),
                        local_backup_operation_lock: Mutex::new(()),
                        auth: ArchiveAuthService::new(),
                        local_backup_status: Mutex::new(LocalBackupRuntimeStatus::default()),
                    })
                })
                .clone(),
        }
    }

    pub fn settings(&self) -> crate::settings::ArchiveSettings {
        crate::settings::get_settings().archive.unwrap_or_default()
    }

    pub fn is_enabled(&self) -> bool {
        self.settings().enabled
    }

    pub fn redactor(&self) -> Result<Redactor, String> {
        Redactor::new(&self.settings().redaction_rules)
    }

    pub fn database(&self) -> Result<Arc<ArchiveDatabase>, String> {
        let _restore_guard = self
            .inner
            .restore_lock
            .lock()
            .map_err(|_| "归档数据库恢复锁已损坏".to_string())?;
        let config_dir = crate::config::get_app_config_dir();
        let database_path = config_dir.join("conversation-archive.db");
        let managed_key_path = config_dir.join("secrets").join("conversation-archive.key");
        match local_backup::recover_interrupted_archive_restore(&database_path, &managed_key_path)?
        {
            local_backup::ArchiveRestoreRecovery::None => {}
            local_backup::ArchiveRestoreRecovery::RolledBack => {
                log::warn!("已回滚上次中断的归档恢复事务");
            }
            local_backup::ArchiveRestoreRecovery::CommittedCleanup => {
                log::info!("已完成上次归档恢复事务的提交后清理");
            }
        }
        let key = load_archive_key()?;
        let fingerprint = sha256_hex(&key);
        let mut cache = self
            .inner
            .database
            .lock()
            .map_err(|_| "归档数据库缓存锁已损坏".to_string())?;
        if let Some(cached) = cache.as_ref() {
            if cached.key_fingerprint == fingerprint {
                return Ok(cached.database.clone());
            }
        }
        let database = Arc::new(ArchiveDatabase::open_default()?);
        *cache = Some(CachedDatabase {
            key_fingerprint: fingerprint,
            database: database.clone(),
        });
        Ok(database)
    }

    pub fn ensure_team_ready(&self) -> Result<Arc<ArchiveDatabase>, String> {
        let archive = crate::settings::get_settings().archive.unwrap_or_default();
        if !archive.enabled {
            return Err("团队对话归档尚未启用".to_string());
        }
        archive
            .validate_capture_syntax()
            .map_err(|e| e.to_string())?;
        // Opening a cached database already performs SQLCipher and integrity
        // checks. Writes remain fail-closed; avoid rescanning the entire file
        // on every proxy request.
        self.database()
    }

    pub fn ensure_local_ready(&self) -> Result<Arc<ArchiveDatabase>, String> {
        let settings = crate::settings::get_settings();
        let archive = settings
            .archive
            .as_ref()
            .ok_or_else(|| "对话归档尚未启用".to_string())?;
        if !archive.enabled {
            return Err("对话归档尚未启用".to_string());
        }
        archive
            .validate_capture_syntax()
            .map_err(|error| error.to_string())?;
        self.database()
    }

    /// Prepare only the encrypted local archive.  Team capture remains disabled
    /// and no OIDC/JWKS configuration is required.
    pub fn prepare_local_archive(&self) -> Result<Arc<ArchiveDatabase>, String> {
        initialize_archive_key()?;
        let database = self.database()?;
        database.verify()?;
        Ok(database)
    }

    pub fn local_history_runtime_status(&self) -> LocalHistoryRuntimeStatus {
        local_history_status_store()
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub fn local_memory_runtime_status(&self) -> LocalMemoryRuntimeStatus {
        local_memory_status_store()
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub fn conversation_changes(
        &self,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<ArchiveConversationChangesPage, String> {
        let after_sequence = match cursor.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => value
                .parse::<i64>()
                .map_err(|_| "增量游标无效".to_string())?,
            None => 0,
        };
        self.database()?
            .conversation_changes(after_sequence, page_size)
    }

    pub fn agent_memory_changes(
        &self,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<AgentMemoryChangesPage, String> {
        let after_sequence = match cursor.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => value
                .parse::<i64>()
                .map_err(|_| "记忆增量游标无效".to_string())?,
            None => 0,
        };
        self.database()?
            .agent_memory_changes(after_sequence, page_size)
    }

    pub fn agent_memory_detail(&self, id: &str) -> Result<AgentMemoryDetail, String> {
        self.database()?.agent_memory_detail(id)
    }

    pub fn import_agent_memories(&self) -> Result<AgentMemoryImportResult, String> {
        let mut scan = crate::memory_manager::scan_agent_memories();
        let redactor = self.redactor()?;
        for memory in &mut scan.memories {
            memory.title = redactor.redact_text(&memory.title);
            memory.content = redactor.redact_text(&memory.content);
            memory.content_hash = sha256_hex(memory.content.as_bytes());
            memory.size_bytes = memory.content.len() as u64;
        }
        let (imported, skipped, deleted, imported_by_provider) = self
            .database()?
            .reconcile_agent_memories(&scan.memories, &scan.completed_roots)?;
        for status in &mut scan.statuses {
            status.imported = imported_by_provider
                .get(&status.provider)
                .copied()
                .unwrap_or_default();
        }
        let failed = scan.statuses.iter().map(|status| status.failed).sum();
        if imported > 0 || deleted > 0 {
            self.notify_local_backup_changed();
        }
        Ok(AgentMemoryImportResult {
            imported,
            skipped,
            deleted,
            failed,
            providers: scan.statuses,
            errors: scan.errors,
        })
    }

    pub fn local_identity(&self) -> Result<ArchiveIdentity, String> {
        let machine_id = local_machine_id()?;
        Ok(ArchiveIdentity {
            issuer: "local".to_string(),
            subject: machine_id,
            name: Some("Local TokenManager".to_string()),
            email: None,
            organization: None,
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<ArchiveIdentity, String> {
        let settings = self.settings();
        if !settings.enabled {
            return Err("团队对话归档尚未启用".to_string());
        }
        settings
            .validate_capture_syntax()
            .map_err(|error| error.to_string())?;
        self.inner.auth.validate(token, &settings.oidc).await
    }

    /// Backend enforcement for enabling or changing a live archive. The UI
    /// performs the same preflight for good feedback, but settings mutations
    /// cannot bypass key/database/JWKS validation.
    pub async fn validate_enablement(
        &self,
        all_settings: &crate::settings::AppSettings,
    ) -> Result<(), String> {
        let archive = all_settings
            .archive
            .as_ref()
            .ok_or_else(|| "启用对话归档前必须提供归档配置".to_string())?;
        if !archive.enabled {
            return Ok(());
        }
        archive
            .validate_capture_syntax()
            .map_err(|error| error.to_string())?;
        Redactor::new(&archive.redaction_rules)?;
        self.database()?.verify()?;
        self.inner.auth.check_jwks(&archive.oidc).await
    }

    pub async fn health(&self) -> ArchiveHealth {
        let all_settings = crate::settings::get_settings();
        let settings = all_settings.archive.clone().unwrap_or_default();
        let key_status = archive_key_source();
        let key_configured = archive_key_configured();
        let key_source = key_status
            .as_ref()
            .ok()
            .map(|source| source.as_str().to_string());
        // Syntax validation normally short-circuits while capture is disabled.
        // Health checks must still reject an unsafe/incomplete JWKS URL instead
        // of contacting it merely because values were prefilled in the UI.
        let mut oidc_syntax = settings.clone();
        oidc_syntax.enabled = true;
        let oidc_configured = oidc_syntax.validate_capture_syntax().is_ok()
            && !settings.oidc.issuer.is_empty()
            && !settings.oidc.audience.is_empty()
            && !settings.oidc.jwks_url.is_empty();
        let local_backup_enabled = settings.local_backup.enabled;
        let local_backup_root = resolved_local_backup_directory(&settings);
        let mut database_ok = false;
        let mut fts_ok = false;
        let mut database_path = None;
        let mut database_size_bytes = 0;
        let mut errors = Vec::new();
        if key_configured {
            let service = self.clone();
            match tauri::async_runtime::spawn_blocking(move || {
                let database = service.database()?;
                database.verify_schema()?;
                Ok::<_, String>((
                    database.path().to_string_lossy().to_string(),
                    database.size_bytes(),
                ))
            })
            .await
            {
                Ok(Ok((path, size))) => {
                    database_path = Some(path);
                    database_size_bytes = size;
                    database_ok = true;
                    fts_ok = true;
                }
                Ok(Err(error)) => errors.push(error),
                Err(error) => errors.push(format!("归档健康检查任务失败: {error}")),
            }
        } else {
            errors.push(
                key_status
                    .err()
                    .unwrap_or_else(|| "尚未初始化归档密钥".to_string()),
            );
        }
        let oidc_result = if oidc_configured {
            Some(self.inner.auth.check_jwks(&settings.oidc).await)
        } else {
            None
        };
        let oidc_ok = match oidc_result {
            Some(Ok(())) => true,
            Some(Err(error)) => {
                errors.push(error);
                false
            }
            None => {
                errors.push("OIDC 配置不完整".to_string());
                false
            }
        };
        let runtime_warning = self
            .inner
            .local_backup_status
            .lock()
            .ok()
            .and_then(|status| status.last_error.clone());
        let (local_backup_ok, last_local_backup_at, local_backup_warning) = if !local_backup_enabled
        {
            (true, None, None)
        } else if let Some(warning) = runtime_warning {
            (
                false,
                latest_local_snapshot_at(&local_backup_root),
                Some(warning),
            )
        } else {
            match local_backup::latest_local_archive_snapshot_timestamp(&local_backup_root) {
                Ok(last) => {
                    if last.is_some() {
                        (true, last, None)
                    } else {
                        (false, None, Some("尚未创建归档本地恢复快照".to_string()))
                    }
                }
                Err(error) => (false, None, Some(error)),
            }
        };
        let ready = key_configured && database_ok && fts_ok && oidc_ok;
        ArchiveHealth {
            enabled: settings.enabled,
            ready,
            key_configured,
            database_ok,
            fts_ok,
            oidc_configured,
            oidc_ok,
            local_backup_enabled,
            local_backup_ok,
            local_backup_directory: Some(local_backup_root.to_string_lossy().to_string()),
            last_local_backup_at,
            local_backup_warning,
            key_source,
            database_path,
            database_size_bytes,
            error: (!errors.is_empty()).then(|| errors.join("；")),
        }
    }

    /// Idempotently prepare the local encrypted archive and, when all external
    /// prerequisites already exist, enable capture in the same authoritative
    /// backend operation. External credentials are never invented.
    pub async fn initialize(
        &self,
        mut archive: crate::settings::ArchiveSettings,
    ) -> Result<ArchiveInitializationResult, String> {
        let _guard = archive_initialization_lock().lock().await;
        archive.normalize();
        archive.enabled = false;
        Redactor::new(&archive.redaction_rules)?;

        let database_path = crate::config::get_app_config_dir().join("conversation-archive.db");
        let database_existed = database_path.exists();
        let key_initialization = initialize_archive_key()?;
        self.database()?.verify()?;
        let database_created = !database_existed && database_path.is_file();

        let current = crate::settings::get_settings();
        if current
            .archive
            .as_ref()
            .is_some_and(|settings| settings.enabled)
        {
            let snapshot_warning = self.create_local_snapshot_now().err();
            let health = self.health().await;
            let archive_settings = current.archive.unwrap_or_default();
            let pending_requirements = initialization_requirements(&health, false);
            let warnings = initialization_warnings(&health, &archive_settings, snapshot_warning);
            return Ok(ArchiveInitializationResult {
                key_created: key_initialization.created,
                key_source: key_initialization.source.as_str().to_string(),
                database_created,
                enabled: archive_settings.enabled,
                pending_requirements,
                warnings,
                health,
                archive_settings,
            });
        }

        let mut disabled_settings = current;
        disabled_settings.archive = Some(archive.clone());
        crate::settings::update_settings(disabled_settings).map_err(|error| error.to_string())?;

        // Validate using the enabled candidate, but keep the persisted setting
        // disabled until every local and remote preflight has completed.
        let mut candidate = crate::settings::get_settings();
        let mut enabled_archive = archive.clone();
        enabled_archive.enabled = true;
        candidate.archive = Some(enabled_archive.clone());
        let enablement_failed = match self.validate_enablement(&candidate).await {
            Ok(()) => {
                crate::settings::update_settings(candidate).map_err(|error| error.to_string())?;
                false
            }
            Err(_) => true,
        };

        let snapshot_warning = self.create_local_snapshot_now().err();
        let health = self.health().await;
        let archive_settings = crate::settings::get_settings().archive.unwrap_or(archive);
        let pending_requirements = initialization_requirements(&health, enablement_failed);
        let warnings = initialization_warnings(&health, &archive_settings, snapshot_warning);
        Ok(ArchiveInitializationResult {
            key_created: key_initialization.created,
            key_source: key_initialization.source.as_str().to_string(),
            database_created,
            enabled: archive_settings.enabled,
            pending_requirements,
            warnings,
            health,
            archive_settings,
        })
    }

    pub fn search(
        &self,
        query: &str,
        filters: &ArchiveSearchFilters,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<ArchiveSearchPage, String> {
        self.database()?.search(query, filters, cursor, page_size)
    }

    pub fn detail(&self, id: &str) -> Result<ArchivedConversationDetail, String> {
        self.database()?.detail(id)
    }

    pub fn delete(&self, ids: &[String]) -> Result<ArchiveDeleteResult, String> {
        if ids.is_empty() {
            return Ok(ArchiveDeleteResult { deleted: 0 });
        }
        if ids.len() > 500 {
            return Err("单次最多删除 500 条归档会话".to_string());
        }
        let result = self.database()?.delete(ids)?;
        if result.deleted > 0 {
            self.notify_local_backup_changed();
        }
        Ok(result)
    }

    pub fn preview_local_history(&self) -> Result<HistoryImportPreview, String> {
        let database = self.database()?;
        let redactor = self.redactor()?;
        let sessions = crate::session_manager::scan_sessions();
        let mut by_provider = BTreeMap::new();
        let mut items = Vec::with_capacity(sessions.len());
        let mut importable = 0usize;
        let mut already_imported = 0usize;
        let mut failed = 0usize;
        for session in sessions {
            *by_provider.entry(session.provider_id.clone()).or_insert(0) += 1;
            let source_path = session.source_path.clone().unwrap_or_default();
            let source_path_hash = normalized_source_path_hash(&source_path);
            let loaded = crate::session_manager::load_messages(&session.provider_id, &source_path);
            match loaded {
                Ok(messages) => {
                    let content_hash = local_content_hash(&messages);
                    let fingerprint = import_fingerprint(
                        &session.provider_id,
                        &source_path_hash,
                        &session.session_id,
                        &content_hash,
                    );
                    let imported = database.is_imported(&fingerprint)?;
                    if imported {
                        already_imported += 1;
                    } else {
                        importable += 1;
                    }
                    items.push(HistoryImportPreviewItem {
                        provider: session.provider_id,
                        session_id: session.session_id,
                        title: redactor.redact_text(
                            session.title.as_deref().unwrap_or("Untitled conversation"),
                        ),
                        source_path_hash,
                        message_count: messages.len(),
                        already_imported: imported,
                        error: None,
                    });
                }
                Err(error) => {
                    failed += 1;
                    items.push(HistoryImportPreviewItem {
                        provider: session.provider_id,
                        session_id: session.session_id,
                        title: redactor.redact_text(
                            session.title.as_deref().unwrap_or("Untitled conversation"),
                        ),
                        source_path_hash,
                        message_count: 0,
                        already_imported: false,
                        error: Some(safe_error(&error)),
                    });
                }
            }
        }
        Ok(HistoryImportPreview {
            scanned: items.len(),
            importable,
            already_imported,
            failed,
            by_provider,
            items,
        })
    }

    pub fn import_local_history(&self) -> Result<HistoryImportResult, String> {
        let database = self.database()?;
        let redactor = self.redactor()?;
        let sessions = crate::session_manager::scan_sessions();
        let mut result = HistoryImportResult {
            imported: 0,
            skipped: 0,
            failed: 0,
            errors: Vec::new(),
        };
        for session in sessions {
            let source_path = session.source_path.clone().unwrap_or_default();
            let loaded =
                match crate::session_manager::load_messages(&session.provider_id, &source_path) {
                    Ok(messages) => messages,
                    Err(error) => {
                        result.failed += 1;
                        result.errors.push(format!(
                            "{} / {}: {}",
                            session.provider_id,
                            session.session_id,
                            safe_error(&error)
                        ));
                        continue;
                    }
                };
            let source_path_hash = normalized_source_path_hash(&source_path);
            let content_hash = local_content_hash(&loaded);
            let fingerprint = import_fingerprint(
                &session.provider_id,
                &source_path_hash,
                &session.session_id,
                &content_hash,
            );
            let normalized = loaded
                .into_iter()
                .map(|message| NormalizedMessage {
                    role: normalize_import_role(&message.role).to_string(),
                    content: redactor.redact_text(&message.content),
                    created_at: message.ts,
                    metadata: serde_json::json!({"imported": true}),
                    attachments: Vec::new(),
                })
                .filter(|message| !message.content.trim().is_empty())
                .collect::<Vec<_>>();
            let title = redactor.redact_text(
                session
                    .title
                    .as_deref()
                    .unwrap_or("Imported local conversation"),
            );
            let summary = session
                .summary
                .as_deref()
                .map(|value| redactor.redact_text(value));
            match database.import_local_session(
                &fingerprint,
                &source_path_hash,
                &content_hash,
                &session.provider_id,
                &session.session_id,
                &title,
                summary.as_deref(),
                None,
                session.created_at,
                session.last_active_at,
                &normalized,
            ) {
                Ok(true) => result.imported += 1,
                Ok(false) => result.skipped += 1,
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(format!(
                        "{} / {}: {}",
                        session.provider_id,
                        session.session_id,
                        safe_error(&error)
                    ));
                }
            }
        }
        result.errors.truncate(100);
        if result.imported > 0 {
            self.notify_local_backup_changed();
        }
        Ok(result)
    }

    pub fn export(&self, ids: &[String], format: &str, target: &Path) -> Result<(), String> {
        if ids.is_empty() {
            return Err("请选择至少一条归档会话".to_string());
        }
        if ids.len() > 500 {
            return Err("单次最多导出 500 条归档会话".to_string());
        }
        let format = match format.to_ascii_lowercase().as_str() {
            "json" => "json",
            "markdown" | "md" => "markdown",
            _ => return Err("导出格式必须为 json 或 markdown".to_string()),
        };
        let database = self.database()?;
        if same_path(database.path(), target) {
            return Err("导出目标不能覆盖归档数据库".to_string());
        }
        let details = ids
            .iter()
            .map(|id| database.detail(id))
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = if format == "json" {
            serde_json::to_vec_pretty(&details).map_err(|e| format!("生成 JSON 导出失败: {e}"))?
        } else {
            markdown_export(&details).into_bytes()
        };
        atomic_write(target, &bytes)?;
        database.record_export_audit(ids, format)?;
        self.notify_local_backup_changed();
        Ok(())
    }

    pub fn test_redaction(&self, input: &str) -> Result<String, String> {
        Ok(self.redactor()?.redact_text(input))
    }

    pub fn list_local_snapshots(&self) -> Result<Vec<ArchiveLocalSnapshotSummary>, String> {
        let settings = self.settings();
        let root = resolved_local_backup_directory(&settings);
        local_backup::list_local_archive_snapshot_metadata(&root).map(|snapshots| {
            snapshots
                .into_iter()
                .map(public_local_snapshot_summary)
                .collect()
        })
    }

    pub fn create_local_snapshot_now(&self) -> Result<ArchiveLocalSnapshotSummary, String> {
        let settings = self.settings();
        if !settings.local_backup.enabled {
            return Err("归档本地恢复快照已关闭".to_string());
        }
        let root = resolved_local_backup_directory(&settings);
        self.record_local_backup_attempt(&root);
        let result = (|| {
            let database = self.database()?;
            // Keep the Arc alive before reading the key. A concurrent restore
            // then sees the extra strong reference and is rejected, so this
            // key and database cannot come from different restore generations.
            let key = load_archive_key()?;
            let _operation_guard = self
                .inner
                .local_backup_operation_lock
                .lock()
                .map_err(|_| "归档本地快照操作锁已损坏".to_string())?;
            local_backup::create_local_archive_snapshot(
                &root,
                settings.local_backup.retain_count as usize,
                settings.local_backup.include_key,
                &database,
                &key,
            )
            .map(public_local_snapshot_summary)
        })();
        match &result {
            Ok(snapshot) => {
                self.record_local_backup_success(&root, snapshot.created_at);
            }
            Err(error) => self.record_local_backup_error(error.clone()),
        }
        result
    }

    pub fn delete_local_snapshot(&self, id: &str) -> Result<(), String> {
        let _operation_guard = self
            .inner
            .local_backup_operation_lock
            .lock()
            .map_err(|_| "归档本地快照操作锁已损坏".to_string())?;
        let root = resolved_local_backup_directory(&self.settings());
        local_backup::delete_local_archive_snapshot(&root, id)
    }

    pub fn restore_local_snapshot(&self, id: &str) -> Result<ArchiveLocalSnapshotSummary, String> {
        let _restore_guard = self
            .inner
            .restore_lock
            .lock()
            .map_err(|_| "归档数据库恢复锁已损坏".to_string())?;
        let _operation_guard = self
            .inner
            .local_backup_operation_lock
            .lock()
            .map_err(|_| "归档本地快照操作锁已损坏".to_string())?;
        let settings = self.settings();
        let root = resolved_local_backup_directory(&settings);
        let current_key = load_archive_key()?;
        let key_source = archive_key_source()?;
        let config_dir = crate::config::get_app_config_dir();
        let target_database = config_dir.join("conversation-archive.db");
        let managed_key = (key_source == ArchiveKeySource::ManagedFile)
            .then(|| config_dir.join("secrets").join("conversation-archive.key"));
        local_backup::validate_local_archive_snapshot(&root, id, Some(&current_key))?;

        {
            let mut cache = self
                .inner
                .database
                .lock()
                .map_err(|_| "归档数据库缓存锁已损坏".to_string())?;
            if cache
                .as_ref()
                .is_some_and(|cached| Arc::strong_count(&cached.database) > 1)
            {
                return Err("归档数据库正在处理团队请求，请停止代理后重试恢复".to_string());
            }
            cache.take();
        }

        let result = local_backup::restore_local_archive_snapshot(
            &root,
            id,
            &target_database,
            managed_key.as_deref(),
            &current_key,
        )
        .map(public_local_snapshot_summary);
        drop(_restore_guard);
        match result {
            Ok(summary) => {
                self.database()?.verify()?;
                self.clear_local_backup_error();
                Ok(summary)
            }
            Err(error) => {
                self.record_local_backup_error(error.clone());
                Err(error)
            }
        }
    }

    pub(crate) fn notify_local_backup_changed(&self) {
        if let Some(sender) = LOCAL_BACKUP_SIGNAL.get() {
            let _ = sender.try_send(());
        }
    }

    pub(crate) fn start_local_backup_worker(&self) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        if LOCAL_BACKUP_SIGNAL.set(sender).is_err() {
            return;
        }
        let service = self.clone();
        tauri::async_runtime::spawn(async move {
            while receiver.recv().await.is_some() {
                loop {
                    let settings = service.settings();
                    if !settings.local_backup.enabled {
                        break;
                    }
                    let root = resolved_local_backup_directory(&settings);
                    let interval = Duration::from_secs(
                        u64::from(settings.local_backup.min_interval_minutes) * 60,
                    );
                    if let Some(last_created_at) = service.scheduler_last_attempt_or_success(&root)
                    {
                        let now = chrono::Utc::now().timestamp_millis();
                        let due_at = last_created_at
                            .saturating_add(interval.as_millis().min(i64::MAX as u128) as i64);
                        if due_at > now {
                            let wait = Duration::from_millis((due_at - now) as u64);
                            tokio::select! {
                                _ = tokio::time::sleep(wait) => {}
                                signal = receiver.recv() => {
                                    if signal.is_none() {
                                        return;
                                    }
                                    continue;
                                }
                            }
                        }
                    }

                    let snapshot_service = service.clone();
                    let result = tauri::async_runtime::spawn_blocking(move || {
                        snapshot_service.create_local_snapshot_now()
                    })
                    .await;
                    let succeeded = match result {
                        Ok(Ok(_)) => true,
                        Ok(Err(_)) => false,
                        Err(error) => {
                            service.record_local_backup_error(format!(
                                "归档本地快照任务失败: {error}"
                            ));
                            false
                        }
                    };

                    // Retry warning-only failures after the same minimum
                    // interval even when no additional archive write arrives.
                    // Signals received during the backoff are coalesced by the
                    // bounded channel and never trigger a tight retry loop.
                    if !succeeded {
                        continue;
                    }

                    // A change queued while the snapshot was being produced
                    // needs another snapshot, but never before the configured
                    // minimum interval. With no queued change, go idle.
                    if receiver.try_recv().is_err() {
                        break;
                    }
                }
            }
        });
        self.notify_local_backup_changed();
    }

    pub(crate) fn start_local_history_worker(&self) {
        if LOCAL_HISTORY_WORKER_STARTED.swap(true, Ordering::SeqCst) {
            return;
        }
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
        let _ = LOCAL_HISTORY_SIGNAL.set(sender.clone());
        let watcher_sender = sender.clone();
        std::thread::spawn(move || {
            use notify::{RecommendedWatcher, RecursiveMode, Watcher};
            let callback_sender = watcher_sender.clone();
            let watcher = RecommendedWatcher::new(
                move |result: Result<notify::Event, notify::Error>| {
                    if result.is_ok() {
                        let _ = callback_sender.blocking_send(());
                    }
                },
                notify::Config::default(),
            );
            let Ok(mut watcher) = watcher else {
                log::warn!("无法启动本机会话文件监控，将依赖定时校准");
                return;
            };
            let mut watch_roots = crate::session_manager::watch_roots();
            watch_roots.extend(crate::memory_manager::watch_roots());
            watch_roots.sort();
            watch_roots.dedup();
            for root in watch_roots {
                let target = if root.exists() {
                    root
                } else {
                    root.parent().map(Path::to_path_buf).unwrap_or(root)
                };
                if target.exists() {
                    if let Err(error) = watcher.watch(&target, RecursiveMode::Recursive) {
                        log::debug!("无法监控会话目录 {}: {error}", target.display());
                    }
                }
            }
            loop {
                std::thread::park();
            }
        });

        let service = self.clone();
        tauri::async_runtime::spawn(async move {
            let _ = sender.try_send(());
            loop {
                let interval_seconds = service
                    .settings()
                    .local_history
                    .reconcile_interval_seconds
                    .clamp(30, 86_400);
                tokio::select! {
                    signal = receiver.recv() => {
                        if signal.is_none() { return; }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        while receiver.try_recv().is_ok() {}
                    }
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(interval_seconds))) => {}
                }
                let local_settings = service.settings().local_history;
                let history_enabled = local_settings.auto_import_enabled;
                let memory_enabled = local_settings.memory_import_enabled;
                if !history_enabled && !memory_enabled {
                    continue;
                }
                let started_at = chrono::Utc::now().timestamp_millis();
                if history_enabled {
                    if let Ok(mut status) = local_history_status_store().lock() {
                        status.running = true;
                        status.last_started_at = Some(started_at);
                        status.last_error = None;
                    }
                }
                if memory_enabled {
                    if let Ok(mut status) = local_memory_status_store().lock() {
                        status.running = true;
                        status.last_started_at = Some(started_at);
                        status.last_error = None;
                    }
                }
                let import_service = service.clone();
                let outcome = tauri::async_runtime::spawn_blocking(move || {
                    import_service.prepare_local_archive()?;
                    let history = history_enabled
                        .then(|| import_service.import_local_history())
                        .transpose()?;
                    let memories = memory_enabled
                        .then(|| import_service.import_agent_memories())
                        .transpose()?;
                    Ok::<_, String>((history, memories))
                })
                .await;
                let completed_at = chrono::Utc::now().timestamp_millis();
                match outcome {
                    Ok(Ok((history, memories))) => {
                        if let Some(result) = history {
                            if let Ok(mut status) = local_history_status_store().lock() {
                                status.running = false;
                                status.last_completed_at = Some(completed_at);
                                status.last_imported = result.imported;
                                status.last_skipped = result.skipped;
                                status.last_failed = result.failed;
                                status.last_error = (!result.errors.is_empty()).then(|| {
                                    result
                                        .errors
                                        .into_iter()
                                        .take(3)
                                        .collect::<Vec<_>>()
                                        .join("；")
                                });
                            }
                        }
                        if let Some(result) = memories {
                            if let Ok(mut status) = local_memory_status_store().lock() {
                                status.running = false;
                                status.last_completed_at = Some(completed_at);
                                status.last_imported = result.imported;
                                status.last_skipped = result.skipped;
                                status.last_deleted = result.deleted;
                                status.last_failed = result.failed;
                                status.providers = result.providers;
                                status.last_error = (!result.errors.is_empty()).then(|| {
                                    result
                                        .errors
                                        .into_iter()
                                        .take(3)
                                        .collect::<Vec<_>>()
                                        .join("；")
                                });
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        if history_enabled {
                            if let Ok(mut status) = local_history_status_store().lock() {
                                status.running = false;
                                status.last_completed_at = Some(completed_at);
                                status.last_error = Some(error.clone());
                            }
                        }
                        if memory_enabled {
                            if let Ok(mut status) = local_memory_status_store().lock() {
                                status.running = false;
                                status.last_completed_at = Some(completed_at);
                                status.last_error = Some(error);
                            }
                        }
                    }
                    Err(error) => {
                        let message = format!("本地 Agent 归档任务异常: {error}");
                        if let Ok(mut status) = local_history_status_store().lock() {
                            status.running = false;
                            status.last_error = Some(message.clone());
                        }
                        if let Ok(mut status) = local_memory_status_store().lock() {
                            status.running = false;
                            status.last_error = Some(message);
                        }
                    }
                }
            }
        });
    }

    pub fn trigger_local_history_import(&self) -> bool {
        LOCAL_HISTORY_SIGNAL
            .get()
            .is_some_and(|sender| sender.try_send(()).is_ok())
    }

    fn record_local_backup_success(&self, root: &Path, created_at: i64) {
        if let Ok(mut status) = self.inner.local_backup_status.lock() {
            status.last_error = None;
            status.snapshot_directory = Some(root.to_string_lossy().to_string());
            status.last_success_at = Some(created_at);
        }
    }

    fn record_local_backup_attempt(&self, root: &Path) {
        if let Ok(mut status) = self.inner.local_backup_status.lock() {
            let directory = root.to_string_lossy().to_string();
            if status.snapshot_directory.as_deref() != Some(directory.as_str()) {
                status.snapshot_directory = Some(directory);
                status.last_success_at = None;
            }
            status.last_attempt_at = Some(chrono::Utc::now().timestamp_millis());
        }
    }

    fn record_local_backup_error(&self, error: String) {
        if let Ok(mut status) = self.inner.local_backup_status.lock() {
            status.last_error = Some(error);
        }
    }

    fn clear_local_backup_error(&self) {
        if let Ok(mut status) = self.inner.local_backup_status.lock() {
            status.last_error = None;
        }
    }

    fn scheduler_last_attempt_or_success(&self, root: &Path) -> Option<i64> {
        let directory = root.to_string_lossy().to_string();
        if let Ok(status) = self.inner.local_backup_status.lock() {
            if status.snapshot_directory.as_deref() == Some(directory.as_str()) {
                return status.last_success_at.max(status.last_attempt_at);
            }
        }
        let latest = latest_local_snapshot_at(root);
        if let Ok(mut status) = self.inner.local_backup_status.lock() {
            status.snapshot_directory = Some(directory);
            status.last_success_at = latest;
            status.last_attempt_at = None;
        }
        latest
    }
}

fn public_local_snapshot_summary(
    snapshot: local_backup::LocalArchiveSnapshotSummary,
) -> ArchiveLocalSnapshotSummary {
    ArchiveLocalSnapshotSummary {
        id: snapshot.id,
        created_at: snapshot.created_at,
        database_size_bytes: snapshot.database_size_bytes,
        total_size_bytes: snapshot.total_size_bytes,
        directory: snapshot.directory,
        includes_key: snapshot.includes_key,
    }
}

/// Build the optional archive artifact used by both S3 and WebDAV snapshots.
/// Once an archive database exists it remains part of backups even if capture
/// is temporarily disabled, so a later sync cannot silently remove the only
/// remote copy of permanently retained conversations.
pub(crate) fn build_encrypted_archive_snapshot() -> Result<Option<Vec<u8>>, crate::error::AppError>
{
    let enabled = crate::settings::get_settings()
        .archive
        .as_ref()
        .is_some_and(|settings| settings.enabled);
    let path = crate::config::get_app_config_dir().join("conversation-archive.db");
    if !enabled && !path.exists() {
        return Ok(None);
    }
    ArchiveService::new()
        .database()
        .and_then(|database| database.encrypted_snapshot())
        .map(Some)
        .map_err(crate::error::AppError::Config)
}

/// Verify an encrypted remote artifact with the deployment key, then replace
/// the local archive atomically. The shared connection cache is dropped first;
/// restoration is rejected while a proxy stream still holds the database.
pub(crate) fn restore_encrypted_archive_snapshot(
    bytes: &[u8],
) -> Result<(), crate::error::AppError> {
    let _restore_guard =
        if let Some(inner) = ARCHIVE_SERVICE_INNER.get() {
            Some(inner.restore_lock.lock().map_err(|_| {
                crate::error::AppError::Config("归档数据库恢复锁已损坏".to_string())
            })?)
        } else {
            None
        };
    let key = load_archive_key().map_err(crate::error::AppError::Config)?;
    let config_dir = crate::config::get_app_config_dir();
    std::fs::create_dir_all(&config_dir).map_err(|e| crate::error::AppError::io(&config_dir, e))?;
    let mut temporary = tempfile::NamedTempFile::new_in(&config_dir)
        .map_err(|e| crate::error::AppError::io(&config_dir, e))?;
    temporary
        .write_all(bytes)
        .map_err(|e| crate::error::AppError::io(temporary.path(), e))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|e| crate::error::AppError::io(temporary.path(), e))?;
    ArchiveDatabase::validate_encrypted_file(temporary.path(), &key)
        .map_err(crate::error::AppError::Config)?;

    if let Some(inner) = ARCHIVE_SERVICE_INNER.get() {
        let mut cache = inner
            .database
            .lock()
            .map_err(|_| crate::error::AppError::Config("归档数据库缓存锁已损坏".to_string()))?;
        if let Some(cached) = cache.as_ref() {
            if Arc::strong_count(&cached.database) > 1 {
                return Err(crate::error::AppError::Config(
                    "归档数据库正在处理团队请求，请停止代理后重试恢复".to_string(),
                ));
            }
        }
        cache.take();
    }

    // Detach the validated temporary file before touching the current target;
    // a `keep` failure must never leave the live database renamed away.
    let (_, temporary_path) = temporary
        .keep()
        .map_err(|e| crate::error::AppError::io(e.file.path(), e.error))?;

    let target = config_dir.join("conversation-archive.db");
    let managed_key = config_dir.join("secrets").join("conversation-archive.key");
    let result =
        local_backup::install_archive_database_durably(&temporary_path, &target, &managed_key)
            .map_err(crate::error::AppError::Config);
    if result.is_err() && temporary_path.exists() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

pub(crate) fn validate_encrypted_archive_snapshot(
    bytes: &[u8],
) -> Result<(), crate::error::AppError> {
    let key = load_archive_key().map_err(crate::error::AppError::Config)?;
    let temporary = tempfile::NamedTempFile::new()
        .map_err(|e| crate::error::AppError::Config(format!("创建归档校验文件失败: {e}")))?;
    std::fs::write(temporary.path(), bytes)
        .map_err(|e| crate::error::AppError::io(temporary.path(), e))?;
    ArchiveDatabase::validate_encrypted_file(temporary.path(), &key)
        .map_err(crate::error::AppError::Config)?;
    ensure_archive_restore_idle()
}

fn ensure_archive_restore_idle() -> Result<(), crate::error::AppError> {
    let Some(inner) = ARCHIVE_SERVICE_INNER.get() else {
        return Ok(());
    };
    let _restore_guard = inner
        .restore_lock
        .lock()
        .map_err(|_| crate::error::AppError::Config("归档数据库恢复锁已损坏".to_string()))?;
    let cache = inner
        .database
        .lock()
        .map_err(|_| crate::error::AppError::Config("归档数据库缓存锁已损坏".to_string()))?;
    if cache
        .as_ref()
        .is_some_and(|cached| Arc::strong_count(&cached.database) > 1)
    {
        return Err(crate::error::AppError::Config(
            "归档数据库正在处理团队请求，请停止代理后重试恢复".to_string(),
        ));
    }
    Ok(())
}

impl Default for ArchiveService {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize legacy proxy diagnostics before they reach the process logger.
/// This is intentionally applied even when archive capture is disabled: a
/// later archive enablement must never discover credentials already written by
/// the existing debug/error paths.
pub(crate) fn redact_log_text(input: &str) -> String {
    let settings = crate::settings::get_settings().archive.unwrap_or_default();
    let redactor = Redactor::new(&settings.redaction_rules).unwrap_or_default();
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
        redactor.redact_json(&mut value);
        serde_json::to_string(&value).unwrap_or_else(|_| "[REDACTED:UNSERIALIZABLE]".to_string())
    } else {
        redactor.redact_text(input)
    }
}

pub(crate) fn redact_log_json(value: &serde_json::Value) -> String {
    let mut value = value.clone();
    let settings = crate::settings::get_settings().archive.unwrap_or_default();
    let redactor = Redactor::new(&settings.redaction_rules).unwrap_or_default();
    redactor.redact_json(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| "[REDACTED:UNSERIALIZABLE]".to_string())
}

fn initialization_requirements(health: &ArchiveHealth, enablement_failed: bool) -> Vec<String> {
    let mut requirements = Vec::new();
    if !health.oidc_configured {
        requirements.push("配置 OIDC issuer、audience 和 JWKS URL".to_string());
    } else if !health.oidc_ok {
        requirements.push("修复 OIDC / JWKS 验证".to_string());
    }
    if enablement_failed && health.ready {
        requirements.push("重试归档启用验证".to_string());
    }
    requirements
}

fn initialization_warnings(
    health: &ArchiveHealth,
    archive: &crate::settings::ArchiveSettings,
    snapshot_warning: Option<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if archive.local_backup.enabled {
        if let Some(warning) = snapshot_warning.or_else(|| health.local_backup_warning.clone()) {
            warnings.push(format!("本地恢复快照暂不可用：{warning}"));
        }
        if archive.local_backup.include_key {
            warnings.push(
                "本地恢复快照包含解密密钥；取得快照目录即可读取归档内容，请严格控制目录权限"
                    .to_string(),
            );
        }
    }
    warnings.sort();
    warnings.dedup();
    warnings
}

fn resolved_local_backup_directory(
    settings: &crate::settings::ArchiveSettings,
) -> std::path::PathBuf {
    settings
        .local_backup
        .directory
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::config::get_app_config_dir().join("archive-backups"))
}

fn latest_local_snapshot_at(root: &Path) -> Option<i64> {
    local_backup::latest_local_archive_snapshot_timestamp(root).ok()?
}

fn local_machine_id() -> Result<String, String> {
    let path = crate::config::get_app_config_dir().join("archive-machine-id");
    if let Ok(value) = std::fs::read_to_string(&path) {
        let value = value.trim();
        if uuid::Uuid::parse_str(value).is_ok() {
            return Ok(value.to_string());
        }
    }
    let value = uuid::Uuid::new_v4().to_string();
    atomic_write(&path, value.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("设置本机归档标识权限失败: {e}"))?;
    }
    Ok(value)
}

fn normalized_source_path_hash(source: &str) -> String {
    let normalized = if source.starts_with("sqlite:") {
        source.to_string()
    } else {
        std::fs::canonicalize(source)
            .unwrap_or_else(|_| source.into())
            .to_string_lossy()
            .replace('\\', "/")
    };
    sha256_hex(normalized.as_bytes())
}

fn local_content_hash(messages: &[crate::session_manager::SessionMessage]) -> String {
    let mut digest_input = String::new();
    for message in messages {
        digest_input.push_str(&message.role);
        digest_input.push('\u{1f}');
        digest_input.push_str(&message.content);
        digest_input.push('\u{1e}');
    }
    sha256_hex(digest_input.as_bytes())
}

fn import_fingerprint(
    provider: &str,
    source_path_hash: &str,
    session_id: &str,
    content_hash: &str,
) -> String {
    sha256_hex(
        format!("{provider}\u{1f}{source_path_hash}\u{1f}{session_id}\u{1f}{content_hash}")
            .as_bytes(),
    )
}

fn normalize_import_role(role: &str) -> &str {
    match role.to_ascii_lowercase().as_str() {
        "system" | "developer" => "system",
        "user" | "human" => "user",
        "assistant" | "model" => "assistant",
        "tool" | "function" => "tool",
        _ => "unknown",
    }
}

fn safe_error(error: &str) -> String {
    // Parser errors may contain paths but should never contain conversation
    // bodies. Still bound their length before exposing them in the admin UI.
    error.chars().take(300).collect()
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left == right
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("创建导出目录失败: {e}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("创建导出临时文件失败: {e}"))?;
    temp.write_all(bytes)
        .map_err(|e| format!("写入导出文件失败: {e}"))?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|e| format!("同步导出文件失败: {e}"))?;
    temp.persist(path)
        .map_err(|e| format!("保存导出文件失败: {}", e.error))?;
    Ok(())
}

fn markdown_export(details: &[ArchivedConversationDetail]) -> String {
    let mut output = String::new();
    for detail in details {
        output.push_str("# ");
        output.push_str(&detail.conversation.title.replace('\n', " "));
        output.push_str("\n\n");
        output.push_str(&format!(
            "- Provider: {}\n- Model: {}\n- Status: {}\n- Updated: {}\n\n",
            detail.conversation.provider,
            detail.conversation.model.as_deref().unwrap_or("—"),
            detail.conversation.status,
            detail.conversation.updated_at
        ));
        for message in &detail.messages {
            output.push_str(&format!(
                "## {} · position {} · revision {}\n\n",
                message.role, message.logical_position, message.revision
            ));
            output.push_str(&message.content);
            output.push_str("\n\n");
            for attachment in &message.attachments {
                output.push_str(&format!(
                    "> Attachment: {} · {} bytes · SHA-256 `{}`\n\n",
                    attachment.mime_type.as_deref().unwrap_or("unknown"),
                    attachment.size_bytes,
                    attachment.sha256
                ));
            }
        }
        output.push_str("\n---\n\n");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn health_fixture() -> ArchiveHealth {
        ArchiveHealth {
            enabled: false,
            ready: false,
            key_configured: true,
            database_ok: true,
            fts_ok: true,
            oidc_configured: false,
            oidc_ok: false,
            local_backup_enabled: true,
            local_backup_ok: false,
            local_backup_directory: Some("/tmp/token-manager-archive-backups".to_string()),
            last_local_backup_at: None,
            local_backup_warning: Some("尚未创建归档本地恢复快照".to_string()),
            key_source: Some("managed_file".to_string()),
            database_path: None,
            database_size_bytes: 0,
            error: None,
        }
    }

    #[test]
    fn initialization_requirements_only_include_team_identity_configuration() {
        let requirements = initialization_requirements(&health_fixture(), false);
        assert!(requirements.iter().any(|value| value.contains("OIDC")));
        assert!(!requirements.iter().any(|value| value.contains("S3")));
        assert!(!requirements.iter().any(|value| value.contains("WebDAV")));
    }

    #[test]
    fn initialization_warns_when_local_snapshot_bundles_the_key() {
        let warnings = initialization_warnings(
            &health_fixture(),
            &crate::settings::ArchiveSettings::default(),
            None,
        );
        assert!(warnings.iter().any(|value| value.contains("解密密钥")));
    }

    #[test]
    fn initialization_result_does_not_serialize_key_material_or_path() {
        let secret = base64::engine::general_purpose::STANDARD.encode([0x5a_u8; 32]);
        let result = ArchiveInitializationResult {
            key_created: true,
            key_source: "managed_file".to_string(),
            database_created: true,
            enabled: false,
            pending_requirements: Vec::new(),
            warnings: Vec::new(),
            health: health_fixture(),
            archive_settings: crate::settings::ArchiveSettings::default(),
        };
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(&secret));
        assert!(!serialized.contains("keyPath"));
        assert!(!serialized.contains("keyValue"));
    }
}
