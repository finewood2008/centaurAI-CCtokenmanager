use super::key::load_archive_key;
use super::redaction::sha256_hex;
use super::types::{
    AgentMemoryChange, AgentMemoryChangesPage, AgentMemoryDetail, AgentMemorySummary,
    ArchiveConversationChange, ArchiveConversationChangesPage, ArchiveDeleteResult,
    ArchiveIdentity, ArchiveSearchFilters, ArchiveSearchPage, ArchivedAttachment,
    ArchivedConversationDetail, ArchivedConversationSummary, ArchivedExchange, ArchivedMessage,
    CaptureHandle, NormalizedMessage, NormalizedRequest, ScannedAgentMemory,
};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

const ARCHIVE_SCHEMA_VERSION: i64 = 2;
const MIN_SUPPORTED_SCHEMA_VERSION: i64 = 1;

pub struct ArchiveDatabase {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl ArchiveDatabase {
    pub fn open_default() -> Result<Self, String> {
        let key = load_archive_key()?;
        let path = crate::config::get_app_config_dir().join("conversation-archive.db");
        Self::open(&path, &key)
    }

    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("创建归档数据库目录失败: {e}"))?;
        }
        let existed = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("归档数据库文件不得是符号链接".to_string())
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err("归档数据库路径必须是普通文件".to_string())
            }
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(format!("读取归档数据库文件元数据失败: {error}")),
        };
        if existed {
            // The archive is a dedicated application file, so repairing an
            // overly broad mode is safe and prevents a historical chmod from
            // silently exposing future conversations.
            set_restrictive_permissions(path)?;
        }
        let mut conn = Connection::open(path).map_err(db_error)?;
        set_restrictive_permissions(path)?;
        apply_key(&conn, key)?;
        // This query is deliberately first: with a wrong key SQLCipher returns
        // `file is not a database` before any migration can touch the file.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| "无法打开对话归档：密钥错误或数据库已损坏".to_string())?;
        if existed {
            // Never migrate or otherwise write an existing archive until its
            // ciphertext, logical pages and current schema have all passed
            // read-only validation.
            verify_cipher_integrity(&conn)?;
            verify_archive_schema_compatible(&conn)?;
        }
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(db_error)?;
        create_schema(&mut conn)?;
        verify_cipher_integrity(&conn)?;
        verify_archive_schema(&conn)?;
        recover_incomplete_streams(&mut conn)?;
        set_restrictive_permissions(path)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path)
            .map(|meta| meta.len())
            .unwrap_or(0)
    }

    pub fn verify(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        verify_cipher_integrity(&conn)?;
        verify_archive_schema(&conn)
    }

    /// Cheap structural probe for routine health polling. `open` and restore
    /// preflight already perform the full ciphertext and logical integrity
    /// scans; explicit snapshot validation repeats them before replacement.
    pub fn verify_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        verify_archive_schema(&conn)
    }

    /// Produce a transactionally consistent SQLCipher file using SQLite's
    /// online backup API. The destination is keyed before the first page is
    /// copied, so the snapshot is encrypted at every point in its lifetime.
    pub fn encrypted_snapshot(&self) -> Result<Vec<u8>, String> {
        let key = load_archive_key()?;
        self.encrypted_snapshot_with_key(&key)
    }

    /// Produce an encrypted snapshot with an explicitly supplied key. Local
    /// recovery bundles use this form so the database and bundled key are
    /// guaranteed to describe the same SQLCipher file.
    pub(crate) fn encrypted_snapshot_with_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let temporary =
            tempfile::tempdir().map_err(|e| format!("创建归档快照临时目录失败: {e}"))?;
        let destination_path = temporary.path().join("conversation-archive.db");
        self.encrypted_snapshot_to_path_with_key(&destination_path, key)?;
        std::fs::read(&destination_path).map_err(|e| format!("读取归档加密快照失败: {e}"))
    }

    /// Stream an online SQLCipher backup directly to a destination file. The
    /// source uses an independent read-only connection, so the live capture
    /// connection is not held behind its mutex and writers can continue while
    /// SQLite copies a consistent snapshot.
    pub(crate) fn encrypted_snapshot_to_path_with_key(
        &self,
        destination_path: &Path,
        key: &[u8; 32],
    ) -> Result<(), String> {
        if destination_path == self.path {
            return Err("归档快照目标不能覆盖当前数据库".to_string());
        }
        if destination_path.exists() {
            return Err("归档快照目标文件已存在".to_string());
        }
        let source = Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db_error)?;
        apply_key(&source, key)?;
        source
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| "无法读取归档数据库以创建快照".to_string())?;
        source
            .busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;

        let mut destination = Connection::open_with_flags(
            destination_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db_error)?;
        set_restrictive_permissions(destination_path)?;
        apply_key(&destination, key)?;
        destination
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
            .map_err(db_error)?;
        let backup = rusqlite::backup::Backup::new(&source, &mut destination).map_err(db_error)?;
        backup
            .run_to_completion(128, Duration::from_millis(10), None)
            .map_err(db_error)?;
        drop(backup);
        verify_cipher_integrity(&destination)?;
        destination
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .map_err(db_error)?;
        drop(destination);
        set_restrictive_permissions(destination_path)
    }

    pub fn validate_encrypted_file(path: &Path, key: &[u8; 32]) -> Result<(), String> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db_error)?;
        apply_key(&conn, key)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| "归档快照密钥错误或文件已损坏".to_string())?;
        verify_cipher_integrity(&conn)?;
        verify_archive_schema_compatible(&conn)
    }

    pub fn capture_request(
        &self,
        identity: &ArchiveIdentity,
        external_conversation_id: &str,
        source: &str,
        request: &NormalizedRequest,
    ) -> Result<CaptureHandle, String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let now = now_ms();
        let user_id = upsert_user(&tx, identity, now)?;
        let owner_key = identity.owner_key();
        let title = request
            .messages
            .iter()
            .find(|message| message.role == "user")
            .map(|message| truncate_chars(message.content.trim(), 120))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Untitled conversation".to_string());
        let conversation_id = upsert_conversation(
            &tx,
            &owner_key,
            external_conversation_id,
            Some(&user_id),
            source,
            &request.provider,
            request.model.as_deref(),
            &title,
            now,
        )?;
        let exchange_id = Uuid::new_v4().to_string();
        let request_payload = serde_json::to_string(&request.redacted_payload)
            .map_err(|e| format!("序列化脱敏请求失败: {e}"))?;
        tx.execute(
            "INSERT INTO exchanges
             (id, conversation_id, provider, model, status, stream, request_payload,
              request_message_count, started_at)
             VALUES (?1, ?2, ?3, ?4, 'capturing', ?5, ?6, ?7, ?8)",
            params![
                exchange_id,
                conversation_id,
                request.provider,
                request.model,
                request.stream as i64,
                request_payload,
                request.messages.len() as i64,
                now,
            ],
        )
        .map_err(db_error)?;

        for (position, message) in request.messages.iter().enumerate() {
            let message_id = align_message(
                &tx,
                &conversation_id,
                Some(&exchange_id),
                position as i64,
                message,
                "final",
                now,
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO exchange_messages (exchange_id, message_id, request_position)
                 VALUES (?1, ?2, ?3)",
                params![exchange_id, message_id, position as i64],
            )
            .map_err(db_error)?;
        }
        tx.execute(
            "UPDATE conversations SET updated_at=?2, status='active', model=COALESCE(?3, model)
             WHERE id=?1",
            params![conversation_id, now, request.model],
        )
        .map_err(db_error)?;
        rebuild_fts(&tx, &conversation_id)?;
        record_conversation_change(&tx, &conversation_id, source, now)?;
        tx.commit().map_err(db_error)?;

        Ok(CaptureHandle {
            exchange_id,
            conversation_id,
            request_message_count: request.messages.len(),
            provider: request.provider.clone(),
        })
    }

    pub fn capture_non_stream_response(
        &self,
        handle: &CaptureHandle,
        status_code: u16,
        redacted_payload: &Value,
        messages: &[NormalizedMessage],
    ) -> Result<(), String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let now = now_ms();
        let status = if status_code < 400 {
            "completed"
        } else {
            "upstream_error"
        };
        for (index, message) in messages.iter().enumerate() {
            align_message(
                &tx,
                &handle.conversation_id,
                Some(&handle.exchange_id),
                (handle.request_message_count + index) as i64,
                message,
                "final",
                now,
            )?;
        }
        let response_payload = serde_json::to_string(redacted_payload)
            .map_err(|e| format!("序列化脱敏响应失败: {e}"))?;
        let error_code = error_code_from_payload(status_code, redacted_payload);
        tx.execute(
            "UPDATE exchanges SET status=?2, response_payload=?3, http_status=?4, completed_at=?5,
                                  error_code=?6
             WHERE id=?1",
            params![
                handle.exchange_id,
                status,
                response_payload,
                status_code as i64,
                now,
                error_code
            ],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE conversations SET status=?2, updated_at=?3 WHERE id=?1",
            params![handle.conversation_id, status, now],
        )
        .map_err(db_error)?;
        rebuild_fts(&tx, &handle.conversation_id)?;
        record_conversation_change(&tx, &handle.conversation_id, "local_proxy", now)?;
        tx.commit().map_err(db_error)
    }

    /// Persist response headers before the first SSE frame is exposed to the
    /// client. A failure here is still early enough for middleware to return a
    /// fail-closed 503 without sending any upstream bytes.
    pub fn begin_stream_response(
        &self,
        handle: &CaptureHandle,
        status_code: u16,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        conn.execute(
            "UPDATE exchanges SET http_status=?2 WHERE id=?1 AND status='capturing'",
            params![handle.exchange_id, status_code as i64],
        )
        .map_err(db_error)?;
        Ok(())
    }

    pub fn record_stream_event(
        &self,
        handle: &CaptureHandle,
        event_type: Option<&str>,
        redacted_payload: &str,
        text_delta: &str,
    ) -> Result<(), String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let sequence: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(sequence), -1) + 1 FROM stream_events WHERE exchange_id=?1",
                params![handle.exchange_id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        tx.execute(
            "INSERT INTO stream_events
             (exchange_id, sequence, event_type, payload, text_delta, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                handle.exchange_id,
                sequence,
                event_type,
                redacted_payload,
                text_delta,
                now_ms()
            ],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE exchanges SET status='streaming' WHERE id=?1",
            params![handle.exchange_id],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE conversations SET status='partial', updated_at=?2 WHERE id=?1",
            params![handle.conversation_id, now_ms()],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }

    pub fn finalize_stream(
        &self,
        handle: &CaptureHandle,
        interruption_reason: Option<&str>,
    ) -> Result<(), String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        finalize_stream_tx(&mut conn, &handle.exchange_id, interruption_reason)
    }

    pub fn search(
        &self,
        query: &str,
        filters: &ArchiveSearchFilters,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<ArchiveSearchPage, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let page_size = page_size.clamp(1, 100);
        let offset = cursor
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let (from, where_sql, mut bind) = build_search_clause(query, filters);
        let count_sql = format!("SELECT COUNT(DISTINCT c.id) {from} {where_sql}");
        let total: i64 = conn
            .query_row(&count_sql, params_from_iter(bind.iter()), |row| row.get(0))
            .map_err(db_error)?;
        let sql = format!(
            "SELECT c.id, c.owner_key, c.user_id, u.name, u.email, c.source, c.provider,
                    c.model, c.status, c.title, c.summary, c.created_at, c.updated_at,
                    (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id
                     AND m.revision=(SELECT MAX(m2.revision) FROM messages m2
                                     WHERE m2.conversation_id=m.conversation_id
                                       AND m2.logical_position=m.logical_position)),
                    EXISTS(SELECT 1 FROM messages pm WHERE pm.conversation_id=c.id
                           AND pm.status != 'final')
             {from} {where_sql}
             GROUP BY c.id ORDER BY c.updated_at DESC, c.id DESC LIMIT ? OFFSET ?"
        );
        bind.push(SqlValue::Integer((page_size + 1) as i64));
        bind.push(SqlValue::Integer(offset as i64));
        let mut statement = conn.prepare(&sql).map_err(db_error)?;
        let mut items = statement
            .query_map(params_from_iter(bind.iter()), summary_from_row)
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let has_more = items.len() > page_size;
        items.truncate(page_size);
        Ok(ArchiveSearchPage {
            items,
            next_cursor: has_more.then(|| (offset + page_size).to_string()),
            total: total.max(0) as u64,
        })
    }

    pub fn conversation_changes(
        &self,
        after_sequence: i64,
        page_size: usize,
    ) -> Result<ArchiveConversationChangesPage, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let page_size = page_size.clamp(1, 100);
        let mut statement = conn
            .prepare(
                "SELECT ch.seq, c.id, c.owner_key, c.user_id, u.name, u.email, c.source,
                        c.provider, c.model, c.status, c.title, c.summary, c.created_at,
                        c.updated_at,
                        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id
                         AND m.revision=(SELECT MAX(m2.revision) FROM messages m2
                                         WHERE m2.conversation_id=m.conversation_id
                                           AND m2.logical_position=m.logical_position)),
                        EXISTS(SELECT 1 FROM messages pm WHERE pm.conversation_id=c.id
                               AND pm.status != 'final')
                 FROM conversation_changes ch
                 JOIN conversations c ON c.id=ch.conversation_id
                 LEFT JOIN users u ON u.id=c.user_id
                 WHERE ch.seq>?1 AND c.source IN ('local_history', 'local_proxy')
                 ORDER BY ch.seq ASC LIMIT ?2",
            )
            .map_err(db_error)?;
        let mut items = statement
            .query_map(
                params![after_sequence.max(0), (page_size + 1) as i64],
                |row| {
                    Ok(ArchiveConversationChange {
                        sequence: row.get(0)?,
                        conversation: ArchivedConversationSummary {
                            id: row.get(1)?,
                            owner_key: row.get(2)?,
                            user_id: row.get(3)?,
                            user_name: row.get(4)?,
                            user_email: row.get(5)?,
                            source: row.get(6)?,
                            provider: row.get(7)?,
                            model: row.get(8)?,
                            status: row.get(9)?,
                            title: row.get(10)?,
                            summary: row.get(11)?,
                            created_at: row.get(12)?,
                            updated_at: row.get(13)?,
                            message_count: row.get::<_, i64>(14)?.max(0) as u64,
                            has_partial_response: row.get::<_, i64>(15)? != 0,
                        },
                    })
                },
            )
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let has_more = items.len() > page_size;
        items.truncate(page_size);
        let next_cursor = items.last().map(|item| item.sequence.to_string());
        Ok(ArchiveConversationChangesPage {
            items,
            next_cursor,
            has_more,
        })
    }

    pub fn reconcile_agent_memories(
        &self,
        memories: &[ScannedAgentMemory],
        completed_roots: &[String],
    ) -> Result<(usize, usize, usize, HashMap<String, usize>), String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let now = now_ms();
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut deleted = 0usize;
        let mut imported_by_provider = HashMap::<String, usize>::new();
        let seen_ids = memories
            .iter()
            .map(|memory| memory.id.as_str())
            .collect::<HashSet<_>>();

        for memory in memories {
            let existing = tx
                .query_row(
                    "SELECT content_hash, deleted_at FROM agent_memories WHERE id=?1",
                    [&memory.id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
                )
                .optional()
                .map_err(db_error)?;
            let changed = existing.as_ref().is_none_or(|(content_hash, deleted_at)| {
                content_hash != &memory.content_hash || deleted_at.is_some()
            });
            tx.execute(
                "INSERT INTO agent_memories
                 (id, provider, scope, kind, title, logical_path, project_dir,
                  source_path_hash, scan_root_hash, content, content_hash, size_bytes,
                  source_modified_at, first_seen_at, updated_at, deleted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                   provider=excluded.provider,
                   scope=excluded.scope,
                   kind=excluded.kind,
                   title=excluded.title,
                   logical_path=excluded.logical_path,
                   project_dir=excluded.project_dir,
                   source_path_hash=excluded.source_path_hash,
                   scan_root_hash=excluded.scan_root_hash,
                   content=excluded.content,
                   content_hash=excluded.content_hash,
                   size_bytes=excluded.size_bytes,
                   source_modified_at=excluded.source_modified_at,
                   updated_at=CASE
                     WHEN agent_memories.content_hash != excluded.content_hash
                       OR agent_memories.deleted_at IS NOT NULL
                     THEN excluded.updated_at ELSE agent_memories.updated_at END,
                   deleted_at=NULL",
                params![
                    memory.id,
                    memory.provider,
                    memory.scope,
                    memory.kind,
                    memory.title,
                    memory.path,
                    memory.project_dir,
                    memory.source_path_hash,
                    memory.scan_root_hash,
                    memory.content,
                    memory.content_hash,
                    memory.size_bytes.min(i64::MAX as u64) as i64,
                    memory.source_modified_at,
                    now,
                ],
            )
            .map_err(db_error)?;
            if changed {
                tx.execute(
                    "INSERT INTO agent_memory_changes(memory_id, operation, changed_at)
                     VALUES (?1, 'upsert', ?2)",
                    params![memory.id, now],
                )
                .map_err(db_error)?;
                imported += 1;
                *imported_by_provider
                    .entry(memory.provider.clone())
                    .or_default() += 1;
            } else {
                skipped += 1;
            }
        }

        for root_hash in completed_roots {
            let mut statement = tx
                .prepare(
                    "SELECT id FROM agent_memories
                     WHERE scan_root_hash=?1 AND deleted_at IS NULL",
                )
                .map_err(db_error)?;
            let active_ids = statement
                .query_map([root_hash], |row| row.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            drop(statement);
            for id in active_ids {
                if seen_ids.contains(id.as_str()) {
                    continue;
                }
                tx.execute(
                    "UPDATE agent_memories
                     SET content='', size_bytes=0, deleted_at=?2, updated_at=?2
                     WHERE id=?1 AND deleted_at IS NULL",
                    params![id, now],
                )
                .map_err(db_error)?;
                tx.execute(
                    "INSERT INTO agent_memory_changes(memory_id, operation, changed_at)
                     VALUES (?1, 'delete', ?2)",
                    params![id, now],
                )
                .map_err(db_error)?;
                deleted += 1;
            }
        }
        tx.commit().map_err(db_error)?;
        Ok((imported, skipped, deleted, imported_by_provider))
    }

    pub fn agent_memory_changes(
        &self,
        after_sequence: i64,
        page_size: usize,
    ) -> Result<AgentMemoryChangesPage, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let page_size = page_size.clamp(1, 100);
        let mut statement = conn
            .prepare(
                "SELECT ch.seq, ch.operation,
                        m.id, m.provider, m.scope, m.kind, m.title, m.logical_path,
                        m.project_dir, m.content_hash, m.size_bytes, m.source_modified_at,
                        m.updated_at, m.deleted_at
                 FROM agent_memory_changes ch
                 JOIN agent_memories m ON m.id=ch.memory_id
                 WHERE ch.seq>?1
                   AND NOT EXISTS(
                     SELECT 1 FROM agent_memory_changes newer
                     WHERE newer.memory_id=ch.memory_id AND newer.seq>ch.seq
                   )
                 ORDER BY ch.seq ASC LIMIT ?2",
            )
            .map_err(db_error)?;
        let mut items = statement
            .query_map(
                params![after_sequence.max(0), (page_size + 1) as i64],
                |row| {
                    Ok(AgentMemoryChange {
                        sequence: row.get(0)?,
                        operation: row.get(1)?,
                        memory: agent_memory_summary_from_row(row, 2)?,
                    })
                },
            )
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let has_more = items.len() > page_size;
        items.truncate(page_size);
        let next_cursor = items.last().map(|item| item.sequence.to_string());
        Ok(AgentMemoryChangesPage {
            items,
            next_cursor,
            has_more,
        })
    }

    pub fn agent_memory_detail(&self, id: &str) -> Result<AgentMemoryDetail, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        conn.query_row(
            "SELECT id, provider, scope, kind, title, logical_path, project_dir,
                    content_hash, size_bytes, source_modified_at, updated_at, deleted_at, content
             FROM agent_memories WHERE id=?1 AND deleted_at IS NULL",
            [id],
            |row| {
                Ok(AgentMemoryDetail {
                    memory: agent_memory_summary_from_row(row, 0)?,
                    content: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| "Agent 记忆不存在".to_string())
    }

    pub fn detail(&self, id: &str) -> Result<ArchivedConversationDetail, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let conversation = conn
            .query_row(
                "SELECT c.id, c.owner_key, c.user_id, u.name, u.email, c.source, c.provider,
                        c.model, c.status, c.title, c.summary, c.created_at, c.updated_at,
                        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id
                         AND m.revision=(SELECT MAX(m2.revision) FROM messages m2
                                         WHERE m2.conversation_id=m.conversation_id
                                           AND m2.logical_position=m.logical_position)),
                        EXISTS(SELECT 1 FROM messages pm WHERE pm.conversation_id=c.id
                               AND pm.status != 'final')
                 FROM conversations c LEFT JOIN users u ON u.id=c.user_id WHERE c.id=?1",
                params![id],
                summary_from_row,
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| "归档会话不存在".to_string())?;

        let mut message_statement = conn
            .prepare(
                "SELECT m.id, m.logical_position, m.revision, m.role, m.content,
                        m.content_hash, m.created_at, m.token_count, m.cost, m.status,
                        m.metadata_json
                 FROM messages m WHERE m.conversation_id=?1
                 ORDER BY m.logical_position ASC, m.revision ASC",
            )
            .map_err(db_error)?;
        let mut messages = message_statement
            .query_map(params![id], |row| {
                let metadata: String = row.get(10)?;
                Ok(ArchivedMessage {
                    id: row.get(0)?,
                    logical_position: row.get(1)?,
                    revision: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    content_hash: row.get(5)?,
                    created_at: row.get(6)?,
                    token_count: row.get(7)?,
                    cost: row.get(8)?,
                    status: row.get(9)?,
                    metadata: serde_json::from_str(&metadata).unwrap_or_else(|_| json!({})),
                    attachments: Vec::new(),
                })
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        for message in &mut messages {
            let mut attachment_statement = conn
                .prepare(
                    "SELECT id, reference_type, mime_type, file_name, size_bytes, sha256
                     FROM attachments WHERE message_id=?1 ORDER BY id",
                )
                .map_err(db_error)?;
            message.attachments = attachment_statement
                .query_map(params![message.id], |row| {
                    Ok(ArchivedAttachment {
                        id: row.get(0)?,
                        reference_type: row.get(1)?,
                        mime_type: row.get(2)?,
                        file_name: row.get(3)?,
                        size_bytes: row.get::<_, i64>(4)?.max(0) as u64,
                        sha256: row.get(5)?,
                    })
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
        }

        let mut exchange_statement = conn
            .prepare(
                "SELECT e.id, e.provider, e.model, e.status, e.stream, e.started_at,
                        e.completed_at, e.http_status, e.error_code, e.request_payload,
                        e.response_payload,
                        (SELECT COUNT(*) FROM stream_events se WHERE se.exchange_id=e.id)
                 FROM exchanges e WHERE e.conversation_id=?1 ORDER BY e.started_at",
            )
            .map_err(db_error)?;
        let exchanges = exchange_statement
            .query_map(params![id], |row| {
                let request_payload: String = row.get(9)?;
                let response_payload: Option<String> = row.get(10)?;
                Ok(ArchivedExchange {
                    id: row.get(0)?,
                    provider: row.get(1)?,
                    model: row.get(2)?,
                    status: row.get(3)?,
                    stream: row.get::<_, i64>(4)? != 0,
                    started_at: row.get(5)?,
                    completed_at: row.get(6)?,
                    http_status: row.get(7)?,
                    error_code: row.get(8)?,
                    request_payload: serde_json::from_str(&request_payload).unwrap_or(Value::Null),
                    response_payload: response_payload
                        .and_then(|value| serde_json::from_str(&value).ok()),
                    event_count: row.get::<_, i64>(11)?.max(0) as u64,
                })
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;

        Ok(ArchivedConversationDetail {
            conversation,
            messages,
            exchanges,
        })
    }

    pub fn delete(&self, ids: &[String]) -> Result<ArchiveDeleteResult, String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let mut deleted = 0usize;
        for id in ids {
            let target_hash = sha256_hex(id.as_bytes());
            tx.execute(
                "DELETE FROM conversation_fts WHERE conversation_id=?1",
                params![id],
            )
            .map_err(db_error)?;
            let affected = tx
                .execute("DELETE FROM conversations WHERE id=?1", params![id])
                .map_err(db_error)?;
            if affected > 0 {
                deleted += 1;
                tx.execute(
                    "INSERT INTO audit_log (action, target_hash, item_count, created_at)
                     VALUES ('delete', ?1, 1, ?2)",
                    params![target_hash, now_ms()],
                )
                .map_err(db_error)?;
            }
        }
        tx.commit().map_err(db_error)?;
        Ok(ArchiveDeleteResult { deleted })
    }

    pub fn is_imported(&self, fingerprint: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM import_sources WHERE fingerprint=?1)",
                params![fingerprint],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        Ok(exists != 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn import_local_session(
        &self,
        fingerprint: &str,
        source_path_hash: &str,
        content_hash: &str,
        provider: &str,
        session_id: &str,
        title: &str,
        summary: Option<&str>,
        model: Option<&str>,
        created_at: Option<i64>,
        updated_at: Option<i64>,
        messages: &[NormalizedMessage],
    ) -> Result<bool, String> {
        let mut conn = self.conn.lock().map_err(lock_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let exists: i64 = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM import_sources WHERE fingerprint=?1)",
                params![fingerprint],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if exists != 0 {
            tx.rollback().map_err(db_error)?;
            return Ok(false);
        }
        let now = now_ms();
        let external_id = format!(
            "{provider}:{session_id}:{}",
            &source_path_hash[..16.min(source_path_hash.len())]
        );
        let conversation_id = upsert_conversation(
            &tx,
            "local-history:unattributed",
            &external_id,
            None,
            "local_history",
            provider,
            model,
            if title.trim().is_empty() {
                "Imported local conversation"
            } else {
                title
            },
            created_at.unwrap_or(now),
        )?;
        tx.execute(
            "UPDATE conversations SET summary=?2, status='imported', updated_at=?3 WHERE id=?1",
            params![conversation_id, summary, updated_at.unwrap_or(now)],
        )
        .map_err(db_error)?;
        for (position, message) in messages.iter().enumerate() {
            align_message(
                &tx,
                &conversation_id,
                None,
                position as i64,
                message,
                "final",
                message.created_at.unwrap_or(now),
            )?;
        }
        tx.execute(
            "INSERT INTO import_sources
             (fingerprint, conversation_id, provider, source_path_hash, source_session_id,
              content_hash, imported_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                fingerprint,
                conversation_id,
                provider,
                source_path_hash,
                sha256_hex(session_id.as_bytes()),
                content_hash,
                now
            ],
        )
        .map_err(db_error)?;
        tx.execute(
            "INSERT INTO audit_log (action, target_hash, item_count, created_at)
             VALUES ('import', ?1, ?2, ?3)",
            params![
                sha256_hex(conversation_id.as_bytes()),
                messages.len() as i64,
                now
            ],
        )
        .map_err(db_error)?;
        rebuild_fts(&tx, &conversation_id)?;
        record_conversation_change(&tx, &conversation_id, "local_history", now)?;
        tx.commit().map_err(db_error)?;
        Ok(true)
    }

    pub fn record_export_audit(&self, ids: &[String], format: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let combined = ids.join("\u{1f}");
        conn.execute(
            "INSERT INTO audit_log (action, target_hash, item_count, metadata_json, created_at)
             VALUES ('export', ?1, ?2, ?3, ?4)",
            params![
                sha256_hex(combined.as_bytes()),
                ids.len() as i64,
                json!({"format": format}).to_string(),
                now_ms()
            ],
        )
        .map_err(db_error)?;
        Ok(())
    }
}

fn apply_key(conn: &Connection, key: &[u8; 32]) -> Result<(), String> {
    let hex_key = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // SQLCipher raw-key form prevents locale/encoding ambiguity and avoids a
    // password KDF mismatch across machines. `hex_key` is never logged.
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))
        .map_err(|_| "无法设置对话归档加密密钥".to_string())
}

fn verify_cipher_integrity(conn: &Connection) -> Result<(), String> {
    let mut statement = conn
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|_| "当前 SQLite 构建不支持 SQLCipher".to_string())?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| "归档数据库完整性检查失败".to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "归档数据库完整性检查失败".to_string())?;
    if rows.iter().any(|result| !result.eq_ignore_ascii_case("ok")) {
        return Err("归档数据库完整性检查失败".to_string());
    }
    let logical_rows = conn
        .prepare("PRAGMA integrity_check")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| "归档数据库逻辑完整性检查失败".to_string())?;
    if logical_rows.len() != 1 || !logical_rows[0].eq_ignore_ascii_case("ok") {
        return Err("归档数据库逻辑完整性检查失败".to_string());
    }
    Ok(())
}

fn archive_schema_version(conn: &Connection) -> Result<i64, String> {
    let version: String = conn
        .query_row(
            "SELECT value FROM archive_state WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "归档快照缺少有效的 schema_version".to_string())?;
    version
        .parse::<i64>()
        .map_err(|_| "归档快照 schema_version 无效".to_string())
}

fn verify_archive_schema_compatible(conn: &Connection) -> Result<(), String> {
    let version = archive_schema_version(conn)?;
    if !(MIN_SUPPORTED_SCHEMA_VERSION..=ARCHIVE_SCHEMA_VERSION).contains(&version) {
        return Err(format!(
            "归档快照 schema 版本不兼容（支持 {MIN_SUPPORTED_SCHEMA_VERSION}..={ARCHIVE_SCHEMA_VERSION}）"
        ));
    }
    verify_archive_schema_for_version(conn, version)
}

fn verify_archive_schema(conn: &Connection) -> Result<(), String> {
    let version = archive_schema_version(conn)?;
    if version != ARCHIVE_SCHEMA_VERSION {
        return Err(format!(
            "归档快照 schema 版本不兼容（需要 {ARCHIVE_SCHEMA_VERSION}）"
        ));
    }
    verify_archive_schema_for_version(conn, version)
}

fn verify_archive_schema_for_version(conn: &Connection, version: i64) -> Result<(), String> {
    const BASE_REQUIRED_TABLES: &[&str] = &[
        "archive_state",
        "users",
        "conversations",
        "exchanges",
        "messages",
        "exchange_messages",
        "attachments",
        "stream_events",
        "import_sources",
        "audit_log",
    ];
    const MEMORY_REQUIRED_TABLES: &[&str] = &["agent_memories", "agent_memory_changes"];
    for table in BASE_REQUIRED_TABLES.iter().chain(
        (version >= 2)
            .then_some(MEMORY_REQUIRED_TABLES)
            .into_iter()
            .flatten(),
    ) {
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if exists == 0 {
            return Err(format!("归档快照缺少必需数据表 {table}"));
        }
    }
    let fts: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='conversation_fts'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "归档快照缺少全文索引".to_string())?;
    if !fts.to_ascii_lowercase().contains("tokenize='trigram'") {
        return Err("归档全文索引未使用 trigram tokenizer".to_string());
    }
    Ok(())
}

fn create_schema(conn: &mut Connection) -> Result<(), String> {
    let tx = conn.transaction().map_err(db_error)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS archive_state (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS users (
             id TEXT PRIMARY KEY,
             issuer TEXT NOT NULL,
             subject TEXT NOT NULL,
             name TEXT,
             email TEXT,
             organization TEXT,
             first_seen_at INTEGER NOT NULL,
             last_seen_at INTEGER NOT NULL,
             UNIQUE(issuer, subject)
         );
         CREATE TABLE IF NOT EXISTS conversations (
             id TEXT PRIMARY KEY,
             owner_key TEXT NOT NULL,
             external_conversation_id TEXT NOT NULL,
             user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
             source TEXT NOT NULL,
             provider TEXT NOT NULL,
             model TEXT,
             status TEXT NOT NULL,
             title TEXT NOT NULL,
             summary TEXT,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             UNIQUE(owner_key, external_conversation_id, source)
         );
         CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(updated_at DESC);
         CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);
         CREATE INDEX IF NOT EXISTS idx_conversations_filters ON conversations(provider, source, status, model);
         CREATE TABLE IF NOT EXISTS exchanges (
             id TEXT PRIMARY KEY,
             conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
             provider TEXT NOT NULL,
             model TEXT,
             status TEXT NOT NULL,
             stream INTEGER NOT NULL DEFAULT 0,
             request_payload TEXT NOT NULL,
             response_payload TEXT,
             request_message_count INTEGER NOT NULL DEFAULT 0,
             started_at INTEGER NOT NULL,
             completed_at INTEGER,
             http_status INTEGER,
             error_code TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_exchanges_conversation ON exchanges(conversation_id, started_at);
         CREATE TABLE IF NOT EXISTS messages (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
             exchange_id TEXT REFERENCES exchanges(id) ON DELETE SET NULL,
             logical_position INTEGER NOT NULL,
             revision INTEGER NOT NULL DEFAULT 0,
             role TEXT NOT NULL,
             content TEXT NOT NULL,
             content_hash TEXT NOT NULL,
             created_at INTEGER,
             token_count INTEGER,
             cost TEXT,
             status TEXT NOT NULL DEFAULT 'final',
             metadata_json TEXT NOT NULL DEFAULT '{}',
             UNIQUE(conversation_id, logical_position, revision)
         );
         CREATE INDEX IF NOT EXISTS idx_messages_timeline ON messages(conversation_id, logical_position, revision);
         CREATE TABLE IF NOT EXISTS exchange_messages (
             exchange_id TEXT NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
             message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
             request_position INTEGER NOT NULL,
             PRIMARY KEY(exchange_id, request_position)
         );
         CREATE TABLE IF NOT EXISTS attachments (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
             exchange_id TEXT REFERENCES exchanges(id) ON DELETE CASCADE,
             reference_type TEXT NOT NULL,
             mime_type TEXT,
             file_name TEXT,
             size_bytes INTEGER NOT NULL,
             sha256 TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS stream_events (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             exchange_id TEXT NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
             sequence INTEGER NOT NULL,
             event_type TEXT,
             payload TEXT NOT NULL,
             text_delta TEXT NOT NULL DEFAULT '',
             created_at INTEGER NOT NULL,
             UNIQUE(exchange_id, sequence)
         );
         CREATE TABLE IF NOT EXISTS import_sources (
             fingerprint TEXT PRIMARY KEY,
             conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
             provider TEXT NOT NULL,
             source_path_hash TEXT NOT NULL,
             source_session_id TEXT NOT NULL,
             content_hash TEXT NOT NULL,
             imported_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS conversation_changes (
             seq INTEGER PRIMARY KEY AUTOINCREMENT,
             conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
             source TEXT NOT NULL,
             changed_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_conversation_changes_source_seq
             ON conversation_changes(source, seq);
         CREATE TABLE IF NOT EXISTS agent_memories (
             id TEXT PRIMARY KEY,
             provider TEXT NOT NULL,
             scope TEXT NOT NULL,
             kind TEXT NOT NULL,
             title TEXT NOT NULL,
             logical_path TEXT NOT NULL,
             project_dir TEXT,
             source_path_hash TEXT NOT NULL,
             scan_root_hash TEXT NOT NULL,
             content TEXT NOT NULL,
             content_hash TEXT NOT NULL,
             size_bytes INTEGER NOT NULL,
             source_modified_at INTEGER,
             first_seen_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             deleted_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_agent_memories_provider
             ON agent_memories(provider, updated_at DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_memories_scan_root
             ON agent_memories(scan_root_hash, deleted_at);
         CREATE TABLE IF NOT EXISTS agent_memory_changes (
             seq INTEGER PRIMARY KEY AUTOINCREMENT,
             memory_id TEXT NOT NULL REFERENCES agent_memories(id) ON DELETE CASCADE,
             operation TEXT NOT NULL CHECK(operation IN ('upsert', 'delete')),
             changed_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_agent_memory_changes_seq
             ON agent_memory_changes(seq);
         CREATE TABLE IF NOT EXISTS audit_log (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             action TEXT NOT NULL,
             target_hash TEXT NOT NULL,
             item_count INTEGER NOT NULL,
             metadata_json TEXT NOT NULL DEFAULT '{}',
             created_at INTEGER NOT NULL
         );
         CREATE VIRTUAL TABLE IF NOT EXISTS conversation_fts USING fts5(
             conversation_id UNINDEXED,
             title,
             summary,
             body,
             tokenize='trigram'
         );",
    )
    .map_err(|e| format!("创建归档数据库结构失败（需要 SQLCipher + FTS5 trigram）: {e}"))?;
    tx.execute(
        "INSERT INTO conversation_changes (conversation_id, source, changed_at)
         SELECT c.id, c.source, c.updated_at FROM conversations c
         WHERE c.source IN ('local_history', 'local_proxy')
           AND NOT EXISTS(SELECT 1 FROM conversation_changes ch
                          WHERE ch.conversation_id=c.id)",
        [],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO archive_state (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![ARCHIVE_SCHEMA_VERSION.to_string()],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

fn upsert_user(
    tx: &Transaction<'_>,
    identity: &ArchiveIdentity,
    now: i64,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO users
         (id, issuer, subject, name, email, organization, first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(issuer, subject) DO UPDATE SET
           name=COALESCE(excluded.name, users.name),
           email=COALESCE(excluded.email, users.email),
           organization=COALESCE(excluded.organization, users.organization),
           last_seen_at=excluded.last_seen_at",
        params![
            id,
            identity.issuer,
            identity.subject,
            identity.name,
            identity.email,
            identity.organization,
            now
        ],
    )
    .map_err(db_error)?;
    tx.query_row(
        "SELECT id FROM users WHERE issuer=?1 AND subject=?2",
        params![identity.issuer, identity.subject],
        |row| row.get(0),
    )
    .map_err(db_error)
}

fn record_conversation_change(
    tx: &Transaction<'_>,
    conversation_id: &str,
    source: &str,
    changed_at: i64,
) -> Result<(), String> {
    if source == "local_history" || source == "local_proxy" {
        tx.execute(
            "INSERT INTO conversation_changes (conversation_id, source, changed_at)
             VALUES (?1, ?2, ?3)",
            params![conversation_id, source, changed_at],
        )
        .map_err(db_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_conversation(
    tx: &Transaction<'_>,
    owner_key: &str,
    external_id: &str,
    user_id: Option<&str>,
    source: &str,
    provider: &str,
    model: Option<&str>,
    title: &str,
    now: i64,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    // The external ID is only a stable ownership/deduplication key. Persist a
    // one-way digest so a client cannot smuggle a credential into this field.
    let external_id = sha256_hex(external_id.as_bytes());
    tx.execute(
        "INSERT INTO conversations
         (id, owner_key, external_conversation_id, user_id, source, provider, model,
          status, title, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?9)
         ON CONFLICT(owner_key, external_conversation_id, source) DO UPDATE SET
           user_id=COALESCE(excluded.user_id, conversations.user_id),
           provider=excluded.provider,
           model=COALESCE(excluded.model, conversations.model),
           updated_at=excluded.updated_at",
        params![
            id,
            owner_key,
            external_id,
            user_id,
            source,
            provider,
            model,
            title,
            now
        ],
    )
    .map_err(db_error)?;
    tx.query_row(
        "SELECT id FROM conversations
         WHERE owner_key=?1 AND external_conversation_id=?2 AND source=?3",
        params![owner_key, external_id, source],
        |row| row.get(0),
    )
    .map_err(db_error)
}

fn align_message(
    tx: &Transaction<'_>,
    conversation_id: &str,
    exchange_id: Option<&str>,
    position: i64,
    message: &NormalizedMessage,
    status: &str,
    fallback_created_at: i64,
) -> Result<i64, String> {
    let content_hash = sha256_hex(format!("{}\u{1f}{}", message.role, message.content).as_bytes());
    let previous = tx
        .query_row(
            "SELECT id, revision, role, content_hash FROM messages
             WHERE conversation_id=?1 AND logical_position=?2
             ORDER BY revision DESC LIMIT 1",
            params![conversation_id, position],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    if let Some((id, _, role, hash)) = previous.as_ref() {
        if role == &message.role && hash == &content_hash {
            return Ok(*id);
        }
    }
    let revision = previous.map_or(0, |(_, revision, _, _)| revision + 1);
    let metadata = serde_json::to_string(&message.metadata)
        .map_err(|e| format!("序列化消息元数据失败: {e}"))?;
    let token_count = token_count_from_metadata(&message.metadata);
    let cost = cost_from_metadata(&message.metadata);
    tx.execute(
        "INSERT INTO messages
         (conversation_id, exchange_id, logical_position, revision, role, content,
          content_hash, created_at, token_count, cost, status, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            conversation_id,
            exchange_id,
            position,
            revision,
            message.role,
            message.content,
            content_hash,
            message.created_at.unwrap_or(fallback_created_at),
            token_count,
            cost,
            status,
            metadata
        ],
    )
    .map_err(db_error)?;
    let message_id = tx.last_insert_rowid();
    for attachment in &message.attachments {
        tx.execute(
            "INSERT INTO attachments
             (message_id, exchange_id, reference_type, mime_type, file_name, size_bytes, sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message_id,
                exchange_id,
                attachment.reference_type,
                attachment.mime_type,
                attachment.file_name,
                attachment.size_bytes as i64,
                attachment.sha256
            ],
        )
        .map_err(db_error)?;
    }
    Ok(message_id)
}

fn token_count_from_metadata(metadata: &Value) -> Option<i64> {
    let usage = metadata.get("usage")?;
    for key in ["total_tokens", "totalTokens", "totalTokenCount"] {
        if let Some(value) = usage.get(key).and_then(Value::as_i64) {
            return Some(value);
        }
    }
    let input = ["input_tokens", "prompt_tokens", "promptTokenCount"]
        .into_iter()
        .find_map(|key| usage.get(key).and_then(Value::as_i64))
        .unwrap_or(0);
    let output = ["output_tokens", "completion_tokens", "candidatesTokenCount"]
        .into_iter()
        .find_map(|key| usage.get(key).and_then(Value::as_i64))
        .unwrap_or(0);
    (input > 0 || output > 0).then_some(input + output)
}

fn cost_from_metadata(metadata: &Value) -> Option<String> {
    let usage = metadata.get("usage").unwrap_or(metadata);
    ["cost", "total_cost", "totalCost"]
        .into_iter()
        .find_map(|key| usage.get(key))
        .and_then(|value| match value {
            Value::Number(value) => Some(value.to_string()),
            Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
            _ => None,
        })
}

fn error_code_from_payload(status_code: u16, payload: &Value) -> Option<String> {
    if status_code < 400 {
        return None;
    }
    let value = payload
        .pointer("/error/code")
        .or_else(|| payload.pointer("/error/type"))
        .or_else(|| payload.get("code"))
        .or_else(|| payload.get("type"));
    let value = value.and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    });
    Some(
        value
            .map(|value| truncate_chars(&value, 120))
            .unwrap_or_else(|| format!("http_{status_code}")),
    )
}

fn rebuild_fts(tx: &Transaction<'_>, conversation_id: &str) -> Result<(), String> {
    tx.execute(
        "DELETE FROM conversation_fts WHERE conversation_id=?1",
        params![conversation_id],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO conversation_fts (conversation_id, title, summary, body)
         SELECT c.id, c.title, COALESCE(c.summary, ''),
                COALESCE((
                    SELECT group_concat(latest.content, char(10)) FROM messages latest
                    WHERE latest.conversation_id=c.id
                      AND latest.revision=(
                          SELECT MAX(m2.revision) FROM messages m2
                          WHERE m2.conversation_id=latest.conversation_id
                            AND m2.logical_position=latest.logical_position
                      )
                    ORDER BY latest.logical_position
                ), '')
         FROM conversations c WHERE c.id=?1",
        params![conversation_id],
    )
    .map_err(db_error)?;
    Ok(())
}

fn recover_incomplete_streams(conn: &mut Connection) -> Result<(), String> {
    let ids = {
        let mut statement = conn
            .prepare("SELECT id FROM exchanges WHERE status IN ('capturing', 'streaming')")
            .map_err(db_error)?;
        let values = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        values
    };
    for id in ids {
        finalize_stream_tx(conn, &id, Some("application_restart"))?;
    }
    Ok(())
}

fn finalize_stream_tx(
    conn: &mut Connection,
    exchange_id: &str,
    interruption_reason: Option<&str>,
) -> Result<(), String> {
    let tx = conn.transaction().map_err(db_error)?;
    let exchange = tx
        .query_row(
            "SELECT conversation_id, request_message_count, status, http_status, provider
             FROM exchanges WHERE id=?1",
            params![exchange_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| "流式 exchange 不存在".to_string())?;
    if !matches!(exchange.2.as_str(), "capturing" | "streaming") {
        tx.rollback().map_err(db_error)?;
        return Ok(());
    }
    let events = {
        let mut statement = tx
            .prepare(
                "SELECT payload, text_delta FROM stream_events
                 WHERE exchange_id=?1 ORDER BY sequence",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map(params![exchange_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        rows
    };
    let text = events
        .iter()
        .map(|(_, delta)| delta.as_str())
        .collect::<String>();
    let usage = stream_usage_metadata(events.iter().map(|(payload, _)| payload.as_str()));
    let upstream_error = exchange.3.is_some_and(|status| status >= 400);
    let final_status = match interruption_reason {
        Some("capture_error") => "capture_error",
        Some(_) => "interrupted",
        None if upstream_error => "upstream_error",
        None => "completed",
    };
    if !text.is_empty() {
        let mut metadata = json!({
            "stream": true,
            "interruptionReason": interruption_reason,
            "provider": exchange.4,
        });
        if let Some(usage) = usage {
            metadata["usage"] = usage;
        }
        let message = NormalizedMessage {
            role: "assistant".to_string(),
            content: text,
            created_at: Some(now_ms()),
            metadata,
            attachments: Vec::new(),
        };
        align_message(
            &tx,
            &exchange.0,
            Some(exchange_id),
            exchange.1,
            &message,
            if interruption_reason.is_some() {
                "partial"
            } else {
                "final"
            },
            now_ms(),
        )?;
    }
    tx.execute(
        "UPDATE exchanges SET status=?2, completed_at=?3, error_code=?4 WHERE id=?1",
        params![
            exchange_id,
            final_status,
            now_ms(),
            interruption_reason
                .map(str::to_string)
                .or_else(|| upstream_error.then(|| format!("http_{}", exchange.3.unwrap_or(0))))
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "UPDATE conversations SET status=?2, updated_at=?3 WHERE id=?1",
        params![exchange.0, final_status, now_ms()],
    )
    .map_err(db_error)?;
    rebuild_fts(&tx, &exchange.0)?;
    record_conversation_change(&tx, &exchange.0, "local_proxy", now_ms())?;
    tx.commit().map_err(db_error)
}

fn stream_usage_metadata<'a>(payloads: impl Iterator<Item = &'a str>) -> Option<Value> {
    let mut merged = serde_json::Map::new();
    for payload in payloads {
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        for candidate in [
            value.get("usage"),
            value.get("usageMetadata"),
            value.pointer("/message/usage"),
            value.pointer("/response/usage"),
        ]
        .into_iter()
        .flatten()
        {
            if let Value::Object(fields) = candidate {
                for (key, value) in fields {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
    }
    (!merged.is_empty()).then_some(Value::Object(merged))
}

fn build_search_clause(
    query: &str,
    filters: &ArchiveSearchFilters,
) -> (String, String, Vec<SqlValue>) {
    let query = query.trim();
    let use_fts = query.chars().count() >= 3;
    let from = if use_fts {
        "FROM conversations c LEFT JOIN users u ON u.id=c.user_id JOIN conversation_fts ON conversation_fts.conversation_id=c.id".to_string()
    } else {
        "FROM conversations c LEFT JOIN users u ON u.id=c.user_id".to_string()
    };
    let mut clauses = Vec::new();
    let mut bind = Vec::new();
    if !query.is_empty() {
        if use_fts {
            clauses.push("conversation_fts MATCH ?".to_string());
            bind.push(SqlValue::Text(fts_query(query)));
        } else {
            clauses.push(
                "(c.title LIKE ? ESCAPE '\\' OR COALESCE(c.summary, '') LIKE ? ESCAPE '\\'
                  OR EXISTS(SELECT 1 FROM messages sm WHERE sm.conversation_id=c.id
                            AND sm.content LIKE ? ESCAPE '\\'))"
                    .to_string(),
            );
            let like = format!("%{}%", escape_like(query));
            bind.extend([
                SqlValue::Text(like.clone()),
                SqlValue::Text(like.clone()),
                SqlValue::Text(like),
            ]);
        }
    }
    if let Some(user) = filters
        .user_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        clauses.push(
            "(c.user_id=? OR u.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\')".to_string(),
        );
        let like = format!("%{}%", escape_like(user));
        bind.extend([
            SqlValue::Text(user.clone()),
            SqlValue::Text(like.clone()),
            SqlValue::Text(like),
        ]);
    }
    for (column, value) in [
        ("c.source", filters.source.as_ref()),
        ("c.provider", filters.provider.as_ref()),
        ("c.model", filters.model.as_ref()),
        ("c.status", filters.status.as_ref()),
    ] {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            clauses.push(format!("{column}=?"));
            bind.push(SqlValue::Text(value.clone()));
        }
    }
    if let Some(date_from) = filters.date_from {
        clauses.push("c.updated_at>=?".to_string());
        bind.push(SqlValue::Integer(date_from));
    }
    if let Some(date_to) = filters.date_to {
        clauses.push("c.updated_at<=?".to_string());
        bind.push(SqlValue::Integer(date_to));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    (from, where_sql, bind)
}

fn fts_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArchivedConversationSummary> {
    Ok(ArchivedConversationSummary {
        id: row.get(0)?,
        owner_key: row.get(1)?,
        user_id: row.get(2)?,
        user_name: row.get(3)?,
        user_email: row.get(4)?,
        source: row.get(5)?,
        provider: row.get(6)?,
        model: row.get(7)?,
        status: row.get(8)?,
        title: row.get(9)?,
        summary: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        message_count: row.get::<_, i64>(13)?.max(0) as u64,
        has_partial_response: row.get::<_, i64>(14)? != 0,
    })
}

fn agent_memory_summary_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<AgentMemorySummary> {
    Ok(AgentMemorySummary {
        id: row.get(offset)?,
        provider: row.get(offset + 1)?,
        scope: row.get(offset + 2)?,
        kind: row.get(offset + 3)?,
        title: row.get(offset + 4)?,
        path: row.get(offset + 5)?,
        project_dir: row.get(offset + 6)?,
        content_hash: row.get(offset + 7)?,
        size_bytes: row.get::<_, i64>(offset + 8)?.max(0) as u64,
        source_modified_at: row.get(offset + 9)?,
        updated_at: row.get(offset + 10)?,
        deleted_at: row.get(offset + 11)?,
    })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut output: String = value.chars().take(max).collect();
    if value.chars().count() > max {
        output.push('…');
    }
    output
}

fn db_error(error: rusqlite::Error) -> String {
    // SQL strings and bound values are intentionally omitted. Bound values may
    // contain archived conversation text.
    format!("归档数据库操作失败 ({:?})", error.sqlite_error_code())
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> String {
    "归档数据库锁已损坏".to_string()
}

#[cfg(unix)]
fn set_restrictive_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("设置归档数据库权限失败: {e}"))
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::normalize::normalize_request;
    use crate::archive::redaction::Redactor;
    use crate::archive::types::{NormalizedAttachment, NormalizedRequest};
    use base64::Engine;
    use serial_test::serial;
    use tempfile::tempdir;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn identity() -> ArchiveIdentity {
        ArchiveIdentity {
            issuer: "https://issuer.example".to_string(),
            subject: "user-1".to_string(),
            name: Some("Alice".to_string()),
            email: None,
            organization: None,
        }
    }

    fn request(content: &str) -> NormalizedRequest {
        NormalizedRequest {
            provider: "openai_chat".to_string(),
            model: Some("gpt-test".to_string()),
            stream: false,
            redacted_payload: json!({"messages": [{"role": "user", "content": content}]}),
            messages: vec![NormalizedMessage {
                role: "user".to_string(),
                content: content.to_string(),
                created_at: None,
                metadata: json!({}),
                attachments: vec![NormalizedAttachment {
                    reference_type: "inline_base64".to_string(),
                    mime_type: Some("image/png".to_string()),
                    file_name: None,
                    size_bytes: 4,
                    sha256: "abcd".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn encrypted_database_rejects_wrong_key_and_supports_fts() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("archive.db");
        let db = ArchiveDatabase::open(&path, &key(7)).unwrap();
        let capture = db
            .capture_request(
                &identity(),
                "conversation-1",
                "team_gateway",
                &request("中文全文检索 hello"),
            )
            .unwrap();
        db.capture_non_stream_response(&capture, 200, &json!({"choices": []}), &[])
            .unwrap();
        let page = db
            .search("全文检索", &ArchiveSearchFilters::default(), None, 20)
            .unwrap();
        assert_eq!(page.total, 1);
        drop(db);
        assert!(ArchiveDatabase::open(&path, &key(8)).is_err());
        let bytes = std::fs::read(path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("中文全文检索"));
    }

    #[test]
    fn conversation_change_feed_is_incremental_and_excludes_team_gateway() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(19)).unwrap();
        db.capture_request(
            &identity(),
            "team-conversation",
            "team_gateway",
            &request("team only"),
        )
        .unwrap();
        let local = db
            .capture_request(
                &identity(),
                "local-conversation",
                "local_proxy",
                &request("personal memory"),
            )
            .unwrap();
        db.capture_non_stream_response(&local, 200, &json!({"ok": true}), &[])
            .unwrap();

        let page = db.conversation_changes(0, 100).unwrap();
        assert!(!page.items.is_empty());
        assert!(page
            .items
            .iter()
            .all(|item| item.conversation.source == "local_proxy"));
        let cursor = page.items.last().unwrap().sequence;
        assert!(db
            .conversation_changes(cursor, 100)
            .unwrap()
            .items
            .is_empty());
    }

    fn scanned_memory(id: &str, root: &str, content: &str) -> ScannedAgentMemory {
        ScannedAgentMemory {
            id: id.to_string(),
            provider: "codex".to_string(),
            scope: "agent".to_string(),
            kind: "learned_memory".to_string(),
            title: "Codex memory".to_string(),
            path: "~/.codex/memory.md".to_string(),
            project_dir: None,
            source_path_hash: "source-hash".to_string(),
            scan_root_hash: root.to_string(),
            content: content.to_string(),
            content_hash: sha256_hex(content.as_bytes()),
            size_bytes: content.len() as u64,
            source_modified_at: Some(1_700_000_000_000),
        }
    }

    #[test]
    fn agent_memory_feed_is_incremental_and_mirrors_deletion() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(20)).unwrap();
        let memory = scanned_memory("memory-1", "root-1", "remember cursor");
        let first_reconcile = db
            .reconcile_agent_memories(std::slice::from_ref(&memory), &["root-1".to_string()])
            .unwrap();
        assert_eq!(first_reconcile.0, 1);
        assert_eq!(first_reconcile.1, 0);
        assert_eq!(first_reconcile.2, 0);
        assert_eq!(first_reconcile.3.get("codex"), Some(&1));
        let first = db.agent_memory_changes(0, 100).unwrap();
        assert_eq!(first.items.len(), 1);
        assert_eq!(first.items[0].operation, "upsert");
        assert_eq!(
            db.agent_memory_detail("memory-1").unwrap().content,
            "remember cursor"
        );
        let cursor = first.items[0].sequence;

        let unchanged = db
            .reconcile_agent_memories(std::slice::from_ref(&memory), &["root-1".to_string()])
            .unwrap();
        assert_eq!((unchanged.0, unchanged.1, unchanged.2), (0, 1, 0));
        assert!(db
            .agent_memory_changes(cursor, 100)
            .unwrap()
            .items
            .is_empty());

        let removed = db
            .reconcile_agent_memories(&[], &["root-1".to_string()])
            .unwrap();
        assert_eq!((removed.0, removed.1, removed.2), (0, 0, 1));
        let deleted = db.agent_memory_changes(cursor, 100).unwrap();
        assert_eq!(deleted.items.len(), 1);
        assert_eq!(deleted.items[0].operation, "delete");
        let compacted = db.agent_memory_changes(0, 100).unwrap();
        assert_eq!(compacted.items.len(), 1);
        assert_eq!(compacted.items[0].operation, "delete");
        assert!(db.agent_memory_detail("memory-1").is_err());
    }

    #[test]
    fn opening_v1_archive_migrates_memory_tables_transactionally() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("archive.db");
        let encryption_key = key(21);
        drop(ArchiveDatabase::open(&path, &encryption_key).unwrap());

        let conn = Connection::open(&path).unwrap();
        apply_key(&conn, &encryption_key).unwrap();
        conn.execute_batch(
            "DROP TABLE agent_memory_changes;
             DROP TABLE agent_memories;
             UPDATE archive_state SET value='1' WHERE key='schema_version';",
        )
        .unwrap();
        drop(conn);

        let migrated = ArchiveDatabase::open(&path, &encryption_key).unwrap();
        migrated.verify_schema().unwrap();
        assert!(migrated
            .agent_memory_changes(0, 10)
            .unwrap()
            .items
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn existing_archive_repairs_permissions_and_rejects_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempdir().unwrap();
        let path = temp.path().join("archive.db");
        let encryption_key = key(11);
        drop(ArchiveDatabase::open(&path, &encryption_key).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        drop(ArchiveDatabase::open(&path, &encryption_key).unwrap());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let alias = temp.path().join("archive-link.db");
        symlink(&path, &alias).unwrap();
        assert!(ArchiveDatabase::open(&alias, &encryption_key).is_err());
    }

    #[test]
    fn persisted_payload_contains_only_redacted_text_and_attachment_metadata() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(6)).unwrap();
        let raw = json!({
            "model": "gpt-test",
            "authorization": "Bearer header.payload.signature",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "password=hunter2 sk-example123456789012345"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}}
                ]
            }]
        });
        let normalized =
            normalize_request("/v1/chat/completions", &raw, &Redactor::default()).unwrap();
        let handle = db
            .capture_request(
                &identity(),
                "conversation-secret",
                "team_gateway",
                &normalized,
            )
            .unwrap();
        let detail = db.detail(&handle.conversation_id).unwrap();
        let serialized = serde_json::to_string(&detail).unwrap();
        assert!(!serialized.contains("hunter2"));
        assert!(!serialized.contains("example123"));
        assert!(!serialized.contains("header.payload.signature"));
        assert!(!serialized.contains("aGVsbG8"));
        assert!(serialized.contains("REDACTED"));
        assert_eq!(detail.messages[0].attachments.len(), 1);
        assert_eq!(detail.messages[0].attachments[0].size_bytes, 5);
    }

    #[test]
    fn repeated_context_reuses_message_and_changed_position_adds_revision() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(3)).unwrap();
        db.capture_request(
            &identity(),
            "conversation-1",
            "team_gateway",
            &request("same"),
        )
        .unwrap();
        db.capture_request(
            &identity(),
            "conversation-1",
            "team_gateway",
            &request("same"),
        )
        .unwrap();
        db.capture_request(
            &identity(),
            "conversation-1",
            "team_gateway",
            &request("edited"),
        )
        .unwrap();
        let page = db
            .search("", &ArchiveSearchFilters::default(), None, 20)
            .unwrap();
        let detail = db.detail(&page.items[0].id).unwrap();
        assert_eq!(detail.messages.len(), 2);
        assert_eq!(detail.messages[1].revision, 1);
    }

    #[test]
    fn same_text_at_different_positions_is_not_deduplicated() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(4)).unwrap();
        let mut value = request("repeat");
        value.messages.push(NormalizedMessage {
            role: "assistant".to_string(),
            content: "answer".to_string(),
            created_at: None,
            metadata: json!({}),
            attachments: Vec::new(),
        });
        value.messages.push(NormalizedMessage {
            role: "user".to_string(),
            content: "repeat".to_string(),
            created_at: None,
            metadata: json!({}),
            attachments: Vec::new(),
        });
        let handle = db
            .capture_request(&identity(), "conversation-2", "team_gateway", &value)
            .unwrap();
        let detail = db.detail(&handle.conversation_id).unwrap();
        assert_eq!(detail.messages.len(), 3);
        assert_eq!(detail.messages[0].content, detail.messages[2].content);
        assert_ne!(
            detail.messages[0].logical_position,
            detail.messages[2].logical_position
        );
    }

    #[test]
    fn non_stream_capture_persists_message_usage_and_upstream_error() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(10)).unwrap();
        let handle = db
            .capture_request(
                &identity(),
                "non-stream-conversation",
                "team_gateway",
                &request("non-stream request"),
            )
            .unwrap();
        let response = NormalizedMessage {
            role: "assistant".to_string(),
            content: "request rejected".to_string(),
            created_at: None,
            metadata: json!({
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 3,
                    "cost": "0.02"
                }
            }),
            attachments: Vec::new(),
        };
        db.capture_non_stream_response(
            &handle,
            429,
            &json!({"error": {"code": "rate_limit"}}),
            &[response],
        )
        .unwrap();

        let detail = db.detail(&handle.conversation_id).unwrap();
        let assistant = detail
            .messages
            .iter()
            .find(|message| message.role == "assistant")
            .unwrap();
        assert_eq!(assistant.token_count, Some(5));
        assert_eq!(assistant.cost.as_deref(), Some("0.02"));
        assert_eq!(detail.exchanges[0].http_status, Some(429));
        assert_eq!(detail.exchanges[0].status, "upstream_error");
        assert_eq!(
            detail.exchanges[0].error_code.as_deref(),
            Some("rate_limit")
        );
    }

    #[test]
    fn stream_capture_persists_status_usage_cost_and_upstream_error() {
        let temp = tempdir().unwrap();
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key(5)).unwrap();
        let mut streamed = request("stream request");
        streamed.stream = true;
        let handle = db
            .capture_request(
                &identity(),
                "stream-conversation",
                "team_gateway",
                &streamed,
            )
            .unwrap();
        db.begin_stream_response(&handle, 200).unwrap();
        db.record_stream_event(
            &handle,
            Some("response.completed"),
            r#"{"usage":{"input_tokens":2,"output_tokens":3,"cost":"0.01"}}"#,
            "streamed answer",
        )
        .unwrap();
        db.finalize_stream(&handle, None).unwrap();
        let detail = db.detail(&handle.conversation_id).unwrap();
        let assistant = detail
            .messages
            .iter()
            .find(|message| message.role == "assistant")
            .unwrap();
        assert_eq!(assistant.token_count, Some(5));
        assert_eq!(assistant.cost.as_deref(), Some("0.01"));
        assert_eq!(detail.exchanges[0].http_status, Some(200));
        assert_eq!(detail.exchanges[0].status, "completed");

        let failed = db
            .capture_request(
                &identity(),
                "failed-stream-conversation",
                "team_gateway",
                &streamed,
            )
            .unwrap();
        db.begin_stream_response(&failed, 429).unwrap();
        db.finalize_stream(&failed, None).unwrap();
        let detail = db.detail(&failed.conversation_id).unwrap();
        assert_eq!(detail.exchanges[0].status, "upstream_error");
        assert_eq!(detail.exchanges[0].error_code.as_deref(), Some("http_429"));
    }

    #[test]
    #[serial]
    fn online_snapshot_stays_encrypted_and_validates_with_deployment_key() {
        let temp = tempdir().unwrap();
        let key = key(9);
        std::env::set_var(
            crate::archive::key::ARCHIVE_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode(key),
        );
        let db = ArchiveDatabase::open(&temp.path().join("archive.db"), &key).unwrap();
        db.capture_request(
            &identity(),
            "snapshot-conversation",
            "team_gateway",
            &request("snapshot secret body"),
        )
        .unwrap();
        let bytes = db.encrypted_snapshot().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("snapshot secret body"));
        let snapshot_path = temp.path().join("snapshot.db");
        std::fs::write(&snapshot_path, bytes).unwrap();
        ArchiveDatabase::validate_encrypted_file(&snapshot_path, &key).unwrap();
        assert!(ArchiveDatabase::validate_encrypted_file(&snapshot_path, &[8; 32]).is_err());
        std::env::remove_var(crate::archive::key::ARCHIVE_KEY_ENV);
    }

    #[test]
    fn encrypted_snapshot_preflight_rejects_incompatible_schema() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("incompatible.db");
        let encryption_key = key(10);
        drop(ArchiveDatabase::open(&path, &encryption_key).unwrap());

        let conn = Connection::open(&path).unwrap();
        apply_key(&conn, &encryption_key).unwrap();
        conn.execute(
            "UPDATE archive_state SET value='999' WHERE key='schema_version'",
            [],
        )
        .unwrap();
        drop(conn);

        let error = ArchiveDatabase::validate_encrypted_file(&path, &encryption_key)
            .expect_err("incompatible archive schema must be rejected before restore");
        assert!(error.contains("schema"));
    }
}
