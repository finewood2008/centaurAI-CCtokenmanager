use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ArchiveIdentity {
    pub issuer: String,
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
}

impl ArchiveIdentity {
    pub fn owner_key(&self) -> String {
        if self.issuer == "local" {
            format!("local:{}", self.subject)
        } else {
            format!("{}\u{1f}{}", self.issuer, self.subject)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedAttachment {
    pub reference_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct NormalizedMessage {
    pub role: String,
    pub content: String,
    pub created_at: Option<i64>,
    pub metadata: Value,
    pub attachments: Vec<NormalizedAttachment>,
}

#[derive(Debug, Clone)]
pub struct NormalizedRequest {
    pub provider: String,
    pub model: Option<String>,
    pub stream: bool,
    pub redacted_payload: Value,
    pub messages: Vec<NormalizedMessage>,
}

#[derive(Debug, Clone)]
pub struct CaptureHandle {
    pub exchange_id: String,
    pub conversation_id: String,
    pub request_message_count: usize,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveHealth {
    pub enabled: bool,
    pub ready: bool,
    pub key_configured: bool,
    pub database_ok: bool,
    pub fts_ok: bool,
    pub oidc_configured: bool,
    pub oidc_ok: bool,
    pub local_backup_enabled: bool,
    pub local_backup_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_backup_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_local_backup_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_backup_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_path: Option<String>,
    pub database_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of the idempotent local archive bootstrap. The encryption key is
/// deliberately never included in this payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveInitializationResult {
    pub key_created: bool,
    pub key_source: String,
    pub database_created: bool,
    pub enabled: bool,
    pub pending_requirements: Vec<String>,
    pub warnings: Vec<String>,
    pub health: ArchiveHealth,
    pub archive_settings: crate::settings::ArchiveSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveLocalSnapshotSummary {
    pub id: String,
    pub created_at: i64,
    pub database_size_bytes: u64,
    pub total_size_bytes: u64,
    pub directory: String,
    pub includes_key: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveSearchFilters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_from: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_to: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedConversationSummary {
    pub id: String,
    pub owner_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    pub source: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub status: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub message_count: u64,
    pub has_partial_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveSearchPage {
    pub items: Vec<ArchivedConversationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedAttachment {
    pub id: i64,
    pub reference_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedMessage {
    pub id: i64,
    pub logical_position: i64,
    pub revision: i64,
    pub role: String,
    pub content: String,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<String>,
    pub status: String,
    pub metadata: Value,
    pub attachments: Vec<ArchivedAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedExchange {
    pub id: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub status: String,
    pub stream: bool,
    pub started_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub request_payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_payload: Option<Value>,
    pub event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedConversationDetail {
    pub conversation: ArchivedConversationSummary,
    pub messages: Vec<ArchivedMessage>,
    pub exchanges: Vec<ArchivedExchange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveConversationChange {
    pub sequence: i64,
    pub conversation: ArchivedConversationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveConversationChangesPage {
    pub items: Vec<ArchiveConversationChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemorySummary {
    pub id: String,
    pub provider: String,
    pub scope: String,
    pub kind: String,
    pub title: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    pub content_hash: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_modified_at: Option<i64>,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemoryDetail {
    pub memory: AgentMemorySummary,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemoryChange {
    pub sequence: i64,
    pub operation: String,
    pub memory: AgentMemorySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemoryChangesPage {
    pub items: Vec<AgentMemoryChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct ScannedAgentMemory {
    pub id: String,
    pub provider: String,
    pub scope: String,
    pub kind: String,
    pub title: String,
    pub path: String,
    pub project_dir: Option<String>,
    pub source_path_hash: String,
    pub scan_root_hash: String,
    pub content: String,
    pub content_hash: String,
    pub size_bytes: u64,
    pub source_modified_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemoryProviderStatus {
    pub provider: String,
    pub discovered: usize,
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_completed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMemoryImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub deleted: usize,
    pub failed: usize,
    pub providers: Vec<AgentMemoryProviderStatus>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryImportPreviewItem {
    pub provider: String,
    pub session_id: String,
    pub title: String,
    pub source_path_hash: String,
    pub message_count: usize,
    pub already_imported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryImportPreview {
    pub scanned: usize,
    pub importable: usize,
    pub already_imported: usize,
    pub failed: usize,
    pub by_provider: BTreeMap<String, usize>,
    pub items: Vec<HistoryImportPreviewItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveDeleteResult {
    pub deleted: usize,
}
