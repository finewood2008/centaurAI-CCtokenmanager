#![allow(non_snake_case)]

use crate::archive::{
    ArchiveDeleteResult, ArchiveHealth, ArchiveInitializationResult, ArchiveLocalSnapshotSummary,
    ArchiveSearchFilters, ArchiveSearchPage, ArchivedConversationDetail, HistoryImportPreview,
    HistoryImportResult,
};
use crate::settings::ArchiveSettings;
use crate::store::AppState;

#[tauri::command]
pub async fn get_archive_health(
    state: tauri::State<'_, AppState>,
) -> Result<ArchiveHealth, String> {
    Ok(state.archive.health().await)
}

#[tauri::command]
pub async fn initialize_conversation_archive(
    state: tauri::State<'_, AppState>,
    archive: ArchiveSettings,
) -> Result<ArchiveInitializationResult, String> {
    state.archive.initialize(archive).await
}

#[tauri::command]
pub async fn initialize_local_conversation_archive(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.prepare_local_archive())
        .await
        .map_err(|e| format!("本机归档初始化任务失败: {e}"))??;
    Ok(true)
}

#[tauri::command]
pub async fn trigger_local_history_import(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state.archive.trigger_local_history_import())
}

#[tauri::command]
pub async fn get_local_conversation_api_status(
    state: tauri::State<'_, AppState>,
) -> Result<crate::archive::local_api::LocalConversationApiStatus, String> {
    Ok(crate::archive::local_api::status(&state.archive))
}

#[tauri::command]
pub async fn reveal_local_conversation_api_token() -> Result<String, String> {
    crate::archive::local_api::get_or_create_token()
}

#[tauri::command]
pub async fn rotate_local_conversation_api_token() -> Result<String, String> {
    crate::archive::local_api::rotate_token()
}

#[tauri::command]
pub async fn preview_local_history_import(
    state: tauri::State<'_, AppState>,
) -> Result<HistoryImportPreview, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.preview_local_history())
        .await
        .map_err(|e| format!("本机历史扫描任务失败: {e}"))?
}

#[tauri::command]
pub async fn import_local_history(
    state: tauri::State<'_, AppState>,
) -> Result<HistoryImportResult, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.import_local_history())
        .await
        .map_err(|e| format!("本机历史导入任务失败: {e}"))?
}

#[tauri::command]
pub async fn search_archived_conversations(
    state: tauri::State<'_, AppState>,
    query: String,
    filters: ArchiveSearchFilters,
    cursor: Option<String>,
    pageSize: usize,
) -> Result<ArchiveSearchPage, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || {
        archive.search(&query, &filters, cursor.as_deref(), pageSize)
    })
    .await
    .map_err(|e| format!("归档检索任务失败: {e}"))?
}

#[tauri::command]
pub async fn get_archived_conversation(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<ArchivedConversationDetail, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.detail(&id))
        .await
        .map_err(|e| format!("读取归档会话任务失败: {e}"))?
}

#[tauri::command]
pub async fn export_archived_conversations(
    state: tauri::State<'_, AppState>,
    ids: Vec<String>,
    format: String,
    targetPath: String,
) -> Result<bool, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || {
        archive.export(&ids, &format, std::path::Path::new(&targetPath))
    })
    .await
    .map_err(|e| format!("归档导出任务失败: {e}"))??;
    Ok(true)
}

#[tauri::command]
pub async fn delete_archived_conversations(
    state: tauri::State<'_, AppState>,
    ids: Vec<String>,
) -> Result<ArchiveDeleteResult, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.delete(&ids))
        .await
        .map_err(|e| format!("归档删除任务失败: {e}"))?
}

#[tauri::command]
pub async fn list_archive_local_snapshots(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ArchiveLocalSnapshotSummary>, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.list_local_snapshots())
        .await
        .map_err(|e| format!("读取归档本地快照任务失败: {e}"))?
}

#[tauri::command]
pub async fn create_archive_local_snapshot(
    state: tauri::State<'_, AppState>,
) -> Result<ArchiveLocalSnapshotSummary, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.create_local_snapshot_now())
        .await
        .map_err(|e| format!("创建归档本地快照任务失败: {e}"))?
}

#[tauri::command]
pub async fn restore_archive_local_snapshot(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<ArchiveLocalSnapshotSummary, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.restore_local_snapshot(&id))
        .await
        .map_err(|e| format!("恢复归档本地快照任务失败: {e}"))?
}

#[tauri::command]
pub async fn delete_archive_local_snapshot(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<bool, String> {
    let archive = state.archive.clone();
    tauri::async_runtime::spawn_blocking(move || archive.delete_local_snapshot(&id))
        .await
        .map_err(|e| format!("删除归档本地快照任务失败: {e}"))??;
    Ok(true)
}

#[tauri::command]
pub async fn test_archive_redaction(
    state: tauri::State<'_, AppState>,
    input: String,
) -> Result<String, String> {
    state.archive.test_redaction(&input)
}
