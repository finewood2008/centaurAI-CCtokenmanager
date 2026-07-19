use super::{
    AgentMemoryChangesPage, AgentMemoryDetail, ArchiveConversationChangesPage, ArchiveService,
    ArchivedConversationDetail,
};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const API_PORT: u16 = 15_722;
static API_STARTED: AtomicBool = AtomicBool::new(false);
static TOKEN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone)]
struct ApiState {
    archive: Arc<ArchiveService>,
}

#[derive(Debug, Deserialize)]
struct ChangesQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConversationApiStatus {
    pub enabled: bool,
    pub url: String,
    pub token_configured: bool,
    pub auto_import_enabled: bool,
    pub memory_import_enabled: bool,
    pub identity_write_enabled: bool,
    pub capabilities: Vec<String>,
    pub runtime: super::LocalHistoryRuntimeStatus,
    pub memory_runtime: super::LocalMemoryRuntimeStatus,
    pub adapters: Vec<crate::session_manager::providers::plugin::AdapterInfo>,
}

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

fn token_path() -> PathBuf {
    crate::config::get_app_config_dir()
        .join("secrets")
        .join("local-conversation-api.token")
}

#[cfg(unix)]
fn secure_permissions(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("设置本机 API 凭据权限失败: {error}"))
}

#[cfg(not(unix))]
fn secure_permissions(_path: &std::path::Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn token_lock() -> &'static Mutex<()> {
    TOKEN_LOCK.get_or_init(|| Mutex::new(()))
}

fn get_or_create_token_unlocked() -> Result<String, String> {
    let path = token_path();
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("检查本机 API 令牌失败: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("本机 API 令牌必须是普通文件".to_string());
        }
        secure_permissions(&path, 0o600)?;
        let token = fs::read_to_string(&path)
            .map_err(|error| format!("读取本机 API 令牌失败: {error}"))?
            .trim()
            .to_string();
        if token.len() < 32 {
            return Err("本机 API 令牌文件无效".to_string());
        }
        return Ok(token);
    }
    let parent = path
        .parent()
        .ok_or_else(|| "本机 API 令牌目录无效".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建令牌目录失败: {error}"))?;
    secure_permissions(parent, 0o700)?;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("生成 API 令牌失败: {error}"))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("创建 API 令牌失败: {error}"))?;
    file.write_all(token.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("写入 API 令牌失败: {error}"))?;
    secure_permissions(&path, 0o600)?;
    Ok(token)
}

pub fn get_or_create_token() -> Result<String, String> {
    let _guard = token_lock()
        .lock()
        .map_err(|_| "本机 API 令牌锁已损坏".to_string())?;
    get_or_create_token_unlocked()
}

pub fn rotate_token() -> Result<String, String> {
    let _guard = token_lock()
        .lock()
        .map_err(|_| "本机 API 令牌锁已损坏".to_string())?;
    let path = token_path();
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("检查本机 API 令牌失败: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("本机 API 令牌必须是普通文件".to_string());
        }
        fs::remove_file(&path).map_err(|error| format!("轮换 API 令牌失败: {error}"))?;
    }
    get_or_create_token_unlocked()
}

fn token_matches(expected: &str, supplied: &str) -> bool {
    let Ok(mut expected_mac) = Hmac::<Sha256>::new_from_slice(expected.as_bytes()) else {
        return false;
    };
    expected_mac.update(b"centaurai-local-conversation-api");
    let tag = expected_mac.finalize().into_bytes();
    let Ok(mut supplied_mac) = Hmac::<Sha256>::new_from_slice(supplied.as_bytes()) else {
        return false;
    };
    supplied_mac.update(b"centaurai-local-conversation-api");
    supplied_mac.verify_slice(&tag).is_ok()
}

fn authorize(headers: &HeaderMap, archive: &ArchiveService) -> Result<(), ApiError> {
    if !archive.settings().local_history.api_enabled {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "本机对话 API 未启用".to_string(),
        ));
    }
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "缺少 Bearer Token".to_string()))?;
    let expected = get_or_create_token()
        .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    if !token_matches(&expected, supplied) {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "Bearer Token 无效".to_string(),
        ));
    }
    Ok(())
}

async fn health(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let settings = state.archive.settings();
    let capabilities = api_capabilities(settings.local_history.identity_write_enabled);
    Json(json!({
        "status": "ok",
        "apiVersion": 1,
        "enabled": settings.local_history.api_enabled,
        "autoImportEnabled": settings.local_history.auto_import_enabled,
        "memoryImportEnabled": settings.local_history.memory_import_enabled,
        "identityWriteEnabled": settings.local_history.identity_write_enabled,
        "capabilities": capabilities,
    }))
}

fn api_capabilities(identity_write_enabled: bool) -> Vec<String> {
    let mut capabilities = vec!["conversations".to_string(), "memories".to_string()];
    if identity_write_enabled {
        capabilities.push("identity-write".to_string());
    }
    capabilities
}

async fn adapters(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &state.archive)?;
    Ok(Json(json!({
        "adapters": crate::session_manager::providers::plugin::adapter_infos()
    })))
}

async fn changes(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<ArchiveConversationChangesPage>, ApiError> {
    authorize(&headers, &state.archive)?;
    state
        .archive
        .conversation_changes(query.cursor.as_deref(), query.limit.unwrap_or(50))
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error))
}

async fn detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ArchivedConversationDetail>, ApiError> {
    authorize(&headers, &state.archive)?;
    let detail = state
        .archive
        .detail(&id)
        .map_err(|error| ApiError(StatusCode::NOT_FOUND, error))?;
    if !matches!(
        detail.conversation.source.as_str(),
        "local_history" | "local_proxy"
    ) {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "归档会话不存在".to_string(),
        ));
    }
    Ok(Json(detail))
}

async fn memory_changes(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<AgentMemoryChangesPage>, ApiError> {
    authorize(&headers, &state.archive)?;
    state
        .archive
        .agent_memory_changes(query.cursor.as_deref(), query.limit.unwrap_or(50))
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error))
}

async fn memory_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<AgentMemoryDetail>, ApiError> {
    authorize(&headers, &state.archive)?;
    state
        .archive
        .agent_memory_detail(&id)
        .map(Json)
        .map_err(|error| ApiError(StatusCode::NOT_FOUND, error))
}

async fn identity_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<crate::identity_manager::IdentityStatusResponse>, ApiError> {
    authorize(&headers, &state.archive)?;
    let enabled = state
        .archive
        .settings()
        .local_history
        .identity_write_enabled;
    Ok(Json(crate::identity_manager::status(enabled)))
}

async fn identity_apply(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(snapshot): Json<crate::identity_manager::IdentitySnapshotRequest>,
) -> Result<Json<crate::identity_manager::IdentityApplyResponse>, ApiError> {
    authorize(&headers, &state.archive)?;
    if !state
        .archive
        .settings()
        .local_history
        .identity_write_enabled
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "TokenManager 尚未开启“允许身份写入”".to_string(),
        ));
    }
    crate::identity_manager::apply(snapshot)
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error))
}

pub fn status(archive: &ArchiveService) -> LocalConversationApiStatus {
    let settings = archive.settings();
    LocalConversationApiStatus {
        enabled: settings.local_history.api_enabled,
        url: format!("http://127.0.0.1:{API_PORT}"),
        token_configured: token_path().is_file(),
        auto_import_enabled: settings.local_history.auto_import_enabled,
        memory_import_enabled: settings.local_history.memory_import_enabled,
        identity_write_enabled: settings.local_history.identity_write_enabled,
        capabilities: api_capabilities(settings.local_history.identity_write_enabled),
        runtime: archive.local_history_runtime_status(),
        memory_runtime: archive.local_memory_runtime_status(),
        adapters: crate::session_manager::providers::plugin::adapter_infos(),
    }
}

pub fn start(archive: Arc<ArchiveService>) {
    if API_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let app = Router::new()
            .route("/v1/health", get(health))
            .route("/v1/adapters", get(adapters))
            .route("/v1/conversations/changes", get(changes))
            .route("/v1/conversations/{id}", get(detail))
            .route("/v1/memories/changes", get(memory_changes))
            .route("/v1/memories/{id}", get(memory_detail))
            .route("/v1/identity/status", get(identity_status))
            .route("/v1/identity", put(identity_apply))
            .with_state(ApiState { archive });
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), API_PORT);
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                log::info!("本机对话与身份 API 已监听 http://{address}");
                if let Err(error) = axum::serve(listener, app).await {
                    log::error!("本机对话 API 运行失败: {error}");
                }
            }
            Err(error) => log::error!("本机对话 API 无法监听 {address}: {error}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_comparison_rejects_different_values() {
        let expected = "expected-token-value-with-sufficient-length";
        assert!(token_matches(expected, expected));
        assert!(!token_matches(
            expected,
            "different-token-value-with-sufficient-length"
        ));
        assert!(!token_matches(expected, ""));
    }

    #[test]
    fn identity_write_capability_is_only_advertised_when_enabled() {
        assert!(!api_capabilities(false).contains(&"identity-write".to_string()));
        assert!(api_capabilities(true).contains(&"identity-write".to_string()));
    }
}
