use crate::session_manager::{SessionMessage, SessionMeta};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

const PROTOCOL_VERSION: u32 = 1;
const MAX_OUTPUT_BYTES: u64 = 50 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterManifest {
    pub schema_version: u32,
    pub id: String,
    pub display_name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub watch_paths: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterInfo {
    pub id: String,
    pub display_name: String,
    pub kind: String,
    pub enabled: bool,
    pub capabilities: Vec<String>,
    pub watch_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginRequest<'a> {
    protocol_version: u32,
    request_id: String,
    method: &'a str,
    params: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginResponse {
    protocol_version: u32,
    request_id: String,
    ok: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginMemoryMeta {
    pub source_ref: String,
    #[serde(default = "default_memory_scope")]
    pub scope: String,
    #[serde(default = "default_memory_kind")]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub project_dir: Option<String>,
    #[serde(default)]
    pub modified_at: Option<i64>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PluginMemoryScanResult {
    pub provider_id: String,
    pub memories: Vec<PluginMemoryMeta>,
    pub error: Option<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

fn default_memory_scope() -> String {
    "agent".to_string()
}

fn default_memory_kind() -> String {
    "memory".to_string()
}

pub fn adapter_directory() -> PathBuf {
    crate::config::get_app_config_dir().join("session-adapters")
}

fn safe_adapter_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.'))
}

fn validate_manifest(manifest: &AdapterManifest) -> Result<(), String> {
    if manifest.schema_version != PROTOCOL_VERSION {
        return Err(format!(
            "不支持的适配器清单版本 {}",
            manifest.schema_version
        ));
    }
    if !safe_adapter_id(&manifest.id) {
        return Err("适配器 ID 只能包含字母、数字、点、横线和下划线".to_string());
    }
    if manifest.display_name.trim().is_empty() {
        return Err("适配器名称不能为空".to_string());
    }
    let command = Path::new(&manifest.command);
    if !command.is_absolute() || !command.is_file() {
        return Err("适配器 command 必须指向存在的绝对文件路径".to_string());
    }
    if !(1..=120).contains(&manifest.timeout_seconds) {
        return Err("适配器 timeoutSeconds 必须在 1 到 120 秒之间".to_string());
    }
    Ok(())
}

fn manifests() -> Vec<(PathBuf, Result<AdapterManifest, String>)> {
    let directory = adapter_directory();
    let Ok(entries) = fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut results = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            let parsed = fs::read_to_string(&path)
                .map_err(|error| format!("读取清单失败: {error}"))
                .and_then(|content| {
                    serde_json::from_str::<AdapterManifest>(&content)
                        .map_err(|error| format!("解析清单失败: {error}"))
                })
                .and_then(|manifest| {
                    validate_manifest(&manifest)?;
                    Ok(manifest)
                });
            (path, parsed)
        })
        .collect::<Vec<_>>();
    results.sort_by(|left, right| left.0.cmp(&right.0));
    results
}

fn find_manifest(provider_id: &str) -> Result<AdapterManifest, String> {
    let id = provider_id
        .strip_prefix("plugin:")
        .ok_or_else(|| "无效的插件 Provider ID".to_string())?;
    manifests()
        .into_iter()
        .filter_map(|(_, manifest)| manifest.ok())
        .find(|manifest| manifest.enabled && manifest.id == id)
        .ok_or_else(|| format!("适配器未启用或不存在: {id}"))
}

fn read_limited<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("读取适配器输出失败: {error}"))?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err("适配器输出超过 50 MB 限制".to_string());
    }
    Ok(bytes)
}

fn invoke(manifest: &AdapterManifest, method: &str, params: Value) -> Result<Value, String> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::to_vec(&PluginRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        method,
        params,
    })
    .map_err(|error| format!("序列化适配器请求失败: {error}"))?;

    let mut child = Command::new(&manifest.command)
        .args(&manifest.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("启动适配器失败: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "无法打开适配器标准输入".to_string())?
        .write_all(&payload)
        .map_err(|error| format!("写入适配器请求失败: {error}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "无法读取适配器标准输出".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "无法读取适配器错误输出".to_string())?;
    let stdout_reader = std::thread::spawn(move || read_limited(stdout));
    let stderr_reader = std::thread::spawn(move || read_limited(stderr));

    let status = match child
        .wait_timeout(Duration::from_secs(manifest.timeout_seconds))
        .map_err(|error| format!("等待适配器失败: {error}"))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("适配器执行超过 {} 秒", manifest.timeout_seconds));
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "适配器标准输出读取线程异常".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "适配器错误输出读取线程异常".to_string())??;
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "适配器退出失败: {}",
            detail.chars().take(500).collect::<String>()
        ));
    }
    let response: PluginResponse = serde_json::from_slice(&stdout)
        .map_err(|error| format!("适配器返回的 JSON 无效: {error}"))?;
    if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
        return Err("适配器响应版本或 requestId 不匹配".to_string());
    }
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "适配器返回未知错误".to_string()));
    }
    Ok(response.result)
}

pub fn scan_sessions() -> Vec<SessionMeta> {
    let mut sessions = Vec::new();
    for manifest in manifests()
        .into_iter()
        .filter_map(|(_, result)| result.ok())
        .filter(|manifest| manifest.enabled && manifest.capabilities.iter().any(|v| v == "scan"))
    {
        let result = invoke(&manifest, "scan", json!({}));
        let Ok(result) = result else {
            log::warn!(
                "会话适配器 {} 扫描失败: {}",
                manifest.id,
                result.unwrap_err()
            );
            continue;
        };
        let parsed = result
            .get("sessions")
            .cloned()
            .and_then(|value| serde_json::from_value::<Vec<SessionMeta>>(value).ok())
            .unwrap_or_default();
        for mut session in parsed {
            if session.session_id.trim().is_empty() || session.session_id.len() > 512 {
                continue;
            }
            session.provider_id = format!("plugin:{}", manifest.id);
            sessions.push(session);
        }
    }
    sessions
}

pub fn load_messages(provider_id: &str, source_path: &str) -> Result<Vec<SessionMessage>, String> {
    let manifest = find_manifest(provider_id)?;
    if !manifest.capabilities.iter().any(|value| value == "load") {
        return Err("适配器不支持读取消息".to_string());
    }
    let result = invoke(&manifest, "load", json!({"sourceRef": source_path}))?;
    serde_json::from_value(result.get("messages").cloned().unwrap_or(Value::Null))
        .map_err(|error| format!("适配器消息格式无效: {error}"))
}

pub fn scan_memories() -> Vec<PluginMemoryScanResult> {
    let mut scans = Vec::new();
    for manifest in manifests()
        .into_iter()
        .filter_map(|(_, result)| result.ok())
        .filter(|manifest| {
            manifest.enabled
                && manifest
                    .capabilities
                    .iter()
                    .any(|value| value == "memory-scan")
        })
    {
        let provider_id = format!("plugin:{}", manifest.id);
        match invoke(&manifest, "memory-scan", json!({})) {
            Ok(result) => {
                let parsed = result
                    .get("memories")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<Vec<PluginMemoryMeta>>(value).ok())
                    .unwrap_or_default();
                scans.push(PluginMemoryScanResult {
                    provider_id,
                    memories: parsed
                        .into_iter()
                        .filter(|item| !item.source_ref.trim().is_empty())
                        .collect(),
                    error: None,
                });
            }
            Err(error) => {
                log::warn!("记忆适配器 {} 扫描失败: {error}", manifest.id);
                scans.push(PluginMemoryScanResult {
                    provider_id,
                    memories: Vec::new(),
                    error: Some(error),
                });
            }
        }
    }
    scans
}

pub fn load_memory(provider_id: &str, source_ref: &str) -> Result<String, String> {
    let manifest = find_manifest(provider_id)?;
    if !manifest
        .capabilities
        .iter()
        .any(|value| value == "memory-load")
    {
        return Err("适配器未声明记忆读取能力".to_string());
    }
    let result = invoke(&manifest, "memory-load", json!({"sourceRef": source_ref}))?;
    result
        .get("content")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| "适配器记忆格式无效".to_string())
}

pub fn delete_session(
    provider_id: &str,
    session_id: &str,
    source_path: &str,
) -> Result<bool, String> {
    let manifest = find_manifest(provider_id)?;
    if !manifest.capabilities.iter().any(|value| value == "delete") {
        return Err("适配器未声明删除能力".to_string());
    }
    let result = invoke(
        &manifest,
        "delete",
        json!({"sessionId": session_id, "sourceRef": source_path}),
    )?;
    Ok(result
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

pub fn watch_paths() -> Vec<PathBuf> {
    manifests()
        .into_iter()
        .filter_map(|(_, result)| result.ok())
        .filter(|manifest| manifest.enabled)
        .flat_map(|manifest| manifest.watch_paths)
        .map(|path| {
            let expanded = path.strip_prefix("~/").map_or_else(
                || PathBuf::from(&path),
                |suffix| dirs::home_dir().unwrap_or_default().join(suffix),
            );
            expanded
        })
        .filter(|path| path.is_absolute())
        .collect()
}

pub fn adapter_infos() -> Vec<AdapterInfo> {
    let mut infos = vec![
        ("claude", "Claude"),
        ("codex", "Codex"),
        ("gemini", "Gemini"),
        ("opencode", "OpenCode"),
        ("openclaw", "OpenClaw"),
        ("hermes", "Hermes"),
    ]
    .into_iter()
    .map(|(id, display_name)| AdapterInfo {
        id: id.to_string(),
        display_name: display_name.to_string(),
        kind: "builtin".to_string(),
        enabled: true,
        capabilities: vec![
            "scan".to_string(),
            "load".to_string(),
            "memory-scan".to_string(),
            "memory-load".to_string(),
        ],
        watch_paths: Vec::new(),
        error: None,
    })
    .collect::<Vec<_>>();
    infos.extend(manifests().into_iter().map(|(path, result)| {
        match result {
            Ok(manifest) => AdapterInfo {
                id: format!("plugin:{}", manifest.id),
                display_name: manifest.display_name,
                kind: "process".to_string(),
                enabled: manifest.enabled,
                capabilities: manifest.capabilities,
                watch_paths: manifest.watch_paths,
                error: None,
            },
            Err(error) => AdapterInfo {
                id: format!(
                    "invalid:{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(path.to_string_lossy().as_bytes())
                ),
                display_name: path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("Invalid adapter")
                    .to_string(),
                kind: "process".to_string(),
                enabled: false,
                capabilities: Vec::new(),
                watch_paths: Vec::new(),
                error: Some(error),
            },
        }
    }));
    infos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(command: &str, args: Vec<String>) -> AdapterManifest {
        AdapterManifest {
            schema_version: 1,
            id: "example-agent".to_string(),
            display_name: "Example Agent".to_string(),
            command: command.to_string(),
            args,
            enabled: true,
            capabilities: vec!["scan".to_string(), "load".to_string()],
            watch_paths: Vec::new(),
            timeout_seconds: 5,
        }
    }

    #[test]
    fn rejects_unsafe_manifest_id_and_relative_command() {
        let mut candidate = manifest("relative-command", Vec::new());
        candidate.id = "../../unsafe".to_string();
        assert!(validate_manifest(&candidate).is_err());
        candidate.id = "safe-id".to_string();
        assert!(validate_manifest(&candidate).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn invokes_versioned_json_process_protocol() {
        let script = r#"payload=$(cat)
request_id=$(printf '%s' "$payload" | sed -n 's/.*"requestId":"\([^"]*\)".*/\1/p')
printf '{"protocolVersion":1,"requestId":"%s","ok":true,"result":{"messages":[{"role":"user","content":"hello"}]}}' "$request_id""#;
        let candidate = manifest("/bin/sh", vec!["-c".to_string(), script.to_string()]);
        validate_manifest(&candidate).expect("valid manifest");
        let result =
            invoke(&candidate, "load", json!({"sourceRef":"opaque"})).expect("plugin response");
        assert_eq!(result["messages"][0]["content"], "hello");
    }

    #[cfg(unix)]
    #[test]
    fn terminates_timed_out_plugin() {
        let mut candidate = manifest(
            "/bin/sh",
            vec!["-c".to_string(), "cat >/dev/null; sleep 3".to_string()],
        );
        candidate.timeout_seconds = 1;
        let error = invoke(&candidate, "scan", json!({})).expect_err("must time out");
        assert!(error.contains("超过 1 秒"));
    }
}
