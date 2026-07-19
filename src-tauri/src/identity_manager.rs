use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::config::{atomic_write, get_app_config_dir, get_claude_config_dir};

pub const IDENTITY_START_MARKER: &str = "<!-- CENTAURAI_IDENTITY_START";
pub const IDENTITY_END_MARKER: &str = "<!-- CENTAURAI_IDENTITY_END -->";
const MAX_IDENTITY_FILE_BYTES: usize = 2 * 1024 * 1024;
const SCHEMA_VERSION: u32 = 1;
const REQUIRED_FILES: [&str; 4] = ["SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md"];

static APPLY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySnapshotRequest {
    pub schema_version: u32,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityFileResult {
    pub canonical_files: Vec<String>,
    pub target_path: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTargetResult {
    pub agent: String,
    pub detected: bool,
    pub status: String,
    pub files: Vec<IdentityFileResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityApplyResponse {
    pub schema_version: u32,
    pub revision: String,
    pub state: String,
    pub attempted_at: i64,
    pub targets: Vec<IdentityTargetResult>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatusResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempted_at: Option<i64>,
    pub state: String,
    pub targets: Vec<IdentityTargetResult>,
}

#[derive(Debug, Clone)]
struct TargetFileSpec {
    canonical_files: Vec<&'static str>,
    path: PathBuf,
    body: String,
}

#[derive(Debug, Clone)]
struct TargetSpec {
    agent: &'static str,
    root: PathBuf,
    files: Vec<TargetFileSpec>,
}

impl IdentitySnapshotRequest {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "不支持的身份快照版本 {}，当前仅支持版本 {SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        let actual = self.files.keys().cloned().collect::<BTreeSet<_>>();
        let required = REQUIRED_FILES
            .iter()
            .map(|value| value.to_string())
            .collect::<BTreeSet<_>>();
        if actual != required {
            return Err(format!(
                "身份快照必须且只能包含：{}",
                REQUIRED_FILES.join("、")
            ));
        }
        for (name, content) in &self.files {
            if content.len() > MAX_IDENTITY_FILE_BYTES {
                return Err(format!("{name} 超过 2 MiB 安全上限"));
            }
            if content.contains(IDENTITY_START_MARKER) || content.contains(IDENTITY_END_MARKER) {
                return Err(format!("{name} 包含保留的 CentaurAI 托管标记"));
            }
        }
        Ok(())
    }

    fn content(&self, name: &str) -> &str {
        self.files.get(name).map(String::as_str).unwrap_or("")
    }

    fn revision(&self) -> String {
        let mut hasher = Sha256::new();
        for name in REQUIRED_FILES {
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(self.content(name).as_bytes());
            hasher.update([0xff]);
        }
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn combined_body(snapshot: &IdentitySnapshotRequest, names: &[&str]) -> String {
    let mut sections = vec![
        "# CentaurAI 统一身份（托管）".to_string(),
        "".to_string(),
        "> 由个人记忆库统一维护；如与区块外规则冲突，以本区块为准。".to_string(),
    ];
    for name in names {
        sections.push(String::new());
        sections.push(format!("## {name}"));
        sections.push(String::new());
        sections.push(snapshot.content(name).trim().to_string());
    }
    sections.join("\n").trim_end().to_string()
}

fn target_specs(snapshot: &IdentitySnapshotRequest) -> Vec<TargetSpec> {
    let claude = get_claude_config_dir();
    let codex = crate::codex_config::get_codex_config_dir();
    let gemini = crate::gemini_config::get_gemini_dir();
    let opencode = crate::opencode_config::get_opencode_dir();
    let openclaw = crate::openclaw_config::get_openclaw_dir();
    let hermes = crate::hermes_config::get_hermes_dir();
    let all = ["IDENTITY.md", "SOUL.md", "USER.md", "AGENTS.md"];

    vec![
        TargetSpec {
            agent: "claude",
            root: claude.clone(),
            files: vec![TargetFileSpec {
                canonical_files: all.to_vec(),
                path: claude.join("CLAUDE.md"),
                body: combined_body(snapshot, &all),
            }],
        },
        TargetSpec {
            agent: "codex",
            root: codex.clone(),
            files: vec![TargetFileSpec {
                canonical_files: all.to_vec(),
                path: codex.join("AGENTS.md"),
                body: combined_body(snapshot, &all),
            }],
        },
        TargetSpec {
            agent: "gemini",
            root: gemini.clone(),
            files: vec![TargetFileSpec {
                canonical_files: all.to_vec(),
                path: gemini.join("GEMINI.md"),
                body: combined_body(snapshot, &all),
            }],
        },
        TargetSpec {
            agent: "opencode",
            root: opencode.clone(),
            files: vec![TargetFileSpec {
                canonical_files: all.to_vec(),
                path: opencode.join("AGENTS.md"),
                body: combined_body(snapshot, &all),
            }],
        },
        TargetSpec {
            agent: "openclaw",
            root: openclaw.clone(),
            files: REQUIRED_FILES
                .iter()
                .map(|name| TargetFileSpec {
                    canonical_files: vec![*name],
                    path: openclaw.join("workspace").join(name),
                    body: combined_body(snapshot, &[*name]),
                })
                .collect(),
        },
        TargetSpec {
            agent: "hermes",
            root: hermes.clone(),
            files: vec![
                TargetFileSpec {
                    canonical_files: vec!["IDENTITY.md", "SOUL.md"],
                    path: hermes.join("SOUL.md"),
                    body: combined_body(snapshot, &["IDENTITY.md", "SOUL.md"]),
                },
                TargetFileSpec {
                    canonical_files: vec!["AGENTS.md"],
                    path: hermes.join("AGENTS.md"),
                    body: combined_body(snapshot, &["AGENTS.md"]),
                },
                TargetFileSpec {
                    canonical_files: vec!["USER.md"],
                    path: hermes.join("memories").join("USER.md"),
                    body: combined_body(snapshot, &["USER.md"]),
                },
            ],
        },
    ]
}

fn safe_detected_root(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn remove_managed_block(content: &str) -> Result<String, String> {
    let Some(start) = content.find(IDENTITY_START_MARKER) else {
        return Ok(content.to_string());
    };
    if content[start + IDENTITY_START_MARKER.len()..].contains(IDENTITY_START_MARKER) {
        return Err("目标文件包含多个 CentaurAI 身份托管区块".to_string());
    }
    let Some(relative_end) = content[start..].find(IDENTITY_END_MARKER) else {
        return Err("目标文件中的 CentaurAI 身份托管区块不完整".to_string());
    };
    let end = start + relative_end + IDENTITY_END_MARKER.len();
    let mut unmanaged = String::new();
    unmanaged.push_str(content[..start].trim_end());
    let tail = content[end..].trim_start_matches(['\r', '\n']);
    if !unmanaged.is_empty() && !tail.is_empty() {
        unmanaged.push_str("\n\n");
    }
    unmanaged.push_str(tail);
    Ok(unmanaged.trim().to_string())
}

/// Remove the centrally-managed identity block before native-memory hashing or export.
pub fn strip_managed_identity(content: &str) -> String {
    remove_managed_block(content).unwrap_or_else(|_| content.to_string())
}

fn render_target_content(existing: &str, body: &str, revision: &str) -> Result<String, String> {
    let unmanaged = remove_managed_block(existing)?;
    let block =
        format!("{IDENTITY_START_MARKER} revision={revision} -->\n{body}\n{IDENTITY_END_MARKER}");
    if unmanaged.is_empty() {
        Ok(format!("{block}\n"))
    } else {
        Ok(format!("{}\n\n{block}\n", unmanaged.trim_end()))
    }
}

fn backup_file(agent: &str, path: &Path, content: &[u8]) -> Result<PathBuf, String> {
    let directory = get_app_config_dir()
        .join("backups")
        .join("identity")
        .join(agent);
    fs::create_dir_all(&directory).map_err(|error| format!("创建身份备份目录失败: {error}"))?;
    let stem = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("identity.md");
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S_%3f");
    let mut candidate = directory.join(format!("{timestamp}_{stem}"));
    let mut counter = 1usize;
    while candidate.exists() {
        candidate = directory.join(format!("{timestamp}_{counter}_{stem}"));
        counter += 1;
    }
    atomic_write(&candidate, content).map_err(|error| error.to_string())?;
    cleanup_backups(&directory)?;
    Ok(candidate)
}

fn cleanup_backups(directory: &Path) -> Result<(), String> {
    let retain = crate::settings::effective_backup_retain_count();
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("读取身份备份目录失败: {error}"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .collect::<Vec<_>>();
    if entries.len() <= retain {
        return Ok(());
    }
    entries.sort_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());
    let remove_count = entries.len().saturating_sub(retain);
    for entry in entries.into_iter().take(remove_count) {
        let _ = fs::remove_file(entry.path());
    }
    Ok(())
}

fn apply_target_file(agent: &str, spec: &TargetFileSpec, revision: &str) -> IdentityFileResult {
    let canonical_files = spec
        .canonical_files
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let target_path = spec.path.display().to_string();
    let existing = if spec.path.exists() {
        match fs::symlink_metadata(&spec.path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return IdentityFileResult {
                    canonical_files,
                    target_path,
                    status: "failed".to_string(),
                    backup_path: None,
                    error: Some("目标身份文件必须是普通文件，不能是符号链接".to_string()),
                };
            }
            Ok(_) => match fs::read_to_string(&spec.path) {
                Ok(content) => content,
                Err(error) => {
                    return IdentityFileResult {
                        canonical_files,
                        target_path,
                        status: "failed".to_string(),
                        backup_path: None,
                        error: Some(format!("读取目标身份文件失败: {error}")),
                    };
                }
            },
            Err(error) => {
                return IdentityFileResult {
                    canonical_files,
                    target_path,
                    status: "failed".to_string(),
                    backup_path: None,
                    error: Some(format!("检查目标身份文件失败: {error}")),
                };
            }
        }
    } else {
        String::new()
    };

    let next = match render_target_content(&existing, &spec.body, revision) {
        Ok(content) => content,
        Err(error) => {
            return IdentityFileResult {
                canonical_files,
                target_path,
                status: "failed".to_string(),
                backup_path: None,
                error: Some(error),
            };
        }
    };
    if existing == next {
        return IdentityFileResult {
            canonical_files,
            target_path,
            status: "unchanged".to_string(),
            backup_path: None,
            error: None,
        };
    }

    let backup_path = if existing.is_empty() {
        None
    } else {
        match backup_file(agent, &spec.path, existing.as_bytes()) {
            Ok(path) => Some(path.display().to_string()),
            Err(error) => {
                return IdentityFileResult {
                    canonical_files,
                    target_path,
                    status: "failed".to_string(),
                    backup_path: None,
                    error: Some(error),
                };
            }
        }
    };
    match atomic_write(&spec.path, next.as_bytes()) {
        Ok(()) => IdentityFileResult {
            canonical_files,
            target_path,
            status: "applied".to_string(),
            backup_path,
            error: None,
        },
        Err(error) => IdentityFileResult {
            canonical_files,
            target_path,
            status: "failed".to_string(),
            backup_path,
            error: Some(error.to_string()),
        },
    }
}

fn status_path() -> PathBuf {
    get_app_config_dir().join("identity-sync-status.json")
}

fn save_status(response: &IdentityApplyResponse) {
    match serde_json::to_vec_pretty(response) {
        Ok(payload) => {
            if let Err(error) = atomic_write(&status_path(), &payload) {
                log::warn!("保存身份同步状态失败: {error}");
            }
        }
        Err(error) => log::warn!("序列化身份同步状态失败: {error}"),
    }
}

fn load_status() -> Option<IdentityApplyResponse> {
    fs::read(status_path())
        .ok()
        .and_then(|payload| serde_json::from_slice(&payload).ok())
}

pub fn status(enabled: bool) -> IdentityStatusResponse {
    let previous = load_status();
    IdentityStatusResponse {
        enabled,
        last_revision: previous.as_ref().map(|value| value.revision.clone()),
        last_attempted_at: previous.as_ref().map(|value| value.attempted_at),
        state: previous
            .as_ref()
            .map(|value| value.state.clone())
            .unwrap_or_else(|| "never".to_string()),
        targets: previous.map(|value| value.targets).unwrap_or_default(),
    }
}

pub fn apply(snapshot: IdentitySnapshotRequest) -> Result<IdentityApplyResponse, String> {
    snapshot.validate()?;
    let revision = snapshot.revision();
    let _guard = APPLY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "身份同步锁已损坏".to_string())?;

    let mut targets = Vec::new();
    let mut applied = 0usize;
    let mut failed = 0usize;
    let mut detected = 0usize;
    for target in target_specs(&snapshot) {
        if !safe_detected_root(&target.root) {
            targets.push(IdentityTargetResult {
                agent: target.agent.to_string(),
                detected: false,
                status: "not_detected".to_string(),
                files: Vec::new(),
                error: None,
            });
            continue;
        }
        detected += 1;
        let files = target
            .files
            .iter()
            .map(|file| apply_target_file(target.agent, file, &revision))
            .collect::<Vec<_>>();
        let target_failed = files.iter().any(|file| file.status == "failed");
        let target_applied = files.iter().any(|file| file.status == "applied");
        if target_failed {
            failed += 1;
        } else if target_applied {
            applied += 1;
        }
        targets.push(IdentityTargetResult {
            agent: target.agent.to_string(),
            detected: true,
            status: if target_failed {
                "failed"
            } else if target_applied {
                "applied"
            } else {
                "unchanged"
            }
            .to_string(),
            files,
            error: None,
        });
    }
    targets.push(IdentityTargetResult {
        agent: "claude-desktop".to_string(),
        detected: false,
        status: "unsupported".to_string(),
        files: Vec::new(),
        error: Some("Claude Desktop 没有受支持的本机身份规则文件".to_string()),
    });

    let state = if detected == 0 || failed > 0 {
        "partial"
    } else if applied > 0 {
        "applied"
    } else {
        "unchanged"
    };
    let response = IdentityApplyResponse {
        schema_version: SCHEMA_VERSION,
        revision,
        state: state.to_string(),
        attempted_at: Utc::now().timestamp_millis(),
        targets,
    };
    save_status(&response);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> IdentitySnapshotRequest {
        IdentitySnapshotRequest {
            schema_version: 1,
            files: BTreeMap::from([
                ("SOUL.md".to_string(), "# Soul\n\nsteady".to_string()),
                ("AGENTS.md".to_string(), "# Rules\n\nverify".to_string()),
                (
                    "IDENTITY.md".to_string(),
                    "# Identity\n\nCentaur".to_string(),
                ),
                ("USER.md".to_string(), "# User\n\nChinese".to_string()),
            ]),
        }
    }

    #[test]
    fn validates_exact_canonical_file_set() {
        assert!(snapshot().validate().is_ok());
        let mut invalid = snapshot();
        invalid.files.remove("SOUL.md");
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn managed_block_replacement_preserves_unmanaged_content() {
        let first = render_target_content("# Local\n\nkeep", "# Managed\none", "r1").unwrap();
        let second = render_target_content(&first, "# Managed\ntwo", "r2").unwrap();
        assert!(second.contains("# Local\n\nkeep"));
        assert!(!second.contains("# Managed\none"));
        assert!(second.contains("# Managed\ntwo"));
        assert_eq!(second.matches(IDENTITY_START_MARKER).count(), 1);
    }

    #[test]
    fn scanner_strip_removes_only_managed_identity() {
        let content = render_target_content("# Native\n\nkeep", "# Managed\nhide", "r1").unwrap();
        assert_eq!(strip_managed_identity(&content), "# Native\n\nkeep");
    }

    #[test]
    fn revision_is_stable_and_content_sensitive() {
        let first = snapshot();
        let mut second = snapshot();
        assert_eq!(first.revision(), second.revision());
        second
            .files
            .insert("USER.md".to_string(), "changed".to_string());
        assert_ne!(first.revision(), second.revision());
    }

    #[test]
    fn target_file_is_created_once_and_then_remains_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("AGENTS.md");
        let spec = TargetFileSpec {
            canonical_files: vec!["AGENTS.md"],
            path: path.clone(),
            body: "# Managed rules".to_string(),
        };
        let first = apply_target_file("test-agent", &spec, "revision-1");
        assert_eq!(first.status, "applied");
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("# Managed rules"));
        let second = apply_target_file("test-agent", &spec, "revision-1");
        assert_eq!(second.status, "unchanged");
        assert!(second.backup_path.is_none());
    }
}
