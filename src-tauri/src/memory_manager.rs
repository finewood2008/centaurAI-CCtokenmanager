use crate::archive::{AgentMemoryProviderStatus, ScannedAgentMemory};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROVIDER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 24;
const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".cache",
    "vendor",
];

#[derive(Debug, Default)]
pub struct AgentMemoryScan {
    pub memories: Vec<ScannedAgentMemory>,
    pub completed_roots: Vec<String>,
    pub statuses: Vec<AgentMemoryProviderStatus>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct RootSpec {
    provider: String,
    scope: String,
    root: PathBuf,
    display_root: String,
    project_dir: Option<String>,
    max_depth: usize,
    candidate_names: HashSet<String>,
    instruction_patterns: Vec<String>,
}

#[derive(Default)]
struct ProviderProgress {
    discovered: usize,
    skipped: usize,
    failed: usize,
    bytes: u64,
    errors: Vec<String>,
}

pub fn watch_roots() -> Vec<PathBuf> {
    let mut roots = configured_roots()
        .into_iter()
        .map(|root| root.root)
        .collect::<Vec<_>>();
    roots.extend(project_roots().into_values().flatten());
    roots.sort();
    roots.dedup();
    roots
}

pub fn scan_agent_memories() -> AgentMemoryScan {
    let mut result = AgentMemoryScan::default();
    let mut progress = BTreeMap::<String, ProviderProgress>::new();
    let mut seen_ids = HashSet::new();
    let mut roots = configured_roots();
    for (provider, paths) in project_roots() {
        if !matches!(
            provider.as_str(),
            "claude" | "codex" | "gemini" | "opencode" | "openclaw" | "hermes"
        ) {
            continue;
        }
        for project_root in paths {
            if roots.iter().any(|configured| {
                configured.provider == provider && project_root.starts_with(&configured.root)
            }) {
                continue;
            }
            let mut spec = root(&provider, "project", project_root.clone(), ".");
            spec.project_dir = Some(project_root.to_string_lossy().to_string());
            roots.push(spec);
            if matches!(
                provider.as_str(),
                "claude" | "codex" | "gemini" | "opencode"
            ) {
                let mut ancestor = project_root.parent();
                let mut depth = 0usize;
                while let Some(path) = ancestor {
                    if depth >= 16 {
                        break;
                    }
                    if !roots
                        .iter()
                        .any(|existing| existing.provider == provider && existing.root == path)
                    {
                        let mut ancestor_spec = root(&provider, "project", path.to_path_buf(), ".");
                        ancestor_spec.project_dir =
                            Some(project_root.to_string_lossy().to_string());
                        ancestor_spec.max_depth = 0;
                        roots.push(ancestor_spec);
                    }
                    if path.parent().is_none() {
                        break;
                    }
                    ancestor = path.parent();
                    depth += 1;
                }
            }
        }
    }

    roots.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.root.cmp(&right.root))
    });
    roots.dedup_by(|left, right| left.provider == right.provider && left.root == right.root);

    for root in roots {
        let provider_progress = progress.entry(root.provider.clone()).or_default();
        match scan_root(&root, provider_progress, &mut seen_ids) {
            Ok((memories, root_hash)) => {
                provider_progress.discovered += memories.len();
                result.memories.extend(memories);
                result.completed_roots.push(root_hash);
            }
            Err(error) => {
                provider_progress.failed += 1;
                provider_progress.errors.push(error.clone());
                result.errors.push(error);
            }
        }
    }

    scan_plugin_memories(&mut result, &mut progress, &mut seen_ids);

    let completed_at = chrono::Utc::now().timestamp_millis();
    result.statuses = progress
        .into_iter()
        .map(|(provider, progress)| AgentMemoryProviderStatus {
            provider,
            discovered: progress.discovered,
            imported: 0,
            skipped: progress.skipped,
            failed: progress.failed,
            last_completed_at: Some(completed_at),
            last_error: (!progress.errors.is_empty()).then(|| {
                progress
                    .errors
                    .into_iter()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("；")
            }),
        })
        .collect();
    result.completed_roots.sort();
    result.completed_roots.dedup();
    result
}

fn configured_roots() -> Vec<RootSpec> {
    let home = crate::config::get_home_dir();
    let mut roots = vec![
        root(
            "claude",
            "global",
            crate::config::get_claude_config_dir(),
            "~/.claude",
        ),
        RootSpec {
            provider: "claude".to_string(),
            scope: "global".to_string(),
            root: home,
            display_root: "~".to_string(),
            project_dir: None,
            max_depth: 0,
            candidate_names: provider_candidate_names("claude"),
            instruction_patterns: Vec::new(),
        },
        root(
            "codex",
            "global",
            crate::codex_config::get_codex_config_dir(),
            "~/.codex",
        ),
        root(
            "gemini",
            "global",
            crate::gemini_config::get_gemini_dir(),
            "~/.gemini",
        ),
        root(
            "opencode",
            "global",
            crate::opencode_config::get_opencode_dir(),
            "~/.config/opencode",
        ),
        root(
            "openclaw",
            "agent",
            crate::openclaw_config::get_openclaw_dir().join("workspace"),
            "~/.openclaw/workspace",
        ),
        root(
            "hermes",
            "agent",
            crate::hermes_config::get_hermes_dir(),
            "~/.hermes",
        ),
    ];
    if let Some(custom_auto_memory) = claude_auto_memory_directory() {
        let claude_root = crate::config::get_claude_config_dir();
        if !custom_auto_memory.starts_with(&claude_root) {
            roots.push(root(
                "claude",
                "agent",
                custom_auto_memory,
                "claude-auto-memory",
            ));
        }
    }
    if let Some(managed_root) = claude_managed_root() {
        roots.push(root("claude", "managed", managed_root, "managed-claude"));
    }
    roots
}

fn root(provider: &str, scope: &str, root: PathBuf, display_root: &str) -> RootSpec {
    let instruction_patterns = if provider == "opencode" {
        opencode_instruction_patterns(&root)
    } else {
        Vec::new()
    };
    RootSpec {
        provider: provider.to_string(),
        scope: scope.to_string(),
        root,
        display_root: display_root.to_string(),
        project_dir: None,
        max_depth: MAX_SCAN_DEPTH,
        candidate_names: provider_candidate_names(provider),
        instruction_patterns,
    }
}

fn provider_candidate_names(provider: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    if provider == "gemini" {
        names.insert("GEMINI.md".to_string());
        let settings_path = crate::gemini_config::get_gemini_dir().join("settings.json");
        if let Ok(content) = fs::read_to_string(settings_path) {
            if let Ok(settings) = serde_json::from_str::<Value>(&content) {
                if let Some(file_names) = settings.pointer("/context/fileName") {
                    match file_names {
                        Value::String(name) => {
                            if safe_context_filename(name) {
                                names.insert(name.clone());
                            }
                        }
                        Value::Array(values) => {
                            for name in values.iter().filter_map(Value::as_str) {
                                if safe_context_filename(name) {
                                    names.insert(name.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    names
}

fn safe_context_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
}

fn claude_auto_memory_directory() -> Option<PathBuf> {
    let settings_path = crate::config::get_claude_config_dir().join("settings.json");
    let content = fs::read_to_string(settings_path).ok()?;
    let settings = serde_json::from_str::<Value>(&content).ok()?;
    let configured = settings.get("autoMemoryDirectory")?.as_str()?.trim();
    let path = configured
        .strip_prefix("~/")
        .map(|suffix| crate::config::get_home_dir().join(suffix))
        .unwrap_or_else(|| PathBuf::from(configured));
    path.is_absolute().then_some(path)
}

fn claude_managed_root() -> Option<PathBuf> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        return Some(PathBuf::from("/etc/claude-code"));
    }
    #[cfg(target_os = "macos")]
    {
        return Some(PathBuf::from("/Library/Application Support/ClaudeCode"));
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .map(|root| root.join("ClaudeCode"));
    }
    #[allow(unreachable_code)]
    None
}

fn opencode_instruction_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();
    for config_path in [
        root.join("opencode.json"),
        root.join(".opencode/opencode.json"),
    ] {
        let Ok(content) = fs::read_to_string(&config_path) else {
            continue;
        };
        let Ok(config) = serde_json::from_str::<Value>(&content) else {
            continue;
        };
        let Some(values) = config.get("instructions").and_then(Value::as_array) else {
            continue;
        };
        for value in values.iter().filter_map(Value::as_str) {
            let value = value.trim().replace('\\', "/");
            if value.is_empty()
                || value.starts_with("http://")
                || value.starts_with("https://")
                || Path::new(&value).is_absolute()
                || Path::new(&value)
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                continue;
            }
            patterns.push(value);
        }
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

fn project_roots() -> BTreeMap<String, Vec<PathBuf>> {
    let mut roots = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for session in crate::session_manager::scan_sessions() {
        let Some(project_dir) = session.project_dir else {
            continue;
        };
        let path = PathBuf::from(project_dir);
        if !path.is_absolute() || !path.is_dir() {
            continue;
        }
        let Ok(canonical) = path.canonicalize() else {
            continue;
        };
        roots
            .entry(session.provider_id)
            .or_default()
            .insert(canonical);
    }
    roots
        .into_iter()
        .map(|(provider, paths)| {
            let mut ordered = paths.into_iter().collect::<Vec<_>>();
            ordered.sort_by_key(|path| path.components().count());
            let mut collapsed = Vec::<PathBuf>::new();
            for path in ordered {
                if !collapsed.iter().any(|root| path.starts_with(root)) {
                    collapsed.push(path);
                }
            }
            (provider, collapsed)
        })
        .collect()
}

fn scan_root(
    spec: &RootSpec,
    progress: &mut ProviderProgress,
    seen_ids: &mut HashSet<String>,
) -> Result<(Vec<ScannedAgentMemory>, String), String> {
    if !spec.root.exists() {
        // An absent optional source is a complete empty snapshot. This lets a
        // previously removed root produce tombstones without treating a normal
        // first-run installation as an error.
        return Ok((Vec::new(), digest_path_identity(&spec.provider, &spec.root)));
    }
    let metadata = fs::symlink_metadata(&spec.root)
        .map_err(|error| format!("检查 {} 记忆根目录失败: {error}", spec.provider))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} 记忆根目录不是安全的普通目录", spec.provider));
    }
    let canonical_root = spec
        .root
        .canonicalize()
        .map_err(|error| format!("解析 {} 记忆根目录失败: {error}", spec.provider))?;
    let root_hash = digest_path_identity(&spec.provider, &canonical_root);
    let mut files = Vec::new();
    collect_candidate_files(spec, &canonical_root, &canonical_root, 0, &mut files)?;
    expand_imported_files(spec, &canonical_root, &mut files)?;
    files.sort();
    files.dedup();

    let mut memories = Vec::new();
    for path in files {
        if progress.bytes >= MAX_PROVIDER_BYTES {
            progress.skipped += 1;
            return Err(format!("{} 记忆扫描超过 64 MiB 安全上限", spec.provider));
        }
        if spec.provider == "codex"
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("memories_") && name.ends_with(".sqlite"))
        {
            let sqlite_memories = scan_codex_sqlite(spec, &canonical_root, &path, &root_hash)?;
            progress.bytes = progress.bytes.saturating_add(
                sqlite_memories
                    .iter()
                    .map(|memory| memory.size_bytes)
                    .sum::<u64>(),
            );
            for memory in sqlite_memories {
                if seen_ids.insert(memory.id.clone()) {
                    memories.push(memory);
                }
            }
            continue;
        }
        match read_memory_file(spec, &canonical_root, &path, &root_hash) {
            Ok(memory) => {
                if memory.content.trim().is_empty() {
                    progress.skipped += 1;
                    continue;
                }
                progress.bytes = progress.bytes.saturating_add(memory.size_bytes);
                if seen_ids.insert(memory.id.clone()) {
                    memories.push(memory);
                }
            }
            Err(error) => {
                progress.failed += 1;
                progress.errors.push(error.clone());
                return Err(error);
            }
        }
    }
    Ok((memories, root_hash))
}

fn expand_imported_files(
    spec: &RootSpec,
    canonical_root: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if !matches!(spec.provider.as_str(), "claude" | "gemini") {
        return Ok(());
    }
    let mut seen = files.iter().cloned().collect::<HashSet<_>>();
    let mut queue = files.clone();
    let mut index = 0usize;
    while index < queue.len() && index < 2_000 {
        let source = queue[index].clone();
        index += 1;
        let metadata = fs::metadata(&source)
            .map_err(|error| format!("检查 {} 导入记忆失败: {error}", spec.provider))?;
        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(&source) else {
            continue;
        };
        let content = crate::identity_manager::strip_managed_identity(&content);
        for line in content.lines() {
            let trimmed = line.trim();
            let Some(reference) = trimmed.strip_prefix('@').map(str::trim) else {
                continue;
            };
            let reference = reference
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|character| matches!(character, '`' | '"' | '\''));
            if reference.is_empty()
                || reference.starts_with("http://")
                || reference.starts_with("https://")
            {
                continue;
            }
            let candidate = source.parent().unwrap_or(canonical_root).join(reference);
            let Ok(canonical) = candidate.canonicalize() else {
                continue;
            };
            if !canonical.starts_with(canonical_root) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&canonical) else {
                continue;
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_FILE_BYTES
            {
                continue;
            }
            if seen.insert(canonical.clone()) {
                files.push(canonical.clone());
                queue.push(canonical);
            }
        }
    }
    Ok(())
}

fn collect_candidate_files(
    spec: &RootSpec,
    canonical_root: &Path,
    directory: &Path,
    depth: usize,
    output: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if depth > MAX_SCAN_DEPTH {
        return Ok(());
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("读取 {} 记忆目录失败: {error}", spec.provider))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("读取 {} 记忆条目失败: {error}", spec.provider))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("检查 {} 记忆条目失败: {error}", spec.provider))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if SKIPPED_DIRECTORIES.contains(&name) {
                continue;
            }
            if depth < spec.max_depth {
                collect_candidate_files(spec, canonical_root, &path, depth + 1, output)?;
            }
        } else if metadata.is_file() && is_candidate(spec, canonical_root, &path) {
            output.push(path);
        }
    }
    Ok(())
}

fn is_candidate(spec: &RootSpec, root: &Path, path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let relative = path.strip_prefix(root).unwrap_or(path);
    let components = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    match spec.provider.as_str() {
        "claude" => {
            matches!(name, "CLAUDE.md" | "CLAUDE.local.md" | "MEMORY.md")
                || (name.ends_with(".md")
                    && components
                        .iter()
                        .any(|part| *part == "rules" || *part == "memory"))
        }
        "codex" => {
            matches!(name, "AGENTS.md" | "AGENTS.override.md" | "default.rules")
                || (name.starts_with("memories_") && name.ends_with(".sqlite"))
        }
        "gemini" => spec.candidate_names.contains(name),
        "opencode" => {
            matches!(name, "AGENTS.md" | "CLAUDE.md" | "MEMORY.md")
                || spec.instruction_patterns.iter().any(|pattern| {
                    glob_matches(pattern, &relative.to_string_lossy().replace('\\', "/"))
                })
        }
        "openclaw" => {
            matches!(
                name,
                "AGENTS.md"
                    | "MEMORY.md"
                    | "USER.md"
                    | "SOUL.md"
                    | "IDENTITY.md"
                    | "TOOLS.md"
                    | "HEARTBEAT.md"
            ) || (name.ends_with(".md") && components.iter().any(|part| *part == "memory"))
        }
        "hermes" => matches!(name, "AGENTS.md" | "MEMORY.md" | "USER.md" | "SOUL.md"),
        _ => false,
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let mut expression = String::from("^");
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' if chars.get(index + 1) == Some(&'*') => {
                expression.push_str(".*");
                index += 2;
            }
            '*' => {
                expression.push_str("[^/]*");
                index += 1;
            }
            '?' => {
                expression.push_str("[^/]");
                index += 1;
            }
            character => {
                expression.push_str(&regex::escape(&character.to_string()));
                index += 1;
            }
        }
    }
    expression.push('$');
    regex::Regex::new(&expression).is_ok_and(|compiled| compiled.is_match(value))
}

fn read_memory_file(
    spec: &RootSpec,
    canonical_root: &Path,
    path: &Path,
    root_hash: &str,
) -> Result<ScannedAgentMemory, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("检查 {} 记忆文件失败: {error}", spec.provider))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} 记忆来源不是普通文件", spec.provider));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{} 记忆文件 {} 超过 2 MiB 安全上限",
            spec.provider,
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("unknown")
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("解析 {} 记忆文件失败: {error}", spec.provider))?;
    if !canonical.starts_with(canonical_root) {
        return Err(format!("{} 记忆文件越出允许根目录", spec.provider));
    }
    let content = fs::read_to_string(&canonical)
        .map_err(|error| format!("读取 {} 记忆文件失败: {error}", spec.provider))?;
    let content = crate::identity_manager::strip_managed_identity(&content);
    let relative = canonical.strip_prefix(canonical_root).unwrap_or(&canonical);
    let relative_display = relative.to_string_lossy().replace('\\', "/");
    let logical_path = if spec.display_root == "." {
        relative_display.clone()
    } else {
        format!(
            "{}/{}",
            spec.display_root.trim_end_matches('/'),
            relative_display
        )
    };
    let source_identity = format!("{}\u{1f}{}", canonical.display(), relative_display);
    let source_hash = digest(source_identity.as_bytes());
    let id =
        digest(format!("{}\u{1f}{}\u{1f}{}", spec.provider, spec.scope, source_hash).as_bytes());
    let source_modified_at = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_millis().min(i64::MAX as u128) as i64);
    Ok(ScannedAgentMemory {
        id,
        provider: spec.provider.clone(),
        scope: spec.scope.clone(),
        kind: memory_kind(path),
        title: first_title(&content).unwrap_or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("Agent memory")
                .to_string()
        }),
        path: logical_path,
        project_dir: spec.project_dir.clone(),
        source_path_hash: source_hash,
        scan_root_hash: root_hash.to_string(),
        content_hash: digest(content.as_bytes()),
        size_bytes: content.len() as u64,
        source_modified_at,
        content,
    })
}

fn scan_codex_sqlite(
    spec: &RootSpec,
    canonical_root: &Path,
    path: &Path,
    root_hash: &str,
) -> Result<Vec<ScannedAgentMemory>, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("解析 Codex 记忆数据库失败: {error}"))?;
    if !canonical.starts_with(canonical_root) {
        return Err("Codex 记忆数据库越出允许根目录".to_string());
    }
    let conn = Connection::open_with_flags(
        &canonical,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("打开 Codex 记忆数据库失败: {error}"))?;
    let exists: i64 = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='stage1_outputs')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("检查 Codex 记忆数据库失败: {error}"))?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT thread_id, source_updated_at, raw_memory, rollout_summary, generated_at
             FROM stage1_outputs ORDER BY source_updated_at ASC, thread_id ASC",
        )
        .map_err(|error| format!("准备 Codex 记忆查询失败: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| format!("读取 Codex 记忆数据库失败: {error}"))?;
    let mut memories = Vec::new();
    for row in rows {
        let (thread_id, source_updated_at, raw_memory, summary, generated_at) =
            row.map_err(|error| format!("解析 Codex 记忆记录失败: {error}"))?;
        let content = if summary.trim().is_empty() {
            raw_memory
        } else if raw_memory.trim().is_empty() {
            summary
        } else {
            format!("# Rollout summary\n\n{summary}\n\n# Raw memory\n\n{raw_memory}")
        };
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err("Codex 单条原生记忆超过 2 MiB 安全上限".to_string());
        }
        let source_hash = digest(format!("{}\u{1f}{thread_id}", canonical.display()).as_bytes());
        let id = digest(format!("codex\u{1f}native\u{1f}{source_hash}").as_bytes());
        memories.push(ScannedAgentMemory {
            id,
            provider: spec.provider.clone(),
            scope: "agent".to_string(),
            kind: "learned_memory".to_string(),
            title: first_title(&content).unwrap_or_else(|| "Codex rollout memory".to_string()),
            path: format!(
                "~/.codex/memories.sqlite/{}.md",
                &digest(thread_id.as_bytes())[..24]
            ),
            project_dir: None,
            source_path_hash: source_hash,
            scan_root_hash: root_hash.to_string(),
            content_hash: digest(content.as_bytes()),
            size_bytes: content.len() as u64,
            source_modified_at: Some(normalize_epoch_ms(source_updated_at.max(generated_at))),
            content,
        });
    }
    Ok(memories)
}

fn scan_plugin_memories(
    result: &mut AgentMemoryScan,
    progress: &mut BTreeMap<String, ProviderProgress>,
    seen_ids: &mut HashSet<String>,
) {
    for scan in crate::session_manager::providers::plugin::scan_memories() {
        let provider = scan.provider_id;
        let entry = progress.entry(provider.clone()).or_default();
        if let Some(error) = scan.error {
            entry.failed += 1;
            entry.errors.push(error.clone());
            result.errors.push(error);
            continue;
        }
        let root_hash = digest(format!("{provider}\u{1f}plugin").as_bytes());
        let mut complete = true;
        for item in scan.memories {
            match crate::session_manager::providers::plugin::load_memory(
                &provider,
                &item.source_ref,
            ) {
                Ok(content) if content.len() as u64 <= MAX_FILE_BYTES => {
                    let source_hash =
                        digest(format!("{provider}\u{1f}{}", item.source_ref).as_bytes());
                    let id = digest(
                        format!("{provider}\u{1f}{}\u{1f}{source_hash}", item.scope).as_bytes(),
                    );
                    if seen_ids.insert(id.clone()) {
                        entry.discovered += 1;
                        entry.bytes = entry.bytes.saturating_add(content.len() as u64);
                        result.memories.push(ScannedAgentMemory {
                            id,
                            provider: provider.clone(),
                            scope: item.scope,
                            kind: item.kind,
                            title: if item.title.trim().is_empty() {
                                first_title(&content).unwrap_or_else(|| "Plugin memory".to_string())
                            } else {
                                item.title
                            },
                            path: if item.path.trim().is_empty() {
                                "plugin-memory".to_string()
                            } else {
                                item.path
                            },
                            project_dir: item.project_dir,
                            source_path_hash: source_hash.clone(),
                            scan_root_hash: root_hash.clone(),
                            content_hash: digest(content.as_bytes()),
                            size_bytes: item.size_bytes.unwrap_or(content.len() as u64),
                            source_modified_at: item.modified_at,
                            content,
                        });
                    }
                }
                Ok(_) => {
                    complete = false;
                    entry.skipped += 1;
                    entry
                        .errors
                        .push("插件单条记忆超过 2 MiB 安全上限".to_string());
                }
                Err(error) => {
                    complete = false;
                    entry.failed += 1;
                    entry.errors.push(error.clone());
                    result.errors.push(error);
                }
            }
        }
        if complete {
            result.completed_roots.push(root_hash);
        }
    }
}

fn memory_kind(path: &Path) -> String {
    match path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "USER.md" => "user_profile",
        "SOUL.md" | "IDENTITY.md" => "identity",
        "MEMORY.md" => "learned_memory",
        "AGENTS.md" | "AGENTS.override.md" | "CLAUDE.md" | "CLAUDE.local.md" | "GEMINI.md"
        | "default.rules" => "instruction",
        _ => "memory_topic",
    }
    .to_string()
}

fn first_title(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix('#')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(160).collect())
    })
}

fn normalize_epoch_ms(value: i64) -> i64 {
    if value.abs() < 10_000_000_000 {
        value.saturating_mul(1000)
    } else {
        value
    }
}

fn digest_path_identity(provider: &str, path: &Path) -> String {
    digest(format!("{provider}\u{1f}{}", path.display()).as_bytes())
}

fn digest(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn recognizes_only_provider_memory_allowlist() {
        let spec = root("claude", "project", PathBuf::from("/tmp/project"), ".");
        assert!(is_candidate(
            &spec,
            Path::new("/tmp/project"),
            Path::new("/tmp/project/CLAUDE.md")
        ));
        assert!(is_candidate(
            &spec,
            Path::new("/tmp/project"),
            Path::new("/tmp/project/.claude/rules/api.md")
        ));
        assert!(!is_candidate(
            &spec,
            Path::new("/tmp/project"),
            Path::new("/tmp/project/.env")
        ));
    }

    #[test]
    fn generated_ids_do_not_expose_source_paths() {
        let value = digest_path_identity("codex", Path::new("/secret/project"));
        assert_eq!(value.len(), 64);
        assert!(!value.contains("secret"));
    }

    #[test]
    fn scans_allowlisted_files_and_local_memory_imports_only() {
        let temp = tempdir().unwrap();
        let project = temp.path();
        fs::create_dir_all(project.join("docs")).unwrap();
        fs::write(
            project.join("CLAUDE.md"),
            "# Project memory\n\n@docs/context.md\n",
        )
        .unwrap();
        fs::write(
            project.join("docs/context.md"),
            "# Imported context\n\nUse SQLite.",
        )
        .unwrap();
        fs::write(project.join(".env"), "API_TOKEN=must-not-be-read").unwrap();
        let spec = root("claude", "project", project.to_path_buf(), ".");
        let mut progress = ProviderProgress::default();
        let mut seen = HashSet::new();
        let (memories, _) = scan_root(&spec, &mut progress, &mut seen).unwrap();
        assert_eq!(memories.len(), 2);
        assert!(memories.iter().any(|memory| memory.path == "CLAUDE.md"));
        assert!(memories
            .iter()
            .any(|memory| memory.path == "docs/context.md"));
        assert!(memories
            .iter()
            .all(|memory| !memory.content.contains("must-not-be-read")));
    }

    #[test]
    fn incomplete_root_is_reported_instead_of_becoming_a_delete_snapshot() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("AGENTS.md"),
            vec![b'x'; (MAX_FILE_BYTES + 1) as usize],
        )
        .unwrap();
        let spec = root("codex", "project", temp.path().to_path_buf(), ".");
        let mut progress = ProviderProgress::default();
        let mut seen = HashSet::new();
        assert!(scan_root(&spec, &mut progress, &mut seen).is_err());
    }
}
