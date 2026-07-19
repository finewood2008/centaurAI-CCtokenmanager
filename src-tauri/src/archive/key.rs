use base64::Engine;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const ARCHIVE_KEY_ENV: &str = "TOKEN_MANAGER_ARCHIVE_KEY";

const SECRETS_DIRECTORY: &str = "secrets";
const MANAGED_KEY_FILE: &str = "conversation-archive.key";
const ARCHIVE_DATABASE_FILE: &str = "conversation-archive.db";
const MAX_ENCODED_KEY_BYTES: u64 = 512;

static KEY_INITIALIZATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveKeySource {
    Environment,
    ManagedFile,
}

impl ArchiveKeySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::ManagedFile => "managed_file",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyInitialization {
    pub(crate) source: ArchiveKeySource,
    pub(crate) created: bool,
}

/// Load the deployment-provided key or the locally managed key. An explicitly
/// configured environment variable always wins, including when it is invalid:
/// silently falling back in that case could open or create a different archive.
pub(crate) fn load_archive_key() -> Result<[u8; 32], String> {
    load_archive_key_in(&crate::config::get_app_config_dir())
}

pub(crate) fn archive_key_configured() -> bool {
    load_archive_key().is_ok()
}

pub(crate) fn archive_key_source() -> Result<ArchiveKeySource, String> {
    archive_key_source_in(&crate::config::get_app_config_dir())
}

/// Ensure a key exists without ever returning its bytes to the caller. This is
/// idempotent and uses an atomic no-clobber publish for cross-process races.
pub(crate) fn initialize_archive_key() -> Result<KeyInitialization, String> {
    initialize_archive_key_in(&crate::config::get_app_config_dir())
}

fn load_archive_key_in(config_dir: &Path) -> Result<[u8; 32], String> {
    if let Some(key) = load_environment_key()? {
        return Ok(key);
    }
    load_managed_key(config_dir)?.ok_or_else(|| {
        format!(
            "未配置 {ARCHIVE_KEY_ENV}，且未找到受保护的归档密钥文件 {}",
            managed_archive_key_path_in(config_dir).display()
        )
    })
}

fn archive_key_source_in(config_dir: &Path) -> Result<ArchiveKeySource, String> {
    if load_environment_key()?.is_some() {
        return Ok(ArchiveKeySource::Environment);
    }
    if load_managed_key(config_dir)?.is_some() {
        return Ok(ArchiveKeySource::ManagedFile);
    }
    Err(format!(
        "未配置 {ARCHIVE_KEY_ENV}，且未找到受保护的归档密钥文件 {}",
        managed_archive_key_path_in(config_dir).display()
    ))
}

fn initialize_archive_key_in(config_dir: &Path) -> Result<KeyInitialization, String> {
    let _guard = KEY_INITIALIZATION_LOCK
        .lock()
        .map_err(|_| "归档密钥初始化锁已损坏".to_string())?;

    if load_environment_key()?.is_some() {
        return Ok(KeyInitialization {
            source: ArchiveKeySource::Environment,
            created: false,
        });
    }
    if load_managed_key(config_dir)?.is_some() {
        return Ok(KeyInitialization {
            source: ArchiveKeySource::ManagedFile,
            created: false,
        });
    }

    let database_path = config_dir.join(ARCHIVE_DATABASE_FILE);
    if path_entry_exists(&database_path)? {
        return Err(format!(
            "检测到已有归档数据库 {}，但缺少对应密钥；为避免数据丢失，拒绝生成新密钥，请恢复原始 {ARCHIVE_KEY_ENV} 或密钥文件",
            database_path.display()
        ));
    }

    ensure_secrets_directory(config_dir)?;

    // Recheck after creating/validating the directory in case another process
    // published the key while this process was waiting.
    if load_managed_key(config_dir)?.is_some() {
        return Ok(KeyInitialization {
            source: ArchiveKeySource::ManagedFile,
            created: false,
        });
    }

    let key_path = managed_archive_key_path_in(config_dir);
    let mut key = [0_u8; 32];
    getrandom::getrandom(&mut key).map_err(|_| "生成归档加密密钥失败".to_string())?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    let secrets_dir = key_path
        .parent()
        .ok_or_else(|| "归档密钥路径无效".to_string())?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".conversation-archive.key.")
        .tempfile_in(secrets_dir)
        .map_err(|error| format!("创建归档密钥临时文件失败: {error}"))?;
    set_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(encoded.as_bytes())
        .map_err(|error| format!("写入归档密钥失败: {error}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("同步归档密钥失败: {error}"))?;

    match temporary.persist_noclobber(&key_path) {
        Ok(_) => {
            sync_directory(secrets_dir)?;
            // Validate the published file through the same strict read path.
            load_managed_key(config_dir)?.ok_or_else(|| "归档密钥写入后无法读取".to_string())?;
            Ok(KeyInitialization {
                source: ArchiveKeySource::ManagedFile,
                created: true,
            })
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            load_managed_key(config_dir)?
                .ok_or_else(|| format!("归档密钥文件 {} 已存在但无法读取", key_path.display()))?;
            Ok(KeyInitialization {
                source: ArchiveKeySource::ManagedFile,
                created: false,
            })
        }
        Err(error) => Err(format!("保存归档密钥失败: {}", error.error)),
    }
}

fn load_environment_key() -> Result<Option<[u8; 32]>, String> {
    let Some(value) = std::env::var_os(ARCHIVE_KEY_ENV) else {
        return Ok(None);
    };
    let encoded = value
        .into_string()
        .map_err(|_| format!("{ARCHIVE_KEY_ENV} 必须是 UTF-8 Base64 字符串"))?;
    decode_key(encoded.trim(), ARCHIVE_KEY_ENV).map(Some)
}

fn load_managed_key(config_dir: &Path) -> Result<Option<[u8; 32]>, String> {
    let secrets_dir = config_dir.join(SECRETS_DIRECTORY);
    let Some(directory_metadata) = symlink_metadata_if_present(&secrets_dir)? else {
        return Ok(None);
    };
    validate_secrets_directory(&secrets_dir, &directory_metadata)?;

    let key_path = managed_archive_key_path_in(config_dir);
    let Some(path_metadata) = symlink_metadata_if_present(&key_path)? else {
        return Ok(None);
    };
    validate_key_file(&key_path, &path_metadata)?;

    let mut file = OpenOptions::new()
        .read(true)
        .open(&key_path)
        .map_err(|error| format!("打开归档密钥文件失败: {error}"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("读取归档密钥文件元数据失败: {error}"))?;
    validate_key_file(&key_path, &opened_metadata)?;
    reject_replaced_file(&key_path, &path_metadata, &opened_metadata)?;

    if opened_metadata.len() > MAX_ENCODED_KEY_BYTES {
        return Err(format!("归档密钥文件 {} 过大", key_path.display()));
    }
    let mut encoded = Vec::new();
    Read::take(&mut file, MAX_ENCODED_KEY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| format!("读取归档密钥文件失败: {error}"))?;
    if encoded.len() as u64 > MAX_ENCODED_KEY_BYTES {
        return Err(format!("归档密钥文件 {} 过大", key_path.display()));
    }
    let encoded = std::str::from_utf8(&encoded)
        .map_err(|_| format!("归档密钥文件 {} 必须是 UTF-8 Base64", key_path.display()))?;
    decode_key(encoded.trim(), &key_path.display().to_string()).map(Some)
}

fn decode_key(encoded: &str, source: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| format!("{source} 必须是 Base64 编码"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{source} 解码后必须恰好为 32 字节"))
}

fn managed_archive_key_path_in(config_dir: &Path) -> PathBuf {
    config_dir.join(SECRETS_DIRECTORY).join(MANAGED_KEY_FILE)
}

fn ensure_secrets_directory(config_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(config_dir)
        .map_err(|error| format!("创建应用配置目录失败: {error}"))?;
    let secrets_dir = config_dir.join(SECRETS_DIRECTORY);
    match symlink_metadata_if_present(&secrets_dir)? {
        Some(metadata) => validate_secrets_directory(&secrets_dir, &metadata),
        None => create_secrets_directory(&secrets_dir),
    }
}

#[cfg(unix)]
fn create_secrets_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("设置归档密钥目录权限失败: {error}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("创建归档密钥目录失败: {error}")),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("读取归档密钥目录元数据失败: {error}"))?;
    validate_secrets_directory(path, &metadata)
}

#[cfg(not(unix))]
fn create_secrets_directory(path: &Path) -> Result<(), String> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("创建归档密钥目录失败: {error}")),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("读取归档密钥目录元数据失败: {error}"))?;
    validate_secrets_directory(path, &metadata)
}

fn validate_secrets_directory(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!("归档密钥目录 {} 不得是符号链接", path.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("归档密钥目录 {} 不是目录", path.display()));
    }
    validate_directory_permissions(path, metadata)
}

fn validate_key_file(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!("归档密钥文件 {} 不得是符号链接", path.display()));
    }
    if !metadata.is_file() {
        return Err(format!("归档密钥文件 {} 不是普通文件", path.display()));
    }
    validate_file_permissions(path, metadata)
}

#[cfg(unix)]
fn validate_directory_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "归档密钥目录 {} 权限必须为 0700，当前为 {mode:04o}",
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
            "归档密钥文件 {} 权限必须为 0600，当前为 {mode:04o}",
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
fn set_file_permissions(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置归档密钥文件 {} 权限失败: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn reject_replaced_file(
    path: &Path,
    path_metadata: &std::fs::Metadata,
    opened_metadata: &std::fs::Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(format!(
            "归档密钥文件 {} 在读取期间已被替换，请重试",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_replaced_file(
    _path: &Path,
    _path_metadata: &std::fs::Metadata,
    _opened_metadata: &std::fs::Metadata,
) -> Result<(), String> {
    Ok(())
}

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    symlink_metadata_if_present(path).map(|metadata| metadata.is_some())
}

fn symlink_metadata_if_present(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 {} 元数据失败: {error}", path.display())),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("同步归档密钥目录失败: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::OsString;
    use tempfile::tempdir;

    struct EnvironmentGuard(Option<OsString>);

    impl EnvironmentGuard {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var_os(ARCHIVE_KEY_ENV);
            match value {
                Some(value) => std::env::set_var(ARCHIVE_KEY_ENV, value),
                None => std::env::remove_var(ARCHIVE_KEY_ENV),
            }
            Self(previous)
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var(ARCHIVE_KEY_ENV, value),
                None => std::env::remove_var(ARCHIVE_KEY_ENV),
            }
        }
    }

    fn encoded_key(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn write_managed_key(config_dir: &Path, byte: u8) {
        ensure_secrets_directory(config_dir).unwrap();
        let path = managed_archive_key_path_in(config_dir);
        std::fs::write(&path, encoded_key(byte)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    #[serial]
    fn environment_key_takes_precedence_over_managed_file() {
        let _environment = EnvironmentGuard::set(Some(&encoded_key(7)));
        let temp = tempdir().unwrap();
        write_managed_key(temp.path(), 8);

        assert_eq!(load_archive_key_in(temp.path()).unwrap(), [7; 32]);
        assert_eq!(
            archive_key_source_in(temp.path()).unwrap(),
            ArchiveKeySource::Environment
        );
        assert_eq!(ArchiveKeySource::Environment.as_str(), "environment");
        let initialized = initialize_archive_key_in(temp.path()).unwrap();
        assert_eq!(initialized.source, ArchiveKeySource::Environment);
        assert!(!initialized.created);
    }

    #[test]
    #[serial]
    fn invalid_environment_key_never_falls_back() {
        let _environment = EnvironmentGuard::set(Some("not-base64"));
        let temp = tempdir().unwrap();
        write_managed_key(temp.path(), 8);

        assert!(load_archive_key_in(temp.path()).is_err());
        assert!(archive_key_source_in(temp.path()).is_err());
        assert!(initialize_archive_key_in(temp.path()).is_err());
    }

    #[test]
    #[serial]
    fn initializes_managed_key_once_with_restrictive_permissions() {
        let _environment = EnvironmentGuard::set(None);
        let temp = tempdir().unwrap();

        let first = initialize_archive_key_in(temp.path()).unwrap();
        let first_key = load_archive_key_in(temp.path()).unwrap();
        let second = initialize_archive_key_in(temp.path()).unwrap();
        let second_key = load_archive_key_in(temp.path()).unwrap();

        assert_eq!(first.source, ArchiveKeySource::ManagedFile);
        assert!(first.created);
        assert_eq!(second.source, ArchiveKeySource::ManagedFile);
        assert!(!second.created);
        assert_eq!(first_key, second_key);
        let stored = std::fs::read_to_string(managed_archive_key_path_in(temp.path())).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(stored)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            archive_key_source_in(temp.path()).unwrap(),
            ArchiveKeySource::ManagedFile
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory_mode = std::fs::metadata(temp.path().join(SECRETS_DIRECTORY))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(managed_archive_key_path_in(temp.path()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    #[serial]
    fn refuses_to_replace_missing_key_for_existing_database() {
        let _environment = EnvironmentGuard::set(None);
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join(ARCHIVE_DATABASE_FILE),
            b"encrypted archive",
        )
        .unwrap();

        let error = initialize_archive_key_in(temp.path()).unwrap_err();
        assert!(error.contains("已有归档数据库"));
        assert!(!managed_archive_key_path_in(temp.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn rejects_symlinks_non_regular_files_and_unsafe_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let _environment = EnvironmentGuard::set(None);
        let temp = tempdir().unwrap();
        ensure_secrets_directory(temp.path()).unwrap();
        let key_path = managed_archive_key_path_in(temp.path());
        let target = temp.path().join("target-key");
        std::fs::write(&target, encoded_key(3)).unwrap();
        symlink(&target, &key_path).unwrap();
        assert!(load_archive_key_in(temp.path())
            .unwrap_err()
            .contains("符号链接"));

        std::fs::remove_file(&key_path).unwrap();
        std::fs::create_dir(&key_path).unwrap();
        assert!(load_archive_key_in(temp.path())
            .unwrap_err()
            .contains("不是普通文件"));

        std::fs::remove_dir(&key_path).unwrap();
        std::fs::write(&key_path, encoded_key(3)).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_archive_key_in(temp.path())
            .unwrap_err()
            .contains("权限必须为 0600"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn rejects_symlinked_and_unsafe_secrets_directories() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let _environment = EnvironmentGuard::set(None);
        let temp = tempdir().unwrap();
        let external = temp.path().join("external-secrets");
        std::fs::create_dir(&external).unwrap();
        symlink(&external, temp.path().join(SECRETS_DIRECTORY)).unwrap();
        assert!(initialize_archive_key_in(temp.path())
            .unwrap_err()
            .contains("符号链接"));

        std::fs::remove_file(temp.path().join(SECRETS_DIRECTORY)).unwrap();
        std::fs::create_dir(temp.path().join(SECRETS_DIRECTORY)).unwrap();
        std::fs::set_permissions(
            temp.path().join(SECRETS_DIRECTORY),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(initialize_archive_key_in(temp.path())
            .unwrap_err()
            .contains("权限必须为 0700"));
    }

    #[test]
    #[serial]
    fn concurrent_initialization_publishes_only_one_key() {
        let _environment = EnvironmentGuard::set(None);
        let temp = tempdir().unwrap();
        let config_dir = std::sync::Arc::new(temp.path().to_path_buf());
        let threads = (0..8)
            .map(|_| {
                let config_dir = config_dir.clone();
                std::thread::spawn(move || initialize_archive_key_in(&config_dir).unwrap())
            })
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.created).count(), 1);
        assert!(results
            .iter()
            .all(|result| result.source == ArchiveKeySource::ManagedFile));
        assert!(load_archive_key_in(temp.path()).is_ok());
    }
}
