use crate::archive::ArchiveService;
use crate::database::Database;
use crate::services::{ProxyService, UsageCache};
use std::sync::Arc;

/// 全局应用状态
pub struct AppState {
    pub db: Arc<Database>,
    pub archive: Arc<ArchiveService>,
    pub proxy_service: ProxyService,
    pub usage_cache: Arc<UsageCache>,
}

impl AppState {
    /// 创建新的应用状态
    pub fn new(db: Arc<Database>) -> Self {
        let proxy_service = ProxyService::new(db.clone());
        let archive = proxy_service.archive_service();

        Self {
            db,
            archive,
            proxy_service,
            usage_cache: Arc::new(UsageCache::new()),
        }
    }
}
