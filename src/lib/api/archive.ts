import { invoke } from "@tauri-apps/api/core";
import type {
  ArchiveHealth,
  ArchiveInitializationResult,
  ArchiveLocalSnapshotSummary,
  ArchiveSearchFilters,
  ArchiveSearchPage,
  ArchiveSettings,
  ArchivedConversationDetail,
  HistoryImportPreview,
  HistoryImportResult,
  LocalConversationApiStatus,
} from "@/types";

export const archiveApi = {
  async initialize(
    archive: ArchiveSettings,
  ): Promise<ArchiveInitializationResult> {
    return await invoke("initialize_conversation_archive", { archive });
  },

  async health(): Promise<ArchiveHealth> {
    return await invoke("get_archive_health");
  },

  async initializeLocal(): Promise<boolean> {
    return await invoke("initialize_local_conversation_archive");
  },

  async triggerLocalHistoryImport(): Promise<boolean> {
    return await invoke("trigger_local_history_import");
  },

  async localApiStatus(): Promise<LocalConversationApiStatus> {
    return await invoke("get_local_conversation_api_status");
  },

  async revealLocalApiToken(): Promise<string> {
    return await invoke("reveal_local_conversation_api_token");
  },

  async rotateLocalApiToken(): Promise<string> {
    return await invoke("rotate_local_conversation_api_token");
  },

  async listLocalSnapshots(): Promise<ArchiveLocalSnapshotSummary[]> {
    return await invoke("list_archive_local_snapshots");
  },

  async createLocalSnapshot(): Promise<ArchiveLocalSnapshotSummary> {
    return await invoke("create_archive_local_snapshot");
  },

  async restoreLocalSnapshot(id: string): Promise<void> {
    await invoke("restore_archive_local_snapshot", { id });
  },

  async deleteLocalSnapshot(id: string): Promise<void> {
    await invoke("delete_archive_local_snapshot", { id });
  },

  async previewImport(): Promise<HistoryImportPreview> {
    return await invoke("preview_local_history_import");
  },

  async importLocalHistory(): Promise<HistoryImportResult> {
    return await invoke("import_local_history");
  },

  async search(options: {
    query: string;
    filters: ArchiveSearchFilters;
    cursor?: string;
    pageSize?: number;
  }): Promise<ArchiveSearchPage> {
    return await invoke("search_archived_conversations", {
      query: options.query,
      filters: options.filters,
      cursor: options.cursor ?? null,
      pageSize: options.pageSize ?? 50,
    });
  },

  async get(id: string): Promise<ArchivedConversationDetail> {
    return await invoke("get_archived_conversation", { id });
  },

  async export(
    ids: string[],
    format: "json" | "markdown",
    targetPath: string,
  ): Promise<boolean> {
    return await invoke("export_archived_conversations", {
      ids,
      format,
      targetPath,
    });
  },

  async delete(ids: string[]): Promise<{ deleted: number }> {
    return await invoke("delete_archived_conversations", { ids });
  },

  async testRedaction(input: string): Promise<string> {
    return await invoke("test_archive_redaction", { input });
  },
};
