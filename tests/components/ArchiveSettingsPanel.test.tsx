import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ArchiveSettingsPanel } from "@/components/settings/ArchiveSettingsPanel";
import type {
  ArchiveHealth,
  ArchiveInitializationResult,
  ArchiveLocalSnapshotSummary,
  ArchiveSettings,
  Settings,
} from "@/types";

const { archiveApiMock, settingsApiMock, toastMock } = vi.hoisted(() => ({
  archiveApiMock: {
    health: vi.fn(),
    localApiStatus: vi.fn(),
    initializeLocal: vi.fn(),
    triggerLocalHistoryImport: vi.fn(),
    revealLocalApiToken: vi.fn(),
    rotateLocalApiToken: vi.fn(),
    initialize: vi.fn(),
    listLocalSnapshots: vi.fn(),
    createLocalSnapshot: vi.fn(),
    restoreLocalSnapshot: vi.fn(),
    deleteLocalSnapshot: vi.fn(),
    testRedaction: vi.fn(),
  },
  settingsApiMock: {
    pickDirectory: vi.fn(),
  },
  toastMock: {
    success: vi.fn(),
    warning: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  archiveApi: archiveApiMock,
  settingsApi: settingsApiMock,
}));
vi.mock("sonner", () => ({ toast: toastMock }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (_key: string, options?: { defaultValue?: string }) =>
      options?.defaultValue ?? _key,
  }),
}));

const archive: ArchiveSettings = {
  enabled: false,
  oidc: {
    issuer: "",
    audience: "",
    jwksUrl: "",
    allowedAlgorithms: ["RS256"],
    nameClaim: "name",
    emailClaim: "email",
    organizationClaim: "organization",
  },
  redactionRules: [],
  localBackup: {
    enabled: true,
    minIntervalMinutes: 15,
    retainCount: 30,
    includeKey: true,
  },
  localHistory: {
    autoImportEnabled: false,
    memoryImportEnabled: true,
    apiEnabled: false,
    identityWriteEnabled: false,
    reconcileIntervalSeconds: 300,
  },
};

const localHealth: ArchiveHealth = {
  enabled: false,
  ready: false,
  keyConfigured: true,
  keySource: "managed_file",
  databaseOk: true,
  ftsOk: true,
  oidcConfigured: false,
  oidcOk: false,
  localBackupEnabled: true,
  localBackupOk: false,
  localBackupDirectory: "/var/lib/tokenmanager/archive-backups",
  localBackupWarning: "本地快照目录不可写",
  databaseSizeBytes: 4096,
  error: "OIDC 尚未配置",
};

const snapshot: ArchiveLocalSnapshotSummary = {
  id: "snapshot-20260719",
  createdAt: 1_768_000_000,
  databaseSizeBytes: 4096,
  totalSizeBytes: 8192,
  directory: "/var/lib/tokenmanager/archive-backups/snapshot-20260719",
  includesKey: true,
};

describe("ArchiveSettingsPanel one-click initialization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    archiveApiMock.health.mockResolvedValue(localHealth);
    archiveApiMock.localApiStatus.mockResolvedValue({
      enabled: false,
      url: "http://127.0.0.1:15722",
      tokenConfigured: false,
      autoImportEnabled: false,
      memoryImportEnabled: true,
      identityWriteEnabled: false,
      capabilities: ["conversations", "memories"],
      runtime: {
        running: false,
        lastImported: 0,
        lastSkipped: 0,
        lastFailed: 0,
      },
      memoryRuntime: {
        running: false,
        lastImported: 0,
        lastSkipped: 0,
        lastDeleted: 0,
        lastFailed: 0,
        providers: [],
      },
      adapters: [],
    });
    archiveApiMock.listLocalSnapshots.mockResolvedValue([]);
    archiveApiMock.createLocalSnapshot.mockResolvedValue(snapshot);
    archiveApiMock.restoreLocalSnapshot.mockResolvedValue(undefined);
    archiveApiMock.deleteLocalSnapshot.mockResolvedValue(undefined);
  });

  it("applies the backend result and presents pending requirements without exposing a key", async () => {
    const result: ArchiveInitializationResult = {
      keyCreated: true,
      keySource: "managed_file",
      databaseCreated: true,
      enabled: false,
      pendingRequirements: ["配置 OIDC / JWKS"],
      warnings: ["本地快照目录不可写；归档仍可继续使用"],
      health: localHealth,
      archiveSettings: archive,
    };
    archiveApiMock.initialize.mockResolvedValue(result);
    const onSettingsApplied = vi.fn();

    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={vi.fn()}
        onSettingsApplied={onSettingsApplied}
      />,
    );

    const initializeButton = await screen.findByRole("button", {
      name: "一键初始化",
    });
    expect(initializeButton).toBeEnabled();
    fireEvent.click(initializeButton);

    await waitFor(() => {
      expect(archiveApiMock.initialize).toHaveBeenCalledWith(archive);
    });
    expect(onSettingsApplied).toHaveBeenCalledWith(archive);
    expect(
      await screen.findByText("本机安全初始化已完成，归档暂未启用"),
    ).toBeInTheDocument();
    expect(screen.getByText("配置 OIDC / JWKS")).toBeInTheDocument();
    expect(
      screen.getByText("本地快照目录不可写；归档仍可继续使用"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/密钥不会写入设置、日志或导出/),
    ).toBeInTheDocument();
    expect(toastMock.warning).toHaveBeenCalledTimes(1);
  });

  it("selects and saves a local-only snapshot directory", async () => {
    settingsApiMock.pickDirectory.mockResolvedValue("/data/private-archive");
    const onAutoSave = vi.fn().mockResolvedValue(true);

    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={onAutoSave}
        onSettingsApplied={vi.fn()}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "选择目录" }));
    await waitFor(() => {
      expect(screen.getByLabelText("本地快照目录")).toHaveValue(
        "/data/private-archive",
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "保存快照设置" }));
    await waitFor(() => {
      expect(onAutoSave).toHaveBeenCalledWith({
        archive: {
          ...archive,
          localBackup: {
            ...archive.localBackup,
            directory: "/data/private-archive",
          },
        },
      });
    });
  });

  it("creates, restores, and permanently deletes local snapshots with confirmation", async () => {
    archiveApiMock.listLocalSnapshots.mockResolvedValue([snapshot]);

    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={vi.fn()}
        onSettingsApplied={vi.fn()}
      />,
    );

    expect(await screen.findByText(snapshot.directory)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "立即创建" }));
    await waitFor(() => {
      expect(archiveApiMock.createLocalSnapshot).toHaveBeenCalledTimes(1);
    });

    fireEvent.click(screen.getByRole("button", { name: "恢复" }));
    expect(await screen.findByText("确认恢复本地归档")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "确认恢复" }));
    await waitFor(() => {
      expect(archiveApiMock.restoreLocalSnapshot).toHaveBeenCalledWith(
        snapshot.id,
      );
    });

    fireEvent.click(
      screen.getByRole("button", { name: `删除快照 ${snapshot.id}` }),
    );
    expect(await screen.findByText("永久删除本地快照")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "永久删除" }));
    await waitFor(() => {
      expect(archiveApiMock.deleteLocalSnapshot).toHaveBeenCalledWith(
        snapshot.id,
      );
    });
  });

  it("persists the visible key-inclusion choice before creating a snapshot", async () => {
    const onAutoSave = vi.fn().mockResolvedValue(true);
    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={onAutoSave}
        onSettingsApplied={vi.fn()}
      />,
    );

    fireEvent.click(
      await screen.findByRole("switch", { name: "快照包含恢复密钥" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "立即创建" }));

    await waitFor(() => {
      expect(onAutoSave).toHaveBeenCalledWith({
        archive: {
          ...archive,
          localBackup: { ...archive.localBackup, includeKey: false },
        },
      });
      expect(archiveApiMock.createLocalSnapshot).toHaveBeenCalledTimes(1);
    });
  });

  it("initializes the local archive before enabling incremental Agent history", async () => {
    archiveApiMock.initializeLocal.mockResolvedValue(true);
    archiveApiMock.triggerLocalHistoryImport.mockResolvedValue(true);
    const onAutoSave = vi.fn().mockResolvedValue(true);
    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={onAutoSave}
        onSettingsApplied={vi.fn()}
      />,
    );

    fireEvent.click(
      await screen.findByRole("switch", {
        name: "启用本机会话自动增量归档",
      }),
    );

    await waitFor(() => {
      expect(archiveApiMock.initializeLocal).toHaveBeenCalledTimes(1);
      expect(archiveApiMock.triggerLocalHistoryImport).toHaveBeenCalledTimes(1);
      expect(onAutoSave).toHaveBeenCalledWith({
        archive: {
          ...archive,
          localHistory: {
            ...archive.localHistory,
            autoImportEnabled: true,
          },
        },
      });
    });
  });

  it("enables the loopback API when identity writing is allowed", async () => {
    archiveApiMock.initializeLocal.mockResolvedValue(true);
    archiveApiMock.triggerLocalHistoryImport.mockResolvedValue(true);
    const onAutoSave = vi.fn().mockResolvedValue(true);
    render(
      <ArchiveSettingsPanel
        settings={{ archive } as Settings}
        onAutoSave={onAutoSave}
        onSettingsApplied={vi.fn()}
      />,
    );

    fireEvent.click(
      await screen.findByRole("switch", {
        name: "允许个人记忆库写入统一身份",
      }),
    );

    await waitFor(() => {
      expect(onAutoSave).toHaveBeenCalledWith({
        archive: {
          ...archive,
          localHistory: {
            ...archive.localHistory,
            apiEnabled: true,
            identityWriteEnabled: true,
          },
        },
      });
    });
  });
});
