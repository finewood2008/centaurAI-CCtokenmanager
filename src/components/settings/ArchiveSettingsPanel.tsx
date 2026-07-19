import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import {
  CheckCircle2,
  Copy,
  Database,
  FolderOpen,
  HardDrive,
  KeyRound,
  Loader2,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  Sparkles,
  Plug,
  Trash2,
} from "lucide-react";
import { archiveApi, settingsApi } from "@/lib/api";
import type {
  ArchiveHealth,
  ArchiveInitializationResult,
  ArchiveLocalSnapshotSummary,
  ArchiveRedactionRule,
  ArchiveSettings,
  LocalConversationApiStatus,
  Settings,
} from "@/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { extractErrorMessage } from "@/utils/errorUtils";

const defaultArchiveSettings: ArchiveSettings = {
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

function normalizeArchiveSettings(
  archive: ArchiveSettings | undefined,
): ArchiveSettings {
  return {
    ...defaultArchiveSettings,
    ...archive,
    oidc: {
      ...defaultArchiveSettings.oidc,
      ...archive?.oidc,
    },
    redactionRules: archive?.redactionRules ?? [],
    localBackup: {
      ...defaultArchiveSettings.localBackup,
      ...archive?.localBackup,
    },
    localHistory: {
      ...defaultArchiveSettings.localHistory,
      ...archive?.localHistory,
    },
  };
}

function formatBytes(value: number) {
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatTimestamp(value?: number) {
  if (!value) return "—";
  const milliseconds = value < 10_000_000_000 ? value * 1000 : value;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function rulesToText(rules: ArchiveRedactionRule[]) {
  return rules
    .filter((rule) => rule.enabled)
    .map((rule) => `${rule.name}::${rule.pattern}`)
    .join("\n");
}

function textToRules(value: string): ArchiveRedactionRule[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const separator = line.indexOf("::");
      return separator > 0
        ? {
            name: line.slice(0, separator).trim(),
            pattern: line.slice(separator + 2).trim(),
            enabled: true,
          }
        : { name: `RULE_${index + 1}`, pattern: line, enabled: true };
    });
}

interface ArchiveSettingsPanelProps {
  settings: Settings;
  onAutoSave: (updates: { archive: ArchiveSettings }) => Promise<unknown>;
  onSettingsApplied: (archive: ArchiveSettings) => void;
}

export function ArchiveSettingsPanel({
  settings,
  onAutoSave,
  onSettingsApplied,
}: ArchiveSettingsPanelProps) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<ArchiveSettings>(
    normalizeArchiveSettings(settings.archive),
  );
  const [rulesText, setRulesText] = useState(
    rulesToText(settings.archive?.redactionRules ?? []),
  );
  const [health, setHealth] = useState<ArchiveHealth | null>(null);
  const [initialization, setInitialization] =
    useState<ArchiveInitializationResult | null>(null);
  const [snapshots, setSnapshots] = useState<ArchiveLocalSnapshotSummary[]>([]);
  const [snapshotBusy, setSnapshotBusy] = useState(false);
  const [restoreSnapshot, setRestoreSnapshot] =
    useState<ArchiveLocalSnapshotSummary | null>(null);
  const [deleteSnapshot, setDeleteSnapshot] =
    useState<ArchiveLocalSnapshotSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [testInput, setTestInput] = useState("");
  const [testOutput, setTestOutput] = useState("");
  const [localApiStatus, setLocalApiStatus] =
    useState<LocalConversationApiStatus | null>(null);

  useEffect(() => {
    const archive = normalizeArchiveSettings(settings.archive);
    setDraft(archive);
    setRulesText(rulesToText(archive.redactionRules));
  }, [settings.archive]);

  const effectiveDraft = useMemo<ArchiveSettings>(
    () => ({ ...draft, redactionRules: textToRules(rulesText) }),
    [draft, rulesText],
  );

  const refreshHealth = async () => {
    setBusy(true);
    try {
      const next = await archiveApi.health();
      setHealth(next);
      return next;
    } catch (error) {
      toast.error(extractErrorMessage(error));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const refreshLocalApiStatus = async () => {
    try {
      const status = await archiveApi.localApiStatus();
      setLocalApiStatus(status);
      return status;
    } catch (error) {
      toast.error(extractErrorMessage(error));
      return null;
    }
  };

  const refreshSnapshots = async (showError = true) => {
    try {
      const next = await archiveApi.listLocalSnapshots();
      setSnapshots(next);
      return next;
    } catch (error) {
      if (showError) toast.error(extractErrorMessage(error));
      return null;
    }
  };

  useEffect(() => {
    void refreshHealth();
    void refreshSnapshots(false);
    void refreshLocalApiStatus();
    // Health is explicitly refreshed after saves; avoid OIDC traffic per keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveConfiguration = async (archive = effectiveDraft) => {
    setBusy(true);
    try {
      await onAutoSave({ archive });
      setDraft(archive);
      toast.success(
        t("archive.settingsSaved", { defaultValue: "归档配置已保存" }),
      );
      setHealth(await archiveApi.health());
      return true;
    } catch (error) {
      toast.error(extractErrorMessage(error));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const initializeArchive = async () => {
    setBusy(true);
    setInitialization(null);
    try {
      const result = await archiveApi.initialize(effectiveDraft);
      const appliedSettings = normalizeArchiveSettings(result.archiveSettings);
      setInitialization(result);
      setHealth(result.health);
      setDraft(appliedSettings);
      setRulesText(rulesToText(appliedSettings.redactionRules));
      onSettingsApplied(appliedSettings);
      await refreshSnapshots(false);

      if (result.enabled) {
        toast.success("归档已完成初始化并启用");
      } else {
        toast.warning("本机初始化已完成，请处理剩余配置后再次初始化");
      }
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const toggleEnabled = async (enabled: boolean) => {
    if (!enabled) {
      await saveConfiguration({ ...effectiveDraft, enabled: false });
      return;
    }
    // Persist the non-secret OIDC/redaction configuration first, then require
    // a live key/database/JWKS health check before enabling capture.
    const disabledDraft = { ...effectiveDraft, enabled: false };
    if (!(await saveConfiguration(disabledDraft))) return;
    setBusy(true);
    try {
      const nextHealth = await archiveApi.health();
      setHealth(nextHealth);
      if (!nextHealth.ready) {
        toast.error(
          nextHealth.error ||
            t("archive.notReady", {
              defaultValue: "归档健康检查未通过，不能启用",
            }),
        );
        return;
      }
      const enabledDraft = { ...disabledDraft, enabled: true };
      await onAutoSave({ archive: enabledDraft });
      const appliedHealth = await archiveApi.health();
      setHealth(appliedHealth);
      if (!appliedHealth.enabled) {
        throw new Error("后端未接受归档启用配置，请检查健康状态");
      }
      setDraft(enabledDraft);
      toast.success(
        t("archive.enabled", { defaultValue: "团队对话归档已启用" }),
      );
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const runRedactionTest = async () => {
    setBusy(true);
    try {
      // Save rules while capture remains in its current state so the test uses
      // exactly the configuration shown in the editor.
      await onAutoSave({ archive: effectiveDraft });
      setTestOutput(await archiveApi.testRedaction(testInput));
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const updateOidc = (
    key: keyof ArchiveSettings["oidc"],
    value: string | string[],
  ) => {
    setDraft((current) => ({
      ...current,
      oidc: { ...current.oidc, [key]: value },
    }));
  };

  const updateLocalBackup = <K extends keyof ArchiveSettings["localBackup"]>(
    key: K,
    value: ArchiveSettings["localBackup"][K],
  ) => {
    setDraft((current) => ({
      ...current,
      localBackup: { ...current.localBackup, [key]: value },
    }));
  };

  const saveLocalHistory = async (
    updates: Partial<ArchiveSettings["localHistory"]>,
  ) => {
    const localHistory = { ...effectiveDraft.localHistory, ...updates };
    setBusy(true);
    try {
      if (updates.apiEnabled === false) {
        localHistory.identityWriteEnabled = false;
      }
      if (updates.identityWriteEnabled === true) {
        localHistory.apiEnabled = true;
      }
      if (
        localHistory.autoImportEnabled ||
        localHistory.memoryImportEnabled ||
        localHistory.apiEnabled ||
        localHistory.identityWriteEnabled
      ) {
        await archiveApi.initializeLocal();
      }
      const archive = { ...effectiveDraft, localHistory };
      await onAutoSave({ archive });
      setDraft(archive);
      if (localHistory.autoImportEnabled || localHistory.memoryImportEnabled) {
        await archiveApi.triggerLocalHistoryImport();
      }
      await Promise.all([refreshHealth(), refreshLocalApiStatus()]);
      toast.success("本机会话接入配置已保存");
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const copyLocalApiToken = async (rotate = false) => {
    setBusy(true);
    try {
      const token = rotate
        ? await archiveApi.rotateLocalApiToken()
        : await archiveApi.revealLocalApiToken();
      await navigator.clipboard.writeText(token);
      await refreshLocalApiStatus();
      toast.success(
        rotate ? "新令牌已复制，旧令牌已失效" : "本机 API 令牌已复制",
      );
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const pickLocalBackupDirectory = async () => {
    try {
      const selected = await settingsApi.pickDirectory(
        draft.localBackup.directory ?? health?.localBackupDirectory,
      );
      if (selected) updateLocalBackup("directory", selected);
    } catch (error) {
      toast.error(extractErrorMessage(error));
    }
  };

  const createLocalSnapshot = async () => {
    setSnapshotBusy(true);
    try {
      // A manual snapshot must reflect the options currently shown in the
      // panel (especially the sensitive "include recovery key" switch), not
      // an older persisted draft.
      if (!(await saveConfiguration())) return;
      await archiveApi.createLocalSnapshot();
      await Promise.all([refreshSnapshots(false), refreshHealth()]);
      toast.success("本地恢复快照已创建");
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setSnapshotBusy(false);
    }
  };

  const confirmRestoreSnapshot = async () => {
    if (!restoreSnapshot) return;
    setSnapshotBusy(true);
    try {
      await archiveApi.restoreLocalSnapshot(restoreSnapshot.id);
      setRestoreSnapshot(null);
      await Promise.all([refreshSnapshots(false), refreshHealth()]);
      toast.success("本地归档已从快照恢复");
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setSnapshotBusy(false);
    }
  };

  const confirmDeleteSnapshot = async () => {
    if (!deleteSnapshot) return;
    setSnapshotBusy(true);
    try {
      await archiveApi.deleteLocalSnapshot(deleteSnapshot.id);
      setDeleteSnapshot(null);
      await refreshSnapshots(false);
      toast.success("本地快照已永久删除");
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setSnapshotBusy(false);
    }
  };

  return (
    <div className="space-y-5 pb-6">
      <Alert variant={health?.ready ? "default" : "destructive"}>
        {health?.ready ? <CheckCircle2 /> : <ShieldAlert />}
        <AlertTitle>
          {health?.ready ? "归档健康检查通过" : "归档尚未就绪"}
        </AlertTitle>
        <AlertDescription>
          {health?.error ||
            "密钥、SQLCipher、FTS5 和 OIDC/JWKS 均正常；归档数据仅保存在本机。"}
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="text-lg">团队对话归档</CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              `/team` 强制 OIDC；本机代理无需 JWT，但启用后同样按本机身份归档。
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={draft.enabled ? "default" : "secondary"}>
              {draft.enabled ? "已启用" : "已关闭"}
            </Badge>
            <Switch
              checked={draft.enabled}
              disabled={busy}
              onCheckedChange={(checked) => void toggleEnabled(checked)}
              aria-label="启用团队对话归档"
            />
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3">
          <div className="col-span-2 flex items-center justify-between gap-4 rounded-lg border bg-muted/20 p-4">
            <div>
              <div className="text-sm font-medium">安全一键初始化</div>
              <p className="mt-1 text-xs text-muted-foreground">
                自动创建或复用归档密钥、初始化 SQLCipher 数据库，并检查 OIDC /
                JWKS；本地快照异常只告警，不阻止归档启用。
              </p>
            </div>
            <Button onClick={() => void initializeArchive()} disabled={busy}>
              {busy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Sparkles className="mr-2 h-4 w-4" />
              )}
              {busy ? "正在初始化…" : "一键初始化"}
            </Button>
          </div>
          {initialization ? (
            <div
              className={`col-span-2 rounded-lg border p-3 text-sm ${
                initialization.enabled
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "border-amber-500/40 bg-amber-500/5"
              }`}
              role="status"
            >
              <div className="font-medium">
                {initialization.enabled
                  ? "初始化完成，归档已启用"
                  : "本机安全初始化已完成，归档暂未启用"}
              </div>
              <div className="mt-1 text-xs text-muted-foreground">
                密钥：
                {initialization.keyCreated ? "已新建" : "已复用"}（
                {formatKeySource(initialization.keySource)}）；数据库：
                {initialization.databaseCreated ? "已创建" : "已复用"}。
              </div>
              {initialization.pendingRequirements.length > 0 ? (
                <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
                  {initialization.pendingRequirements.map((requirement) => (
                    <li key={requirement}>{requirement}</li>
                  ))}
                </ul>
              ) : null}
              {(initialization.warnings ?? []).length > 0 ? (
                <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-amber-700 dark:text-amber-300">
                  {(initialization.warnings ?? []).map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          {[
            ["归档密钥", health?.keyConfigured],
            ["SQLCipher 数据库", health?.databaseOk],
            ["FTS5 trigram", health?.ftsOk],
            ["OIDC / JWKS", health?.oidcOk],
          ].map(([label, ok]) => (
            <div
              key={String(label)}
              className="flex items-center justify-between rounded-lg border px-3 py-2 text-sm"
            >
              <span>{label}</span>
              <Badge variant={ok ? "secondary" : "destructive"}>
                {ok ? "正常" : "未就绪"}
              </Badge>
            </div>
          ))}
          <div className="flex items-center justify-between rounded-lg border px-3 py-2 text-sm">
            <span>数据库大小</span>
            <span>{health ? formatBytes(health.databaseSizeBytes) : "—"}</span>
          </div>
          <div className="col-span-2 flex justify-end">
            <Button
              variant="outline"
              onClick={() => void refreshHealth()}
              disabled={busy}
            >
              <RefreshCw
                className={busy ? "mr-2 h-4 w-4 animate-spin" : "mr-2 h-4 w-4"}
              />
              重新检查
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Plug className="h-5 w-5" />
            本地 Agent 对话与记忆接入
          </CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            自动归档本机 Agent 历史和长期记忆，并通过仅监听 127.0.0.1 的本机 API
            与半人马 AI 个人记忆库同步。该功能不需要 OIDC。
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <div className="text-sm font-medium">自动增量归档</div>
                <div className="text-xs text-muted-foreground">
                  文件变化触发，并每{" "}
                  {Math.round(draft.localHistory.reconcileIntervalSeconds / 60)}{" "}
                  分钟完整校准
                </div>
              </div>
              <Switch
                checked={draft.localHistory.autoImportEnabled}
                disabled={busy}
                onCheckedChange={(checked) =>
                  void saveLocalHistory({ autoImportEnabled: checked })
                }
                aria-label="启用本机会话自动增量归档"
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <div className="text-sm font-medium">自动抓取 Agent 记忆</div>
                <div className="text-xs text-muted-foreground">
                  全局、项目和 Agent 原生记忆白名单
                </div>
              </div>
              <Switch
                checked={draft.localHistory.memoryImportEnabled}
                disabled={busy}
                onCheckedChange={(checked) =>
                  void saveLocalHistory({ memoryImportEnabled: checked })
                }
                aria-label="启用 Agent 记忆自动抓取"
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <div className="text-sm font-medium">个人记忆本机 API</div>
                <div className="text-xs text-muted-foreground">
                  {localApiStatus?.url ?? "http://127.0.0.1:15722"}
                </div>
              </div>
              <Switch
                checked={draft.localHistory.apiEnabled}
                disabled={busy}
                onCheckedChange={(checked) =>
                  void saveLocalHistory({ apiEnabled: checked })
                }
                aria-label="启用个人记忆本机 API"
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <div className="text-sm font-medium">允许身份写入</div>
                <div className="text-xs text-muted-foreground">
                  将统一身份写入已检测 Agent 的托管区块
                </div>
              </div>
              <Switch
                checked={draft.localHistory.identityWriteEnabled}
                disabled={busy}
                onCheckedChange={(checked) =>
                  void saveLocalHistory({ identityWriteEnabled: checked })
                }
                aria-label="允许个人记忆库写入统一身份"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/20 p-3">
            <Badge
              variant={
                localApiStatus?.runtime.running ? "default" : "secondary"
              }
            >
              {localApiStatus?.runtime.running ? "正在同步" : "等待变化"}
            </Badge>
            <span className="text-xs text-muted-foreground">
              上次完成：
              {formatTimestamp(localApiStatus?.runtime.lastCompletedAt)} · 导入{" "}
              {localApiStatus?.runtime.lastImported ?? 0} · 失败{" "}
              {localApiStatus?.runtime.lastFailed ?? 0}
            </span>
            <span className="text-xs text-muted-foreground">
              记忆：导入 {localApiStatus?.memoryRuntime.lastImported ?? 0} ·
              删除 {localApiStatus?.memoryRuntime.lastDeleted ?? 0} · 失败{" "}
              {localApiStatus?.memoryRuntime.lastFailed ?? 0}
            </span>
            <span className="spacer" />
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !draft.localHistory.apiEnabled}
              onClick={() => void copyLocalApiToken(false)}
            >
              <Copy className="mr-2 h-4 w-4" />
              复制令牌
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !draft.localHistory.apiEnabled}
              onClick={() => void copyLocalApiToken(true)}
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              轮换令牌
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => void refreshLocalApiStatus()}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              刷新
            </Button>
          </div>

          {localApiStatus?.runtime.lastError ? (
            <Alert variant="destructive">
              <ShieldAlert />
              <AlertTitle>最近一次本机会话同步存在错误</AlertTitle>
              <AlertDescription>
                {localApiStatus.runtime.lastError}
              </AlertDescription>
            </Alert>
          ) : null}

          <div>
            <div className="mb-2 text-sm font-medium">会话适配器</div>
            <div className="grid grid-cols-2 gap-2">
              {(localApiStatus?.adapters ?? []).map((adapter) => (
                <div
                  key={adapter.id}
                  className="rounded-lg border px-3 py-2 text-sm"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span>{adapter.displayName}</span>
                    <Badge
                      variant={
                        adapter.error
                          ? "destructive"
                          : adapter.enabled
                            ? "secondary"
                            : "outline"
                      }
                    >
                      {adapter.kind === "builtin"
                        ? "内置"
                        : adapter.enabled
                          ? "插件"
                          : "已停用"}
                    </Badge>
                  </div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">
                    {adapter.error || adapter.capabilities.join(" · ")}
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              外部适配器清单放入应用配置目录的 session-adapters
              文件夹；适配器以版本化 JSON 协议提供 scan/load，并可选提供
              resume/delete。
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2 text-lg">
              <HardDrive className="h-5 w-5" />
              本地恢复快照
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              自动快照只写入本机目录，S3/WebDAV
              自动同步永不包含归档；仅可在云同步页逐次手动授权上传。 请勿选择
              OneDrive、iCloud、NAS 挂载目录或其他由操作系统/第三方同步的目录。
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Badge
              variant={
                !draft.localBackup.enabled
                  ? "outline"
                  : health?.localBackupOk
                    ? "secondary"
                    : "destructive"
              }
            >
              {!draft.localBackup.enabled
                ? "已关闭"
                : health?.localBackupOk
                  ? "正常"
                  : "需检查"}
            </Badge>
            <Switch
              checked={draft.localBackup.enabled}
              disabled={busy || snapshotBusy}
              onCheckedChange={(checked) =>
                updateLocalBackup("enabled", checked)
              }
              aria-label="启用本地自动快照"
            />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {health?.localBackupWarning ? (
            <Alert variant="destructive">
              <ShieldAlert />
              <AlertTitle>本地快照需要处理（不影响对话归档）</AlertTitle>
              <AlertDescription>{health.localBackupWarning}</AlertDescription>
            </Alert>
          ) : null}

          <div className="grid grid-cols-2 gap-4">
            <Field label="快照目录" className="col-span-2">
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={
                    draft.localBackup.directory ??
                    health?.localBackupDirectory ??
                    "使用应用默认本机目录"
                  }
                  className="font-mono text-xs"
                  aria-label="本地快照目录"
                />
                <Button
                  variant="outline"
                  onClick={() => void pickLocalBackupDirectory()}
                  disabled={busy || snapshotBusy}
                >
                  <FolderOpen className="mr-2 h-4 w-4" />
                  选择目录
                </Button>
              </div>
            </Field>
            <Field label="最短快照间隔（分钟）">
              <Input
                type="number"
                min={1}
                max={1440}
                value={draft.localBackup.minIntervalMinutes}
                onChange={(event) =>
                  updateLocalBackup(
                    "minIntervalMinutes",
                    Math.min(
                      1440,
                      Math.max(1, Number(event.target.value) || 1),
                    ),
                  )
                }
                aria-label="最短快照间隔"
              />
            </Field>
            <Field label="保留快照数量">
              <Input
                type="number"
                min={1}
                max={365}
                value={draft.localBackup.retainCount}
                onChange={(event) =>
                  updateLocalBackup(
                    "retainCount",
                    Math.min(365, Math.max(1, Number(event.target.value) || 1)),
                  )
                }
                aria-label="保留快照数量"
              />
            </Field>
          </div>

          <div className="flex items-center justify-between rounded-lg border px-3 py-2">
            <div>
              <div className="text-sm font-medium">快照包含恢复密钥</div>
              <div className="text-xs text-muted-foreground">
                默认开启；任何能读取快照目录的人都可以解密其中的归档。
              </div>
            </div>
            <Switch
              checked={draft.localBackup.includeKey}
              disabled={busy || snapshotBusy}
              onCheckedChange={(checked) =>
                updateLocalBackup("includeKey", checked)
              }
              aria-label="快照包含恢复密钥"
            />
          </div>

          <div className="flex items-center justify-between gap-3">
            <div className="text-xs text-muted-foreground">
              最近快照：{formatTimestamp(health?.lastLocalBackupAt)}
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => void saveConfiguration()}
                disabled={busy || snapshotBusy}
              >
                <Save className="mr-2 h-4 w-4" />
                保存快照设置
              </Button>
              <Button
                variant="outline"
                onClick={() => void refreshSnapshots()}
                disabled={snapshotBusy}
              >
                <RefreshCw
                  className={
                    snapshotBusy ? "mr-2 h-4 w-4 animate-spin" : "mr-2 h-4 w-4"
                  }
                />
                刷新列表
              </Button>
              <Button
                onClick={() => void createLocalSnapshot()}
                disabled={busy || snapshotBusy || !health?.databaseOk}
              >
                {snapshotBusy ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Save className="mr-2 h-4 w-4" />
                )}
                立即创建
              </Button>
            </div>
          </div>

          <div className="max-h-64 space-y-2 overflow-y-auto">
            {snapshots.length === 0 ? (
              <div className="rounded-lg border border-dashed p-5 text-center text-sm text-muted-foreground">
                暂无本地恢复快照
              </div>
            ) : (
              snapshots.map((snapshot) => (
                <div
                  key={snapshot.id}
                  className="flex items-center justify-between gap-3 rounded-lg border p-3"
                >
                  <div className="min-w-0">
                    <div className="text-sm font-medium">
                      {formatTimestamp(snapshot.createdAt)}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      {formatBytes(snapshot.totalSizeBytes)} · 数据库{" "}
                      {formatBytes(snapshot.databaseSizeBytes)} ·
                      {snapshot.includesKey ? " 包含恢复密钥" : " 不含恢复密钥"}
                    </div>
                    <div className="truncate font-mono text-[11px] text-muted-foreground">
                      {snapshot.directory}
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={snapshotBusy}
                      onClick={() => setRestoreSnapshot(snapshot)}
                    >
                      <RotateCcw className="mr-1 h-3.5 w-3.5" />
                      恢复
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-destructive hover:text-destructive"
                      disabled={snapshotBusy}
                      onClick={() => setDeleteSnapshot(snapshot)}
                      title="永久删除快照"
                      aria-label={`删除快照 ${snapshot.id}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <KeyRound className="h-5 w-5" />
            OIDC / JWKS
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4">
          <Field label="Issuer" className="col-span-2">
            <Input
              value={draft.oidc.issuer}
              onChange={(event) => updateOidc("issuer", event.target.value)}
              placeholder="https://login.example.com/realms/team"
            />
          </Field>
          <Field label="Audience">
            <Input
              value={draft.oidc.audience}
              onChange={(event) => updateOidc("audience", event.target.value)}
              placeholder="token-manager-team"
            />
          </Field>
          <Field label="JWKS URL">
            <Input
              value={draft.oidc.jwksUrl}
              onChange={(event) => updateOidc("jwksUrl", event.target.value)}
              placeholder="https://login.example.com/.well-known/jwks.json"
            />
          </Field>
          <Field label="允许的签名算法">
            <Input
              value={draft.oidc.allowedAlgorithms.join(", ")}
              onChange={(event) =>
                updateOidc(
                  "allowedAlgorithms",
                  event.target.value
                    .split(",")
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder="RS256"
            />
          </Field>
          <Field label="姓名 Claim">
            <Input
              value={draft.oidc.nameClaim}
              onChange={(event) => updateOidc("nameClaim", event.target.value)}
              placeholder="name"
            />
          </Field>
          <Field label="邮箱 Claim">
            <Input
              value={draft.oidc.emailClaim}
              onChange={(event) => updateOidc("emailClaim", event.target.value)}
              placeholder="email"
            />
          </Field>
          <Field label="组织 Claim">
            <Input
              value={draft.oidc.organizationClaim}
              onChange={(event) =>
                updateOidc("organizationClaim", event.target.value)
              }
              placeholder="organization"
            />
          </Field>
          <div className="col-span-2 rounded-lg border border-dashed p-3 text-xs text-muted-foreground">
            一键初始化会优先使用环境变量
            <code className="mx-1">TOKEN_MANAGER_ARCHIVE_KEY</code>；未配置时，
            自动生成 Base64 编码的 32
            字节密钥并保存到仅当前用户可读的本机密钥文件。
            密钥不会写入设置、日志或导出；开启“快照包含恢复密钥”后，本地快照会包含密钥，
            请像保护归档数据库一样保护快照目录。
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Database className="h-5 w-5" />
            脱敏规则
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field label="自定义正则（每行 name::pattern）">
            <Textarea
              value={rulesText}
              onChange={(event) => setRulesText(event.target.value)}
              className="min-h-32 font-mono text-xs"
              placeholder={
                "EMPLOYEE_ID::EMP-[0-9]{6}\nINTERNAL_HOST::[a-z0-9-]+\\.corp\\.example"
              }
            />
          </Field>
          <p className="text-xs text-muted-foreground">
            内置规则始终先处理 Authorization、JWT、Cookie、API
            Key、密码、私钥、URL 凭据和 Base64
            附件；自定义规则用于组织特有字段。
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Textarea
              value={testInput}
              onChange={(event) => setTestInput(event.target.value)}
              placeholder="输入脱敏测试文本"
            />
            <Textarea
              value={testOutput}
              readOnly
              placeholder="脱敏结果"
              className="bg-muted/30"
            />
          </div>
          <div className="flex justify-between">
            <Button
              variant="outline"
              onClick={() => void runRedactionTest()}
              disabled={busy || !testInput}
            >
              测试脱敏
            </Button>
            <Button onClick={() => void saveConfiguration()} disabled={busy}>
              {busy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Save className="mr-2 h-4 w-4" />
              )}
              保存归档配置
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog
        open={restoreSnapshot !== null}
        onOpenChange={(open) => !open && setRestoreSnapshot(null)}
      >
        <DialogContent className="max-w-md" zIndex="alert">
          <DialogHeader>
            <DialogTitle>确认恢复本地归档</DialogTitle>
            <DialogDescription>
              恢复会替换当前归档数据库；系统会先校验快照、密钥和 SQLCipher
              完整性。活动中的归档流会导致恢复被拒绝。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRestoreSnapshot(null)}
              disabled={snapshotBusy}
            >
              取消
            </Button>
            <Button
              onClick={() => void confirmRestoreSnapshot()}
              disabled={snapshotBusy}
            >
              {snapshotBusy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              确认恢复
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={deleteSnapshot !== null}
        onOpenChange={(open) => !open && setDeleteSnapshot(null)}
      >
        <DialogContent className="max-w-md" zIndex="alert">
          <DialogHeader>
            <DialogTitle>永久删除本地快照</DialogTitle>
            <DialogDescription>
              此操作无法撤销，只会删除选中的恢复快照，不会删除当前归档数据库。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteSnapshot(null)}
              disabled={snapshotBusy}
            >
              取消
            </Button>
            <Button
              variant="destructive"
              onClick={() => void confirmDeleteSnapshot()}
              disabled={snapshotBusy}
            >
              {snapshotBusy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              永久删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function formatKeySource(source: string) {
  const normalized = source.toLowerCase();
  if (normalized.includes("env")) return "环境变量";
  if (normalized.includes("managed") || normalized.includes("file")) {
    return "本机安全密钥文件";
  }
  return "安全密钥存储";
}

function Field({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={className}>
      <Label className="mb-1.5 block text-xs text-muted-foreground">
        {label}
      </Label>
      {children}
    </div>
  );
}
