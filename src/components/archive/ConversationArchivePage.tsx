import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import {
  Archive,
  CheckSquare,
  Download,
  FileSearch,
  HardDrive,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { archiveApi, settingsApi } from "@/lib/api";
import type {
  ArchiveHealth,
  ArchiveSearchFilters,
  ArchivedConversationDetail,
  ArchivedConversationSummary,
  HistoryImportPreview,
} from "@/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { cn } from "@/lib/utils";
import { extractErrorMessage } from "@/utils/errorUtils";

const PAGE_SIZE = 50;

const emptyFilters: ArchiveSearchFilters = {};

function formatTime(value?: number) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024)
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function dateBoundary(value: string, endOfDay = false): number | undefined {
  if (!value) return undefined;
  const date = new Date(`${value}T${endOfDay ? "23:59:59.999" : "00:00:00"}`);
  return Number.isNaN(date.getTime()) ? undefined : date.getTime();
}

function latestRevisionMap(detail?: ArchivedConversationDetail) {
  const revisions = new Map<number, number>();
  detail?.messages.forEach((message) => {
    revisions.set(
      message.logicalPosition,
      Math.max(revisions.get(message.logicalPosition) ?? 0, message.revision),
    );
  });
  return revisions;
}

export function ConversationArchivePage() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<ArchiveHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [items, setItems] = useState<ArchivedConversationSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<ArchiveSearchFilters>(emptyFilters);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [selectedId, setSelectedId] = useState<string>();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<ArchivedConversationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [deleteTargets, setDeleteTargets] = useState<string[] | null>(null);
  const [preview, setPreview] = useState<HistoryImportPreview | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const detailScrollRef = useRef<HTMLDivElement | null>(null);
  const searchRequestRef = useRef(0);

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      setHealth(await archiveApi.health());
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshHealth();
  }, [refreshHealth]);

  const effectiveFilters = useMemo<ArchiveSearchFilters>(
    () => ({
      ...filters,
      dateFrom: dateBoundary(dateFrom),
      dateTo: dateBoundary(dateTo, true),
    }),
    [dateFrom, dateTo, filters],
  );

  const runSearch = useCallback(
    async (append = false) => {
      const requestId = ++searchRequestRef.current;
      append ? setLoadingMore(true) : setLoading(true);
      try {
        const page = await archiveApi.search({
          query,
          filters: effectiveFilters,
          cursor: append ? nextCursor : undefined,
          pageSize: PAGE_SIZE,
        });
        if (requestId !== searchRequestRef.current) return;
        setItems((current) =>
          append ? [...current, ...page.items] : page.items,
        );
        setTotal(page.total);
        setNextCursor(page.nextCursor);
        if (!append) {
          setSelectedIds(new Set());
          setSelectedId((current) =>
            current && page.items.some((item) => item.id === current)
              ? current
              : page.items[0]?.id,
          );
        }
      } catch (error) {
        if (requestId !== searchRequestRef.current) return;
        setItems([]);
        setTotal(0);
        toast.error(extractErrorMessage(error));
      } finally {
        if (requestId === searchRequestRef.current) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [effectiveFilters, nextCursor, query],
  );

  useEffect(() => {
    const timeout = window.setTimeout(() => void runSearch(false), 250);
    return () => window.clearTimeout(timeout);
    // nextCursor is deliberately excluded: pagination must not restart a query.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, effectiveFilters]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    archiveApi
      .get(selectedId)
      .then((value) => {
        if (!cancelled) setDetail(value);
      })
      .catch((error) => {
        if (!cancelled) toast.error(extractErrorMessage(error));
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  const revisions = useMemo(
    () => latestRevisionMap(detail ?? undefined),
    [detail],
  );
  const virtualizer = useVirtualizer({
    count: detail?.messages.length ?? 0,
    getScrollElement: () => detailScrollRef.current,
    estimateSize: () => 180,
    overscan: 6,
    gap: 12,
  });

  const toggleSelection = (id: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const exportIds = selectedIds.size
    ? Array.from(selectedIds)
    : selectedId
      ? [selectedId]
      : [];

  const handleExport = async (format: "json" | "markdown") => {
    if (!exportIds.length) return;
    try {
      const extension = format === "json" ? "json" : "md";
      const path = await settingsApi.saveFileDialog(
        `conversation-archive-${new Date().toISOString().slice(0, 10)}.${extension}`,
      );
      if (!path) return;
      await archiveApi.export(exportIds, format, path);
      toast.success(
        t("archive.exportSuccess", { defaultValue: "归档导出完成" }),
      );
    } catch (error) {
      toast.error(extractErrorMessage(error));
    }
  };

  const handleDelete = async () => {
    if (!deleteTargets?.length) return;
    try {
      const result = await archiveApi.delete(deleteTargets);
      toast.success(
        t("archive.deleteSuccess", {
          defaultValue: `已永久删除 ${result.deleted} 条归档会话`,
          count: result.deleted,
        }),
      );
      setSelectedIds(new Set());
      setDeleteTargets(null);
      setSelectedId(undefined);
      await runSearch(false);
    } catch (error) {
      toast.error(extractErrorMessage(error));
    }
  };

  const handlePreview = async () => {
    setImportBusy(true);
    try {
      setPreview(await archiveApi.previewImport());
      setPreviewOpen(true);
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setImportBusy(false);
    }
  };

  const handleImport = async () => {
    setImportBusy(true);
    try {
      const result = await archiveApi.importLocalHistory();
      toast.success(
        t("archive.importSuccess", {
          defaultValue: `导入 ${result.imported} 条，跳过 ${result.skipped} 条，失败 ${result.failed} 条`,
        }),
      );
      if (result.errors.length) {
        toast.warning(result.errors.slice(0, 3).join("\n"));
      }
      setPreviewOpen(false);
      await runSearch(false);
      await refreshHealth();
    } catch (error) {
      toast.error(extractErrorMessage(error));
    } finally {
      setImportBusy(false);
    }
  };

  const updateFilter = (key: keyof ArchiveSearchFilters, value: string) => {
    setFilters((current) => ({
      ...current,
      [key]: value === "all" || !value ? undefined : value,
    }));
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 px-5 pb-5">
      <div
        className={cn(
          "flex flex-wrap items-center gap-3 rounded-xl border px-4 py-3 text-sm",
          health?.ready
            ? "border-emerald-500/30 bg-emerald-500/5"
            : "border-amber-500/30 bg-amber-500/5",
        )}
      >
        {healthLoading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : health?.ready ? (
          <ShieldCheck className="h-4 w-4 text-emerald-500" />
        ) : (
          <HardDrive className="h-4 w-4 text-amber-500" />
        )}
        <span className="font-medium">
          {health?.ready
            ? t("archive.healthReady", {
                defaultValue: "SQLCipher、FTS、OIDC 与备份均正常",
              })
            : health?.error ||
              t("archive.healthUnavailable", {
                defaultValue: "归档尚未就绪",
              })}
        </span>
        {health && (
          <span className="text-muted-foreground">
            {formatBytes(health.databaseSizeBytes)} ·{" "}
            {health.enabled ? "已启用" : "未启用"}
          </span>
        )}
        <Button
          size="sm"
          variant="ghost"
          className="ml-auto"
          onClick={() => void refreshHealth()}
          disabled={healthLoading}
        >
          <RefreshCw
            className={cn("mr-2 h-4 w-4", healthLoading && "animate-spin")}
          />
          {t("common.refresh", { defaultValue: "刷新" })}
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => void handlePreview()}
          disabled={importBusy || !health?.databaseOk}
        >
          <Upload className="mr-2 h-4 w-4" />
          {t("archive.importLocal", { defaultValue: "导入本机历史" })}
        </Button>
      </div>

      <div className="grid grid-cols-12 gap-2 rounded-xl border bg-card/70 p-3">
        <div className="relative col-span-4">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("archive.searchPlaceholder", {
              defaultValue: "搜索标题、摘要和完整消息正文",
            })}
            className="pl-9"
          />
        </div>
        <Select
          value={filters.provider ?? "all"}
          onValueChange={(value) => updateFilter("provider", value)}
        >
          <SelectTrigger className="col-span-2">
            <span>{filters.provider ?? "全部 Provider"}</span>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部 Provider</SelectItem>
            <SelectItem value="claude">Claude</SelectItem>
            <SelectItem value="openai_chat">OpenAI Chat</SelectItem>
            <SelectItem value="openai_responses">OpenAI Responses</SelectItem>
            <SelectItem value="gemini">Gemini</SelectItem>
            <SelectItem value="codex">Codex 历史</SelectItem>
            <SelectItem value="opencode">OpenCode 历史</SelectItem>
            <SelectItem value="openclaw">OpenClaw 历史</SelectItem>
            <SelectItem value="hermes">Hermes 历史</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={filters.source ?? "all"}
          onValueChange={(value) => updateFilter("source", value)}
        >
          <SelectTrigger className="col-span-2">
            <span>
              {filters.source === "team_gateway"
                ? "团队网关"
                : filters.source === "local_proxy"
                  ? "本地代理"
                  : filters.source === "local_history"
                    ? "本机历史"
                    : "全部来源"}
            </span>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部来源</SelectItem>
            <SelectItem value="team_gateway">团队网关</SelectItem>
            <SelectItem value="local_proxy">本地代理</SelectItem>
            <SelectItem value="local_history">本机历史</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={filters.status ?? "all"}
          onValueChange={(value) => updateFilter("status", value)}
        >
          <SelectTrigger className="col-span-2">
            <span>{filters.status ?? "全部状态"}</span>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="completed">completed</SelectItem>
            <SelectItem value="active">active</SelectItem>
            <SelectItem value="partial">partial</SelectItem>
            <SelectItem value="interrupted">interrupted</SelectItem>
            <SelectItem value="capture_error">capture_error</SelectItem>
            <SelectItem value="upstream_error">upstream_error</SelectItem>
            <SelectItem value="imported">imported</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          className="col-span-2"
          onClick={() => {
            setQuery("");
            setFilters(emptyFilters);
            setDateFrom("");
            setDateTo("");
          }}
        >
          清除筛选
        </Button>
        <Input
          className="col-span-2"
          value={filters.userId ?? ""}
          onChange={(event) => updateFilter("userId", event.target.value)}
          placeholder="用户 ID"
        />
        <Input
          className="col-span-2"
          value={filters.model ?? ""}
          onChange={(event) => updateFilter("model", event.target.value)}
          placeholder="模型"
        />
        <Input
          type="date"
          className="col-span-2"
          value={dateFrom}
          onChange={(event) => setDateFrom(event.target.value)}
          aria-label="开始日期"
        />
        <Input
          type="date"
          className="col-span-2"
          value={dateTo}
          onChange={(event) => setDateTo(event.target.value)}
          aria-label="结束日期"
        />
        <div className="col-span-4 flex items-center justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={!exportIds.length}
            onClick={() => void handleExport("json")}
          >
            <Download className="mr-2 h-4 w-4" />
            JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!exportIds.length}
            onClick={() => void handleExport("markdown")}
          >
            <Download className="mr-2 h-4 w-4" />
            Markdown
          </Button>
          <Button
            variant="destructive"
            size="sm"
            disabled={!exportIds.length}
            onClick={() => setDeleteTargets(exportIds)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            永久删除
          </Button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-[360px_minmax(0,1fr)] gap-3">
        <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card/80">
          <div className="flex items-center gap-2 border-b px-3 py-2 text-xs text-muted-foreground">
            <CheckSquare className="h-3.5 w-3.5" />
            {total} 条会话 · 已选 {selectedIds.size} 条
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {loading ? (
              <div className="grid h-full place-items-center">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : items.length === 0 ? (
              <div className="grid h-full place-items-center text-sm text-muted-foreground">
                <div className="text-center">
                  <FileSearch className="mx-auto mb-2 h-8 w-8" />
                  没有匹配的归档会话
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {items.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    onClick={() => setSelectedId(item.id)}
                    className={cn(
                      "w-full rounded-lg border p-3 text-left transition-colors",
                      selectedId === item.id
                        ? "border-primary/50 bg-primary/8"
                        : "border-border/70 hover:bg-muted/50",
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <Checkbox
                        checked={selectedIds.has(item.id)}
                        onClick={(event) => event.stopPropagation()}
                        onCheckedChange={() => toggleSelection(item.id)}
                        aria-label={`选择 ${item.title}`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-semibold">
                          {item.title}
                        </div>
                        <div className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                          {item.summary || "无摘要"}
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-1.5">
                          <Badge variant="outline" className="text-[10px]">
                            {item.provider}
                          </Badge>
                          <Badge variant="secondary" className="text-[10px]">
                            {item.status}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground">
                            {item.messageCount} 条消息
                          </span>
                        </div>
                        <div className="mt-1.5 truncate text-[10px] text-muted-foreground">
                          {item.userName || item.userEmail || "未归属本机历史"}{" "}
                          · {formatTime(item.updatedAt)}
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
                {nextCursor && (
                  <Button
                    variant="ghost"
                    className="w-full"
                    disabled={loadingMore}
                    onClick={() => void runSearch(true)}
                  >
                    {loadingMore && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    加载更多
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border bg-card/80">
          {detailLoading ? (
            <div className="grid h-full place-items-center">
              <Loader2 className="h-7 w-7 animate-spin text-muted-foreground" />
            </div>
          ) : !detail ? (
            <div className="grid h-full place-items-center text-muted-foreground">
              <div className="text-center">
                <Archive className="mx-auto mb-3 h-10 w-10" />
                选择一条会话查看完整时间线
              </div>
            </div>
          ) : (
            <>
              <div className="border-b px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <h2 className="truncate text-lg font-semibold">
                      {detail.conversation.title}
                    </h2>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span>{detail.conversation.provider}</span>
                      <span>{detail.conversation.model || "未知模型"}</span>
                      <span>{detail.conversation.source}</span>
                      <span>{formatTime(detail.conversation.updatedAt)}</span>
                    </div>
                  </div>
                  <Badge
                    variant={
                      detail.conversation.hasPartialResponse
                        ? "destructive"
                        : "secondary"
                    }
                  >
                    {detail.conversation.status}
                  </Badge>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {detail.exchanges.map((exchange) => (
                    <div
                      key={exchange.id}
                      className="rounded-md border bg-muted/30 px-2 py-1 text-[10px] text-muted-foreground"
                      title={exchange.errorCode || undefined}
                    >
                      {exchange.stream ? "SSE" : "HTTP"}{" "}
                      {exchange.httpStatus ?? "—"} · {exchange.status} ·{" "}
                      {exchange.eventCount} events
                      {exchange.errorCode ? ` · ${exchange.errorCode}` : ""}
                    </div>
                  ))}
                </div>
              </div>
              <div
                ref={detailScrollRef}
                className="min-h-0 flex-1 overflow-y-auto px-5 py-4"
              >
                <div
                  className="relative w-full"
                  style={{ height: virtualizer.getTotalSize() }}
                >
                  {virtualizer.getVirtualItems().map((virtualItem) => {
                    const message = detail.messages[virtualItem.index];
                    const isLatest =
                      revisions.get(message.logicalPosition) ===
                      message.revision;
                    return (
                      <div
                        key={message.id}
                        ref={virtualizer.measureElement}
                        data-index={virtualItem.index}
                        className="absolute left-0 top-0 w-full pb-3"
                        style={{
                          transform: `translateY(${virtualItem.start}px)`,
                        }}
                      >
                        <article
                          className={cn(
                            "rounded-lg border p-4",
                            message.role === "user"
                              ? "ml-8 border-primary/25 bg-primary/5"
                              : message.role === "assistant"
                                ? "mr-8 border-blue-500/25 bg-blue-500/5"
                                : "border-border bg-muted/30",
                            !isLatest && "opacity-70",
                          )}
                        >
                          <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
                            <span className="font-semibold uppercase">
                              {message.role}
                            </span>
                            <Badge variant={isLatest ? "secondary" : "outline"}>
                              position {message.logicalPosition} · revision{" "}
                              {message.revision}
                            </Badge>
                            {message.status !== "final" && (
                              <Badge variant="destructive">
                                {message.status}
                              </Badge>
                            )}
                            <span className="ml-auto text-muted-foreground">
                              {formatTime(message.createdAt)}
                            </span>
                          </div>
                          <div className="whitespace-pre-wrap break-words text-sm leading-relaxed [overflow-wrap:anywhere]">
                            {message.content}
                          </div>
                          {(message.tokenCount != null || message.cost) && (
                            <div className="mt-3 text-xs text-muted-foreground">
                              {message.tokenCount != null
                                ? `${message.tokenCount} tokens`
                                : ""}
                              {message.cost ? ` · ${message.cost}` : ""}
                            </div>
                          )}
                          {message.attachments.length > 0 && (
                            <div className="mt-3 space-y-1 border-t pt-2">
                              {message.attachments.map((attachment) => (
                                <div
                                  key={attachment.id}
                                  className="flex flex-wrap gap-2 text-xs text-muted-foreground"
                                >
                                  <span>{attachment.fileName || "附件"}</span>
                                  <span>
                                    {attachment.mimeType || "unknown MIME"}
                                  </span>
                                  <span>
                                    {formatBytes(attachment.sizeBytes)}
                                  </span>
                                  <code className="truncate">
                                    sha256:{attachment.sha256}
                                  </code>
                                </div>
                              ))}
                            </div>
                          )}
                        </article>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <ConfirmDialog
        isOpen={Boolean(deleteTargets?.length)}
        title="永久删除归档会话"
        message={`将永久删除 ${deleteTargets?.length ?? 0} 条集中归档及其消息、事件、附件和全文索引。原始本机会话文件不受影响。此操作不可撤销。`}
        confirmText="永久删除"
        onCancel={() => setDeleteTargets(null)}
        onConfirm={() => void handleDelete()}
      />

      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-3xl" zIndex="alert">
          <DialogHeader>
            <DialogTitle>本机历史导入预览</DialogTitle>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
            {preview && (
              <>
                <div className="mb-4 grid grid-cols-4 gap-3">
                  {[
                    ["扫描", preview.scanned],
                    ["可导入", preview.importable],
                    ["已导入", preview.alreadyImported],
                    ["损坏/失败", preview.failed],
                  ].map(([label, value]) => (
                    <div
                      key={String(label)}
                      className="rounded-lg border p-3 text-center"
                    >
                      <div className="text-xl font-semibold">{value}</div>
                      <div className="text-xs text-muted-foreground">
                        {label}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mb-3 flex flex-wrap gap-2">
                  {Object.entries(preview.byProvider).map(
                    ([provider, count]) => (
                      <Badge key={provider} variant="outline">
                        {provider}: {count}
                      </Badge>
                    ),
                  )}
                </div>
                <div className="max-h-80 space-y-1 overflow-y-auto rounded-lg border p-2">
                  {preview.items.slice(0, 100).map((item) => (
                    <div
                      key={`${item.provider}:${item.sessionId}:${item.sourcePathHash}`}
                      className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm hover:bg-muted/40"
                    >
                      <Badge variant="outline">{item.provider}</Badge>
                      <span className="min-w-0 flex-1 truncate">
                        {item.title}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {item.messageCount} 条
                      </span>
                      <span className="text-xs">
                        {item.error
                          ? "失败"
                          : item.alreadyImported
                            ? "已导入"
                            : "待导入"}
                      </span>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  导入过程只读 Claude、Codex、Gemini、OpenCode、OpenClaw 和
                  Hermes 原始文件；来源文件不会被修改或删除。
                </p>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPreviewOpen(false)}>
              取消
            </Button>
            <Button
              onClick={() => void handleImport()}
              disabled={importBusy || !preview?.importable}
            >
              {importBusy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Upload className="mr-2 h-4 w-4" />
              )}
              确认导入 {preview?.importable ?? 0} 条
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
