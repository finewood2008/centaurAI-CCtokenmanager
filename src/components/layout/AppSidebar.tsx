import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import {
  ArrowLeft,
  BarChart2,
  Book,
  Brain,
  Cpu,
  FolderOpen,
  History,
  Info,
  KeyRound,
  LayoutDashboard,
  Layers3,
  PackageOpen,
  PanelLeftClose,
  Plus,
  Route,
  Settings,
  Settings2,
  Shield,
  SlidersHorizontal,
  Wrench,
} from "lucide-react";
import type { AppId } from "@/lib/api";
import { McpIcon } from "@/components/BrandIcons";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import tokenManagerLogo from "@/assets/icons/app-icon.png";

export type AppView =
  | "providers"
  | "settings"
  | "prompts"
  | "skills"
  | "skillsDiscovery"
  | "mcp"
  | "sessions"
  | "workspace"
  | "openclawEnv"
  | "openclawTools"
  | "openclawAgents"
  | "hermesMemory";

export type SettingsTab =
  | "general"
  | "proxy"
  | "auth"
  | "advanced"
  | "usage"
  | "environment"
  | "about";

interface AppSidebarProps {
  activeApp: AppId;
  currentView: AppView;
  settingsTab: SettingsTab;
  collapsed: boolean;
  hasSkillsSupport: boolean;
  hasSessionSupport: boolean;
  isProxyActive?: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  onNavigate: (view: AppView) => void;
  onSettingsTabChange: (tab: SettingsTab) => void;
  onAddProvider: () => void;
  onOpenHermesWebUI: () => void;
}

interface NavItem {
  id: string;
  label: string;
  icon: ReactNode;
  onClick: () => void;
  active?: boolean;
}

function SidebarButton({
  item,
  collapsed,
  primary = false,
}: {
  item: NavItem;
  collapsed: boolean;
  primary?: boolean;
}) {
  const button = (
    <button
      type="button"
      onClick={item.onClick}
      aria-label={item.label}
      aria-current={item.active ? "page" : undefined}
      className={cn(
        "group relative flex h-10 w-full items-center rounded-xl text-sm font-medium transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-card",
        collapsed ? "justify-center px-0" : "gap-3 px-3",
        primary
          ? "bg-primary text-primary-foreground shadow-md shadow-primary/20 hover:bg-primary/90"
          : item.active
            ? "bg-accent text-accent-foreground shadow-sm ring-1 ring-primary/15"
            : "text-muted-foreground hover:bg-secondary/80 hover:text-foreground",
      )}
    >
      {item.active && !primary && (
        <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-primary" />
      )}
      <span
        className={cn(
          "flex h-5 w-5 shrink-0 items-center justify-center",
          !primary && item.active && "text-primary",
        )}
      >
        {item.icon}
      </span>
      {!collapsed && <span className="truncate">{item.label}</span>}
    </button>
  );

  if (!collapsed) return button;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={10}>
        {item.label}
      </TooltipContent>
    </Tooltip>
  );
}

function GroupLabel({
  children,
  collapsed,
}: {
  children: ReactNode;
  collapsed: boolean;
}) {
  if (collapsed) {
    return <div className="mx-2 my-2 h-px bg-border" aria-hidden="true" />;
  }

  return (
    <div className="px-3 pb-1.5 pt-3 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
      {children}
    </div>
  );
}

export function AppSidebar({
  activeApp,
  currentView,
  settingsTab,
  collapsed,
  hasSkillsSupport,
  hasSessionSupport,
  isProxyActive = false,
  onCollapsedChange,
  onNavigate,
  onSettingsTabChange,
  onAddProvider,
  onOpenHermesWebUI,
}: AppSidebarProps) {
  const { t } = useTranslation();
  const isSettingsMode = currentView === "settings";

  const toolItems: NavItem[] = [];
  const addTool = (
    view: AppView,
    icon: ReactNode,
    label: string,
    activeViews: AppView[] = [view],
  ) => {
    toolItems.push({
      id: view,
      icon,
      label,
      active: activeViews.includes(currentView),
      onClick: () => onNavigate(view),
    });
  };

  if (activeApp === "openclaw") {
    addTool(
      "workspace",
      <FolderOpen className="h-4 w-4" />,
      t("workspace.manage"),
    );
    addTool(
      "openclawEnv",
      <KeyRound className="h-4 w-4" />,
      t("openclaw.env.title"),
    );
    addTool(
      "openclawTools",
      <Shield className="h-4 w-4" />,
      t("openclaw.tools.title"),
    );
    addTool(
      "openclawAgents",
      <Cpu className="h-4 w-4" />,
      t("openclaw.agents.title"),
    );
    addTool(
      "sessions",
      <History className="h-4 w-4" />,
      t("sessionManager.title"),
    );
  } else if (activeApp === "hermes") {
    addTool("skills", <Wrench className="h-4 w-4" />, t("skills.manage"), [
      "skills",
      "skillsDiscovery",
    ]);
    addTool(
      "hermesMemory",
      <Brain className="h-4 w-4" />,
      t("hermes.memory.title"),
    );
    toolItems.push({
      id: "hermesWebUI",
      icon: <LayoutDashboard className="h-4 w-4" />,
      label: t("hermes.webui.open"),
      onClick: onOpenHermesWebUI,
    });
    addTool("mcp", <McpIcon size={16} />, t("mcp.title"));
  } else {
    if (hasSkillsSupport) {
      addTool("skills", <Wrench className="h-4 w-4" />, t("skills.manage"), [
        "skills",
        "skillsDiscovery",
      ]);
    }
    addTool("prompts", <Book className="h-4 w-4" />, t("prompts.manage"));
    if (hasSessionSupport) {
      addTool(
        "sessions",
        <History className="h-4 w-4" />,
        t("sessionManager.title"),
      );
    }
    addTool("mcp", <McpIcon size={16} />, t("mcp.title"));
  }

  const settingsItems: NavItem[] = [
    {
      id: "general",
      icon: <SlidersHorizontal className="h-4 w-4" />,
      label: t("settings.tabGeneral"),
      onClick: () => onSettingsTabChange("general"),
    },
    {
      id: "proxy",
      icon: <Route className="h-4 w-4" />,
      label: t("settings.tabProxy"),
      onClick: () => onSettingsTabChange("proxy"),
    },
    {
      id: "auth",
      icon: <KeyRound className="h-4 w-4" />,
      label: t("settings.tabAuth", { defaultValue: "认证" }),
      onClick: () => onSettingsTabChange("auth"),
    },
    {
      id: "advanced",
      icon: <Settings2 className="h-4 w-4" />,
      label: t("settings.tabAdvanced"),
      onClick: () => onSettingsTabChange("advanced"),
    },
    {
      id: "usage",
      icon: <BarChart2 className="h-4 w-4" />,
      label: t("usage.title"),
      onClick: () => onSettingsTabChange("usage"),
    },
    {
      id: "environment",
      icon: <PackageOpen className="h-4 w-4" />,
      label: t("settings.tabEnvironment"),
      onClick: () => onSettingsTabChange("environment"),
    },
    {
      id: "about",
      icon: <Info className="h-4 w-4" />,
      label: t("common.about"),
      onClick: () => onSettingsTabChange("about"),
    },
  ].map((item) => ({ ...item, active: item.id === settingsTab }));

  const collapseLabel = collapsed
    ? t("navigation.expandSidebar", { defaultValue: "展开侧边栏" })
    : t("navigation.collapseSidebar", { defaultValue: "折叠侧边栏" });

  return (
    <TooltipProvider delayDuration={250}>
      <aside
        data-testid="app-sidebar"
        data-collapsed={collapsed ? "true" : "false"}
        className={cn(
          "centaur-sidebar relative z-40 flex h-full shrink-0 flex-col overflow-hidden border-r border-border transition-[width] duration-200 ease-out motion-reduce:transition-none",
          collapsed ? "w-[72px]" : "w-[232px]",
        )}
      >
        <div
          className={cn(
            "flex h-[76px] shrink-0 items-center",
            collapsed ? "justify-center px-2" : "px-4",
          )}
        >
          {collapsed ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={() => onCollapsedChange(false)}
                  aria-label={collapseLabel}
                  className="relative rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                >
                  <img
                    src={tokenManagerLogo}
                    alt=""
                    draggable={false}
                    className="h-10 w-10 rounded-xl object-cover shadow-md shadow-primary/10 ring-1 ring-border"
                  />
                  <span className="absolute -bottom-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full border border-border bg-card text-muted-foreground">
                    <Layers3 className="h-2.5 w-2.5" />
                  </span>
                </button>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={10}>
                {collapseLabel}
              </TooltipContent>
            </Tooltip>
          ) : (
            <>
              <img
                src={tokenManagerLogo}
                alt="TOKEN MANAGER"
                draggable={false}
                className="h-10 w-10 shrink-0 rounded-xl object-cover shadow-md shadow-primary/10 ring-1 ring-border"
              />
              <div className="ml-3 min-w-0 flex-1 leading-none">
                <span className="centaur-eyebrow block text-[9px]">
                  CentaurAI
                </span>
                <span className="centaur-title mt-1.5 block truncate text-[13px]">
                  TOKEN MANAGER
                </span>
              </div>
              <button
                type="button"
                onClick={() => onCollapsedChange(true)}
                aria-label={collapseLabel}
                title={collapseLabel}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <PanelLeftClose className="h-4 w-4" />
              </button>
            </>
          )}
        </div>

        <div
          className={cn(
            "flex min-h-0 flex-1 flex-col",
            collapsed ? "px-2" : "px-3",
          )}
        >
          {isSettingsMode ? (
            <>
              <SidebarButton
                collapsed={collapsed}
                item={{
                  id: "back",
                  icon: <ArrowLeft className="h-4 w-4" />,
                  label: t("navigation.backToWorkbench", {
                    defaultValue: "返回工作台",
                  }),
                  onClick: () => onNavigate("providers"),
                }}
              />
              <GroupLabel collapsed={collapsed}>
                {t("common.settings")}
              </GroupLabel>
              <nav className="space-y-1" aria-label={t("common.settings")}>
                {settingsItems.map((item) => (
                  <SidebarButton
                    key={item.id}
                    item={item}
                    collapsed={collapsed}
                  />
                ))}
              </nav>
            </>
          ) : (
            <>
              <SidebarButton
                primary
                collapsed={collapsed}
                item={{
                  id: "add",
                  icon: <Plus className="h-5 w-5" />,
                  label: t("provider.addProvider"),
                  onClick: onAddProvider,
                }}
              />

              <GroupLabel collapsed={collapsed}>
                {t("navigation.workbench", { defaultValue: "工作台" })}
              </GroupLabel>
              <nav
                className="space-y-1"
                aria-label={t("navigation.workbench", {
                  defaultValue: "工作台",
                })}
              >
                <SidebarButton
                  collapsed={collapsed}
                  item={{
                    id: "providers",
                    icon: <Layers3 className="h-4 w-4" />,
                    label: t("provider.tabProvider"),
                    active: currentView === "providers",
                    onClick: () => onNavigate("providers"),
                  }}
                />
              </nav>

              <GroupLabel collapsed={collapsed}>
                {t("common.tools", { defaultValue: "工具" })}
              </GroupLabel>
              <nav
                className="min-h-0 space-y-1 overflow-y-auto"
                aria-label={t("common.tools", { defaultValue: "工具" })}
              >
                {toolItems.map((item) => (
                  <SidebarButton
                    key={item.id}
                    item={item}
                    collapsed={collapsed}
                  />
                ))}
              </nav>

              <div className="mt-auto border-t border-border py-3">
                <SidebarButton
                  collapsed={collapsed}
                  item={{
                    id: "settings",
                    icon: <Settings className="h-4 w-4" />,
                    label: t("common.settings"),
                    onClick: () => onNavigate("settings"),
                  }}
                />
                {isProxyActive && !collapsed && (
                  <div className="mt-2 flex items-center gap-2 px-3 text-[11px] text-emerald-700 dark:text-emerald-400">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                    {t("navigation.proxyActive", {
                      defaultValue: "本地路由运行中",
                    })}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </aside>
    </TooltipProvider>
  );
}
