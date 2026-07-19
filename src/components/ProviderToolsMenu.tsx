import { useTranslation } from "react-i18next";
import {
  Archive,
  Book,
  Brain,
  ChevronDown,
  Cpu,
  FolderOpen,
  History,
  KeyRound,
  LayoutDashboard,
  Shield,
  Wrench,
} from "lucide-react";
import type { AppId } from "@/lib/api";
import { McpIcon } from "@/components/BrandIcons";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type ProviderToolView =
  | "prompts"
  | "skills"
  | "mcp"
  | "sessions"
  | "archive"
  | "workspace"
  | "openclawEnv"
  | "openclawTools"
  | "openclawAgents"
  | "hermesMemory";

interface ProviderToolsMenuProps {
  activeApp: AppId;
  hasSkillsSupport: boolean;
  hasSessionSupport: boolean;
  onOpenView: (view: ProviderToolView) => void;
  onOpenHermesWebUI: () => void;
}

export function ProviderToolsMenu({
  activeApp,
  hasSkillsSupport,
  hasSessionSupport,
  onOpenView,
  onOpenHermesWebUI,
}: ProviderToolsMenuProps) {
  const { t } = useTranslation();

  const item = (
    view: ProviderToolView,
    icon: React.ReactNode,
    label: string,
  ) => (
    <DropdownMenuItem onSelect={() => onOpenView(view)}>
      {icon}
      <span>{label}</span>
    </DropdownMenuItem>
  );

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-9 gap-1.5 border border-border bg-card/70 text-muted-foreground shadow-sm hover:border-primary/35 hover:text-foreground"
        >
          <Wrench className="h-4 w-4" />
          <span>{t("common.tools", { defaultValue: "工具" })}</span>
          <ChevronDown className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-48">
        {activeApp === "openclaw" ? (
          <>
            {item(
              "workspace",
              <FolderOpen className="h-4 w-4" />,
              t("workspace.manage"),
            )}
            {item(
              "openclawEnv",
              <KeyRound className="h-4 w-4" />,
              t("openclaw.env.title"),
            )}
            {item(
              "openclawTools",
              <Shield className="h-4 w-4" />,
              t("openclaw.tools.title"),
            )}
            {item(
              "openclawAgents",
              <Cpu className="h-4 w-4" />,
              t("openclaw.agents.title"),
            )}
            {item(
              "sessions",
              <History className="h-4 w-4" />,
              t("sessionManager.title"),
            )}
          </>
        ) : activeApp === "hermes" ? (
          <>
            {item("skills", <Wrench className="h-4 w-4" />, t("skills.manage"))}
            {item(
              "hermesMemory",
              <Brain className="h-4 w-4" />,
              t("hermes.memory.title"),
            )}
            <DropdownMenuItem onSelect={onOpenHermesWebUI}>
              <LayoutDashboard className="h-4 w-4" />
              <span>{t("hermes.webui.open")}</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {item("mcp", <McpIcon size={16} />, t("mcp.title"))}
          </>
        ) : (
          <>
            {hasSkillsSupport &&
              item(
                "skills",
                <Wrench className="h-4 w-4" />,
                t("skills.manage"),
              )}
            {item("prompts", <Book className="h-4 w-4" />, t("prompts.manage"))}
            {hasSessionSupport &&
              item(
                "sessions",
                <History className="h-4 w-4" />,
                t("sessionManager.title"),
              )}
            {item("mcp", <McpIcon size={16} />, t("mcp.title"))}
          </>
        )}
        <DropdownMenuSeparator />
        {item(
          "archive",
          <Archive className="h-4 w-4" />,
          t("archive.title", { defaultValue: "对话归档" }),
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
