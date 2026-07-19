import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AppSidebar, type AppView } from "@/components/layout/AppSidebar";

function renderSidebar(
  overrides: Partial<React.ComponentProps<typeof AppSidebar>> = {},
) {
  const onNavigate = vi.fn<(view: AppView) => void>();
  const onSettingsTabChange = vi.fn();
  const onAddProvider = vi.fn();
  const onCollapsedChange = vi.fn();
  const onOpenHermesWebUI = vi.fn();

  render(
    <AppSidebar
      activeApp="claude"
      currentView="providers"
      settingsTab="general"
      collapsed={false}
      hasSkillsSupport
      hasSessionSupport
      onNavigate={onNavigate}
      onSettingsTabChange={onSettingsTabChange}
      onAddProvider={onAddProvider}
      onCollapsedChange={onCollapsedChange}
      onOpenHermesWebUI={onOpenHermesWebUI}
      {...overrides}
    />,
  );

  return {
    onNavigate,
    onSettingsTabChange,
    onAddProvider,
    onCollapsedChange,
    onOpenHermesWebUI,
  };
}

describe("AppSidebar", () => {
  it("shows the provider primary action and common tool navigation", () => {
    const handlers = renderSidebar();

    fireEvent.click(
      screen.getByRole("button", { name: "provider.addProvider" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "skills.manage" }));
    fireEvent.click(screen.getByRole("button", { name: "common.settings" }));

    expect(handlers.onAddProvider).toHaveBeenCalledTimes(1);
    expect(handlers.onNavigate).toHaveBeenCalledWith("skills");
    expect(handlers.onNavigate).toHaveBeenCalledWith("settings");
    expect(
      screen.getByRole("button", { name: "provider.tabProvider" }),
    ).toHaveAttribute("aria-current", "page");
  });

  it("uses the app-specific OpenClaw tool set", () => {
    renderSidebar({ activeApp: "openclaw" });

    expect(
      screen.getByRole("button", { name: "workspace.manage" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "openclaw.env.title" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "prompts.manage" }),
    ).not.toBeInTheDocument();
  });

  it("keeps Hermes Web UI as an action instead of a routed view", () => {
    const handlers = renderSidebar({ activeApp: "hermes" });

    fireEvent.click(screen.getByRole("button", { name: "hermes.webui.open" }));

    expect(handlers.onOpenHermesWebUI).toHaveBeenCalledTimes(1);
    expect(handlers.onNavigate).not.toHaveBeenCalled();
  });

  it("switches the same sidebar to settings navigation", () => {
    const handlers = renderSidebar({
      currentView: "settings",
      settingsTab: "usage",
    });

    expect(
      screen.queryByRole("button", { name: "provider.addProvider" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "usage.title" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    fireEvent.click(
      screen.getByRole("button", { name: "settings.tabAdvanced" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: /navigation\.backToWorkbench|返回工作台/,
      }),
    );

    expect(handlers.onSettingsTabChange).toHaveBeenCalledWith("advanced");
    expect(handlers.onNavigate).toHaveBeenCalledWith("providers");
  });

  it("renders icon-only controls when collapsed and can expand again", () => {
    const handlers = renderSidebar({ collapsed: true });
    const sidebar = screen.getByTestId("app-sidebar");

    expect(sidebar).toHaveAttribute("data-collapsed", "true");
    expect(screen.queryByText("provider.addProvider")).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", {
        name: /navigation\.expandSidebar|展开侧边栏/,
      }),
    );
    expect(handlers.onCollapsedChange).toHaveBeenCalledWith(false);
  });
});
