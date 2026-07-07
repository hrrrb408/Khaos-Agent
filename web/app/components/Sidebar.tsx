"use client";

import type { ChatMode, ChatSession } from "../types";

type SidebarProps = {
  sessions: ChatSession[];
  activeSessionId: string;
  mode: ChatMode;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  onSelectSession: (sessionId: string) => void;
  onNewChat: () => void;
  onDeleteSession: (sessionId: string) => void;
  onModeChange: (mode: ChatMode) => void;
  onOpenSettings: () => void;
};

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function Sidebar({
  sessions,
  activeSessionId,
  mode,
  collapsed,
  onToggleCollapsed,
  onSelectSession,
  onNewChat,
  onDeleteSession,
  onModeChange,
  onOpenSettings,
}: SidebarProps) {
  return (
    <aside className={`sidebar ${collapsed ? "sidebar--collapsed" : ""}`}>
      <div className="sidebar__brand">
        <button type="button" className="logo-mark" onClick={onToggleCollapsed} aria-label="Toggle sidebar">
          K
        </button>
        {!collapsed && (
          <div>
            <strong>Khaos</strong>
            <span>Agent platform</span>
          </div>
        )}
      </div>

      {!collapsed && (
        <>
          <button type="button" className="new-chat" onClick={onNewChat}>
            New Chat
          </button>

          <nav className="session-list" aria-label="Chat sessions">
            {sessions.length === 0 ? (
              <p className="session-empty">No saved sessions</p>
            ) : (
              sessions.map((session) => (
                <div key={session.id} className={`session-row ${session.id === activeSessionId ? "session-row--active" : ""}`}>
                  <button type="button" onClick={() => onSelectSession(session.id)}>
                    <span>{session.title}</span>
                    <small>{session.mode} · {formatDate(session.updated_at)}</small>
                  </button>
                  <button
                    type="button"
                    className="session-delete"
                    onClick={() => onDeleteSession(session.id)}
                    aria-label={`Delete ${session.title}`}
                  >
                    ×
                  </button>
                </div>
              ))
            )}
          </nav>

          <div className="sidebar__footer">
            <button type="button" className="settings-button" onClick={onOpenSettings}>
              Settings
            </button>
            <div className="mode-switch" role="group" aria-label="Mode switch">
              <button
                type="button"
                className={mode === "office" ? "is-active" : ""}
                onClick={() => onModeChange("office")}
              >
                Office
              </button>
              <button
                type="button"
                className={mode === "coding" ? "is-active" : ""}
                onClick={() => onModeChange("coding")}
              >
                Coding
              </button>
            </div>
          </div>
        </>
      )}
    </aside>
  );
}
