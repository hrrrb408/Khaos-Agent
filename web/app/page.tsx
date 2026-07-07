"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ChatArea } from "./components/ChatArea";
import { SettingsModal } from "./components/SettingsModal";
import { Sidebar } from "./components/Sidebar";
import { useChat } from "./hooks/useChat";
import { useSessions } from "./hooks/useSessions";
import { useSettings } from "./hooks/useSettings";
import type { ChatMode } from "./types";

export default function Page() {
  const { settings, saveSettings, isLoaded } = useSettings();
  const sessions = useSessions("office");
  const [selectedMode, setSelectedMode] = useState<ChatMode>("office");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const activeMode = useMemo(
    () => sessions.activeSession?.mode ?? selectedMode,
    [selectedMode, sessions.activeSession?.mode],
  );

  useEffect(() => {
    if (sessions.activeSession?.mode) {
      setSelectedMode(sessions.activeSession.mode);
    }
  }, [sessions.activeSession?.mode]);

  useEffect(() => {
    if (isLoaded) {
      void sessions.syncGatewaySessions(settings.gatewayUrl, settings.apiKey);
    }
  }, [isLoaded, sessions.syncGatewaySessions, settings.apiKey, settings.gatewayUrl]);

  const getSessionId = useCallback((mode: ChatMode) => {
    return sessions.ensureSession(mode).id;
  }, [sessions]);

  const chat = useChat({
    settings,
    getSessionId,
    updateMessages: sessions.updateSessionMessages,
  });

  function handleModeChange(mode: ChatMode) {
    setSelectedMode(mode);
    if (sessions.activeSession) {
      sessions.setSessionMode(sessions.activeSession.id, mode);
    }
  }

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">Skip to chat</a>
      <Sidebar
        sessions={sessions.sessions}
        activeSessionId={sessions.activeSessionId}
        mode={activeMode}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={() => setSidebarCollapsed((value) => !value)}
        onSelectSession={sessions.setActiveSessionId}
        onNewChat={() => sessions.createSession(selectedMode)}
        onDeleteSession={sessions.deleteSession}
        onModeChange={handleModeChange}
        onOpenSettings={() => setSettingsOpen(true)}
      />
      <ChatArea
        session={sessions.activeSession}
        mode={activeMode}
        modelName={settings.modelName}
        isSending={chat.isSending}
        error={chat.lastError}
        doneStats={chat.doneStats}
        onSend={(message) => void chat.sendMessage(activeMode, message)}
        onOpenSettings={() => setSettingsOpen(true)}
        onConfirmPermission={chat.confirmPermission}
      />
      <SettingsModal
        open={settingsOpen}
        settings={settings}
        onClose={() => setSettingsOpen(false)}
        onSave={saveSettings}
      />
    </div>
  );
}
