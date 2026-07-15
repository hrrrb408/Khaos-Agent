"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChatMode, ChatSession, ConversationItem } from "../types";

const SESSIONS_KEY = "khaos.web.sessions";

function nowIso(): string {
  return new Date().toISOString();
}

function makeId(): string {
  return `web-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function titleFromMessage(message: string): string {
  const compact = message.replace(/\s+/g, " ").trim();
  return compact ? compact.slice(0, 20) : "New chat";
}

function readSessions(): ChatSession[] {
  if (typeof window === "undefined") return [];
  try {
    const stored = window.localStorage.getItem(SESSIONS_KEY);
    if (!stored) return [];
    const sessions = JSON.parse(stored) as ChatSession[];
    return Array.isArray(sessions) ? sessions : [];
  } catch {
    return [];
  }
}

function writeSessions(sessions: ChatSession[]) {
  window.localStorage.setItem(SESSIONS_KEY, JSON.stringify(sessions));
}

export function useSessions(initialMode: ChatMode) {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState("");

  useEffect(() => {
    const loaded = readSessions();
    setSessions(loaded);
    if (loaded[0]) {
      setActiveSessionId(loaded[0].id);
    }
  }, []);

  const persist = useCallback((updater: (previous: ChatSession[]) => ChatSession[]) => {
    setSessions((previous) => {
      const next = updater(previous);
      writeSessions(next);
      return next;
    });
  }, []);

  const createSession = useCallback((mode: ChatMode = initialMode) => {
    const stamp = nowIso();
    const session: ChatSession = {
      id: makeId(),
      title: "New chat",
      mode,
      created_at: stamp,
      updated_at: stamp,
      messages: [],
    };
    persist((previous) => [session, ...previous]);
    setActiveSessionId(session.id);
    return session;
  }, [initialMode, persist]);

  const ensureSession = useCallback((mode: ChatMode) => {
    const existing = sessions.find((session) => session.id === activeSessionId);
    if (existing) return existing;
    return createSession(mode);
  }, [activeSessionId, createSession, sessions]);

  const updateSessionMessages = useCallback((
    sessionId: string,
    updater: (messages: ConversationItem[]) => ConversationItem[],
    options?: { titleFrom?: string; mode?: ChatMode },
  ) => {
    persist((previous) => previous.map((session) => {
      if (session.id !== sessionId) return session;
      const messages = updater(session.messages);
      const title = session.title === "New chat" && options?.titleFrom
        ? titleFromMessage(options.titleFrom)
        : session.title;
      return {
        ...session,
        title,
        mode: options?.mode ?? session.mode,
        updated_at: nowIso(),
        messages,
      };
    }).sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at)));
  }, [persist]);

  const deleteSession = useCallback((sessionId: string) => {
    persist((previous) => {
      const next = previous.filter((session) => session.id !== sessionId);
      if (sessionId === activeSessionId) {
        setActiveSessionId(next[0]?.id ?? "");
      }
      return next;
    });
  }, [activeSessionId, persist]);

  const setSessionMode = useCallback((sessionId: string, mode: ChatMode) => {
    persist((previous) => previous.map((session) => (
      session.id === sessionId ? { ...session, mode, updated_at: nowIso() } : session
    )));
  }, [persist]);

  const syncGatewaySessions = useCallback(async (gatewayUrl: string, apiKey: string) => {
    try {
      const response = await fetch(`${gatewayUrl}/api/sessions`, {
        headers: apiKey ? { "X-Khaos-Key": apiKey } : {},
      });
      if (!response.ok) return;
      const remote = await response.json() as Array<{ session_id?: string; mode?: ChatMode; message?: string }>;
      if (!Array.isArray(remote)) return;
      persist((previous) => {
        const known = new Set(previous.map((session) => session.id));
        const additions = remote
          .filter((item) => item.session_id && !known.has(item.session_id))
          .map((item) => {
            const stamp = nowIso();
            return {
              id: item.session_id as string,
              title: titleFromMessage(item.message ?? "Gateway session"),
              mode: item.mode === "coding" ? "coding" : "office",
              created_at: stamp,
              updated_at: stamp,
              messages: [],
            } satisfies ChatSession;
          });
        return additions.length ? [...additions, ...previous] : previous;
      });
    } catch {
      // The local session store is the fallback source of truth.
    }
  }, [persist]);

  const activeSession = useMemo(
    () => sessions.find((session) => session.id === activeSessionId) ?? null,
    [activeSessionId, sessions],
  );

  return {
    sessions,
    activeSession,
    activeSessionId,
    setActiveSessionId,
    createSession,
    ensureSession,
    updateSessionMessages,
    deleteSession,
    setSessionMode,
    syncGatewaySessions,
  };
}
