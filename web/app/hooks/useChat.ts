"use client";

import { useCallback, useRef, useState } from "react";
import type {
  ChatMode,
  ChatMessage,
  ChatSettings,
  ConversationItem,
  DoneStats,
  StreamEventMessage,
  StreamEventName,
} from "../types";

const streamEvents: StreamEventName[] = ["tool_call", "tool_result", "permission_request", "error", "done"];

function nowIso(): string {
  return new Date().toISOString();
}

function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function contentFromPayload(payload: Record<string, unknown>): string {
  const candidate = payload.content ?? payload.text ?? payload.delta ?? payload.message;
  if (typeof candidate === "string") return candidate;
  return JSON.stringify(payload);
}

function statsFromPayload(payload: Record<string, unknown>): DoneStats {
  const total = payload.total_tokens;
  const prompt = payload.prompt_tokens;
  const completion = payload.completion_tokens;
  return {
    totalTokens: typeof total === "number" ? total : undefined,
    promptTokens: typeof prompt === "number" ? prompt : undefined,
    completionTokens: typeof completion === "number" ? completion : undefined,
  };
}

function errorFromPayload(payload: Record<string, unknown>): string {
  const candidate = payload.error ?? payload.message ?? payload.detail;
  if (typeof candidate === "string" && candidate.trim()) return candidate;
  return "Stream failed.";
}

function requestErrorMessage(error: unknown, gatewayUrl: string): string {
  if (error instanceof TypeError && error.message === "Failed to fetch") {
    return `Cannot reach Khaos Gateway at ${gatewayUrl}. Start the Go gateway or update Gateway URL in Settings.`;
  }
  return error instanceof Error ? error.message : "Chat request failed.";
}

type UseChatArgs = {
  settings: ChatSettings;
  getSessionId: (mode: ChatMode) => string;
  updateMessages: (
    sessionId: string,
    updater: (messages: ConversationItem[]) => ConversationItem[],
    options?: { titleFrom?: string; mode?: ChatMode },
  ) => void;
};

export function useChat({ settings, getSessionId, updateMessages }: UseChatArgs) {
  const [isSending, setIsSending] = useState(false);
  const [lastError, setLastError] = useState("");
  const [doneStats, setDoneStats] = useState<DoneStats | null>(null);
  const sourceRef = useRef<AbortController | null>(null);
  const assistantMessageIdRef = useRef("");
  const assistantTextRef = useRef("");

  const closeStream = useCallback(() => {
    sourceRef.current?.abort();
    sourceRef.current = null;
  }, []);

  const appendAssistantChunk = useCallback((sessionId: string, chunk: string) => {
    if (!assistantMessageIdRef.current) {
      assistantMessageIdRef.current = makeId("assistant");
      assistantTextRef.current = "";
      const message: ChatMessage = {
        id: assistantMessageIdRef.current,
        type: "message",
        role: "assistant",
        content: "",
        createdAt: nowIso(),
        isStreaming: true,
      };
      updateMessages(sessionId, (messages) => [...messages, message]);
    }

    assistantTextRef.current += chunk;
    const assistantId = assistantMessageIdRef.current;
    const nextContent = assistantTextRef.current;
    updateMessages(sessionId, (messages) => messages.map((item) => (
      item.type === "message" && item.id === assistantId
        ? { ...item, content: nextContent, isStreaming: true }
        : item
    )));
  }, [updateMessages]);

  const finishAssistant = useCallback((sessionId: string) => {
    const assistantId = assistantMessageIdRef.current;
    if (!assistantId) return;
    updateMessages(sessionId, (messages) => messages.map((item) => (
      item.type === "message" && item.id === assistantId
        ? { ...item, isStreaming: false }
        : item
    )));
    assistantMessageIdRef.current = "";
    assistantTextRef.current = "";
  }, [updateMessages]);

  const addEventItem = useCallback((sessionId: string, event: StreamEventName, data: Record<string, unknown>) => {
    const item: StreamEventMessage = {
      id: makeId(event),
      type: "event",
      event,
      data,
      createdAt: nowIso(),
    };
    updateMessages(sessionId, (messages) => [...messages, item]);
  }, [updateMessages]);

  const sendMessage = useCallback(async (mode: ChatMode, rawMessage: string) => {
    const message = rawMessage.trim();
    if (!message || isSending) return;

    closeStream();
    setIsSending(true);
    setLastError("");
    setDoneStats(null);
    assistantMessageIdRef.current = "";
    assistantTextRef.current = "";

    const sessionId = getSessionId(mode);
    const userMessage: ChatMessage = {
      id: makeId("user"),
      type: "message",
      role: "user",
      content: message,
      createdAt: nowIso(),
    };
    updateMessages(sessionId, (messages) => [...messages, userMessage], { titleFrom: message, mode });

    try {
      const controller = new AbortController();
      sourceRef.current = controller;
      const response = await fetch(`${settings.gatewayUrl}/api/chat/${sessionId}/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(settings.apiKey ? { "X-Khaos-Key": settings.apiKey } : {}),
        },
        body: JSON.stringify({ mode, message }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Chat request failed with ${response.status}`);
      }

      if (!response.body) throw new Error("Gateway returned no response stream.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffered = "";
      let terminal = false;
      while (!terminal) {
        const { value, done } = await reader.read();
        buffered += decoder.decode(value, { stream: !done });
        const lines = buffered.split("\n");
        buffered = done ? "" : (lines.pop() ?? "");
        for (const line of lines) {
          if (!line.trim()) continue;
          const item = JSON.parse(line) as { event?: StreamEventName | "message"; data?: Record<string, unknown> };
          const eventName = item.event;
          const data = item.data ?? {};
          if (eventName === "message") {
            appendAssistantChunk(sessionId, contentFromPayload(data));
            continue;
          }
          if (!eventName || !streamEvents.includes(eventName)) continue;
          if (eventName !== "done") finishAssistant(sessionId);
          addEventItem(sessionId, eventName, data);
          if (eventName === "done") {
            finishAssistant(sessionId);
            setDoneStats(statsFromPayload(data));
            terminal = true;
          } else if (eventName === "error") {
            setLastError(errorFromPayload(data));
            terminal = true;
          }
        }
        if (done) break;
      }
      if (!terminal) throw new Error("Gateway stream ended without a terminal event.");
      sourceRef.current = null;
      setIsSending(false);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        sourceRef.current = null;
        setIsSending(false);
        return;
      }
      sourceRef.current?.abort();
      sourceRef.current = null;
      const errorMessage = requestErrorMessage(error, settings.gatewayUrl);
      setLastError(errorMessage);
      addEventItem(sessionId, "error", { error: errorMessage });
      setIsSending(false);
    }
  }, [
    addEventItem,
    appendAssistantChunk,
    closeStream,
    finishAssistant,
    getSessionId,
    isSending,
    settings.apiKey,
    settings.gatewayUrl,
    updateMessages,
  ]);

  const confirmPermission = useCallback(async (sessionId: string, toolCallId: string, approved: boolean) => {
    try {
      const response = await fetch(`${settings.gatewayUrl}/api/chat/${sessionId}/confirm`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(settings.apiKey ? { "X-Khaos-Key": settings.apiKey } : {}),
        },
        body: JSON.stringify({ tool_call_id: toolCallId, approved, remember: false }),
      });
      if (!response.ok) {
        throw new Error(`Permission response failed with ${response.status}`);
      }
      addEventItem(sessionId, "tool_result", {
        status: approved ? "allowed" : "denied",
        tool_call_id: toolCallId,
      });
    } catch (error) {
      setLastError(error instanceof Error ? error.message : "Permission response failed.");
    }
  }, [addEventItem, settings.apiKey, settings.gatewayUrl]);

  return {
    isSending,
    lastError,
    doneStats,
    sendMessage,
    confirmPermission,
    closeStream,
  };
}
