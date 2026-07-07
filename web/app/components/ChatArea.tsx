"use client";

import { useEffect, useRef } from "react";
import type { ChatMode, ChatSession, DoneStats } from "../types";
import { InputBar } from "./InputBar";
import { MessageBubble } from "./MessageBubble";
import { ToolCard } from "./ToolCard";

type ChatAreaProps = {
  session: ChatSession | null;
  mode: ChatMode;
  modelName: string;
  isSending: boolean;
  error: string;
  doneStats: DoneStats | null;
  onSend: (message: string) => void;
  onOpenSettings: () => void;
  onConfirmPermission: (sessionId: string, toolCallId: string, approved: boolean) => void;
};

function tokenText(stats: DoneStats | null): string {
  if (!stats) return "";
  const pieces = [
    typeof stats.totalTokens === "number" ? `${stats.totalTokens} total` : "",
    typeof stats.promptTokens === "number" ? `${stats.promptTokens} prompt` : "",
    typeof stats.completionTokens === "number" ? `${stats.completionTokens} completion` : "",
  ].filter(Boolean);
  return pieces.join(" · ");
}

export function ChatArea({
  session,
  mode,
  modelName,
  isSending,
  error,
  doneStats,
  onSend,
  onOpenSettings,
  onConfirmPermission,
}: ChatAreaProps) {
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [session?.messages, isSending]);

  return (
    <main className="chat-area" id="main-content">
      <header className="topbar">
        <div>
          <span className={`mode-chip mode-chip--${mode}`}>{mode}</span>
          <span className="model-label">{modelName || "default model"}</span>
        </div>
        <button type="button" className="icon-button" onClick={onOpenSettings} aria-label="Open settings">
          ⚙
        </button>
      </header>

      <section className="messages" aria-live="polite">
        {!session || session.messages.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state__eyebrow">Khaos agent console</p>
            <h1>Start a focused session.</h1>
            <p>Choose a mode, send a task, and the stream will keep tool events, permission requests, and model output in one timeline.</p>
          </div>
        ) : (
          session.messages.map((item) => (
            item.type === "message" ? (
              <MessageBubble key={item.id} message={item} />
            ) : (
              <ToolCard
                key={item.id}
                item={item}
                sessionId={session.id}
                onConfirmPermission={onConfirmPermission}
              />
            )
          ))
        )}
        {error && <div className="error-banner">{error}</div>}
        {tokenText(doneStats) && <div className="token-footer">Tokens: {tokenText(doneStats)}</div>}
        <div ref={bottomRef} />
      </section>

      <InputBar disabled={isSending} onSend={onSend} />
    </main>
  );
}
