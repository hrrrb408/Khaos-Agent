"use client";

import { useMemo, useState } from "react";
import type { StreamEventMessage } from "../types";

type ToolCardProps = {
  item: StreamEventMessage;
  sessionId: string;
  onConfirmPermission: (sessionId: string, toolCallId: string, approved: boolean) => void;
};

function labelFor(event: StreamEventMessage["event"]): string {
  switch (event) {
    case "tool_call":
      return "Tool call";
    case "tool_result":
      return "Tool result";
    case "permission_request":
      return "Permission request";
    case "error":
      return "Error";
    case "done":
      return "Done";
  }
}

function summaryFor(data: Record<string, unknown>): string {
  const name = data.name ?? data.tool ?? data.action ?? data.error ?? data.status;
  if (typeof name === "string") return name;
  return "Details";
}

function permissionId(data: Record<string, unknown>): string {
  const id = data.id ?? data.tool_call_id ?? data.call_id;
  return typeof id === "string" ? id : "";
}

export function ToolCard({ item, sessionId, onConfirmPermission }: ToolCardProps) {
  const [isOpen, setIsOpen] = useState(item.event === "error" || item.event === "permission_request");
  const detail = useMemo(() => JSON.stringify(item.data, null, 2), [item.data]);
  const callId = permissionId(item.data);

  return (
    <article className={`tool-card tool-card--${item.event}`}>
      <button className="tool-card__header" type="button" onClick={() => setIsOpen((value) => !value)}>
        <span className="tool-card__event">{labelFor(item.event)}</span>
        <span className="tool-card__summary">{summaryFor(item.data)}</span>
        <span className="tool-card__chevron" aria-hidden="true">{isOpen ? "−" : "+"}</span>
      </button>
      {isOpen && (
        <div className="tool-card__body">
          <pre>{detail}</pre>
          {item.event === "permission_request" && callId && (
            <div className="permission-actions">
              <button type="button" onClick={() => onConfirmPermission(sessionId, callId, true)}>
                Allow
              </button>
              <button type="button" className="button-danger" onClick={() => onConfirmPermission(sessionId, callId, false)}>
                Deny
              </button>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
