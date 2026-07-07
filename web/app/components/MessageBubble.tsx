"use client";

import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import rehypeHighlight from "rehype-highlight";
import remarkGfm from "remark-gfm";
import type { ChatMessage } from "../types";

type MessageBubbleProps = {
  message: ChatMessage;
};

function hasOpenFence(content: string): boolean {
  const matches = content.match(/```/g);
  return Boolean(matches && matches.length % 2 === 1);
}

function languageFromClass(className?: string): string {
  const match = /language-(\w+)/.exec(className ?? "");
  return match?.[1] ?? "text";
}

function CodeBlock({ className, children, inline }: { className?: string; children?: React.ReactNode; inline?: boolean }) {
  const [copied, setCopied] = useState(false);
  const code = String(children ?? "").replace(/\n$/, "");
  const language = languageFromClass(className);

  if (inline) {
    return <code className="markdown-inline-code">{children}</code>;
  }

  async function copyCode() {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="code-block">
      <div className="code-block__bar">
        <span>{language}</span>
        <button type="button" onClick={copyCode}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre>
        <code className={className}>{children}</code>
      </pre>
    </div>
  );
}

export function MessageBubble({ message }: MessageBubbleProps) {
  const shouldBufferMarkdown = useMemo(
    () => message.role === "assistant" && hasOpenFence(message.content),
    [message.content, message.role],
  );

  if (message.role === "system") {
    return <div className="message-system">{message.content}</div>;
  }

  return (
    <article className={`message message--${message.role}`}>
      <div className="message__meta">
        <span>{message.role === "user" ? "You" : "Khaos"}</span>
        {message.isStreaming && <span className="streaming-dot">streaming</span>}
      </div>
      <div className="message__body">
        {message.role === "assistant" ? (
          shouldBufferMarkdown ? (
            <pre className="markdown-buffer">{message.content}</pre>
          ) : (
            <div className="markdown-body">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeHighlight]}
                components={{
                  a: ({ href, children }) => (
                    <a href={href} target="_blank" rel="noreferrer">{children}</a>
                  ),
                  code: CodeBlock as any,
                }}
              >
                {message.content}
              </ReactMarkdown>
            </div>
          )
        ) : (
          <p>{message.content}</p>
        )}
      </div>
    </article>
  );
}
