"use client";

import { useEffect, useRef, useState } from "react";

type InputBarProps = {
  disabled: boolean;
  onSend: (message: string) => void;
};

export function InputBar({ disabled, onSend }: InputBarProps) {
  const [value, setValue] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    const node = textareaRef.current;
    if (!node) return;
    node.style.height = "0px";
    node.style.height = `${Math.min(node.scrollHeight, 200)}px`;
  }, [value]);

  function submit() {
    const message = value.trim();
    if (!message || disabled) return;
    onSend(message);
    setValue("");
  }

  return (
    <form className="input-bar" onSubmit={(event) => { event.preventDefault(); submit(); }}>
      <textarea
        ref={textareaRef}
        value={value}
        placeholder="Message Khaos"
        rows={1}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            submit();
          }
        }}
      />
      <button type="submit" disabled={disabled || !value.trim()} aria-label="Send message">
        {disabled ? <span className="spinner" aria-hidden="true" /> : "Send"}
      </button>
    </form>
  );
}
