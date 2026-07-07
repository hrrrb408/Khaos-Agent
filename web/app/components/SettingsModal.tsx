"use client";

import { useEffect, useState } from "react";
import type { ChatSettings } from "../types";

type SettingsModalProps = {
  open: boolean;
  settings: ChatSettings;
  onClose: () => void;
  onSave: (settings: ChatSettings) => void;
};

export function SettingsModal({ open, settings, onClose, onSave }: SettingsModalProps) {
  const [draft, setDraft] = useState(settings);
  const [showKey, setShowKey] = useState(false);

  useEffect(() => {
    setDraft(settings);
  }, [settings, open]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title" onMouseDown={(event) => event.stopPropagation()}>
        <header>
          <div>
            <p>Runtime</p>
            <h2 id="settings-title">Settings</h2>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close settings">×</button>
        </header>

        <label>
          Gateway URL
          <input
            value={draft.gatewayUrl}
            onChange={(event) => setDraft({ ...draft, gatewayUrl: event.target.value })}
            placeholder="http://127.0.0.1:8080"
          />
        </label>

        <label>
          API Key
          <div className="password-row">
            <input
              type={showKey ? "text" : "password"}
              value={draft.apiKey}
              onChange={(event) => setDraft({ ...draft, apiKey: event.target.value })}
              placeholder="X-Khaos-Key"
            />
            <button type="button" onClick={() => setShowKey((value) => !value)}>
              {showKey ? "Hide" : "Show"}
            </button>
          </div>
        </label>

        <label>
          Model name
          <input
            value={draft.modelName}
            onChange={(event) => setDraft({ ...draft, modelName: event.target.value })}
            placeholder="default"
          />
        </label>

        <footer>
          <button type="button" className="button-secondary" onClick={onClose}>Cancel</button>
          <button
            type="button"
            onClick={() => {
              onSave(draft);
              onClose();
            }}
          >
            Save
          </button>
        </footer>
      </section>
    </div>
  );
}
