"use client";

import { useCallback, useEffect, useState } from "react";
import type { ChatSettings } from "../types";

const SETTINGS_KEY = "khaos.web.settings";

const defaultSettings: ChatSettings = {
  gatewayUrl: "http://127.0.0.1:8080",
  apiKey: "",
  modelName: "default",
};

function readSettings(): ChatSettings {
  if (typeof window === "undefined") return defaultSettings;
  try {
    const stored = window.localStorage.getItem(SETTINGS_KEY);
    if (!stored) return defaultSettings;
    const parsed = JSON.parse(stored) as Partial<ChatSettings>;
    // The gateway master key is intentionally memory-only. Persisting it in
    // localStorage makes a same-origin XSS a durable credential theft.
    return { ...defaultSettings, ...parsed, apiKey: "" };
  } catch {
    return defaultSettings;
  }
}

function extractModelName(config: Record<string, unknown>): string {
  const candidates = [
    config.model,
    config.model_name,
    config.default_model,
    config.current_model,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate;
    }
  }
  return "";
}

export function useSettings() {
  const [settings, setSettingsState] = useState<ChatSettings>(defaultSettings);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    setSettingsState(readSettings());
    setIsLoaded(true);
  }, []);

  const saveSettings = useCallback((next: ChatSettings) => {
    setSettingsState(next);
    window.localStorage.setItem(
      SETTINGS_KEY,
      JSON.stringify({ ...next, apiKey: "" }),
    );
    if (next.apiKey) {
      void fetch(`${next.gatewayUrl}/api/auth/session`, {
        method: "POST",
        credentials: "include",
        headers: { "X-Khaos-Key": next.apiKey },
      }).then((response) => {
        if (response.ok) {
          setSettingsState((current) => ({ ...current, apiKey: "" }));
        }
      }).catch(() => {
        // Retain the memory-only bootstrap key so the user can retry.
      });
    }
  }, []);

  const refreshConfig = useCallback(async () => {
    const current = settings;
    try {
      const response = await fetch(`${current.gatewayUrl}/api/config`, {
        credentials: "include",
        headers: current.apiKey ? { "X-Khaos-Key": current.apiKey } : {},
      });
      if (!response.ok) return;
      const config = (await response.json()) as Record<string, unknown>;
      const modelName = extractModelName(config);
      if (modelName && modelName !== current.modelName) {
        saveSettings({ ...current, modelName });
      }
    } catch {
      // Local settings remain authoritative when the gateway is offline.
    }
  }, [saveSettings, settings]);

  useEffect(() => {
    if (isLoaded) {
      void refreshConfig();
    }
  }, [isLoaded, refreshConfig]);

  return { settings, saveSettings, isLoaded };
}
