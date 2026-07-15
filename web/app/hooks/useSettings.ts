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
    return { ...defaultSettings, ...JSON.parse(stored) };
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
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
  }, []);

  const refreshConfig = useCallback(async () => {
    const current = readSettings();
    try {
      const response = await fetch(`${current.gatewayUrl}/api/config`, {
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
  }, [saveSettings]);

  useEffect(() => {
    if (isLoaded) {
      void refreshConfig();
    }
  }, [isLoaded, refreshConfig]);

  return { settings, saveSettings, isLoaded };
}
