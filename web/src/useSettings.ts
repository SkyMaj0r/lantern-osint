import { useCallback, useState } from "react";

const STORAGE_KEY = "lantern.settings";

export interface LanternSettings {
  apiUrl: string;
  token: string;
  /** Collector names the user has opted out of. Stored as an opt-out list,
   * not opt-in, so a newly added server-side collector is enabled by
   * default instead of silently missing from an old saved opt-in list. */
  disabledSources: string[];
}

const DEFAULTS: LanternSettings = {
  apiUrl: "http://127.0.0.1:8000",
  token: "",
  disabledSources: [],
};

function load(): LanternSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw);
    return { ...DEFAULTS, ...parsed };
  } catch {
    return DEFAULTS;
  }
}

/** Per-viewer convenience only (which API to hit, and that viewer's own
 * bearer token for their own local server) — never shared, never read
 * back by anything but this browser. */
export function useSettings() {
  const [settings, setSettings] = useState<LanternSettings>(load);

  const update = useCallback((next: Partial<LanternSettings>) => {
    setSettings((prev) => {
      const merged = { ...prev, ...next };
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
      } catch {
        // Private browsing / blocked storage — settings just won't persist.
      }
      return merged;
    });
  }, []);

  return { settings, update };
}
