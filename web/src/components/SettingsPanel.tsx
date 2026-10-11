import { useState } from "react";
import type { LanternSettings } from "../useSettings";

interface SettingsPanelProps {
  settings: LanternSettings;
  onUpdate: (next: Partial<LanternSettings>) => void;
  availableSources: string[];
}

export function SettingsPanel({ settings, onUpdate, availableSources }: SettingsPanelProps) {
  const [open, setOpen] = useState(false);

  function toggleSource(name: string) {
    const disabled = new Set(settings.disabledSources);
    if (disabled.has(name)) {
      disabled.delete(name);
    } else {
      disabled.add(name);
    }
    onUpdate({ disabledSources: [...disabled] });
  }

  return (
    <div className="settings">
      <button
        type="button"
        className="settings__toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.6" />
          <path
            d="M12 2.5v2.2M12 19.3v2.2M4.9 4.9l1.55 1.55M17.55 17.55l1.55 1.55M2.5 12h2.2M19.3 12h2.2M4.9 19.1l1.55-1.55M17.55 6.45l1.55-1.55"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
          />
        </svg>
        Settings
      </button>

      {open && (
        <>
          <button
            type="button"
            className="settings__backdrop"
            aria-label="Close settings"
            onClick={() => setOpen(false)}
          />
          <div className="settings__panel" role="dialog" aria-label="Settings">
            <div className="settings__header">
              <span>Settings</span>
              <button type="button" className="settings__close" onClick={() => setOpen(false)} aria-label="Close">
                ×
              </button>
            </div>

            <label className="settings__field">
              <span>API URL</span>
              <input
                type="text"
                value={settings.apiUrl}
                onChange={(e) => onUpdate({ apiUrl: e.target.value })}
                placeholder="http://127.0.0.1:8000"
              />
            </label>
            <label className="settings__field">
              <span>Bearer token</span>
              <input
                type="password"
                value={settings.token}
                onChange={(e) => onUpdate({ token: e.target.value })}
                placeholder="API_BEARER_TOKEN from .env"
              />
            </label>
            <p className="settings__note">
              Stored only in this browser. Matches <code>API_BEARER_TOKEN</code> in the server's{" "}
              <code>.env</code>.
            </p>

            {availableSources.length > 0 && (
              <div className="settings__field">
                <span>Modules</span>
                <div className="settings__sources">
                  {availableSources.map((name) => (
                    <label key={name} className="settings__source">
                      <input
                        type="checkbox"
                        checked={!settings.disabledSources.includes(name)}
                        onChange={() => toggleSource(name)}
                      />
                      {name}
                    </label>
                  ))}
                </div>
                <p className="settings__note">Unchecked modules are skipped on every search.</p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
