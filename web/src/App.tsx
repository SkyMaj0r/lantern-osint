import { useCallback, useEffect, useRef, useState } from "react";
import { fetchSources, streamSearch } from "./api";
import { SearchBar } from "./components/SearchBar";
import { SettingsPanel } from "./components/SettingsPanel";
import { SourceStatusRow } from "./components/SourceStatus";
import type { SourceState } from "./components/SourceStatus";
import { FindingsList } from "./components/FindingsList";
import { RelationshipsList } from "./components/RelationshipsList";
import { LanternIcon } from "./components/LanternIcon";
import { OathReveal } from "./components/OathReveal";
import { OATH_LINES } from "./oath";
import { useSettings } from "./useSettings";
import type { EntityGraph, EntityType, Finding } from "./types";

const OATH_TRIGGER = "oath";

export default function App() {
  const { settings, update } = useSettings();
  const [query, setQuery] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);
  const [sourceStatuses, setSourceStatuses] = useState<Map<string, SourceState>>(new Map());
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<EntityGraph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [oathMode, setOathMode] = useState(false);
  const [availableSources, setAvailableSources] = useState<string[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    let cancelled = false;
    void fetchSources(settings.apiUrl, settings.token).then((names) => {
      if (!cancelled) setAvailableSources(names);
    });
    return () => {
      cancelled = true;
    };
  }, [settings.apiUrl, settings.token]);

  const runSearch = useCallback(
    (q: string, typeOverride?: EntityType) => {
      abortRef.current?.abort();

      if (q.trim().toLowerCase() === OATH_TRIGGER) {
        setSearching(false);
        setSourceStatuses(new Map());
        setFindings([]);
        setGraph(null);
        setError(null);
        setQuery(q);
        setOathMode(true);
        return;
      }
      setOathMode(false);

      const controller = new AbortController();
      abortRef.current = controller;

      setQuery(q);
      setSearching(true);
      setSourceStatuses(new Map());
      setFindings([]);
      setGraph(null);
      setError(null);

      // Only restrict once the real module list has loaded — otherwise an
      // empty availableSources (not yet fetched) would filter everything
      // out instead of falling back to "run every applicable module."
      const enabledSources =
        availableSources.length > 0
          ? availableSources.filter((s) => !settings.disabledSources.includes(s))
          : undefined;

      void streamSearch(
        settings.apiUrl,
        settings.token,
        q,
        {
          onSources: (sources) => {
            setSourceStatuses(new Map(sources.map((s) => [s, { status: "pending", count: 0 }])));
          },
          onFinding: (finding) => {
            setFindings((prev) => [...prev, finding]);
            setSourceStatuses((prev) => {
              const next = new Map(prev);
              const current = next.get(finding.source) ?? { status: "pending", count: 0 };
              next.set(finding.source, { status: "has_results", count: current.count + 1 });
              return next;
            });
          },
          onDone: (g) => {
            setGraph(g);
            setSourceStatuses((prev) => {
              const next = new Map(prev);
              for (const [source, state] of next) {
                if (state.status === "pending") next.set(source, { ...state, status: "no_results" });
              }
              return next;
            });
            setSearching(false);
          },
          onError: (message) => {
            setError(message);
            setSearching(false);
          },
        },
        controller.signal,
        enabledSources,
        typeOverride,
      );
    },
    [settings.apiUrl, settings.token, settings.disabledSources, availableSources],
  );

  function copyJson() {
    const payload = JSON.stringify({ findings, graph }, null, 2);
    void navigator.clipboard.writeText(payload);
  }

  return (
    <div className="app">
      <header className="app__header">
        <span className="app__wordmark">
          <LanternIcon size={22} />
          Lantern
        </span>
        <SettingsPanel settings={settings} onUpdate={update} availableSources={availableSources} />
      </header>

      <main className="app__main">
        <SearchBar onSearch={runSearch} disabled={searching} />

        {oathMode ? (
          <OathReveal lines={OATH_LINES} />
        ) : (
          <>
            {error && <p className="error" role="alert">{error}</p>}

            <SourceStatusRow statuses={sourceStatuses} />

            {query && !searching && findings.length === 0 && !error && (
              <p className="empty-state">No findings for "{query}".</p>
            )}

            <FindingsList findings={findings} />

            {graph && <RelationshipsList graph={graph} />}
          </>
        )}

        {!oathMode && findings.length > 0 && (
          <div className="summary">
            <span>
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </span>
            <button type="button" className="summary__copy" onClick={copyJson}>
              Copy JSON
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
