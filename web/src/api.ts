import type { EntityGraph, Finding } from "./types";

export interface SearchCallbacks {
  onSources: (sources: string[]) => void;
  onFinding: (finding: Finding) => void;
  onDone: (graph: EntityGraph) => void;
  onError: (message: string) => void;
}

/** Every collector the server has registered, regardless of entity type —
 * for rendering a toggle list before a query has even been classified. */
export async function fetchSources(baseUrl: string, token: string): Promise<string[]> {
  const response = await fetch(`${baseUrl}/sources`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) return [];
  const data = (await response.json()) as { sources: string[] };
  return data.sources;
}

/**
 * The backend streams Server-Sent Events, but the browser's native
 * EventSource API has no way to attach an Authorization header — and the
 * API requires a bearer token on every request, including this one. So
 * this is a small SSE parser over a plain `fetch` stream instead, which
 * keeps the token out of the URL (no query param, nothing in server logs
 * or browser history) rather than working around EventSource's limit.
 */
export async function streamSearch(
  baseUrl: string,
  token: string,
  query: string,
  callbacks: SearchCallbacks,
  signal?: AbortSignal,
  sources?: string[],
  typeOverride?: string,
): Promise<void> {
  const params = new URLSearchParams({ q: query });
  for (const source of sources ?? []) params.append("sources", source);
  // Omitted → the backend auto-detects the type, as before.
  if (typeOverride) params.append("type", typeOverride);

  let response: Response;
  try {
    response = await fetch(`${baseUrl}/search?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal,
    });
  } catch {
    callbacks.onError("Could not reach the API. Is it running, and is the API URL correct?");
    return;
  }

  if (response.status === 401) {
    callbacks.onError("Rejected: check the bearer token in Settings.");
    return;
  }
  if (!response.ok || !response.body) {
    callbacks.onError(`API returned HTTP ${response.status}.`);
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let separatorIndex: number;
    while ((separatorIndex = buffer.indexOf("\n\n")) >= 0) {
      const rawEvent = buffer.slice(0, separatorIndex);
      buffer = buffer.slice(separatorIndex + 2);
      dispatchEvent(rawEvent, callbacks);
    }
  }
}

function dispatchEvent(rawEvent: string, callbacks: SearchCallbacks): void {
  const eventMatch = /^event: (.*)$/m.exec(rawEvent);
  const dataMatch = /^data: (.*)$/m.exec(rawEvent);
  if (!dataMatch) return;

  const eventType = eventMatch?.[1] ?? "message";
  let payload: unknown;
  try {
    payload = JSON.parse(dataMatch[1]);
  } catch {
    return;
  }

  switch (eventType) {
    case "sources":
      callbacks.onSources((payload as { sources: string[] }).sources);
      break;
    case "finding":
      callbacks.onFinding(payload as Finding);
      break;
    case "done":
      callbacks.onDone(payload as EntityGraph);
      break;
    case "error":
      callbacks.onError((payload as { message: string }).message);
      break;
  }
}
