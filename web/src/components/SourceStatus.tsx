import type { SourceStatus } from "../types";

export interface SourceState {
  status: SourceStatus;
  count: number;
}

interface SourceStatusRowProps {
  statuses: Map<string, SourceState>;
}

const STATUS_LABEL: Record<SourceStatus, string> = {
  pending: "checking…",
  has_results: "",
  no_results: "no results",
};

export function SourceStatusRow({ statuses }: SourceStatusRowProps) {
  if (statuses.size === 0) return null;

  return (
    <ul className="source-status" aria-label="Sources checked">
      {Array.from(statuses.entries()).map(([source, { status, count }]) => (
        <li
          key={source}
          className={`source-status__chip source-status__chip--${status}`}
          title={status === "pending" ? "Still checking" : status === "no_results" ? "Checked — nothing found" : `${count} finding(s)`}
        >
          <span className="source-status__dot" aria-hidden="true" />
          {source}
          {status === "has_results" && <span className="source-status__count">{count}</span>}
          {status !== "has_results" && (
            <span className="source-status__state">{STATUS_LABEL[status]}</span>
          )}
        </li>
      ))}
    </ul>
  );
}
