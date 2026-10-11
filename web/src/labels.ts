import type { Finding } from "./types";

const LABEL_KEYS = ["site", "breach", "cve", "group", "computer_name"] as const;

/** Best human-readable label for a Finding. Several sources carry the raw
 * query in `value` (e.g. XposedOrNot's breach findings use the queried
 * email as `value` and the breach name in `data.breach`) — this surfaces
 * the more specific field when one exists, same as the CLI's label logic. */
export function getLabel(finding: Finding): string {
  for (const key of LABEL_KEYS) {
    const v = finding.data[key];
    if (typeof v === "string" && v) return v;
  }
  return finding.value;
}
