import type { Finding } from "../types";
import { getLabel } from "../labels";
import { ConfidenceMark } from "./ConfidenceMark";

interface FindingsListProps {
  findings: Finding[];
}

export function FindingsList({ findings }: FindingsListProps) {
  const bySource = new Map<string, Finding[]>();
  for (const finding of findings) {
    const group = bySource.get(finding.source) ?? [];
    group.push(finding);
    bySource.set(finding.source, group);
  }

  if (bySource.size === 0) return null;

  return (
    <div className="findings">
      {Array.from(bySource.entries()).map(([source, group]) => (
        <section className="findings__group" key={source} aria-label={`Results from ${source}`}>
          <h2 className="findings__source">
            {source} <span className="findings__count">{group.length}</span>
          </h2>
          <ul className="findings__list">
            {group.map((finding, i) => {
              const label = getLabel(finding);
              const showValue = label !== finding.value;
              return (
                <li className="finding" key={`${source}-${i}`}>
                  <div className="finding__main">
                    <span className="finding__label">{label}</span>
                    {showValue && <span className="finding__value">{finding.value}</span>}
                  </div>
                  <div className="finding__meta">
                    <ConfidenceMark confidence={finding.confidence} />
                    {finding.url && (
                      <a href={finding.url} target="_blank" rel="noreferrer" className="finding__link">
                        View source
                      </a>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}
