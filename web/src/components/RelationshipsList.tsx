import type { EntityGraph } from "../types";

interface RelationshipsListProps {
  graph: EntityGraph;
}

/** The brief asks for an entity graph (nodes = entities, edges =
 * relationships) for the web UI. A full node-link diagram is future work;
 * this renders the same information — which entities corroborate each
 * other and why — as a plain list, which is honest about what we have
 * and keeps with "the data is the interface" over decoration. */
export function RelationshipsList({ graph }: RelationshipsListProps) {
  if (graph.edges.length === 0) return null;

  const valueById = new Map(graph.nodes.map((n) => [n.id, n.value]));

  return (
    <section className="relationships" aria-label="Relationships">
      <h2 className="relationships__title">Relationships</h2>
      <ul className="relationships__list">
        {graph.edges.map((edge, i) => (
          <li key={i} className="relationship">
            <span className="relationship__node">{valueById.get(edge.source_id)}</span>
            <span className="relationship__relation">{edge.relation.replace("shares_", "shares ")}</span>
            <span className="relationship__node">{valueById.get(edge.target_id)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
