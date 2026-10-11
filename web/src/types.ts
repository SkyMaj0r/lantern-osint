export type EntityType = "email" | "ip" | "domain" | "username" | "person" | "company";

export interface Finding {
  source: string;
  entity_type: EntityType;
  value: string;
  data: Record<string, unknown>;
  confidence: number;
  url: string | null;
  discovered_at: string;
}

export interface Entity {
  id: string;
  entity_type: EntityType;
  value: string;
  confidence: number;
  findings: Finding[];
}

export interface GraphEdge {
  source_id: string;
  target_id: string;
  relation: string;
  pivot_value: string | null;
}

export interface EntityGraph {
  nodes: Entity[];
  edges: GraphEdge[];
}

export type SourceStatus = "pending" | "has_results" | "no_results";
