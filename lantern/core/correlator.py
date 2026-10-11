from __future__ import annotations

from pydantic import BaseModel

from lantern.core.entities import EntityType
from lantern.core.models import Entity, Finding


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str
    pivot_value: str | None = None


class EntityGraph(BaseModel):
    nodes: list[Entity]
    edges: list[GraphEdge]


def _normalize(value: str) -> str:
    return value.strip().lower()


def extract_pivots(finding: Finding) -> set[tuple[str, str]]:
    """Identifiers a finding's data corroborates, as (kind, normalized value).

    Deliberately conservative: only fields known to be unmasked, structured
    identifiers — never free text, never partially-redacted values (e.g.
    Hudson Rock's top_logins, which are intentionally masked by the source
    and can't confirm a match). Extend this as collectors start extracting
    more structured cross-references.
    """
    pivots: set[tuple[str, str]] = set()
    data = finding.data

    parent_name = data.get("parent_name")
    if parent_name:
        pivots.add(("company", _normalize(parent_name)))

    for hostname in data.get("hostnames") or []:
        if hostname:
            pivots.add(("domain", _normalize(hostname)))

    jurisdiction = data.get("jurisdiction")
    if jurisdiction:
        pivots.add(("jurisdiction", _normalize(jurisdiction)))

    return pivots


def _shared_pivot(a: Finding, b: Finding) -> tuple[str, str] | None:
    shared = extract_pivots(a) & extract_pivots(b)
    return next(iter(shared), None)


def _cites_same_url(a: Finding, b: Finding) -> bool:
    # Two independent sources citing the identical page is itself a
    # corroborating pivot — no need for it to also show up inside `data`.
    # Caught live: DuckDuckGo and Wikipedia both citing the same Wikipedia
    # URL for "Linus Torvalds" stayed unmerged because neither source
    # populates a `data` field the pivot extractor recognized.
    return bool(a.url and b.url and a.url == b.url)


def _cluster_by_corroboration(findings: list[Finding]) -> list[list[Finding]]:
    """Union-find over findings that share a source (same collector call —
    definitionally the same thing) or a corroborating pivot. Findings with
    neither stay in separate clusters, even if their value is identical.
    """
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if (
                findings[i].source == findings[j].source
                or _shared_pivot(findings[i], findings[j])
                or _cites_same_url(findings[i], findings[j])
            ):
                union(i, j)

    clusters: dict[int, list[Finding]] = {}
    for idx, finding in enumerate(findings):
        clusters.setdefault(find(idx), []).append(finding)
    return list(clusters.values())


def _confidence_for_cluster(cluster: list[Finding]) -> float:
    base = max(f.confidence for f in cluster)
    distinct_sources = len({f.source for f in cluster})
    return min(1.0, base + 0.05 * (distinct_sources - 1))


def correlate(findings: list[Finding]) -> list[Entity]:
    """Group Findings into Entities.

    Findings that share an (entity_type, value) are *not* automatically the
    same real-world thing just because the string matches — common names
    and handles collide across unrelated people, companies, and accounts.
    Two findings only merge into one Entity when they come from the same
    source (trivially the same thing — e.g. WhatsMyName's many site hits
    for one username) or when a corroborating pivot connects them.
    Otherwise each stays its own Entity, still returned, just not merged.
    """
    buckets: dict[tuple[EntityType, str], list[Finding]] = {}
    for finding in findings:
        key = (finding.entity_type, _normalize(finding.value))
        buckets.setdefault(key, []).append(finding)

    entities: list[Entity] = []
    for group in buckets.values():
        entity_type = group[0].entity_type
        if len({f.source for f in group}) <= 1:
            entities.append(
                Entity(
                    entity_type=entity_type,
                    value=group[0].value,
                    confidence=_confidence_for_cluster(group),
                    findings=group,
                )
            )
            continue

        for cluster in _cluster_by_corroboration(group):
            entities.append(
                Entity(
                    entity_type=entity_type,
                    value=cluster[0].value,
                    confidence=_confidence_for_cluster(cluster),
                    findings=cluster,
                )
            )

    return entities


def build_graph(entities: list[Entity]) -> EntityGraph:
    """Edges connect *distinct* entities that corroborate each other (e.g. a
    GLEIF subsidiary's parent_name matching another entity's value) — this
    is relationship, not identity: two entities can be linked without being
    merged into one.
    """
    edges: list[GraphEdge] = []
    for i, a in enumerate(entities):
        a_pivots = {pivot for finding in a.findings for pivot in extract_pivots(finding)}
        for b in entities[i + 1 :]:
            for kind, pivot_value in a_pivots:
                if _normalize(b.value) == pivot_value:
                    edges.append(
                        GraphEdge(source_id=a.id, target_id=b.id, relation=f"shares_{kind}", pivot_value=pivot_value)
                    )
    return EntityGraph(nodes=entities, edges=edges)
