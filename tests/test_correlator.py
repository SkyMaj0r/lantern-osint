from __future__ import annotations

import pytest

from lantern.core.correlator import build_graph, correlate
from lantern.core.entities import EntityType
from lantern.core.models import Finding


def _finding(source: str, entity_type: EntityType, value: str, confidence: float, **data) -> Finding:
    return Finding(source=source, entity_type=entity_type, value=value, confidence=confidence, data=data)


def test_many_findings_from_one_source_merge_into_one_entity() -> None:
    findings = [
        _finding("whatsmyname", EntityType.USERNAME, "torvalds", 0.8, site="GitHub"),
        _finding("whatsmyname", EntityType.USERNAME, "torvalds", 0.8, site="Keybase"),
        _finding("whatsmyname", EntityType.USERNAME, "torvalds", 0.8, site="Steam"),
    ]

    entities = correlate(findings)

    assert len(entities) == 1
    assert len(entities[0].findings) == 3


def test_same_value_different_sources_without_pivot_stay_separate() -> None:
    # The "common names match many people" case: two independent sources
    # both say "Apple Inc" but nothing corroborates they're the same one.
    findings = [
        _finding("sec-edgar", EntityType.COMPANY, "Apple Inc", 0.9, cik=320193),
        _finding("some-other-source", EntityType.COMPANY, "Apple Inc", 0.85, registry_id="XYZ"),
    ]

    entities = correlate(findings)

    assert len(entities) == 2
    assert {len(e.findings) for e in entities} == {1}


def test_same_value_different_sources_citing_same_url_merge() -> None:
    # Caught live: DuckDuckGo and Wikipedia both citing the identical
    # Wikipedia page for the same person, with no shared `data` pivot.
    findings = [
        Finding(
            source="duckduckgo",
            entity_type=EntityType.PERSON,
            value="Linus Torvalds",
            confidence=0.55,
            url="https://en.wikipedia.org/wiki/Linus_Torvalds",
        ),
        Finding(
            source="wikipedia",
            entity_type=EntityType.PERSON,
            value="Linus Torvalds",
            confidence=0.6,
            url="https://en.wikipedia.org/wiki/Linus_Torvalds",
        ),
    ]

    entities = correlate(findings)

    assert len(entities) == 1
    assert len(entities[0].findings) == 2


def test_same_value_different_sources_with_shared_pivot_merge() -> None:
    findings = [
        _finding("sec-edgar", EntityType.COMPANY, "Acme Inc", 0.9, jurisdiction="US"),
        _finding("gleif", EntityType.COMPANY, "Acme Inc", 0.85, jurisdiction="US"),
    ]

    entities = correlate(findings)

    assert len(entities) == 1
    assert len(entities[0].findings) == 2


def test_different_values_never_bucketed_together() -> None:
    findings = [
        _finding("gleif", EntityType.COMPANY, "Acme Subsidiary Ltd", 0.85),
        _finding("gleif", EntityType.COMPANY, "Acme Holdings Inc", 0.85),
    ]

    entities = correlate(findings)

    assert len(entities) == 2


def test_different_entity_types_never_merge_even_with_same_string_value() -> None:
    findings = [
        _finding("whatsmyname", EntityType.USERNAME, "acme", 0.8),
        _finding("sec-edgar", EntityType.COMPANY, "acme", 0.9),
    ]

    entities = correlate(findings)

    assert len(entities) == 2
    assert {e.entity_type for e in entities} == {EntityType.USERNAME, EntityType.COMPANY}


def test_confidence_gets_a_bounded_boost_from_corroborating_sources() -> None:
    findings = [
        _finding("sec-edgar", EntityType.COMPANY, "Acme Inc", 0.9, jurisdiction="US"),
        _finding("gleif", EntityType.COMPANY, "Acme Inc", 0.9, jurisdiction="US"),
    ]

    entities = correlate(findings)

    assert len(entities) == 1
    assert entities[0].confidence == pytest.approx(0.95)  # 0.9 base + 0.05 for one extra corroborating source


def test_confidence_never_exceeds_one() -> None:
    findings = [
        _finding("a", EntityType.COMPANY, "Acme Inc", 0.99, jurisdiction="US"),
        _finding("b", EntityType.COMPANY, "Acme Inc", 0.99, jurisdiction="US"),
        _finding("c", EntityType.COMPANY, "Acme Inc", 0.99, jurisdiction="US"),
    ]

    entities = correlate(findings)

    assert entities[0].confidence == 1.0


def test_build_graph_includes_every_entity_as_a_node() -> None:
    findings = [
        _finding("sec-edgar", EntityType.COMPANY, "Acme Inc", 0.9),
        _finding("gleif", EntityType.COMPANY, "Beta Corp", 0.85),
    ]
    entities = correlate(findings)

    graph = build_graph(entities)

    assert len(graph.nodes) == 2


def test_build_graph_creates_edge_for_parent_relationship() -> None:
    findings = [
        _finding("gleif", EntityType.COMPANY, "Acme Subsidiary Ltd", 0.85, parent_name="Acme Holdings Inc"),
        _finding("sec-edgar", EntityType.COMPANY, "Acme Holdings Inc", 0.9),
    ]
    entities = correlate(findings)

    graph = build_graph(entities)

    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.relation == "shares_company"
    assert edge.pivot_value == "acme holdings inc"


def test_build_graph_creates_no_edge_without_a_shared_pivot() -> None:
    findings = [
        _finding("gleif", EntityType.COMPANY, "Acme Subsidiary Ltd", 0.85),
        _finding("sec-edgar", EntityType.COMPANY, "Unrelated Corp", 0.9),
    ]
    entities = correlate(findings)

    graph = build_graph(entities)

    assert graph.edges == []


def test_build_graph_creates_edge_for_shared_hostname_domain_pivot() -> None:
    findings = [
        _finding("shodan-internetdb", EntityType.IP, "1.2.3.4", 0.9, hostnames=["mail.example.com"]),
        _finding("rdap", EntityType.DOMAIN, "mail.example.com", 0.9),
    ]
    entities = correlate(findings)

    graph = build_graph(entities)

    assert len(graph.edges) == 1
    assert graph.edges[0].relation == "shares_domain"
