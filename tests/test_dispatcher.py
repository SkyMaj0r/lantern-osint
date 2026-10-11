from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from lantern.core.cache import Cache
from lantern.core.dispatcher import Dispatcher
from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.settings import Settings
from lantern.modules.base import Collector, Context, RateLimit


def _settings(**overrides) -> Settings:
    return Settings(
        contact_email="test@example.com",
        api_bearer_token="token",
        **overrides,
    )


class StubCollector(Collector):
    def __init__(self, name: str, supported_types: set[EntityType], api_key_setting: str | None = None):
        self.name = name
        self.supported_types = supported_types
        self.rate_limit = RateLimit(requests=100, per_seconds=1.0)
        self.requires_key = api_key_setting is not None
        self.api_key_setting = api_key_setting
        self.calls: list[tuple[str, EntityType]] = []

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        self.calls.append((query, entity_type))
        return [
            Finding(
                source=self.name,
                entity_type=entity_type,
                value=query,
                confidence=0.5,
            )
        ]


class FailingCollector(Collector):
    name = "broken"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=100, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        raise RuntimeError("boom")


def _make_context(tmp_path: Path) -> Context:
    def factory() -> Context:
        return Context(
            http=httpx.AsyncClient(),
            cache=Cache(tmp_path / "cache.db"),
            settings=_settings(),
        )

    return factory


async def test_dispatches_only_to_collectors_supporting_the_type(tmp_path: Path) -> None:
    domain_collector = StubCollector("domain-source", {EntityType.DOMAIN})
    ip_collector = StubCollector("ip-source", {EntityType.IP})
    dispatcher = Dispatcher([domain_collector, ip_collector], _make_context(tmp_path))

    findings = await dispatcher.run("example.com")

    assert domain_collector.calls == [("example.com", EntityType.DOMAIN)]
    assert ip_collector.calls == []
    assert len(findings) == 1
    assert findings[0].source == "domain-source"


async def test_ambiguous_query_dispatches_to_every_applicable_module(tmp_path: Path) -> None:
    username_collector = StubCollector("wmn", {EntityType.USERNAME})
    company_collector = StubCollector("gleif", {EntityType.COMPANY})
    dispatcher = Dispatcher([username_collector, company_collector], _make_context(tmp_path))

    findings = await dispatcher.run("johndoe")

    assert username_collector.calls == [("johndoe", EntityType.USERNAME)]
    assert company_collector.calls == [("johndoe", EntityType.COMPANY)]
    assert len(findings) == 2


async def test_collector_supporting_two_candidate_types_runs_once(tmp_path: Path) -> None:
    # github_users/keybase support USERNAME *and* PERSON; a one-word query is
    # ambiguous across USERNAME+PERSON+COMPANY. The collector must fire once,
    # for the first supported type in classification order (USERNAME), not
    # twice against the same value.
    multi = StubCollector("github_users", {EntityType.USERNAME, EntityType.PERSON})
    dispatcher = Dispatcher([multi], _make_context(tmp_path))

    findings = await dispatcher.run("johndoe")

    assert multi.calls == [("johndoe", EntityType.USERNAME)]
    assert len(findings) == 1


async def test_multiword_name_reaches_person_supporting_collector(tmp_path: Path) -> None:
    # "John Doe" classifies as PERSON+COMPANY (no USERNAME). A collector that
    # supports PERSON still runs — this is the path that lets a full name feed
    # a username collector.
    multi = StubCollector("github_users", {EntityType.USERNAME, EntityType.PERSON})
    dispatcher = Dispatcher([multi], _make_context(tmp_path))

    findings = await dispatcher.run("John Doe")

    assert multi.calls == [("John Doe", EntityType.PERSON)]
    assert len(findings) == 1


async def test_type_override_runs_only_that_types_collectors(tmp_path: Path) -> None:
    # "example.com" would auto-classify as DOMAIN, but forcing PERSON must
    # route it to the person collector instead and skip the domain one.
    domain_collector = StubCollector("rdap", {EntityType.DOMAIN})
    person_collector = StubCollector("searchapi", {EntityType.PERSON})
    dispatcher = Dispatcher([domain_collector, person_collector], _make_context(tmp_path))

    findings = await dispatcher.run("example.com", entity_type=EntityType.PERSON)

    assert person_collector.calls == [("example.com", EntityType.PERSON)]
    assert domain_collector.calls == []
    assert len(findings) == 1


async def test_type_override_validates_the_value(tmp_path: Path) -> None:
    collector = StubCollector("rdap", {EntityType.DOMAIN})
    dispatcher = Dispatcher([collector], _make_context(tmp_path))

    with pytest.raises(ValueError):
        await dispatcher.run("not an ip", entity_type=EntityType.IP)


async def test_failing_collector_is_logged_and_returns_no_findings(tmp_path: Path) -> None:
    dispatcher = Dispatcher([FailingCollector()], _make_context(tmp_path))
    findings = await dispatcher.run("example.com")
    assert findings == []


async def test_collector_missing_required_key_is_skipped(tmp_path: Path) -> None:
    collector = StubCollector("needs-key", {EntityType.DOMAIN}, api_key_setting="virustotal_api_key")
    dispatcher = Dispatcher([collector], _make_context(tmp_path))

    findings = await dispatcher.run("example.com")

    assert findings == []
    assert collector.calls == []


async def test_collector_runs_when_required_key_is_present(tmp_path: Path) -> None:
    def factory() -> Context:
        return Context(
            http=httpx.AsyncClient(),
            cache=Cache(tmp_path / "cache.db"),
            settings=_settings(virustotal_api_key="abc123"),
        )

    collector = StubCollector("needs-key", {EntityType.DOMAIN}, api_key_setting="virustotal_api_key")
    dispatcher = Dispatcher([collector], factory)

    findings = await dispatcher.run("example.com")

    assert len(findings) == 1


async def test_enabled_filter_restricts_to_named_collectors(tmp_path: Path) -> None:
    wanted = StubCollector("virustotal", {EntityType.DOMAIN})
    unwanted = StubCollector("searchapi", {EntityType.DOMAIN})
    dispatcher = Dispatcher([wanted, unwanted], _make_context(tmp_path))

    findings = await dispatcher.run("example.com", enabled={"virustotal"})

    assert wanted.calls == [("example.com", EntityType.DOMAIN)]
    assert unwanted.calls == []
    assert len(findings) == 1
    assert findings[0].source == "virustotal"


async def test_enabled_none_means_unrestricted_same_as_before(tmp_path: Path) -> None:
    a = StubCollector("a", {EntityType.DOMAIN})
    b = StubCollector("b", {EntityType.DOMAIN})
    dispatcher = Dispatcher([a, b], _make_context(tmp_path))

    findings = await dispatcher.run("example.com", enabled=None)

    assert len(findings) == 2


async def test_collector_names_lists_every_registered_collector_regardless_of_type(tmp_path: Path) -> None:
    domain_collector = StubCollector("domain-source", {EntityType.DOMAIN})
    ip_collector = StubCollector("ip-source", {EntityType.IP})
    dispatcher = Dispatcher([domain_collector, ip_collector], _make_context(tmp_path))

    assert sorted(dispatcher.collector_names) == ["domain-source", "ip-source"]
