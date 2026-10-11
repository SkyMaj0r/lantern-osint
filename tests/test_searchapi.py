from __future__ import annotations

from dataclasses import replace

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.search import searchapi as searchapi_module
from lantern.modules.search.searchapi import SearchApiCollector

RESULTS = {
    "organic_results": [
        {"title": "Example Person", "snippet": "A bio snippet", "link": "https://example.com/bio"},
    ]
}


def _with_key(ctx: Context) -> Context:
    return replace(ctx, settings=ctx.settings.model_copy(update={"searchapi_api_key": "test-key"}))


@respx.mock
async def test_collect_returns_findings_for_results(ctx: Context) -> None:
    respx.get(searchapi_module.SEARCH_URL).mock(return_value=httpx.Response(200, json=RESULTS))

    findings = await SearchApiCollector().collect("Example Person", EntityType.PERSON, _with_key(ctx))

    assert len(findings) == 1
    assert findings[0].value == "Example Person"
    assert findings[0].url == "https://example.com/bio"
    assert findings[0].confidence == 0.5


@respx.mock
async def test_collect_returns_empty_on_no_results(ctx: Context) -> None:
    respx.get(searchapi_module.SEARCH_URL).mock(return_value=httpx.Response(200, json={"organic_results": []}))

    findings = await SearchApiCollector().collect("nothing-found-xyz", EntityType.PERSON, _with_key(ctx))

    assert findings == []


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(searchapi_module.SEARCH_URL).mock(side_effect=httpx.ConnectError("boom"))

    findings = await SearchApiCollector().collect("example.com", EntityType.DOMAIN, _with_key(ctx))

    assert findings == []


async def test_collect_degrades_gracefully_without_a_key(ctx: Context) -> None:
    # ctx's default settings have no searchapi_api_key set. The dispatcher
    # normally gates this before calling collect() at all; this proves a
    # direct call doesn't crash on a None param value either.
    findings = await SearchApiCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert findings == []


def test_declares_its_api_key_setting_for_dispatcher_gating() -> None:
    collector = SearchApiCollector()
    assert collector.requires_key is True
    assert collector.api_key_setting == "searchapi_api_key"
