from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.search import wikipedia as wiki_module
from lantern.modules.search.wikipedia import WikipediaCollector

OPENSEARCH_RESPONSE = ["Linus Torvalds", ["Linus Torvalds"], [""], ["https://en.wikipedia.org/wiki/Linus_Torvalds"]]
SUMMARY_RESPONSE = {
    "type": "standard",
    "title": "Linus Torvalds",
    "extract": "Linus Benedict Torvalds is a Finnish and American software engineer.",
    "wikibase_item": "Q34253",
    "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/Linus_Torvalds"}},
}


@respx.mock
async def test_collect_returns_finding_for_known_person(ctx: Context) -> None:
    respx.get(wiki_module.OPENSEARCH_URL).mock(return_value=httpx.Response(200, json=OPENSEARCH_RESPONSE))
    respx.get(wiki_module.SUMMARY_URL.format(title="Linus_Torvalds")).mock(
        return_value=httpx.Response(200, json=SUMMARY_RESPONSE)
    )

    findings = await WikipediaCollector().collect("Linus Torvalds", EntityType.PERSON, ctx)

    assert len(findings) == 1
    assert findings[0].value == "Linus Torvalds"
    assert findings[0].url == "https://en.wikipedia.org/wiki/Linus_Torvalds"
    assert findings[0].data["wikidata_id"] == "Q34253"


@respx.mock
async def test_collect_returns_empty_when_opensearch_finds_nothing(ctx: Context) -> None:
    respx.get(wiki_module.OPENSEARCH_URL).mock(
        return_value=httpx.Response(200, json=["nope", [], [], []])
    )

    findings = await WikipediaCollector().collect("nope", EntityType.PERSON, ctx)

    assert findings == []


@respx.mock
async def test_collect_returns_empty_on_disambiguation_page(ctx: Context) -> None:
    respx.get(wiki_module.OPENSEARCH_URL).mock(
        return_value=httpx.Response(200, json=["Mercury", ["Mercury"], [""], ["https://en.wikipedia.org/wiki/Mercury"]])
    )
    respx.get(wiki_module.SUMMARY_URL.format(title="Mercury")).mock(
        return_value=httpx.Response(200, json={"type": "disambiguation", "title": "Mercury"})
    )

    findings = await WikipediaCollector().collect("Mercury", EntityType.PERSON, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_summary_404(ctx: Context) -> None:
    respx.get(wiki_module.OPENSEARCH_URL).mock(return_value=httpx.Response(200, json=OPENSEARCH_RESPONSE))
    respx.get(wiki_module.SUMMARY_URL.format(title="Linus_Torvalds")).mock(return_value=httpx.Response(404))

    findings = await WikipediaCollector().collect("Linus Torvalds", EntityType.PERSON, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(wiki_module.OPENSEARCH_URL).mock(side_effect=httpx.ConnectError("boom"))

    findings = await WikipediaCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert findings == []
