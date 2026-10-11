from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.domain import crtsh as crtsh_module
from lantern.modules.domain.crtsh import CrtShCollector


@respx.mock
async def test_collect_dedupes_and_filters_subdomains(ctx: Context) -> None:
    respx.get(crtsh_module.SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "www.example.com"},
                {"name_value": "unrelated-site.net"},
            ],
        )
    )

    findings = await CrtShCollector().collect("example.com", EntityType.DOMAIN, ctx)

    values = {f.value for f in findings}
    assert values == {"www.example.com", "mail.example.com", "example.com"}
    assert "unrelated-site.net" not in values


@respx.mock
async def test_collect_returns_empty_on_no_results(ctx: Context) -> None:
    respx.get(crtsh_module.SEARCH_URL).mock(return_value=httpx.Response(200, json=[]))

    findings = await CrtShCollector().collect("nocerts.com", EntityType.DOMAIN, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_malformed_response(ctx: Context) -> None:
    respx.get(crtsh_module.SEARCH_URL).mock(return_value=httpx.Response(200, text="not json"))

    findings = await CrtShCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_request_timeout(ctx: Context) -> None:
    respx.get(crtsh_module.SEARCH_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))

    findings = await CrtShCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert findings == []
