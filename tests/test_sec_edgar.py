from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.company import sec_edgar as sec_module
from lantern.modules.company.sec_edgar import SecEdgarCollector

TICKERS = {
    "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."},
    "1": {"cik_str": 1318605, "ticker": "TSLA", "title": "Tesla, Inc."},
}


@respx.mock
async def test_collect_matches_company_by_name_and_fetches_submission(ctx: Context) -> None:
    respx.get(sec_module.TICKERS_URL).mock(return_value=httpx.Response(200, json=TICKERS))
    respx.get(sec_module.SUBMISSIONS_URL.format(cik=320193)).mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Apple Inc.",
                "sicDescription": "Electronic Computers",
                "addresses": {"business": {"city": "Cupertino", "stateOrCountry": "CA"}},
            },
        )
    )

    findings = await SecEdgarCollector().collect("Apple", EntityType.COMPANY, ctx)

    assert len(findings) == 1
    assert findings[0].value == "Apple Inc."
    assert findings[0].data["cik"] == 320193
    assert findings[0].data["sic_description"] == "Electronic Computers"


@respx.mock
async def test_collect_matches_by_ticker(ctx: Context) -> None:
    respx.get(sec_module.TICKERS_URL).mock(return_value=httpx.Response(200, json=TICKERS))
    respx.get(sec_module.SUBMISSIONS_URL.format(cik=1318605)).mock(
        return_value=httpx.Response(200, json={"name": "Tesla, Inc.", "addresses": {}})
    )

    findings = await SecEdgarCollector().collect("TSLA", EntityType.COMPANY, ctx)

    assert len(findings) == 1
    assert findings[0].data["cik"] == 1318605


@respx.mock
async def test_collect_returns_empty_for_no_match(ctx: Context) -> None:
    respx.get(sec_module.TICKERS_URL).mock(return_value=httpx.Response(200, json=TICKERS))

    findings = await SecEdgarCollector().collect("Nonexistent Company Zyx", EntityType.COMPANY, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_tickers_fetch_failure(ctx: Context) -> None:
    respx.get(sec_module.TICKERS_URL).mock(return_value=httpx.Response(403))

    findings = await SecEdgarCollector().collect("Apple", EntityType.COMPANY, ctx)

    assert findings == []


@respx.mock
async def test_tickers_file_is_cached(ctx: Context) -> None:
    tickers_route = respx.get(sec_module.TICKERS_URL).mock(return_value=httpx.Response(200, json=TICKERS))
    respx.get(sec_module.SUBMISSIONS_URL.format(cik=320193)).mock(
        return_value=httpx.Response(200, json={"name": "Apple Inc.", "addresses": {}})
    )

    collector = SecEdgarCollector()
    await collector.collect("Apple", EntityType.COMPANY, ctx)
    await collector.collect("Apple", EntityType.COMPANY, ctx)

    assert tickers_route.call_count == 1
