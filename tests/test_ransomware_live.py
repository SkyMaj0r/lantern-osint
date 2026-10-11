from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.darknet import ransomware_live as rl_module
from lantern.modules.darknet.ransomware_live import RansomwareLiveCollector, fetch_groups, fetch_recent_victims

VICTIM = {
    "victim": "Acme Corp",
    "group": "lockbit3",
    "country": "US",
    "activity": "Manufacturing",
    "attackdate": "2026-01-01T00:00:00+00:00",
    "discovered": "2026-01-02T00:00:00+00:00",
    "description": "Some description",
    "claim_url": "http://someonionaddress.onion/post/1",
    "url": "https://www.ransomware.live/id/abc123",
}


@respx.mock
async def test_collect_returns_finding_for_matched_victim(ctx: Context) -> None:
    respx.get(f"{rl_module.BASE_URL}/searchvictims/Acme").mock(
        return_value=httpx.Response(200, json=[VICTIM])
    )

    findings = await RansomwareLiveCollector().collect("Acme", EntityType.COMPANY, ctx)

    assert len(findings) == 1
    assert findings[0].value == "Acme Corp"
    assert findings[0].data["group"] == "lockbit3"
    assert findings[0].data["claim_url"] == "http://someonionaddress.onion/post/1"
    assert findings[0].url == "https://www.ransomware.live/id/abc123"


@respx.mock
async def test_collect_returns_empty_on_404(ctx: Context) -> None:
    respx.get(f"{rl_module.BASE_URL}/searchvictims/NoSuchCompany").mock(return_value=httpx.Response(404))

    findings = await RansomwareLiveCollector().collect("NoSuchCompany", EntityType.COMPANY, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_flaky_backend(ctx: Context) -> None:
    respx.get(f"{rl_module.BASE_URL}/searchvictims/Flaky").mock(side_effect=httpx.ConnectError("boom"))

    findings = await RansomwareLiveCollector().collect("Flaky", EntityType.COMPANY, ctx)

    assert findings == []


@respx.mock
async def test_search_result_is_cached(ctx: Context) -> None:
    route = respx.get(f"{rl_module.BASE_URL}/searchvictims/Acme").mock(
        return_value=httpx.Response(200, json=[VICTIM])
    )

    collector = RansomwareLiveCollector()
    await collector.collect("Acme", EntityType.COMPANY, ctx)
    await collector.collect("Acme", EntityType.COMPANY, ctx)

    assert route.call_count == 1


@respx.mock
async def test_fetch_recent_victims_respects_limit(ctx: Context) -> None:
    respx.get(f"{rl_module.BASE_URL}/recentvictims").mock(
        return_value=httpx.Response(200, json=[VICTIM, VICTIM, VICTIM])
    )

    victims = await fetch_recent_victims(ctx, limit=2)

    assert len(victims) == 2


@respx.mock
async def test_fetch_groups_returns_empty_on_failure(ctx: Context) -> None:
    respx.get(f"{rl_module.BASE_URL}/groups").mock(return_value=httpx.Response(404))

    groups = await fetch_groups(ctx)

    assert groups == []
