from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.darknet import hudson_rock as hr_module
from lantern.modules.darknet.hudson_rock import HudsonRockCollector

STEALER_RESPONSE = {
    "message": "infected",
    "stealers": [
        {
            "total_corporate_services": 10,
            "total_user_services": 20,
            "date_compromised": "2026-01-01T00:00:00.000Z",
            "computer_name": "LAPTOP-ABC",
            "operating_system": "Windows 11",
            "antiviruses": ["Windows Defender"],
            "top_logins": ["a***n"],
        }
    ],
}

CLEAN_RESPONSE = {"message": "not infected", "stealers": [], "total_corporate_services": 0, "total_user_services": 0}

DOMAIN_RESPONSE = {
    "total": 100,
    "totalStealers": 50,
    "employees": 5,
    "users": 45,
    "third_parties": 2,
    "data": {"employees_urls": [{"url": "https://sso.example.com", "occurrence": 10}]},
}


@respx.mock
async def test_collect_username_returns_one_finding_per_stealer(ctx: Context) -> None:
    respx.get(f"{hr_module.BASE_URL}/search-by-username").mock(
        return_value=httpx.Response(200, json=STEALER_RESPONSE)
    )

    findings = await HudsonRockCollector().collect("testadmin", EntityType.USERNAME, ctx)

    assert len(findings) == 1
    assert findings[0].data["computer_name"] == "LAPTOP-ABC"
    assert findings[0].entity_type == EntityType.USERNAME


@respx.mock
async def test_collect_email_returns_empty_when_clean(ctx: Context) -> None:
    respx.get(f"{hr_module.BASE_URL}/search-by-email").mock(return_value=httpx.Response(200, json=CLEAN_RESPONSE))

    findings = await HudsonRockCollector().collect("clean@example.com", EntityType.EMAIL, ctx)

    assert findings == []


@respx.mock
async def test_collect_domain_returns_aggregate_finding(ctx: Context) -> None:
    respx.get(f"{hr_module.BASE_URL}/search-by-domain").mock(return_value=httpx.Response(200, json=DOMAIN_RESPONSE))

    findings = await HudsonRockCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert len(findings) == 1
    assert findings[0].data["total_stealers"] == 50
    assert findings[0].data["top_employee_urls"] == ["https://sso.example.com"]


@respx.mock
async def test_collect_domain_with_zero_stealers_is_empty(ctx: Context) -> None:
    respx.get(f"{hr_module.BASE_URL}/search-by-domain").mock(
        return_value=httpx.Response(200, json={"total": 0, "totalStealers": 0})
    )

    findings = await HudsonRockCollector().collect("clean-domain.com", EntityType.DOMAIN, ctx)

    assert findings == []


async def test_collect_returns_empty_for_unsupported_type(ctx: Context) -> None:
    findings = await HudsonRockCollector().collect("1.2.3.4", EntityType.IP, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(f"{hr_module.BASE_URL}/search-by-username").mock(side_effect=httpx.ConnectError("boom"))

    findings = await HudsonRockCollector().collect("x", EntityType.USERNAME, ctx)

    assert findings == []


@respx.mock
async def test_result_is_cached(ctx: Context) -> None:
    route = respx.get(f"{hr_module.BASE_URL}/search-by-username").mock(
        return_value=httpx.Response(200, json=STEALER_RESPONSE)
    )

    collector = HudsonRockCollector()
    await collector.collect("testadmin", EntityType.USERNAME, ctx)
    await collector.collect("testadmin", EntityType.USERNAME, ctx)

    assert route.call_count == 1
