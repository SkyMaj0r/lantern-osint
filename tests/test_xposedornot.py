from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.email import xposedornot as xon_module
from lantern.modules.email.xposedornot import XposedOrNotCollector


@respx.mock
async def test_collect_emits_one_finding_per_breach(ctx: Context) -> None:
    respx.get(xon_module.CHECK_URL.format(email="alice@example.com")).mock(
        return_value=httpx.Response(200, json={"breaches": [["Adobe", "Canva"]]})
    )
    respx.get(xon_module.ANALYTICS_URL).mock(
        return_value=httpx.Response(200, json={"Error": "Not found"})
    )

    findings = await XposedOrNotCollector().collect("alice@example.com", EntityType.EMAIL, ctx)

    breach_findings = [f for f in findings if "breach" in f.data]
    assert {f.data["breach"] for f in breach_findings} == {"Adobe", "Canva"}
    assert all(f.confidence == 0.9 for f in breach_findings)


@respx.mock
async def test_collect_returns_no_findings_for_clean_email(ctx: Context) -> None:
    respx.get(xon_module.CHECK_URL.format(email="clean@example.com")).mock(
        return_value=httpx.Response(404)
    )
    respx.get(xon_module.ANALYTICS_URL).mock(
        return_value=httpx.Response(200, json={"Error": "Not found"})
    )

    findings = await XposedOrNotCollector().collect("clean@example.com", EntityType.EMAIL, ctx)

    assert findings == []


@respx.mock
async def test_collect_includes_analytics_finding_when_present(ctx: Context) -> None:
    respx.get(xon_module.CHECK_URL.format(email="bob@example.com")).mock(
        return_value=httpx.Response(200, json={"breaches": []})
    )
    respx.get(xon_module.ANALYTICS_URL).mock(
        return_value=httpx.Response(200, json={"ExposedBreaches": {"breaches_details": []}})
    )

    findings = await XposedOrNotCollector().collect("bob@example.com", EntityType.EMAIL, ctx)

    assert len(findings) == 1
    assert findings[0].data["type"] == "analytics"
    assert findings[0].confidence == 0.6


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(xon_module.CHECK_URL.format(email="x@example.com")).mock(
        side_effect=httpx.ConnectError("boom")
    )
    respx.get(xon_module.ANALYTICS_URL).mock(side_effect=httpx.ConnectError("boom"))

    findings = await XposedOrNotCollector().collect("x@example.com", EntityType.EMAIL, ctx)

    assert findings == []


@respx.mock
async def test_second_call_uses_cache_not_a_new_request(ctx: Context) -> None:
    check_route = respx.get(xon_module.CHECK_URL.format(email="cached@example.com")).mock(
        return_value=httpx.Response(200, json={"breaches": [["Adobe"]]})
    )
    respx.get(xon_module.ANALYTICS_URL).mock(return_value=httpx.Response(200, json={"Error": "Not found"}))

    collector = XposedOrNotCollector()
    await collector.collect("cached@example.com", EntityType.EMAIL, ctx)
    await collector.collect("cached@example.com", EntityType.EMAIL, ctx)

    assert check_route.call_count == 1
