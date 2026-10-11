from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.domain import rdap as rdap_module
from lantern.modules.domain.rdap import RdapCollector

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
    ]
}


@respx.mock
async def test_collect_returns_finding_for_known_tld(ctx: Context) -> None:
    respx.get(rdap_module.BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    respx.get("https://rdap.verisign.com/com/v1/domain/example.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "handle": "123",
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2000-01-01"}],
                "nameservers": [{"ldhName": "ns1.example.com"}],
            },
        )
    )

    findings = await RdapCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert len(findings) == 1
    assert findings[0].data["registered"] == "2000-01-01"
    assert findings[0].data["nameservers"] == ["ns1.example.com"]


@respx.mock
async def test_collect_returns_empty_for_unregistered_tld(ctx: Context) -> None:
    respx.get(rdap_module.BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))

    findings = await RdapCollector().collect("example.zz", EntityType.DOMAIN, ctx)

    assert findings == []


@respx.mock
async def test_collect_handles_404_gracefully(ctx: Context) -> None:
    respx.get(rdap_module.BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    respx.get("https://rdap.verisign.com/com/v1/domain/nosuchdomain.com").mock(
        return_value=httpx.Response(404)
    )

    findings = await RdapCollector().collect("nosuchdomain.com", EntityType.DOMAIN, ctx)

    assert findings == []


@respx.mock
async def test_bootstrap_registry_is_cached(ctx: Context) -> None:
    bootstrap_route = respx.get(rdap_module.BOOTSTRAP_URL).mock(
        return_value=httpx.Response(200, json=BOOTSTRAP)
    )
    respx.get("https://rdap.verisign.com/com/v1/domain/a.com").mock(return_value=httpx.Response(404))
    respx.get("https://rdap.verisign.com/com/v1/domain/b.com").mock(return_value=httpx.Response(404))

    collector = RdapCollector()
    await collector.collect("a.com", EntityType.DOMAIN, ctx)
    await collector.collect("b.com", EntityType.DOMAIN, ctx)

    assert bootstrap_route.call_count == 1
