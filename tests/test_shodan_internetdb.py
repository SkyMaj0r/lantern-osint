from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.infra import shodan_internetdb as infra_module
from lantern.modules.infra.shodan_internetdb import ShodanInfraCollector


@respx.mock
async def test_collect_for_ip_returns_host_and_cve_findings(ctx: Context) -> None:
    respx.get(infra_module.INTERNETDB_URL.format(ip="1.2.3.4")).mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": "1.2.3.4",
                "ports": [22, 443],
                "hostnames": ["host.example.com"],
                "cpes": [],
                "tags": ["cloud"],
                "vulns": ["CVE-2021-1234"],
            },
        )
    )
    respx.get(infra_module.CVEDB_URL.format(cve_id="CVE-2021-1234")).mock(
        return_value=httpx.Response(200, json={"summary": "A bug", "cvss": 7.5, "published_time": "2021-01-01"})
    )

    findings = await ShodanInfraCollector().collect("1.2.3.4", EntityType.IP, ctx)

    assert len(findings) == 2
    host_finding = next(f for f in findings if "ports" in f.data)
    cve_finding = next(f for f in findings if "cve" in f.data)
    assert host_finding.data["ports"] == [22, 443]
    assert cve_finding.data["summary"] == "A bug"


@respx.mock
async def test_collect_returns_empty_for_unknown_ip(ctx: Context) -> None:
    respx.get(infra_module.INTERNETDB_URL.format(ip="5.6.7.8")).mock(return_value=httpx.Response(404))

    findings = await ShodanInfraCollector().collect("5.6.7.8", EntityType.IP, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_cve_lookup_failure(ctx: Context) -> None:
    respx.get(infra_module.INTERNETDB_URL.format(ip="1.2.3.4")).mock(
        return_value=httpx.Response(200, json={"ports": [80], "hostnames": [], "cpes": [], "tags": [], "vulns": ["CVE-9999-0001"]})
    )
    respx.get(infra_module.CVEDB_URL.format(cve_id="CVE-9999-0001")).mock(side_effect=httpx.ConnectError("boom"))

    findings = await ShodanInfraCollector().collect("1.2.3.4", EntityType.IP, ctx)

    assert len(findings) == 2
    cve_finding = next(f for f in findings if "cve" in f.data)
    assert cve_finding.data == {"cve": "CVE-9999-0001"}


@respx.mock
async def test_collect_resolves_domain_to_ips_first(ctx: Context) -> None:
    respx.get(infra_module.INTERNETDB_URL.format(ip="93.184.216.34")).mock(
        return_value=httpx.Response(200, json={"ports": [443], "hostnames": [], "cpes": [], "tags": [], "vulns": []})
    )

    collector = ShodanInfraCollector()

    async def fake_resolve(query: str, entity_type) -> list[str]:
        return ["93.184.216.34"]

    collector._resolve_ips = fake_resolve

    findings = await collector.collect("example.com", EntityType.DOMAIN, ctx)

    assert len(findings) == 1
    assert findings[0].value == "93.184.216.34"


async def test_collect_returns_empty_when_domain_does_not_resolve(ctx: Context) -> None:
    collector = ShodanInfraCollector()

    async def fake_resolve(query: str, entity_type) -> list[str]:
        return []

    collector._resolve_ips = fake_resolve

    findings = await collector.collect("nonexistent.invalid", EntityType.DOMAIN, ctx)

    assert findings == []
