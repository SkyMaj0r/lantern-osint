from __future__ import annotations

from dataclasses import replace

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.infra import virustotal as vt_module
from lantern.modules.infra.virustotal import VirusTotalCollector

DOMAIN_REPORT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 10},
            "reputation": -5,
            "categories": {"vendor-a": "phishing"},
        }
    }
}

CLEAN_REPORT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 80, "undetected": 5},
            "reputation": 10,
            "categories": {},
        }
    }
}


def _with_key(ctx: Context) -> Context:
    return replace(ctx, settings=ctx.settings.model_copy(update={"virustotal_api_key": "test-key"}))


@respx.mock
async def test_collect_returns_finding_with_malicious_detections(ctx: Context) -> None:
    respx.get(vt_module.DOMAIN_URL.format(domain="evil.example")).mock(
        return_value=httpx.Response(200, json=DOMAIN_REPORT)
    )

    findings = await VirusTotalCollector().collect("evil.example", EntityType.DOMAIN, _with_key(ctx))

    assert len(findings) == 1
    assert findings[0].data["malicious"] == 2
    assert findings[0].confidence == 0.8
    assert findings[0].url == "https://www.virustotal.com/gui/domain/evil.example"


@respx.mock
async def test_collect_lowers_confidence_when_clean(ctx: Context) -> None:
    respx.get(vt_module.IP_URL.format(ip="1.2.3.4")).mock(return_value=httpx.Response(200, json=CLEAN_REPORT))

    findings = await VirusTotalCollector().collect("1.2.3.4", EntityType.IP, _with_key(ctx))

    assert len(findings) == 1
    assert findings[0].confidence == 0.5
    assert findings[0].url == "https://www.virustotal.com/gui/ip-address/1.2.3.4"


@respx.mock
async def test_collect_returns_empty_on_404(ctx: Context) -> None:
    respx.get(vt_module.DOMAIN_URL.format(domain="unseen.example")).mock(return_value=httpx.Response(404))

    findings = await VirusTotalCollector().collect("unseen.example", EntityType.DOMAIN, _with_key(ctx))

    assert findings == []


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(vt_module.DOMAIN_URL.format(domain="example.com")).mock(side_effect=httpx.ConnectError("boom"))

    findings = await VirusTotalCollector().collect("example.com", EntityType.DOMAIN, _with_key(ctx))

    assert findings == []


async def test_collect_degrades_gracefully_without_a_key(ctx: Context) -> None:
    findings = await VirusTotalCollector().collect("example.com", EntityType.DOMAIN, ctx)

    assert findings == []


def test_declares_its_api_key_setting_for_dispatcher_gating() -> None:
    collector = VirusTotalCollector()
    assert collector.requires_key is True
    assert collector.api_key_setting == "virustotal_api_key"
