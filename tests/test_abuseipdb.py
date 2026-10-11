from __future__ import annotations

from dataclasses import replace

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.infra import abuseipdb as abuseipdb_module
from lantern.modules.infra.abuseipdb import AbuseIPDBCollector

REPORTED = {
    "data": {
        "abuseConfidenceScore": 75,
        "totalReports": 12,
        "countryCode": "US",
        "isp": "Example ISP",
        "isTor": False,
    }
}

CLEAN = {
    "data": {
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "countryCode": "US",
        "isp": "Example ISP",
        "isTor": False,
    }
}


def _with_key(ctx: Context) -> Context:
    return replace(ctx, settings=ctx.settings.model_copy(update={"abuseipdb_api_key": "test-key"}))


@respx.mock
async def test_collect_returns_finding_with_abuse_reports(ctx: Context) -> None:
    respx.get(abuseipdb_module.CHECK_URL).mock(return_value=httpx.Response(200, json=REPORTED))

    findings = await AbuseIPDBCollector().collect("1.2.3.4", EntityType.IP, _with_key(ctx))

    assert len(findings) == 1
    assert findings[0].data["abuse_confidence_score"] == 75
    assert findings[0].confidence == 0.85
    assert findings[0].url == "https://www.abuseipdb.com/check/1.2.3.4"


@respx.mock
async def test_collect_lowers_confidence_when_clean(ctx: Context) -> None:
    respx.get(abuseipdb_module.CHECK_URL).mock(return_value=httpx.Response(200, json=CLEAN))

    findings = await AbuseIPDBCollector().collect("1.2.3.4", EntityType.IP, _with_key(ctx))

    assert len(findings) == 1
    assert findings[0].confidence == 0.4


@respx.mock
async def test_collect_tolerates_request_failure(ctx: Context) -> None:
    respx.get(abuseipdb_module.CHECK_URL).mock(side_effect=httpx.ConnectError("boom"))

    findings = await AbuseIPDBCollector().collect("1.2.3.4", EntityType.IP, _with_key(ctx))

    assert findings == []


async def test_collect_degrades_gracefully_without_a_key(ctx: Context) -> None:
    findings = await AbuseIPDBCollector().collect("1.2.3.4", EntityType.IP, ctx)

    assert findings == []


def test_declares_its_api_key_setting_for_dispatcher_gating() -> None:
    collector = AbuseIPDBCollector()
    assert collector.requires_key is True
    assert collector.api_key_setting == "abuseipdb_api_key"
