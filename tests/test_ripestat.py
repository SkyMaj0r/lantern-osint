from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.infra import ripestat as rs_module
from lantern.modules.infra.ripestat import RipeStatCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


@respx.mock
async def test_ip_resolves_to_prefix_and_asn_holder(tmp_path: Path) -> None:
    respx.get(rs_module.NETWORK_INFO_URL).mock(
        return_value=httpx.Response(200, json={"data": {"asns": ["15169"], "prefix": "8.8.8.0/24"}})
    )
    respx.get(rs_module.PREFIX_OVERVIEW_URL).mock(
        return_value=httpx.Response(
            200, json={"data": {"asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}]}}
        )
    )
    findings = await RipeStatCollector().collect("8.8.8.8", EntityType.IP, _context(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.data["prefix"] == "8.8.8.0/24"
    assert f.data["asns"] == [{"asn": "15169", "holder": "GOOGLE - Google LLC"}]
    assert f.url == "https://stat.ripe.net/8.8.8.8"


@respx.mock
async def test_unannounced_ip_is_no_finding(tmp_path: Path) -> None:
    respx.get(rs_module.NETWORK_INFO_URL).mock(
        return_value=httpx.Response(200, json={"data": {"asns": [], "prefix": None}})
    )
    findings = await RipeStatCollector().collect("192.0.2.1", EntityType.IP, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_transient_error_is_not_cached(tmp_path: Path) -> None:
    route = respx.get(rs_module.NETWORK_INFO_URL).mock(side_effect=httpx.ConnectError("boom"))
    ctx = _context(tmp_path)
    assert await RipeStatCollector().collect("8.8.8.8", EntityType.IP, ctx) == []
    route.mock(return_value=httpx.Response(200, json={"data": {"asns": [], "prefix": None}}))
    # The retry reaches the network (returns empty, which is a real result).
    assert await RipeStatCollector().collect("8.8.8.8", EntityType.IP, ctx) == []
