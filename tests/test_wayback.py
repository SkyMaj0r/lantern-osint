from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.domain import wayback as wb_module
from lantern.modules.domain.wayback import WaybackCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


_HEADER = ["timestamp", "original", "statuscode"]


def _by_limit(request: httpx.Request) -> httpx.Response:
    limit = request.url.params.get("limit")
    if limit == "1":  # oldest
        return httpx.Response(200, json=[_HEADER, ["20020120142510", "http://example.com/", "200"]])
    return httpx.Response(200, json=[_HEADER, ["20240815090000", "http://example.com/", "200"]])  # newest


@respx.mock
async def test_first_and_last_captures(tmp_path: Path) -> None:
    respx.get(wb_module.CDX_URL).mock(side_effect=_by_limit)
    findings = await WaybackCollector().collect("example.com", EntityType.DOMAIN, _context(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.data["first_capture"] == "20020120142510"
    assert f.data["last_capture"] == "20240815090000"
    assert f.url == "https://web.archive.org/web/20240815090000/http://example.com/"


@respx.mock
async def test_never_archived_is_no_finding(tmp_path: Path) -> None:
    respx.get(wb_module.CDX_URL).mock(return_value=httpx.Response(200, text=""))
    findings = await WaybackCollector().collect("never-archived.test", EntityType.DOMAIN, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_gateway_timeout_is_transient_not_cached(tmp_path: Path) -> None:
    route = respx.get(wb_module.CDX_URL).mock(return_value=httpx.Response(504, text="gateway timeout"))
    ctx = _context(tmp_path)
    assert await WaybackCollector().collect("example.com", EntityType.DOMAIN, ctx) == []
    # 504 must not be cached as "never archived" — a retry hits CDX again.
    route.mock(side_effect=_by_limit)
    findings = await WaybackCollector().collect("example.com", EntityType.DOMAIN, ctx)
    assert len(findings) == 1
