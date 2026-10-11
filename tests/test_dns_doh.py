from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.domain import dns_doh as dns_module
from lantern.modules.domain.dns_doh import DnsDohCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


def _answer(request: httpx.Request) -> httpx.Response:
    rtype = request.url.params.get("type")
    answers = {
        "A": [{"type": 1, "data": "93.184.216.34"}],
        "MX": [{"type": 15, "data": "10 mail.example.com."}],
    }
    return httpx.Response(200, json={"Status": 0, "Answer": answers.get(rtype, [])})


@respx.mock
async def test_collect_returns_a_finding_per_record_type_with_answers(tmp_path: Path) -> None:
    respx.get(dns_module.RESOLVE_URL).mock(side_effect=_answer)
    findings = await DnsDohCollector().collect("example.com", EntityType.DOMAIN, _context(tmp_path))

    by_type = {f.data["record_type"]: f.data["records"] for f in findings}
    assert by_type["A"] == ["93.184.216.34"]
    assert by_type["MX"] == ["10 mail.example.com."]
    assert "AAAA" not in by_type  # empty answer → no finding
    assert all(f.confidence == 0.9 for f in findings)


@respx.mock
async def test_nxdomain_yields_nothing(tmp_path: Path) -> None:
    respx.get(dns_module.RESOLVE_URL).mock(return_value=httpx.Response(200, json={"Status": 3}))
    findings = await DnsDohCollector().collect("no-such.example", EntityType.DOMAIN, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_total_failure_is_not_cached(tmp_path: Path) -> None:
    route = respx.get(dns_module.RESOLVE_URL).mock(side_effect=httpx.ConnectError("boom"))
    ctx = _context(tmp_path)
    assert await DnsDohCollector().collect("example.com", EntityType.DOMAIN, ctx) == []
    # Every lookup failed → nothing cached → a retry hits the network again.
    route.mock(side_effect=_answer)
    findings = await DnsDohCollector().collect("example.com", EntityType.DOMAIN, ctx)
    assert len(findings) > 0


@respx.mock
async def test_partial_failure_still_returns_the_successes(tmp_path: Path) -> None:
    def partial(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("type") == "TXT":
            raise httpx.ConnectError("txt down")
        return _answer(request)

    respx.get(dns_module.RESOLVE_URL).mock(side_effect=partial)
    findings = await DnsDohCollector().collect("example.com", EntityType.DOMAIN, _context(tmp_path))
    assert {f.data["record_type"] for f in findings} == {"A", "MX"}
