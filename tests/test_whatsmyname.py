from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.username import whatsmyname as wmn_module
from lantern.modules.username.whatsmyname import WhatsMyNameCollector

WMN_FIXTURE = {
    "sites": [
        {
            "name": "GitHub",
            "cat": "coding",
            "uri_check": "https://github.com/{account}",
            "uri_pretty": "https://github.com/{account}",
            "e_code": 200,
            "e_string": "Repositories",
        },
        {
            "name": "ExampleSite",
            "cat": "misc",
            "uri_check": "https://example-site.test/{account}",
            "e_code": 200,
            "e_string": "Profile found",
        },
        {
            "name": "BrokenSite",
            "cat": "misc",
            "uri_check": "https://broken-site.test/{account}",
            "e_code": 200,
            "e_string": "Profile found",
        },
    ]
}


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


@respx.mock
async def test_collect_returns_finding_for_matched_site(tmp_path: Path) -> None:
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/johndoe").mock(
        return_value=httpx.Response(200, text="<html>Repositories: 4</html>")
    )
    respx.get("https://example-site.test/johndoe").mock(return_value=httpx.Response(404, text="Not here"))
    respx.get("https://broken-site.test/johndoe").mock(return_value=httpx.Response(200, text="nope"))

    ctx = _context(tmp_path)
    collector = WhatsMyNameCollector()
    findings = await collector.collect("johndoe", EntityType.USERNAME, ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "whatsmyname"
    assert finding.data["site"] == "GitHub"
    assert finding.confidence == 0.8
    assert finding.url == "https://github.com/johndoe"


@respx.mock
async def test_collect_skips_site_when_string_absent_despite_matching_code(tmp_path: Path) -> None:
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/janedoe").mock(return_value=httpx.Response(200, text="no match here"))
    respx.get("https://example-site.test/janedoe").mock(return_value=httpx.Response(200, text="also no match"))
    respx.get("https://broken-site.test/janedoe").mock(return_value=httpx.Response(200, text="still no match"))

    ctx = _context(tmp_path)
    findings = await WhatsMyNameCollector().collect("janedoe", EntityType.USERNAME, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_a_site_erroring_and_keeps_other_results(tmp_path: Path) -> None:
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/johndoe").mock(
        return_value=httpx.Response(200, text="Repositories: 4")
    )
    respx.get("https://example-site.test/johndoe").mock(side_effect=httpx.ConnectError("boom"))
    respx.get("https://broken-site.test/johndoe").mock(side_effect=httpx.ConnectTimeout("timed out"))

    ctx = _context(tmp_path)
    findings = await WhatsMyNameCollector().collect("johndoe", EntityType.USERNAME, ctx)

    assert len(findings) == 1
    assert findings[0].data["site"] == "GitHub"


@respx.mock
async def test_collect_tolerates_non_http_errors_from_a_site(tmp_path: Path) -> None:
    # Regression test: a real run hit an SSRFError (not an httpx.HTTPError
    # subclass) from one dead-domain site, which wasn't caught and killed
    # the whole asyncio.gather() — losing every other site's result.
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/johndoe").mock(return_value=httpx.Response(200, text="Repositories"))
    respx.get("https://example-site.test/johndoe").mock(side_effect=RuntimeError("boom"))
    respx.get("https://broken-site.test/johndoe").mock(side_effect=RuntimeError("boom"))

    ctx = _context(tmp_path)
    findings = await WhatsMyNameCollector().collect("johndoe", EntityType.USERNAME, ctx)

    assert len(findings) == 1
    assert findings[0].data["site"] == "GitHub"


@respx.mock
async def test_person_is_expanded_into_handle_permutations(tmp_path: Path) -> None:
    # A full name never matches a site directly; WhatsMyName pivots it through
    # likely handles. "John Doe" -> johndoe (+ others), and the GitHub fixture
    # site matches the johndoe profile.
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/johndoe").mock(return_value=httpx.Response(200, text="Repositories"))
    respx.route().mock(return_value=httpx.Response(404, text="no match"))  # every other handle x site

    ctx = _context(tmp_path)
    findings = await WhatsMyNameCollector().collect("John Doe", EntityType.PERSON, ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.data["site"] == "GitHub"
    assert finding.data["matched_handle"] == "johndoe"
    assert finding.data["from_name"] == "John Doe"
    assert finding.confidence == 0.5  # lower than a given handle's 0.8
    assert finding.value == "johndoe"


@respx.mock
async def test_data_file_is_cached_across_calls(tmp_path: Path) -> None:
    data_route = respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/alice").mock(return_value=httpx.Response(200, text="Repositories"))
    respx.get("https://example-site.test/alice").mock(return_value=httpx.Response(404))
    respx.get("https://broken-site.test/alice").mock(return_value=httpx.Response(404))

    ctx = _context(tmp_path)
    collector = WhatsMyNameCollector()
    await collector.collect("alice", EntityType.USERNAME, ctx)
    await collector.collect("alice", EntityType.USERNAME, ctx)

    assert data_route.call_count == 1


@respx.mock
async def test_username_is_url_encoded_in_check_url(tmp_path: Path) -> None:
    respx.get(wmn_module.DATA_URL).mock(return_value=httpx.Response(200, json=WMN_FIXTURE))
    respx.get("https://github.com/john%2Fdoe").mock(return_value=httpx.Response(200, text="Repositories"))
    respx.get("https://example-site.test/john%2Fdoe").mock(return_value=httpx.Response(404))
    respx.get("https://broken-site.test/john%2Fdoe").mock(return_value=httpx.Response(404))

    ctx = _context(tmp_path)
    findings = await WhatsMyNameCollector().collect("john/doe", EntityType.USERNAME, ctx)

    assert len(findings) == 1
    assert findings[0].url == "https://github.com/john%2Fdoe"
