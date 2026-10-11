from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.username import github_users as gh_module
from lantern.modules.username.github_users import GitHubUsersCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


@respx.mock
async def test_username_does_exact_profile_lookup(tmp_path: Path) -> None:
    respx.get(gh_module.USER_URL.format(username="torvalds")).mock(
        return_value=httpx.Response(
            200,
            json={"login": "torvalds", "name": "Linus Torvalds", "html_url": "https://github.com/torvalds", "type": "User"},
        )
    )
    findings = await GitHubUsersCollector().collect("torvalds", EntityType.USERNAME, _context(tmp_path))

    assert len(findings) == 1
    assert findings[0].value == "torvalds"
    assert findings[0].data["name"] == "Linus Torvalds"
    assert findings[0].confidence == 0.7
    assert "from_name" not in findings[0].data


@respx.mock
async def test_username_404_is_no_finding(tmp_path: Path) -> None:
    respx.get(gh_module.USER_URL.format(username="nope")).mock(return_value=httpx.Response(404))
    findings = await GitHubUsersCollector().collect("nope", EntityType.USERNAME, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_person_uses_name_search(tmp_path: Path) -> None:
    respx.get(gh_module.SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {"login": "torvalds", "html_url": "https://github.com/torvalds", "type": "User"},
                    {"login": "someoneelse", "html_url": "https://github.com/someoneelse", "type": "User"},
                ]
            },
        )
    )
    findings = await GitHubUsersCollector().collect("Linus Torvalds", EntityType.PERSON, _context(tmp_path))

    assert [f.value for f in findings] == ["torvalds", "someoneelse"]
    assert all(f.confidence == 0.45 for f in findings)
    assert all(f.data["from_name"] == "Linus Torvalds" for f in findings)


@respx.mock
async def test_transient_error_is_not_cached(tmp_path: Path) -> None:
    route = respx.get(gh_module.USER_URL.format(username="torvalds")).mock(
        side_effect=httpx.ConnectError("boom")
    )
    ctx = _context(tmp_path)
    assert await GitHubUsersCollector().collect("torvalds", EntityType.USERNAME, ctx) == []
    # A second call must retry, not serve a cached empty from the failure.
    route.mock(return_value=httpx.Response(200, json={"login": "torvalds", "html_url": "https://github.com/torvalds", "type": "User"}))
    findings = await GitHubUsersCollector().collect("torvalds", EntityType.USERNAME, ctx)
    assert len(findings) == 1
