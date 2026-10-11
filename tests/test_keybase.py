from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.username import keybase as kb_module
from lantern.modules.username.keybase import KeybaseCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


def _ok(entries: list[dict]) -> dict:
    return {"status": {"code": 0, "name": "OK"}, "list": entries}


@respx.mock
async def test_person_search_returns_profiles(tmp_path: Path) -> None:
    respx.get(kb_module.SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json=_ok([{"keybase": {"username": "linustorvalds", "full_name": "Linus Torvalds", "uid": "abc"}}]),
        )
    )
    findings = await KeybaseCollector().collect("Linus Torvalds", EntityType.PERSON, _context(tmp_path))

    assert len(findings) == 1
    assert findings[0].value == "linustorvalds"
    assert findings[0].url == "https://keybase.io/linustorvalds"
    assert findings[0].confidence == 0.4
    assert findings[0].data["from_name"] == "Linus Torvalds"


@respx.mock
async def test_exact_username_match_scores_higher(tmp_path: Path) -> None:
    respx.get(kb_module.SEARCH_URL).mock(
        return_value=httpx.Response(200, json=_ok([{"keybase": {"username": "chris", "uid": "x"}}]))
    )
    findings = await KeybaseCollector().collect("Chris", EntityType.USERNAME, _context(tmp_path))
    assert findings[0].confidence == 0.7  # case-insensitive exact handle


@respx.mock
async def test_entry_without_username_is_skipped(tmp_path: Path) -> None:
    respx.get(kb_module.SEARCH_URL).mock(
        return_value=httpx.Response(200, json=_ok([{"keybase": {"full_name": "No Handle"}}]))
    )
    findings = await KeybaseCollector().collect("No Handle", EntityType.PERSON, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_non_ok_status_is_not_cached_as_empty(tmp_path: Path) -> None:
    route = respx.get(kb_module.SEARCH_URL).mock(
        return_value=httpx.Response(200, json={"status": {"code": 100, "name": "ERR"}})
    )
    ctx = _context(tmp_path)
    assert await KeybaseCollector().collect("x", EntityType.USERNAME, ctx) == []
    # The error must not have been cached — a retry should hit the API again.
    route.mock(return_value=httpx.Response(200, json=_ok([{"keybase": {"username": "x", "uid": "1"}}])))
    findings = await KeybaseCollector().collect("x", EntityType.USERNAME, ctx)
    assert len(findings) == 1
