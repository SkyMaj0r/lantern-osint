from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest
import respx

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.settings import Settings
from lantern.modules.base import Context
from lantern.modules.email.gravatar import PROFILE_URL, GravatarCollector


def _settings() -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token")


def _context(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=_settings())


def _hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()


@respx.mock
async def test_profile_is_surfaced_with_linked_accounts(tmp_path: Path) -> None:
    digest = _hash("Alice@Example.com")  # hashing lowercases/trims
    respx.get(PROFILE_URL.format(hash=digest)).mock(
        return_value=httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "displayName": "Alice",
                        "profileUrl": "https://gravatar.com/alice",
                        "accounts": [
                            {"shortname": "github", "url": "https://github.com/alice"},
                            {"name": "Twitter", "url": "https://twitter.com/alice"},
                        ],
                    }
                ]
            },
        )
    )
    findings = await GravatarCollector().collect("Alice@Example.com", EntityType.EMAIL, _context(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.value == "Alice"
    assert f.url == "https://gravatar.com/alice"
    assert {a["service"] for a in f.data["accounts"]} == {"github", "Twitter"}


@respx.mock
async def test_no_profile_is_no_finding(tmp_path: Path) -> None:
    digest = _hash("nobody@example.com")
    respx.get(PROFILE_URL.format(hash=digest)).mock(return_value=httpx.Response(404))
    findings = await GravatarCollector().collect("nobody@example.com", EntityType.EMAIL, _context(tmp_path))
    assert findings == []


@respx.mock
async def test_transient_error_is_not_cached(tmp_path: Path) -> None:
    digest = _hash("alice@example.com")
    route = respx.get(PROFILE_URL.format(hash=digest)).mock(side_effect=httpx.ConnectError("boom"))
    ctx = _context(tmp_path)
    assert await GravatarCollector().collect("alice@example.com", EntityType.EMAIL, ctx) == []
    route.mock(return_value=httpx.Response(200, json={"entry": [{"displayName": "Alice", "profileUrl": "u"}]}))
    findings = await GravatarCollector().collect("alice@example.com", EntityType.EMAIL, ctx)
    assert len(findings) == 1
