from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from lantern.core.cache import Cache
from lantern.core.settings import Settings, get_settings
from lantern.modules.base import Context


def make_settings(**overrides) -> Settings:
    return Settings(contact_email="test@example.com", api_bearer_token="token", **overrides)


@pytest.fixture
def ctx(tmp_path: Path) -> Context:
    return Context(http=httpx.AsyncClient(), cache=Cache(tmp_path / "cache.db"), settings=make_settings())


@pytest.fixture(autouse=True)
def _hermetic_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    # get_settings() is @lru_cache'd for real process lifetimes (CLI, API
    # server) — across tests in one pytest session that would leak the
    # first test's env vars into every later one that calls it.
    get_settings.cache_clear()
    # Tests shouldn't depend on whatever the developer's real .env on disk
    # happens to contain — only on env vars a test sets explicitly.
    monkeypatch.setattr("lantern.core.settings.load_dotenv", lambda *a, **k: None)
    yield
    get_settings.cache_clear()
