from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.settings import SettingsError
from lantern.modules.base import Collector, Context, RateLimit


class StubCollector(Collector):
    name = "stub"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=100, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        return [Finding(source=self.name, entity_type=entity_type, value=query, confidence=0.7)]


class OtherStubCollector(Collector):
    name = "other-stub"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=100, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        return [Finding(source=self.name, entity_type=entity_type, value=query, confidence=0.7)]


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CONTACT_EMAIL", "test@example.com")
    monkeypatch.setenv("API_BEARER_TOKEN", "secret-token")
    monkeypatch.setattr("lantern.api.app.default_collectors", lambda: [StubCollector()])

    import lantern.api.app as app_module

    return app_module.create_app()


@pytest.fixture
def api_app_two_sources(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CONTACT_EMAIL", "test@example.com")
    monkeypatch.setenv("API_BEARER_TOKEN", "secret-token")
    monkeypatch.setattr(
        "lantern.api.app.default_collectors", lambda: [StubCollector(), OtherStubCollector()]
    )

    import lantern.api.app as app_module

    return app_module.create_app()


def test_search_without_token_is_rejected(api_app) -> None:
    with TestClient(api_app) as client:
        response = client.get("/search", params={"q": "example.com"})
    assert response.status_code == 401


def test_search_with_wrong_token_is_rejected(api_app) -> None:
    with TestClient(api_app) as client:
        response = client.get(
            "/search", params={"q": "example.com"}, headers={"Authorization": "Bearer wrong"}
        )
    assert response.status_code == 401


def test_search_with_valid_token_streams_findings_then_done(api_app) -> None:
    with TestClient(api_app) as client:
        response = client.get(
            "/search", params={"q": "example.com"}, headers={"Authorization": "Bearer secret-token"}
        )

    assert response.status_code == 200
    body = response.text
    assert "event: sources" in body
    assert '"sources": ["stub"]' in body
    assert "event: finding" in body
    assert "event: done" in body
    assert '"source": "stub"' in body
    assert '"nodes"' in body
    assert '"edges"' in body


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_auto_docs_routes_are_disabled(api_app, path: str) -> None:
    with TestClient(api_app) as client:
        response = client.get(path)
    assert response.status_code == 404


def test_missing_query_param_is_rejected(api_app) -> None:
    with TestClient(api_app) as client:
        response = client.get("/search", headers={"Authorization": "Bearer secret-token"})
    assert response.status_code == 422


def test_sources_endpoint_lists_every_registered_collector(api_app_two_sources) -> None:
    with TestClient(api_app_two_sources) as client:
        response = client.get("/sources", headers={"Authorization": "Bearer secret-token"})

    assert response.status_code == 200
    assert response.json() == {"sources": ["other-stub", "stub"]}


def test_sources_endpoint_requires_a_token(api_app_two_sources) -> None:
    with TestClient(api_app_two_sources) as client:
        response = client.get("/sources")
    assert response.status_code == 401


def test_search_with_sources_param_restricts_which_collectors_run(api_app_two_sources) -> None:
    with TestClient(api_app_two_sources) as client:
        response = client.get(
            "/search",
            params={"q": "example.com", "sources": "stub"},
            headers={"Authorization": "Bearer secret-token"},
        )

    assert response.status_code == 200
    body = response.text
    assert '"sources": ["stub"]' in body
    assert '"source": "stub"' in body
    assert '"source": "other-stub"' not in body


def test_search_without_sources_param_runs_every_applicable_collector(api_app_two_sources) -> None:
    with TestClient(api_app_two_sources) as client:
        response = client.get(
            "/search", params={"q": "example.com"}, headers={"Authorization": "Bearer secret-token"}
        )

    assert response.status_code == 200
    body = response.text
    assert '"source": "stub"' in body
    assert '"source": "other-stub"' in body


def test_startup_fails_without_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTACT_EMAIL", "test@example.com")
    monkeypatch.delenv("API_BEARER_TOKEN", raising=False)
    monkeypatch.setattr("lantern.api.app.default_collectors", lambda: [StubCollector()])

    import lantern.api.app as app_module

    app = app_module.create_app()
    with pytest.raises(SettingsError):
        with TestClient(app):
            pass
