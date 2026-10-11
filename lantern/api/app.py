from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lantern.core.cache import Cache
from lantern.core.correlator import build_graph, correlate
from lantern.core.dispatcher import Dispatcher
from lantern.core.entities import EntityType, classify, classify_as
from lantern.core.models import Finding
from lantern.core.settings import Settings, SettingsError, get_settings
from lantern.core.ssrf import build_guarded_client
from lantern.modules.base import Context
from lantern.modules.registry import default_collectors

logger = logging.getLogger("lantern.api")

# The web UI (Phase 6, Vite's default dev port) is the only expected
# browser caller, and only from the local machine — this API binds to
# 127.0.0.1 by default and is never meant to be exposed beyond it.
_WEB_UI_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if not settings.api_bearer_token:
        raise SettingsError("API_BEARER_TOKEN must be set to run the API (see .env.example)")

    client = build_guarded_client()
    ctx = Context(http=client, cache=Cache(settings.cache_path), settings=settings)
    dispatcher = Dispatcher(default_collectors(), make_context=lambda: ctx)

    app.state.settings = settings
    app.state.dispatcher = dispatcher
    try:
        yield
    finally:
        await client.aclose()


def create_app() -> FastAPI:
    # "Require a bearer token even for local use" is read as applying to
    # the whole API, not just /search — so the auto-generated docs/openapi
    # routes (which FastAPI would otherwise expose unauthenticated) are
    # disabled outright rather than individually protected.
    app = FastAPI(title="Lantern API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_WEB_UI_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["Authorization"],
    )

    bearer_scheme = HTTPBearer(auto_error=False)

    async def require_bearer_token(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> None:
        settings: Settings = app.state.settings
        if not credentials or credentials.credentials != settings.api_bearer_token:
            raise HTTPException(status_code=401, detail="Invalid or missing bearer token")

    @app.get("/sources", dependencies=[Depends(require_bearer_token)])
    async def sources() -> dict[str, list[str]]:
        dispatcher: Dispatcher = app.state.dispatcher
        return {"sources": sorted(dispatcher.collector_names)}

    @app.get("/search", dependencies=[Depends(require_bearer_token)])
    async def search(
        q: str = Query(..., min_length=1),
        sources: list[str] | None = Query(None),
        type: str | None = Query(None),
    ) -> StreamingResponse:
        dispatcher: Dispatcher = app.state.dispatcher
        enabled = set(sources) if sources else None
        return StreamingResponse(
            _stream_search(dispatcher, q, enabled, type), media_type="text/event-stream"
        )

    return app


async def _stream_search(
    dispatcher: Dispatcher,
    query: str,
    enabled: set[str] | None = None,
    type_override: str | None = None,
) -> AsyncIterator[str]:
    """SSE stream: a `sources` event listing every collector that will run
    (so the UI can show a pending state for each before any result
    arrives), one `finding` event per Finding as it arrives, then one
    final `done` event carrying the correlated entity graph (nodes =
    entities, edges = relationships). `enabled`, when given, restricts the
    run to that subset of collector names — the web UI's per-source
    toggle."""
    entity_type: EntityType | None = None
    if type_override is not None:
        try:
            entity_type = EntityType(type_override.lower())
        except ValueError:
            yield _sse_event("error", {"message": f"unknown type {type_override!r}"})
            return

    try:
        classification = (
            classify_as(query, entity_type) if entity_type is not None else classify(query)
        )
    except ValueError as exc:
        yield _sse_event("error", {"message": str(exc)})
        return

    source_names = sorted({collector.name for collector, _ in dispatcher.applicable(classification, enabled)})
    yield _sse_event("sources", {"sources": source_names})

    findings: list[Finding] = []
    try:
        async for finding in dispatcher.stream(query, enabled, entity_type):
            findings.append(finding)
            yield _sse_event("finding", finding.model_dump(mode="json"))
    except Exception:
        logger.exception("search stream failed for %r", query)
        yield _sse_event("error", {"message": "search failed"})
        return

    graph = build_graph(correlate(findings))
    yield _sse_event("done", graph.model_dump(mode="json"))


def _sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
