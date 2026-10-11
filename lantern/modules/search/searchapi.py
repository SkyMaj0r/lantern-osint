from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.searchapi")

SEARCH_URL = "https://www.searchapi.io/api/v1/search"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 60 * 60
MAX_RESULTS = 10


class SearchApiCollector(Collector):
    """Optional general web search enrichment via SearchApi.io's Google
    engine. Free tier: 100 queries total, a one-time trial — does not
    reset monthly. Needs a free key — skipped gracefully
    (dispatcher-level, via api_key_setting) when SEARCHAPI_API_KEY isn't
    set.

    Built as a replacement for the Gemini-grounding search module, which was
    fully removed (see ARCHITECTURE.md) after Google's Search grounding tool
    kept returning 429 RESOURCE_EXHAUSTED as an account-level entitlement
    issue, not something fixable in this codebase.

    Scoped to PERSON and DOMAIN only: USERNAME/COMPANY are already covered
    by WhatsMyName/SEC-EDGAR/GLEIF, and including them would make
    general-search collectors fire 2-3x on one ambiguous query for no
    added benefit.
    """

    name = "searchapi"
    supported_types = {EntityType.PERSON, EntityType.DOMAIN}
    rate_limit = RateLimit(requests=1, per_seconds=1.0)
    requires_key = True
    api_key_setting = "searchapi_api_key"

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        if not ctx.settings.searchapi_api_key:
            # The dispatcher normally gates this via api_key_setting before
            # ever calling collect() — this is a defensive fallback so a
            # direct call can't crash on a None param value instead of
            # degrading gracefully.
            logger.info("%s: no API key configured", self.name)
            return []

        try:
            results = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._search(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as "no results," or it suppresses every
            # retry for the full TTL.
            logger.warning("%s: search failed for %s: %s", self.name, query, exc)
            return []
        if not results:
            return []
        return [
            Finding(
                source=self.name,
                entity_type=entity_type,
                value=result.get("title") or query,
                data={"description": result.get("snippet")},
                confidence=0.5,
                url=result.get("link"),
            )
            for result in results[:MAX_RESULTS]
        ]

    async def _search(self, ctx: Context, query: str) -> list[dict] | None:
        # No try/except here on purpose — see collect()'s comment.
        response = await ctx.http.get(
            SEARCH_URL,
            params={
                "engine": "google",
                "q": query,
                "api_key": ctx.settings.searchapi_api_key,
            },
            headers={
                "User-Agent": ctx.settings.user_agent,
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("organic_results", [])
