from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.wikipedia")

OPENSEARCH_URL = "https://en.wikipedia.org/w/api.php"
SUMMARY_URL = "https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 24 * 60 * 60


class WikipediaCollector(Collector):
    """Free, no key, no signup, ever — a genuinely zero-friction general
    search source, unlike SearchApi.io (one-time 100-search trial, doesn't
    renew). Finds a notable person's/company's page by name and surfaces
    its summary.

    Scoped to PERSON and DOMAIN, matching searchapi: PERSON has no other
    collector, DOMAIN never bundles with other ambiguous types. COMPANY is
    deliberately left out — it's already bundled with PERSON in
    multi-word ambiguous queries (classify()), so adding both here would
    fire this collector twice on one query.
    """

    name = "wikipedia"
    supported_types = {EntityType.PERSON, EntityType.DOMAIN}
    rate_limit = RateLimit(requests=5, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            summary = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._lookup(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as "no page found," or it suppresses every
            # retry for the full TTL.
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not summary:
            return []

        return [
            Finding(
                source=self.name,
                entity_type=entity_type,
                value=summary.get("title", query),
                data={
                    "summary": summary.get("extract", "")[:500],
                    "wikidata_id": summary.get("wikibase_item"),
                },
                confidence=0.6,
                url=summary.get("content_urls", {}).get("desktop", {}).get("page"),
            )
        ]

    async def _lookup(self, ctx: Context, query: str) -> dict | None:
        # No try/except in here or in _find_title, on purpose — see
        # collect()'s comment. A 404 here is the one legitimate "no page"
        # signal (the title search already resolved a real title and the
        # summary endpoint still couldn't find it), so it alone is still
        # safe to treat as a cacheable empty result.
        title = await self._find_title(ctx, query)
        if not title:
            return None
        response = await ctx.http.get(
            SUMMARY_URL.format(title=title.replace(" ", "_")),
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        if data.get("type") == "disambiguation":
            return None
        return data

    async def _find_title(self, ctx: Context, query: str) -> str | None:
        response = await ctx.http.get(
            OPENSEARCH_URL,
            params={"action": "opensearch", "search": query, "limit": 1, "format": "json"},
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        titles = data[1] if len(data) > 1 else []
        return titles[0] if titles else None
