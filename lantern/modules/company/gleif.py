from __future__ import annotations

import asyncio
import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.ratelimit import SourceRateLimiter
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.gleif")

SEARCH_URL = "https://api.gleif.org/api/v1/lei-records"
RESULT_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT = 10.0
MAX_RESULTS = 5
ACCEPT_HEADER = "application/vnd.api+json"


class GleifCollector(Collector):
    """GLEIF LEI lookup by company name. Free, no registration, no key.
    Follows each result's ultimate-parent link (when present) for the
    parent's legal name, bounded to MAX_RESULTS extra calls.
    """

    name = "gleif"
    supported_types = {EntityType.COMPANY}
    rate_limit = RateLimit(requests=5, per_seconds=1.0)
    requires_key = False

    def __init__(self) -> None:
        self._internal_limiter = SourceRateLimiter(RateLimit(requests=5, per_seconds=1.0))

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            records = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._search(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as "no matches" for 24h.
            logger.warning("%s: search failed for %s: %s", self.name, query, exc)
            return []
        if not records:
            return []

        return list(await asyncio.gather(*(self._to_finding(ctx, record) for record in records)))

    async def _search(self, ctx: Context, query: str) -> list[dict] | None:
        # No try/except here on purpose — see collect()'s comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            SEARCH_URL,
            params={"filter[fulltext]": query, "page[size]": MAX_RESULTS},
            headers={"User-Agent": ctx.settings.user_agent, "Accept": ACCEPT_HEADER},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("data", [])

    async def _to_finding(self, ctx: Context, record: dict) -> Finding:
        attrs = record.get("attributes", {})
        entity = attrs.get("entity", {})
        legal_name = entity.get("legalName", {}).get("name", "")
        address = entity.get("legalAddress", {})
        lei = record.get("id")

        parent_link = (
            (record.get("relationships", {}).get("ultimate-parent") or {})
            .get("links", {})
            .get("related")
        )
        parent_name = None
        if parent_link:
            try:
                parent_name = await ctx.cache.get_or_set(
                    self.name,
                    f"parent:{lei}",
                    RESULT_TTL_SECONDS,
                    lambda: self._fetch_parent_name(ctx, parent_link),
                )
            except (httpx.HTTPError, ValueError) as exc:
                # Caught here, not propagated: this runs under
                # asyncio.gather over up to MAX_RESULTS records — letting
                # it propagate would lose every other record's Finding
                # too, not just this one's parent_name. A transient
                # failure also must never get cached as "no parent."
                logger.debug("%s: parent lookup failed for %s: %s", self.name, lei, exc)

        return Finding(
            source=self.name,
            entity_type=EntityType.COMPANY,
            value=legal_name,
            data={
                "lei": lei,
                "jurisdiction": entity.get("legalJurisdiction"),
                "status": entity.get("status"),
                "address": {"city": address.get("city"), "country": address.get("country")},
                "parent_name": parent_name,
            },
            confidence=0.85,
            url=f"https://search.gleif.org/#/record/{lei}",
        )

    async def _fetch_parent_name(self, ctx: Context, link: str) -> str | None:
        # No try/except here on purpose — see _to_finding's comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            link, headers={"User-Agent": ctx.settings.user_agent, "Accept": ACCEPT_HEADER}, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return data.get("attributes", {}).get("entity", {}).get("legalName", {}).get("name")
