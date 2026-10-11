from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.ratelimit import SourceRateLimiter
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.xposedornot")

CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"
ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
REQUEST_TIMEOUT = 10.0
CACHE_TTL_SECONDS = 6 * 60 * 60


class XposedOrNotCollector(Collector):
    """Free, keyless breach lookup — the primary email breach source.
    Throttled to ~1 req/s per the source's own guidance, across both of
    its endpoints.
    """

    name = "xposedornot"
    supported_types = {EntityType.EMAIL}
    rate_limit = RateLimit(requests=1, per_seconds=1.0)
    requires_key = False

    def __init__(self) -> None:
        # Paces this module's own internal calls; the dispatcher-level
        # rate_limit above only throttles how often collect() itself runs.
        self._internal_limiter = SourceRateLimiter(RateLimit(requests=1, per_seconds=1.0))

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []

        check = await self._get_or_set_safely(
            ctx,
            f"check:{query}",
            lambda: self._fetch(ctx, CHECK_URL.format(email=query)),
        )
        for group in (check or {}).get("breaches", []):
            for breach in group:
                findings.append(
                    Finding(
                        source=self.name,
                        entity_type=EntityType.EMAIL,
                        value=query,
                        data={"breach": breach},
                        confidence=0.9,
                    )
                )

        analytics = await self._get_or_set_safely(
            ctx,
            f"analytics:{query}",
            lambda: self._fetch(ctx, ANALYTICS_URL, params={"email": query}),
        )
        if analytics and "Error" not in analytics:
            findings.append(
                Finding(
                    source=self.name,
                    entity_type=EntityType.EMAIL,
                    value=query,
                    data={"type": "analytics", **analytics},
                    confidence=0.6,
                )
            )

        return findings

    async def _get_or_set_safely(self, ctx: Context, key: str, fetch) -> dict | None:
        # Kept outside Cache.get_or_set on purpose: a transient failure
        # (network blip, rate limit, bad JSON) must never get cached as a
        # legitimate "no data" result, or it suppresses every retry for
        # the full TTL. Each of collect()'s two calls gets its own try, so
        # one endpoint failing doesn't take the other down with it.
        try:
            return await ctx.cache.get_or_set(self.name, key, CACHE_TTL_SECONDS, fetch)
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: request failed: %s", self.name, exc)
            return None

    async def _fetch(self, ctx: Context, url: str, params: dict | None = None) -> dict | None:
        # No try/except here on purpose — see _get_or_set_safely.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            url,
            params=params,
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
