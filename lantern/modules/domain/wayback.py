from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.wayback")

CDX_URL = "https://web.archive.org/cdx/search/cdx"
SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}/{original}"
REQUEST_TIMEOUT = 20.0  # CDX is often slow.
RESULT_TTL_SECONDS = 24 * 60 * 60
_FIELDS = "timestamp,original,statuscode"


class WaybackCollector(Collector):
    """Internet Archive Wayback Machine — proof a domain existed and when,
    via its CDX index. Keyless. Surfaces the first and most recent captures,
    so a domain that's since gone dark still shows its history.

    CDX is flaky (504s are common and transient), so any non-2xx is treated
    as a transient failure and left uncached — only a genuinely empty index
    (domain never archived) is cached as "no captures."
    """

    name = "wayback"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=1, per_seconds=2.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            summary = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not summary:
            return []

        newest = summary["last"]
        return [
            Finding(
                source=self.name,
                entity_type=EntityType.DOMAIN,
                value=query,
                data={
                    "first_capture": summary["first"][0],
                    "last_capture": newest[0],
                },
                confidence=0.7,
                url=SNAPSHOT_URL.format(timestamp=newest[0], original=newest[1]),
            )
        ]

    async def _fetch(self, ctx: Context, domain: str) -> dict | None:
        # No try/except here — see collect(). CDX raises on 5xx (transient);
        # an empty index body is a real "never archived" (cacheable).
        first = await self._query(ctx, domain, newest=False)
        if not first:
            return None
        last = await self._query(ctx, domain, newest=True)
        return {"first": first, "last": last or first}

    async def _query(self, ctx: Context, domain: str, *, newest: bool) -> list[str] | None:
        response = await ctx.http.get(
            CDX_URL,
            params={
                "url": domain,
                "output": "json",
                "fl": _FIELDS,
                # limit=-1 returns the row from the end of the index (newest);
                # limit=1 the oldest.
                "limit": -1 if newest else 1,
            },
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        text = response.text.strip()
        if not text:
            return None
        rows = response.json()
        # Row 0 is the field header; data rows follow.
        return rows[1] if len(rows) > 1 else None
