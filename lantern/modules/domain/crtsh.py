from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.crtsh")

SEARCH_URL = "https://crt.sh/"
RESULT_TTL_SECONDS = 60 * 60
REQUEST_TIMEOUT = 20.0  # crt.sh can be slow under load


class CrtShCollector(Collector):
    """Certificate-transparency subdomain discovery via crt.sh's JSON output."""

    name = "crtsh"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=1, per_seconds=2.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            data = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — crt.sh is known to be flaky
            # (observed live 502s); a transient failure must never get
            # cached as "no subdomains," or it suppresses every retry for
            # the full TTL, including after the source recovers.
            logger.warning("%s: request failed for %s: %s", self.name, query, exc)
            return []
        if not data:
            return []

        domain_lower = query.lower()
        subdomains: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name and (name == domain_lower or name.endswith(f".{domain_lower}")):
                    subdomains.add(name)

        return [
            Finding(
                source=self.name,
                entity_type=EntityType.DOMAIN,
                value=name,
                data={"discovered_via": query},
                confidence=0.7,
                url=f"https://crt.sh/?q={query}",
            )
            for name in sorted(subdomains)
        ]

    async def _fetch(self, ctx: Context, domain: str) -> list[dict] | None:
        # No try/except here on purpose — see collect()'s comment.
        response = await ctx.http.get(
            SEARCH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
