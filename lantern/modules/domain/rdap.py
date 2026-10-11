from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.rdap")

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE_KEY = "dns.json"
BOOTSTRAP_TTL_SECONDS = 24 * 60 * 60
RESULT_TTL_SECONDS = 60 * 60
REQUEST_TIMEOUT = 10.0


class RdapCollector(Collector):
    """WHOIS was sunset for gTLDs on 2025-01-28; RDAP is the JSON
    replacement. Resolves the right RDAP server per-TLD from IANA's
    bootstrap registry rather than hardcoding one.
    """

    name = "rdap"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=5, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        base_url = await self._find_rdap_server(ctx, query)
        if base_url is None:
            logger.info("%s: no RDAP server registered for %s", self.name, query)
            return []

        try:
            data = await ctx.cache.get_or_set(
                self.name,
                f"domain:{query}",
                RESULT_TTL_SECONDS,
                lambda: self._fetch_domain(ctx, base_url, query),
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as "not registered," or it suppresses
            # every retry for the full TTL.
            logger.warning("%s: request failed for %s: %s", self.name, query, exc)
            return []
        if not data:
            return []

        return [
            Finding(
                source=self.name,
                entity_type=EntityType.DOMAIN,
                value=query,
                data=_summarize(data),
                confidence=0.9,
                url=f"{base_url.rstrip('/')}/domain/{query}",
            )
        ]

    async def _find_rdap_server(self, ctx: Context, domain: str) -> str | None:
        tld = domain.rstrip(".").rsplit(".", 1)[-1].lower()
        try:
            bootstrap = await ctx.cache.get_or_set(
                self.name, BOOTSTRAP_CACHE_KEY, BOOTSTRAP_TTL_SECONDS, lambda: self._fetch_bootstrap(ctx)
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: failed to load bootstrap registry: %s", self.name, exc)
            return None
        if not bootstrap:
            return None
        for tlds, urls in bootstrap.get("services", []):
            if urls and tld in (t.lower() for t in tlds):
                return urls[0]
        return None

    async def _fetch_bootstrap(self, ctx: Context) -> dict | None:
        # No try/except here on purpose — see _find_rdap_server's comment.
        response = await ctx.http.get(
            BOOTSTRAP_URL, headers={"User-Agent": ctx.settings.user_agent}, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    async def _fetch_domain(self, ctx: Context, base_url: str, domain: str) -> dict | None:
        # No try/except here on purpose — see collect()'s comment.
        url = f"{base_url.rstrip('/')}/domain/{domain}"
        response = await ctx.http.get(
            url, headers={"User-Agent": ctx.settings.user_agent}, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()


def _summarize(data: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if e.get("eventAction")}
    return {
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
    }
