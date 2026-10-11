from __future__ import annotations

import asyncio
import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.dns_doh")

# Google's DNS-over-HTTPS JSON endpoint. Cloudflare's
# (https://cloudflare-dns.com/dns-query, Accept: application/dns-json) is an
# equivalent drop-in if Google ever needs replacing.
RESOLVE_URL = "https://dns.google/resolve"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 60 * 60  # DNS changes; keep it fresh-ish.


class DnsDohCollector(Collector):
    """Live DNS resolution over HTTPS — the records a domain actually
    publishes right now (A/AAAA/MX/NS/TXT), which RDAP (registration) and
    crt.sh (certificates) don't give. Keyless.

    One request per record type, fanned out concurrently. A single type
    failing (transport error) is tolerated; only a total wipeout — every
    type erroring — is treated as transient and left uncached, so a flaky
    moment can't poison the cache with a false "no records."
    """

    name = "dns-doh"
    supported_types = {EntityType.DOMAIN}
    rate_limit = RateLimit(requests=10, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            records = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._resolve_all(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: resolve failed for %s: %s", self.name, query, exc)
            return []
        if not records:
            return []
        return [
            Finding(
                source=self.name,
                entity_type=EntityType.DOMAIN,
                value=query,
                data={"record_type": record_type, "records": values},
                confidence=0.9,  # authoritative DNS — strong signal
                url=None,
            )
            for record_type, values in records.items()
            if values
        ]

    async def _resolve_all(self, ctx: Context, domain: str) -> dict[str, list[str]] | None:
        # No try/except around the cache call — see collect(). Here we gather
        # every record type and keep the successes; a NXDOMAIN/no-answer is a
        # real empty (cacheable), a transport error is not.
        results = await asyncio.gather(
            *(self._query(ctx, domain, rtype) for rtype in RECORD_TYPES),
            return_exceptions=True,
        )
        resolved: dict[str, list[str]] = {}
        errors = 0
        for rtype, outcome in zip(RECORD_TYPES, results):
            if isinstance(outcome, Exception):
                errors += 1
                continue
            resolved[rtype] = outcome
        if errors == len(RECORD_TYPES):
            # Every lookup failed — transient, don't let get_or_set cache it.
            raise httpx.HTTPError(f"all DNS lookups failed for {domain}")
        return resolved

    async def _query(self, ctx: Context, domain: str, record_type: str) -> list[str]:
        response = await ctx.http.get(
            RESOLVE_URL,
            params={"name": domain, "type": record_type},
            headers={"User-Agent": ctx.settings.user_agent, "Accept": "application/dns-json"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        # Status 0 == NOERROR. 3 == NXDOMAIN. Anything non-zero means no usable
        # answer for this type — a real empty, not an error.
        if data.get("Status") != 0:
            return []
        return [answer["data"] for answer in data.get("Answer", []) if answer.get("data")]
