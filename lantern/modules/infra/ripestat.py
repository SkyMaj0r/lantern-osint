from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.ripestat")

# RIPE NCC's RIPEstat Data API — keyless, no card, well maintained. (BGPView,
# the first choice here, was dropped: api.bgpview.io no longer resolves.)
# `sourceapp` is requested by RIPEstat's usage guidelines so they can identify
# traffic.
NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json"
PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
VISUALIZER_URL = "https://stat.ripe.net/{resource}"
SOURCE_APP = "lantern-osint"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 12 * 60 * 60


class RipeStatCollector(Collector):
    """IP -> network attribution: the covering prefix, its origin ASN(s), and
    the owning organization. Complements the reputation sources (VirusTotal,
    AbuseIPDB) and keyless Shodan with "who owns this address space." Keyless.
    """

    name = "ripestat"
    supported_types = {EntityType.IP}
    rate_limit = RateLimit(requests=5, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            info = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not info:
            return []

        return [
            Finding(
                source=self.name,
                entity_type=EntityType.IP,
                value=query,
                data={
                    "prefix": info["prefix"],
                    "asns": info["asns"],  # [{"asn": 15169, "holder": "GOOGLE - Google LLC"}]
                },
                confidence=0.6,
                url=VISUALIZER_URL.format(resource=query),
            )
        ]

    async def _fetch(self, ctx: Context, ip: str) -> dict | None:
        # No try/except here — see collect().
        net = await self._get(ctx, NETWORK_INFO_URL, ip)
        prefix = net.get("prefix")
        asns = net.get("asns") or []
        if not prefix and not asns:
            return None  # RIPEstat has nothing for this address — cacheable empty.

        holders = []
        if prefix:
            overview = await self._get(ctx, PREFIX_OVERVIEW_URL, prefix)
            holders = overview.get("asns") or []
        holder_by_asn = {str(h.get("asn")): h.get("holder") for h in holders}

        return {
            "prefix": prefix,
            "asns": [{"asn": asn, "holder": holder_by_asn.get(str(asn))} for asn in asns],
        }

    async def _get(self, ctx: Context, url: str, resource: str) -> dict:
        response = await ctx.http.get(
            url,
            params={"resource": resource, "sourceapp": SOURCE_APP},
            headers={"User-Agent": ctx.settings.user_agent, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("data", {})
