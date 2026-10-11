from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.virustotal")

DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 6 * 60 * 60


class VirusTotalCollector(Collector):
    """Domain/IP reputation via VirusTotal's public API v3 — free, no
    card, just a community API key. Rate limited to the free public tier's
    documented 4 requests/minute, 500/day (not enforced beyond the
    per-minute pacing below — staying under the daily cap is on the
    operator). Named in the original project brief as a gap; mentioned in
    ARCHITECTURE.md/CLAUDE.md as out of scope "so far" until this module.

    Scoped to IP and DOMAIN — both have a native VirusTotal endpoint, no
    DNS resolution needed (unlike Shodan's InternetDB, which only accepts
    an IP and resolves DOMAIN queries to one first).
    """

    name = "virustotal"
    supported_types = {EntityType.IP, EntityType.DOMAIN}
    rate_limit = RateLimit(requests=4, per_seconds=60.0)
    requires_key = True
    api_key_setting = "virustotal_api_key"

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        if not ctx.settings.virustotal_api_key:
            # The dispatcher normally gates this via api_key_setting before
            # ever calling collect() — this is a defensive fallback so a
            # direct call can't crash on a None header value instead of
            # degrading gracefully.
            logger.info("%s: no API key configured", self.name)
            return []

        try:
            data = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query, entity_type)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure (or a
            # 429 from exceeding the free tier's quota) must never get
            # cached as "not indexed," or it suppresses every retry for
            # the full TTL.
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not data:
            return []

        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        gui_path = "ip-address" if entity_type == EntityType.IP else "domain"

        return [
            Finding(
                source=self.name,
                entity_type=entity_type,
                value=query,
                data={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attributes.get("reputation"),
                    "categories": list(attributes.get("categories", {}).values()),
                },
                confidence=0.8 if malicious or suspicious else 0.5,
                url=f"https://www.virustotal.com/gui/{gui_path}/{query}",
            )
        ]

    async def _fetch(self, ctx: Context, query: str, entity_type: EntityType) -> dict | None:
        # No try/except here on purpose — see collect()'s comment.
        url = IP_URL.format(ip=query) if entity_type == EntityType.IP else DOMAIN_URL.format(domain=query)
        response = await ctx.http.get(
            url,
            headers={"User-Agent": ctx.settings.user_agent, "x-apikey": ctx.settings.virustotal_api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json().get("data", {})
