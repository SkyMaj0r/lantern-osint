from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.abuseipdb")

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 6 * 60 * 60
MAX_AGE_DAYS = 90


class AbuseIPDBCollector(Collector):
    """IP abuse/reputation reports via AbuseIPDB's free API v2 — free key,
    no card, 1,000 checks/day on the free tier (reset 00:00 UTC; not
    enforced beyond this module's per-call pacing — staying under the
    daily cap is on the operator). Pairs with shodan-internetdb: Shodan
    says what's running on an IP, this says whether other people have
    reported abuse from it.

    IP only, deliberately — unlike virustotal/shodan-internetdb, AbuseIPDB
    has no native domain endpoint, and this module doesn't resolve DOMAIN
    queries to an IP first (that resolve-then-fan-out behavior already
    exists in shodan_internetdb.py; duplicating it here for one more
    source isn't worth the added complexity for a DOMAIN-scoped check).
    """

    name = "abuseipdb"
    supported_types = {EntityType.IP}
    rate_limit = RateLimit(requests=1, per_seconds=2.0)
    requires_key = True
    api_key_setting = "abuseipdb_api_key"

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        if not ctx.settings.abuseipdb_api_key:
            # The dispatcher normally gates this via api_key_setting before
            # ever calling collect() — this is a defensive fallback so a
            # direct call can't crash on a None header value instead of
            # degrading gracefully.
            logger.info("%s: no API key configured", self.name)
            return []

        try:
            data = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure (or a
            # 429 from exceeding the free tier's daily quota) must never
            # get cached as "no reports," or it suppresses every retry for
            # the full TTL.
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not data:
            return []

        score = data.get("abuseConfidenceScore", 0)
        return [
            Finding(
                source=self.name,
                entity_type=entity_type,
                value=query,
                data={
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "is_tor": data.get("isTor", False),
                },
                confidence=0.85 if score > 0 else 0.4,
                url=f"https://www.abuseipdb.com/check/{query}",
            )
        ]

    async def _fetch(self, ctx: Context, query: str) -> dict | None:
        # No try/except here on purpose — see collect()'s comment.
        response = await ctx.http.get(
            CHECK_URL,
            params={"ipAddress": query, "maxAgeInDays": MAX_AGE_DAYS},
            headers={
                "User-Agent": ctx.settings.user_agent,
                "Accept": "application/json",
                "Key": ctx.settings.abuseipdb_api_key,
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("data", {})
