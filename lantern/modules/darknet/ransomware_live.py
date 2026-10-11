from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.ransomware_live")

BASE_URL = "https://api.ransomware.live/v2"
REQUEST_TIMEOUT = 10.0
SEARCH_TTL_SECONDS = 60 * 60
RECENT_TTL_SECONDS = 15 * 60
GROUPS_TTL_SECONDS = 24 * 60 * 60


class RansomwareLiveCollector(Collector):
    """Ransomware.live v2 — free, keyless, documented ~10 req/min-scale
    rate limit. Indexes what ransomware groups themselves have leaked or
    claimed (Tier-1 clearnet intelligence about the dark web; no Tor
    involved). `claim_url` in a result is often an .onion address — stored
    as text metadata only, per the hard rule, and never fetched.

    Observed live to be flaky: /recentvictims and /groups sometimes 404
    moments apart with no change on our end. That's the source, not a
    wrong path here — handled the same way as any other degraded source.
    """

    name = "ransomware-live"
    supported_types = {EntityType.COMPANY}
    rate_limit = RateLimit(requests=2, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            victims = await ctx.cache.get_or_set(
                self.name, f"search:{query}", SEARCH_TTL_SECONDS, lambda: self._search(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — this source is known to be
            # flaky (404s observed live on documented, working paths).
            # Caching one of those blips as "no victims" for an hour would
            # have masked every retry during that window — quite possibly
            # part of why it looked more broken than it actually was when
            # this was first investigated.
            logger.warning("%s: search failed for %s: %s", self.name, query, exc)
            return []
        if not victims:
            return []
        return [_to_finding(self.name, victim) for victim in victims]

    async def _search(self, ctx: Context, query: str) -> list[dict] | None:
        # No try/except here, and no special-cased 404, on purpose: unlike
        # RDAP/SEC/Wikipedia where a 404 is a stable "this doesn't exist"
        # answer, this source's 404s are documented flakiness — the exact
        # same request 404'd, then worked moments later with no change on
        # our end. Treating any non-2xx here as "confirmed empty" would be
        # wrong; let it raise and get retried next call instead.
        response = await ctx.http.get(
            f"{BASE_URL}/searchvictims/{query}",
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()


def _to_finding(source: str, victim: dict) -> Finding:
    return Finding(
        source=source,
        entity_type=EntityType.COMPANY,
        value=victim.get("victim", ""),
        data={
            "group": victim.get("group"),
            "country": victim.get("country"),
            "sector": victim.get("activity"),
            "attack_date": victim.get("attackdate"),
            "discovered": victim.get("discovered"),
            "description": victim.get("description"),
            "claim_url": victim.get("claim_url"),
        },
        confidence=0.85,
        url=victim.get("url"),
    )


async def fetch_recent_victims(ctx: Context, limit: int = 20) -> list[dict]:
    """Standalone utility (not entity-driven) for `lantern darknet recent`."""
    try:
        victims = await ctx.cache.get_or_set(
            "ransomware-live", "recentvictims", RECENT_TTL_SECONDS, lambda: _fetch(ctx, f"{BASE_URL}/recentvictims")
        )
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("ransomware-live: request failed for recentvictims: %s", exc)
        return []
    return (victims or [])[:limit]


async def fetch_groups(ctx: Context) -> list[dict]:
    """Standalone utility (not entity-driven) for `lantern darknet groups`."""
    try:
        groups = await ctx.cache.get_or_set(
            "ransomware-live", "groups", GROUPS_TTL_SECONDS, lambda: _fetch(ctx, f"{BASE_URL}/groups")
        )
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("ransomware-live: request failed for groups: %s", exc)
        return []
    return groups or []


async def _fetch(ctx: Context, url: str) -> list[dict] | None:
    # No try/except here on purpose — see fetch_recent_victims'/
    # fetch_groups' comments, and _search's for why 404 isn't
    # special-cased as "confirmed empty" for this particular source.
    response = await ctx.http.get(url, headers={"User-Agent": ctx.settings.user_agent}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()
