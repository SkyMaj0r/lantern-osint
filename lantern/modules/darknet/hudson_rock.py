from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.hudson_rock")

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 60 * 60

_ENDPOINT_BY_TYPE = {
    EntityType.USERNAME: ("search-by-username", "username"),
    EntityType.EMAIL: ("search-by-email", "email"),
    EntityType.DOMAIN: ("search-by-domain", "domain"),
}


class HudsonRockCollector(Collector):
    """Hudson Rock Cavalier's free community `osint-tools` endpoints —
    infostealer exposure by username, email, or domain.

    The brief lists this as needing a key (grouped with VirusTotal). Live
    verification shows the free community endpoints used here do not
    require one — only Hudson Rock's separate paid Cavalier v3 API does.
    Kept keyless to match actual behavior; `HUDSONROCK_API_KEY` stays in
    settings, unused, in case that ever changes.
    """

    name = "hudson-rock"
    supported_types = {EntityType.USERNAME, EntityType.EMAIL, EntityType.DOMAIN}
    rate_limit = RateLimit(requests=1, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        endpoint = _ENDPOINT_BY_TYPE.get(entity_type)
        if endpoint is None:
            return []
        path, param = endpoint

        try:
            data = await ctx.cache.get_or_set(
                self.name,
                f"{path}:{query}",
                RESULT_TTL_SECONDS,
                lambda: self._fetch(ctx, path, param, query),
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as "not infected" for an hour.
            logger.warning("%s: request failed for %s: %s", self.name, query, exc)
            return []
        if not data:
            return []

        if entity_type == EntityType.DOMAIN:
            return _domain_findings(self.name, query, data)
        return _stealer_findings(self.name, entity_type, query, data)

    async def _fetch(self, ctx: Context, path: str, param: str, query: str) -> dict | None:
        # No try/except here on purpose — see collect()'s comment.
        response = await ctx.http.get(
            f"{BASE_URL}/{path}",
            params={param: query},
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()


def _stealer_findings(source: str, entity_type: EntityType, query: str, data: dict) -> list[Finding]:
    stealers = data.get("stealers") or []
    return [
        Finding(
            source=source,
            entity_type=entity_type,
            value=query,
            data={
                "computer_name": stealer.get("computer_name"),
                "operating_system": stealer.get("operating_system"),
                "date_compromised": stealer.get("date_compromised"),
                "total_corporate_services": stealer.get("total_corporate_services"),
                "total_user_services": stealer.get("total_user_services"),
                "antiviruses": stealer.get("antiviruses", []),
                # Already masked by Hudson Rock itself (e.g. "a**********3") —
                # never raw credentials, just the exposure pattern.
                "top_logins": stealer.get("top_logins", []),
            },
            confidence=0.9,
        )
        for stealer in stealers
    ]


def _domain_findings(source: str, query: str, data: dict) -> list[Finding]:
    if not data.get("totalStealers"):
        return []
    return [
        Finding(
            source=source,
            entity_type=EntityType.DOMAIN,
            value=query,
            data={
                "total_stealers": data.get("totalStealers"),
                "employees_infected": data.get("employees"),
                "users_infected": data.get("users"),
                "third_parties_infected": data.get("third_parties"),
                "top_employee_urls": [
                    u.get("url") for u in data.get("data", {}).get("employees_urls", [])[:10]
                ],
            },
            confidence=0.85,
        )
    ]
