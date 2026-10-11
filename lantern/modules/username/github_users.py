from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.github_users")

USER_URL = "https://api.github.com/users/{username}"
SEARCH_URL = "https://api.github.com/search/users"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 6 * 60 * 60
MAX_RESULTS = 5
_ACCEPT = "application/vnd.github+json"


class GitHubUsersCollector(Collector):
    """GitHub's public user API — keyless, so no token is required.

    Two paths, picked by entity type:
      * USERNAME -> GET /users/{login}: an exact profile lookup (404 = no such
        account), high confidence because it's a precise hit.
      * PERSON   -> GET /search/users?q=<name>: GitHub's own server-side name
        search, so a full legal name resolves to candidate profiles without us
        guessing handles. Lower confidence — a name match is softer evidence.

    This is one of the "native full-name" collectors: unlike WhatsMyName, it
    doesn't fan a name out into permutations, it asks GitHub to match the name.

    Rate limits are strict unauthenticated — 10 search req/min, 60 core
    req/hr — so the rate_limit below is pinned to the tighter (search) budget
    and results are cached for hours.
    """

    name = "github_users"
    supported_types = {EntityType.USERNAME, EntityType.PERSON}
    rate_limit = RateLimit(requests=1, per_seconds=6.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        cache_key = f"{entity_type.value}:{query}"
        try:
            results = await ctx.cache.get_or_set(
                self.name, cache_key, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, query, entity_type)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must never be
            # cached as "no results," or it suppresses retries for the full TTL.
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not results:
            return []
        return [
            Finding(
                source=self.name,
                entity_type=EntityType.USERNAME,
                value=result["login"],
                data={
                    "name": result.get("name"),
                    "bio": result.get("bio"),
                    "company": result.get("company"),
                    "location": result.get("location"),
                    "account_type": result.get("type"),
                    **({"from_name": query} if entity_type == EntityType.PERSON else {}),
                },
                confidence=0.7 if entity_type == EntityType.USERNAME else 0.45,
                url=result.get("html_url"),
            )
            for result in results
        ]

    async def _fetch(self, ctx: Context, query: str, entity_type: EntityType) -> list[dict] | None:
        # No try/except here — see collect()'s comment.
        if entity_type == EntityType.PERSON:
            return await self._search(ctx, query)
        return await self._lookup(ctx, query)

    async def _lookup(self, ctx: Context, username: str) -> list[dict] | None:
        response = await ctx.http.get(
            USER_URL.format(username=quote(username, safe="")),
            headers={"User-Agent": ctx.settings.user_agent, "Accept": _ACCEPT},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            # A genuine "no such account" — safe to cache as empty.
            return []
        response.raise_for_status()
        return [response.json()]

    async def _search(self, ctx: Context, name: str) -> list[dict] | None:
        response = await ctx.http.get(
            SEARCH_URL,
            params={"q": name, "per_page": MAX_RESULTS},
            headers={"User-Agent": ctx.settings.user_agent, "Accept": _ACCEPT},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        items = response.json().get("items", [])
        # Search results are terse (login/html_url/type, no name/bio); that's
        # enough to surface the profile. We keep them as-is rather than fan out
        # a profile GET per hit, which would blow the 10/min search budget.
        return items[:MAX_RESULTS]
