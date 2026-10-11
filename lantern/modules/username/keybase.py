from __future__ import annotations

import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.keybase")

SEARCH_URL = "https://keybase.io/_/api/1.0/user/user_search.json"
PROFILE_URL = "https://keybase.io/{username}"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 6 * 60 * 60
MAX_RESULTS = 5


class KeybaseCollector(Collector):
    """Keybase's public user search — keyless.

    `user_search.json?q=` matches both handles and real names server-side, so
    it serves USERNAME and PERSON the same way: ask Keybase to match the term,
    don't guess. That makes it a native full-name collector (like
    github_users), complementing WhatsMyName's permutation approach.

    A USERNAME whose exact handle comes back scores higher than a soft PERSON
    name match.
    """

    name = "keybase"
    supported_types = {EntityType.USERNAME, EntityType.PERSON}
    rate_limit = RateLimit(requests=2, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            results = await ctx.cache.get_or_set(
                self.name, query, RESULT_TTL_SECONDS, lambda: self._search(ctx, query)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure (including a
            # non-OK Keybase status code, raised below) must never be cached
            # as "no results" for the full TTL.
            logger.warning("%s: search failed for %s: %s", self.name, query, exc)
            return []
        if not results:
            return []

        findings = []
        for entry in results[:MAX_RESULTS]:
            kb = entry.get("keybase") or {}
            username = kb.get("username")
            if not username:
                continue
            exact = entity_type == EntityType.USERNAME and username.lower() == query.lower()
            findings.append(
                Finding(
                    source=self.name,
                    entity_type=EntityType.USERNAME,
                    value=username,
                    data={
                        "full_name": kb.get("full_name"),
                        "uid": kb.get("uid"),
                        **({"from_name": query} if entity_type == EntityType.PERSON else {}),
                    },
                    confidence=0.7 if exact else (0.6 if entity_type == EntityType.USERNAME else 0.4),
                    url=PROFILE_URL.format(username=username),
                )
            )
        return findings

    async def _search(self, ctx: Context, query: str) -> list[dict] | None:
        # No try/except here — see collect()'s comment.
        response = await ctx.http.get(
            SEARCH_URL,
            params={"q": query, "num_wanted": MAX_RESULTS},
            headers={"User-Agent": ctx.settings.user_agent, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        # Keybase answers 200 even for app-level failures, signalling via
        # status.code (0 == OK). A non-zero code is an error, not an empty
        # result — raise so the call site skips caching it.
        if data.get("status", {}).get("code") != 0:
            raise ValueError(f"keybase status {data.get('status')}")
        return data.get("list", [])
