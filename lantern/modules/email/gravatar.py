from __future__ import annotations

import hashlib
import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.gravatar")

# Legacy profile endpoint, keyed by the MD5 of the lowercased, trimmed email.
# It 302-redirects to en.gravatar.com (handled by follow_redirects) and 404s
# when no profile is linked to the address. The newer api.gravatar.com/v3
# profile API needs an OAuth token, so this keyless one is what we use.
PROFILE_URL = "https://www.gravatar.com/{hash}.json"
REQUEST_TIMEOUT = 10.0
RESULT_TTL_SECONDS = 24 * 60 * 60


class GravatarCollector(Collector):
    """Email -> public identity. Many people register a Gravatar against an
    address and link social accounts to it; this turns an email into a
    display name, avatar, and those linked profiles. Keyless. The only
    email->identity pivot in the toolset — the breach collectors
    (XposedOrNot) answer a different question.

    The MD5 here is Gravatar's addressing scheme, not a security measure.
    """

    name = "gravatar"
    supported_types = {EntityType.EMAIL}
    rate_limit = RateLimit(requests=5, per_seconds=1.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        digest = hashlib.md5(query.strip().lower().encode(), usedforsecurity=False).hexdigest()
        try:
            entry = await ctx.cache.get_or_set(
                self.name, digest, RESULT_TTL_SECONDS, lambda: self._fetch(ctx, digest)
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s: lookup failed for %s: %s", self.name, query, exc)
            return []
        if not entry:
            return []

        accounts = [
            {"service": a.get("shortname") or a.get("name"), "url": a.get("url")}
            for a in entry.get("accounts", [])
            if a.get("url")
        ]
        return [
            Finding(
                source=self.name,
                entity_type=EntityType.EMAIL,
                value=entry.get("displayName") or query,
                data={
                    "gravatar_hash": digest,
                    "accounts": accounts,
                    "location": entry.get("currentLocation"),
                },
                confidence=0.6,
                url=entry.get("profileUrl"),
            )
        ]

    async def _fetch(self, ctx: Context, digest: str) -> dict | None:
        # No try/except here — see collect(). A 404 is a genuine "no profile
        # for this address," safe to cache as empty.
        response = await ctx.http.get(
            PROFILE_URL.format(hash=digest),
            headers={"User-Agent": ctx.settings.user_agent, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        entries = response.json().get("entry", [])
        return entries[0] if entries else None
