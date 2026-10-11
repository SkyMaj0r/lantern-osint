from __future__ import annotations

import asyncio
import logging
from urllib.parse import quote

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.names import DEFAULT_FANOUT_VARIANTS, username_variants
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.whatsmyname")

DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
DATA_CACHE_KEY = "wmn-data.json"
DATA_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT = 10.0
MAX_CONCURRENT_CHECKS = 20


class WhatsMyNameCollector(Collector):
    """Checks a username against every site in WhatsMyName's maintained
    dataset. No key, no old checker scripts — we fetch the dataset
    ourselves (cached 24h) and apply each entry's own detection rule.
    """

    name = "whatsmyname"
    # PERSON is supported via name->handle permutation (see _handles): a full
    # name never matches a site directly, but the handles derived from it do.
    # USERNAME is the direct path, unchanged. The dispatcher collapses the two
    # so a one-word ambiguous query runs this once, as USERNAME.
    supported_types = {EntityType.USERNAME, EntityType.PERSON}
    rate_limit = RateLimit(requests=1, per_seconds=2.0)
    requires_key = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            sites = await self._load_sites(ctx)
        except Exception:
            logger.exception("%s: failed to load %s", self.name, DATA_CACHE_KEY)
            return []

        handles = self._handles(query, entity_type)
        if not handles:
            return []

        # One semaphore across the whole site x handle fan-out so a PERSON
        # search (several handles) never multiplies live concurrency past the
        # single-username ceiling.
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
        results = await asyncio.gather(
            *(
                self._check_site(site, handle, entity_type, query, ctx, semaphore)
                for handle in handles
                for site in sites
            )
        )
        return [finding for finding in results if finding is not None]

    @staticmethod
    def _handles(query: str, entity_type: EntityType) -> list[str]:
        """The handles to actually check. A USERNAME is checked as-is; a
        PERSON is expanded into a capped set of likely logins."""
        if entity_type == EntityType.PERSON:
            return username_variants(query, limit=DEFAULT_FANOUT_VARIANTS)
        return [query]

    async def _load_sites(self, ctx: Context) -> list[dict]:
        cached = await ctx.cache.get(self.name, DATA_CACHE_KEY)
        if cached is not None:
            return cached.get("sites", [])

        response = await ctx.http.get(
            DATA_URL,
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        await ctx.cache.set(self.name, DATA_CACHE_KEY, data, ttl_seconds=DATA_TTL_SECONDS)
        return data.get("sites", [])

    async def _check_site(
        self,
        site: dict,
        username: str,
        entity_type: EntityType,
        query: str,
        ctx: Context,
        semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        uri_check = site.get("uri_check")
        e_code = site.get("e_code")
        e_string = site.get("e_string")
        if not uri_check or e_code is None or not e_string:
            return None

        encoded = quote(username, safe="")
        url = uri_check.replace("{account}", encoded)

        async with semaphore:
            try:
                response = await ctx.http.get(
                    url,
                    headers={"User-Agent": ctx.settings.user_agent},
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                )
            except Exception as exc:
                # Broad on purpose: one of ~hundreds of independent sites
                # (dead domain, TLS failure, SSRF-blocked redirect target,
                # ...) must never take the other checks down with it.
                logger.debug("%s: %s check failed: %s", self.name, site.get("name"), exc)
                return None

        if response.status_code != e_code or e_string not in response.text:
            return None

        pretty = site.get("uri_pretty") or uri_check
        data = {"site": site.get("name"), "category": site.get("cat")}
        if entity_type == EntityType.PERSON:
            # Record that this was a name->handle guess, not a given handle,
            # and which guess hit — and score it lower, because a derived
            # handle matching a site is weaker evidence than a handle the
            # user actually supplied.
            data["matched_handle"] = username
            data["from_name"] = query
            confidence = 0.5
        else:
            confidence = 0.8
        return Finding(
            source=self.name,
            entity_type=EntityType.USERNAME,
            value=username,
            data=data,
            confidence=confidence,
            url=pretty.replace("{account}", encoded),
        )
