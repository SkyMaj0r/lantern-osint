from __future__ import annotations

import asyncio
import logging

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.ratelimit import SourceRateLimiter
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.sec_edgar")

TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
TICKERS_CACHE_KEY = "company_tickers.json"
TICKERS_TTL_SECONDS = 24 * 60 * 60
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
SUBMISSIONS_TTL_SECONDS = 60 * 60
REQUEST_TIMEOUT = 10.0
MAX_MATCHES = 5


class SecEdgarCollector(Collector):
    """SEC EDGAR company lookup by name. A descriptive User-Agent with a
    real contact email is mandatory — SEC returns 403 without one. Self
    -throttled to the documented 10 req/s across all internal calls.
    """

    name = "sec-edgar"
    supported_types = {EntityType.COMPANY}
    rate_limit = RateLimit(requests=10, per_seconds=1.0)
    requires_key = False

    def __init__(self) -> None:
        self._internal_limiter = SourceRateLimiter(RateLimit(requests=10, per_seconds=1.0))

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        try:
            tickers = await ctx.cache.get_or_set(
                self.name, TICKERS_CACHE_KEY, TICKERS_TTL_SECONDS, lambda: self._fetch_tickers(ctx)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set on purpose — a transient failure must
            # never get cached as an empty ticker list for 24h.
            logger.warning("%s: failed to load company_tickers.json: %s", self.name, exc)
            return []
        if not tickers:
            return []

        matches = _match_companies(tickers, query)[:MAX_MATCHES]
        results = await asyncio.gather(*(self._collect_for_match(ctx, match) for match in matches))
        return [finding for finding in results if finding is not None]

    async def _collect_for_match(self, ctx: Context, match: dict) -> Finding | None:
        cik = match["cik"]
        try:
            submission = await ctx.cache.get_or_set(
                self.name,
                f"submissions:{cik}",
                SUBMISSIONS_TTL_SECONDS,
                lambda: self._fetch_submissions(ctx, cik),
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Caught here, not propagated: this runs under asyncio.gather
            # over up to MAX_MATCHES companies — letting it propagate
            # would cancel every other match's result too.
            logger.warning("%s: request failed for CIK %s: %s", self.name, cik, exc)
            return None
        if not submission:
            return None

        return Finding(
            source=self.name,
            entity_type=EntityType.COMPANY,
            value=submission.get("name", match["title"]),
            data={
                "cik": cik,
                "ticker": match.get("ticker"),
                "sic_description": submission.get("sicDescription"),
                "address": submission.get("addresses", {}).get("business"),
            },
            confidence=0.9,
            url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik:010d}",
        )

    async def _fetch_tickers(self, ctx: Context) -> dict | None:
        # No try/except here on purpose — see collect()'s comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            TICKERS_URL, headers={"User-Agent": ctx.settings.user_agent}, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    async def _fetch_submissions(self, ctx: Context, cik: int) -> dict | None:
        # No try/except here on purpose — see _collect_for_match's comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            SUBMISSIONS_URL.format(cik=cik),
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()


def _match_companies(tickers: dict, query: str) -> list[dict]:
    needle = query.strip().lower()
    matches = []
    for entry in tickers.values():
        title = str(entry.get("title", ""))
        ticker = str(entry.get("ticker", ""))
        if needle == ticker.lower() or needle in title.lower():
            matches.append({"cik": entry["cik_str"], "title": title, "ticker": ticker})
    matches.sort(key=lambda m: (m["title"].lower() != needle and m["ticker"].lower() != needle))
    return matches
