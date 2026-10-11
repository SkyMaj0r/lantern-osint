from __future__ import annotations

import asyncio
import logging
import socket

import httpx

from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.ratelimit import SourceRateLimiter
from lantern.modules.base import Collector, Context, RateLimit

logger = logging.getLogger("lantern.modules.infra")

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CVEDB_URL = "https://cvedb.shodan.io/cve/{cve_id}"
REQUEST_TIMEOUT = 10.0
INTERNETDB_TTL_SECONDS = 60 * 60
CVE_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_CVE_ENRICHMENT = 10


class ShodanInfraCollector(Collector):
    """Shodan InternetDB (open ports/CVEs/CPEs/hostnames/tags), with CVEDB
    enrichment for each CVE. No key, no account, non-commercial use.

    For a domain, resolves it to its IP(s) first via plain DNS — that's a
    local lookup, not an HTTP fetch, so it doesn't go through the
    SSRF-guarded client; it only decides which public IP string to ask
    Shodan's API about next.
    """

    name = "shodan-internetdb"
    supported_types = {EntityType.IP, EntityType.DOMAIN}
    rate_limit = RateLimit(requests=1, per_seconds=1.0)
    requires_key = False

    def __init__(self) -> None:
        self._internal_limiter = SourceRateLimiter(RateLimit(requests=1, per_seconds=1.0))

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]:
        ips = await self._resolve_ips(query, entity_type)
        if not ips:
            return []

        results = await asyncio.gather(*(self._collect_for_ip(ip, ctx) for ip in ips))
        return [finding for sub in results for finding in sub]

    async def _resolve_ips(self, query: str, entity_type: EntityType) -> list[str]:
        if entity_type == EntityType.IP:
            return [query]
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(query, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            logger.info("%s: could not resolve %s: %s", self.name, query, exc)
            return []
        return sorted({info[4][0] for info in infos})

    async def _collect_for_ip(self, ip: str, ctx: Context) -> list[Finding]:
        try:
            data = await ctx.cache.get_or_set(
                self.name, ip, INTERNETDB_TTL_SECONDS, lambda: self._fetch_internetdb(ctx, ip)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Outside get_or_set, and caught right here rather than left
            # to propagate: a transient failure must never get cached as
            # "not indexed," and — since this runs under asyncio.gather
            # over possibly several IPs — letting it propagate would also
            # cancel every other IP's result, not just this one's (the
            # same class of bug fixed in WhatsMyName's fan-out, Phase 2).
            logger.warning("%s: request failed for %s: %s", self.name, ip, exc)
            return []
        if not data:
            return []

        findings = [
            Finding(
                source=self.name,
                entity_type=EntityType.IP,
                value=ip,
                data={
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "tags": data.get("tags", []),
                },
                confidence=0.9,
                url=f"https://internetdb.shodan.io/{ip}",
            )
        ]

        cve_ids = data.get("vulns", [])[:MAX_CVE_ENRICHMENT]
        cve_results = await asyncio.gather(*(self._fetch_cve(ctx, cve_id) for cve_id in cve_ids))
        for cve_id, cve in zip(cve_ids, cve_results):
            findings.append(
                Finding(
                    source=self.name,
                    entity_type=EntityType.IP,
                    value=ip,
                    data={"cve": cve_id, **(cve or {})},
                    confidence=0.8,
                    url=f"https://cvedb.shodan.io/cve/{cve_id}",
                )
            )

        return findings

    async def _fetch_internetdb(self, ctx: Context, ip: str) -> dict | None:
        # No try/except here on purpose — see _collect_for_ip's comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            INTERNETDB_URL.format(ip=ip),
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    async def _fetch_cve(self, ctx: Context, cve_id: str) -> dict | None:
        try:
            return await ctx.cache.get_or_set(
                self.name, f"cve:{cve_id}", CVE_TTL_SECONDS, lambda: self._fetch_cve_raw(ctx, cve_id)
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Caught here, not propagated: this runs under asyncio.gather
            # over possibly several CVEs — letting it propagate would
            # cancel every other CVE lookup too, not just this one's.
            logger.warning("%s: CVE lookup failed for %s: %s", self.name, cve_id, exc)
            return None

    async def _fetch_cve_raw(self, ctx: Context, cve_id: str) -> dict | None:
        # No try/except here on purpose — see _fetch_cve's comment.
        await self._internal_limiter.acquire()
        response = await ctx.http.get(
            CVEDB_URL.format(cve_id=cve_id),
            headers={"User-Agent": ctx.settings.user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        return {
            "summary": data.get("summary"),
            "cvss": data.get("cvss"),
            "published": data.get("published_time"),
        }
