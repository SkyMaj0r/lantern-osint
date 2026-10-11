from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Sequence

from lantern.core.entities import Classification, EntityType, classify, classify_as
from lantern.core.models import Finding
from lantern.core.ratelimit import RateLimiterRegistry
from lantern.modules.base import Collector, Context

logger = logging.getLogger("lantern.dispatcher")


class Dispatcher:
    """Routes a classified (entity_type, value) to every Collector that
    declares support for that type, and runs them concurrently. A module
    that errors or times out is logged and contributes no findings — it
    never takes down the run.
    """

    def __init__(
        self,
        collectors: Sequence[Collector],
        make_context: Callable[[], Context],
        rate_limiters: RateLimiterRegistry | None = None,
    ) -> None:
        self._collectors = list(collectors)
        self._make_context = make_context
        self._rate_limiters = rate_limiters or RateLimiterRegistry()

    @property
    def collector_names(self) -> list[str]:
        """Every registered collector's name, regardless of entity type —
        for a caller (the API's `/sources` endpoint) that wants to offer a
        full toggle list before a query has even been classified."""
        return [collector.name for collector in self._collectors]

    def applicable(
        self, classification: Classification, enabled: set[str] | None = None
    ) -> list[tuple[Collector, EntityType]]:
        """`enabled`, when given, restricts the result to collectors whose
        `name` is in the set — the caller opting in to a subset (e.g. "only
        virustotal") rather than every collector that supports the type.
        `None` means no restriction, same as before this parameter existed.

        A collector that supports more than one of an ambiguous query's
        candidate types (e.g. github_users supports both USERNAME and PERSON,
        and a one-word query classifies as USERNAME+PERSON+COMPANY) runs only
        once, for the first of its supported types in `classification.types`
        order — not once per overlapping type. Without this a name→username
        collector would fire two or three times on a single query against the
        very same value. Collectors that support exactly one candidate type
        (the common case) are unaffected.
        """
        seen: set[str] = set()
        pairs: list[tuple[Collector, EntityType]] = []
        for entity_type in classification.types:
            for collector in self._collectors:
                if entity_type not in collector.supported_types:
                    continue
                if enabled is not None and collector.name not in enabled:
                    continue
                if collector.name in seen:
                    continue
                seen.add(collector.name)
                pairs.append((collector, entity_type))
        return pairs

    async def run(
        self,
        raw_query: str,
        enabled: set[str] | None = None,
        entity_type: EntityType | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        async for finding in self.stream(raw_query, enabled, entity_type):
            findings.append(finding)
        return findings

    async def stream(
        self,
        raw_query: str,
        enabled: set[str] | None = None,
        entity_type: EntityType | None = None,
    ) -> AsyncIterator[Finding]:
        """`entity_type`, when given, is an explicit user override: the query
        is treated as exactly that type (after a format check) instead of
        being auto-classified. `None` keeps the default auto-detect behavior."""
        classification = (
            classify_as(raw_query, entity_type) if entity_type is not None else classify(raw_query)
        )
        pairs = self.applicable(classification, enabled)
        ctx = self._make_context()

        tasks = [
            asyncio.create_task(self._run_one(collector, classification.value, entity_type, ctx))
            for collector, entity_type in pairs
        ]
        for task in asyncio.as_completed(tasks):
            for finding in await task:
                yield finding

    async def _run_one(
        self, collector: Collector, value: str, entity_type: EntityType, ctx: Context
    ) -> list[Finding]:
        if collector.requires_key and not self._has_required_key(collector, ctx):
            logger.info("%s: skipped, no API key configured", collector.name)
            return []

        limiter = self._rate_limiters.for_collector(collector)
        await limiter.acquire()
        try:
            return await collector.collect(value, entity_type, ctx)
        except Exception:
            logger.exception("%s: collect() failed for %s=%s", collector.name, entity_type, value)
            return []

    @staticmethod
    def _has_required_key(collector: Collector, ctx: Context) -> bool:
        # Collectors that require a key are responsible for naming it; the
        # dispatcher only short-circuits the generic case where a collector
        # exposes which settings attribute holds its key.
        key_attr = getattr(collector, "api_key_setting", None)
        if key_attr is None:
            return True
        return bool(getattr(ctx.settings, key_attr, None))
