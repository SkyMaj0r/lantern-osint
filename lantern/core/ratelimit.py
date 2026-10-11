from __future__ import annotations

import asyncio
import time
from collections import deque

from lantern.modules.base import Collector, RateLimit


class SourceRateLimiter:
    """Sliding-window limiter for one source. `acquire()` blocks until a slot
    within `rate_limit.requests` per `rate_limit.per_seconds` is free.
    """

    def __init__(self, rate_limit: RateLimit) -> None:
        self._rate_limit = rate_limit
        self._lock = asyncio.Lock()
        self._timestamps: deque[float] = deque()

    def _prune(self, now: float) -> None:
        window = self._rate_limit.per_seconds
        while self._timestamps and now - self._timestamps[0] >= window:
            self._timestamps.popleft()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._prune(now)
            if len(self._timestamps) >= self._rate_limit.requests:
                sleep_for = self._rate_limit.per_seconds - (now - self._timestamps[0])
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                now = time.monotonic()
                self._prune(now)
            self._timestamps.append(time.monotonic())


class RateLimiterRegistry:
    """One SourceRateLimiter per collector, created lazily on first use."""

    def __init__(self) -> None:
        self._limiters: dict[str, SourceRateLimiter] = {}

    def for_collector(self, collector: Collector) -> SourceRateLimiter:
        limiter = self._limiters.get(collector.name)
        if limiter is None:
            limiter = SourceRateLimiter(collector.rate_limit)
            self._limiters[collector.name] = limiter
        return limiter
