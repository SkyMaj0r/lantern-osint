import time

from lantern.core.ratelimit import SourceRateLimiter
from lantern.modules.base import RateLimit


async def test_limiter_allows_burst_up_to_rate() -> None:
    limiter = SourceRateLimiter(RateLimit(requests=3, per_seconds=1.0))
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    assert time.monotonic() - start < 0.2


async def test_limiter_throttles_beyond_rate() -> None:
    limiter = SourceRateLimiter(RateLimit(requests=2, per_seconds=0.2))
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.2
