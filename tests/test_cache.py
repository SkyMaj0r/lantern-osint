import asyncio
from pathlib import Path

from lantern.core.cache import Cache


async def test_set_then_get_round_trips(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    await cache.set("whatsmyname", "wmn-dat.json", {"sites": [1, 2, 3]}, ttl_seconds=60)
    assert await cache.get("whatsmyname", "wmn-dat.json") == {"sites": [1, 2, 3]}


async def test_get_missing_key_returns_none(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    assert await cache.get("whatsmyname", "missing") is None


async def test_expired_entry_returns_none(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    await cache.set("xposedornot", "a@example.com", {"breached": True}, ttl_seconds=0.01)
    await asyncio.sleep(0.05)
    assert await cache.get("xposedornot", "a@example.com") is None


async def test_set_overwrites_existing_key(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    await cache.set("rdap", "example.com", {"v": 1}, ttl_seconds=60)
    await cache.set("rdap", "example.com", {"v": 2}, ttl_seconds=60)
    assert await cache.get("rdap", "example.com") == {"v": 2}


async def test_get_or_set_calls_fetch_once_and_caches_result(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    calls = 0

    async def fetch() -> dict:
        nonlocal calls
        calls += 1
        return {"breaches": ["Adobe"]}

    first = await cache.get_or_set("xposedornot", "a@example.com", 60, fetch)
    second = await cache.get_or_set("xposedornot", "a@example.com", 60, fetch)

    assert first == {"breaches": ["Adobe"]}
    assert second == {"breaches": ["Adobe"]}
    assert calls == 1


async def test_get_or_set_caches_a_legitimate_none_result(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "cache.db")
    calls = 0

    async def fetch() -> None:
        nonlocal calls
        calls += 1
        return None

    first = await cache.get_or_set("xposedornot", "clean@example.com", 60, fetch)
    second = await cache.get_or_set("xposedornot", "clean@example.com", 60, fetch)

    assert first is None
    assert second is None
    assert calls == 1


async def test_many_concurrent_first_calls_do_not_race_on_init(tmp_path: Path) -> None:
    # Regression test: a dozen-plus collectors all making their first
    # cache call at once (dispatcher fan-out, or a fresh cache file on
    # server start) used to race to CREATE TABLE on the same brand-new
    # file and crash with "database is locked." Distinct keys for the
    # concurrent gets vs. sets below — only testing that concurrent init
    # doesn't crash, not get/set interleaving, which gather doesn't order.
    cache = Cache(tmp_path / "cache.db")

    get_results = await asyncio.gather(*(cache.get(f"unset-source-{i}", "key") for i in range(20)))
    await asyncio.gather(*(cache.set(f"set-source-{i}", "key", {"v": i}, ttl_seconds=60) for i in range(20)))

    assert all(r is None for r in get_results)
    for i in range(20):
        assert await cache.get(f"set-source-{i}", "key") == {"v": i}
