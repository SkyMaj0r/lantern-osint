from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import aiosqlite


class Cache:
    """SQLite-backed TTL cache, keyed per source, so repeated dev queries
    don't hammer the real APIs.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def init(self) -> None:
        if self._initialized:
            return
        # A dozen-plus collectors can all make their first cache call in
        # the same instant (one dispatcher run fans out concurrently, or a
        # fresh/deleted cache file on server start) — without this lock,
        # every one of them sees _initialized=False and races to
        # CREATE TABLE on the same brand-new file, and SQLite rejects the
        # losers with "database is locked" (caught live: two collectors
        # failed outright on the first query after the cache file was
        # deleted). Serializing just the one-time setup avoids the race.
        async with self._init_lock:
            if self._initialized:
                return
            async with aiosqlite.connect(self._path) as db:
                await db.execute("PRAGMA journal_mode=WAL")
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        value TEXT NOT NULL,
                        expires_at REAL NOT NULL
                    )
                    """
                )
                await db.commit()
            self._initialized = True

    @staticmethod
    def _key(source: str, key: str) -> str:
        return f"{source}:{key}"

    async def get(self, source: str, key: str) -> Any | None:
        await self.init()
        async with aiosqlite.connect(self._path) as db:
            cursor = await db.execute(
                "SELECT value, expires_at FROM cache_entries WHERE key = ?",
                (self._key(source, key),),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        value, expires_at = row
        if expires_at < time.time():
            return None
        return json.loads(value)

    async def set(self, source: str, key: str, value: Any, ttl_seconds: float) -> None:
        await self.init()
        expires_at = time.time() + ttl_seconds
        async with aiosqlite.connect(self._path) as db:
            await db.execute(
                """
                INSERT INTO cache_entries (key, source, value, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    expires_at = excluded.expires_at
                """,
                (self._key(source, key), source, json.dumps(value), expires_at),
            )
            await db.commit()

    async def get_or_set(
        self,
        source: str,
        key: str,
        ttl_seconds: float,
        fetch: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Cache-aside helper. `get`/`set` alone can't tell "not cached yet"
        apart from "cached value is None" — both come back as None — so a
        legitimate negative result (e.g. "no breaches found") would never
        get cached and would be re-fetched every call. This wraps the value
        so None is distinguishable from absent.
        """
        cached = await self.get(source, key)
        if cached is not None:
            return cached["value"]
        value = await fetch()
        await self.set(source, key, {"value": value}, ttl_seconds)
        return value
