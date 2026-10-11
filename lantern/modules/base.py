from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx
from pydantic import BaseModel, Field

from lantern.core.cache import Cache
from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.settings import Settings


class RateLimit(BaseModel):
    requests: int = Field(gt=0)
    per_seconds: float = Field(gt=0)


@dataclass
class Context:
    """Shared, per-run resources handed to every Collector.

    `http` must be an SSRF-guarded client (see core/ssrf.build_guarded_client);
    collectors never construct their own.
    """

    http: httpx.AsyncClient
    cache: Cache
    settings: Settings


class Collector(ABC):
    name: str
    supported_types: set[EntityType]
    rate_limit: RateLimit
    requires_key: bool = False
    # Name of the Settings attribute holding this collector's key, if any.
    # The dispatcher skips the collector (logs + []) when that attribute is
    # unset, so a module can declare "I need a key" without the dispatcher
    # needing to know anything source-specific.
    api_key_setting: str | None = None

    @abstractmethod
    async def collect(
        self, query: str, entity_type: EntityType, ctx: Context
    ) -> list[Finding]: ...
