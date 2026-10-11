from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from lantern.core.entities import EntityType


class Finding(BaseModel):
    """One piece of evidence returned by a single Collector.

    Uniform across every source so the correlator never special-cases one.
    """

    source: str
    entity_type: EntityType
    value: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    url: str | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Entity(BaseModel):
    """Findings the correlator has merged into one profile.

    Merging two Findings requires a corroborating pivot beyond a name match
    (shared email, domain, location, ...) — enforced by the correlator, not
    this model. `confidence` is the correlator's aggregate score for the
    merge, distinct from each Finding's own per-source confidence.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
