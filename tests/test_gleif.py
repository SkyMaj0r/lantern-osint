from __future__ import annotations

import httpx
import respx

from lantern.core.entities import EntityType
from lantern.modules.base import Context
from lantern.modules.company import gleif as gleif_module
from lantern.modules.company.gleif import GleifCollector


@respx.mock
async def test_collect_returns_finding_with_parent_name(ctx: Context) -> None:
    respx.get(gleif_module.SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "LEI123",
                        "attributes": {
                            "entity": {
                                "legalName": {"name": "Acme Subsidiary Ltd"},
                                "legalJurisdiction": "US",
                                "status": "ACTIVE",
                                "legalAddress": {"city": "New York", "country": "US"},
                            }
                        },
                        "relationships": {
                            "ultimate-parent": {
                                "links": {"related": "https://api.gleif.org/api/v1/lei-records/LEI999"}
                            }
                        },
                    }
                ]
            },
        )
    )
    respx.get("https://api.gleif.org/api/v1/lei-records/LEI999").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"attributes": {"entity": {"legalName": {"name": "Acme Holdings Inc"}}}}},
        )
    )

    findings = await GleifCollector().collect("Acme", EntityType.COMPANY, ctx)

    assert len(findings) == 1
    assert findings[0].value == "Acme Subsidiary Ltd"
    assert findings[0].data["lei"] == "LEI123"
    assert findings[0].data["parent_name"] == "Acme Holdings Inc"


@respx.mock
async def test_collect_handles_record_without_parent(ctx: Context) -> None:
    respx.get(gleif_module.SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "LEI456",
                        "attributes": {
                            "entity": {
                                "legalName": {"name": "Standalone Co"},
                                "legalJurisdiction": "DE",
                                "status": "ACTIVE",
                                "legalAddress": {"city": "Berlin", "country": "DE"},
                            }
                        },
                        "relationships": {},
                    }
                ]
            },
        )
    )

    findings = await GleifCollector().collect("Standalone", EntityType.COMPANY, ctx)

    assert len(findings) == 1
    assert findings[0].data["parent_name"] is None


@respx.mock
async def test_collect_returns_empty_on_no_matches(ctx: Context) -> None:
    respx.get(gleif_module.SEARCH_URL).mock(return_value=httpx.Response(200, json={"data": []}))

    findings = await GleifCollector().collect("NoSuchCompany", EntityType.COMPANY, ctx)

    assert findings == []


@respx.mock
async def test_collect_tolerates_search_failure(ctx: Context) -> None:
    respx.get(gleif_module.SEARCH_URL).mock(side_effect=httpx.ConnectError("boom"))

    findings = await GleifCollector().collect("Acme", EntityType.COMPANY, ctx)

    assert findings == []
