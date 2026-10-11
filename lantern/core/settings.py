from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel


class Settings(BaseModel):
    # Required: used in the User-Agent on every outbound request (several
    # sources, e.g. SEC EDGAR, 403 without a contact email).
    contact_email: str

    # Required only to run the API (not yet built) — it authenticates every
    # request, even local ones. The CLI never reads this, so it's optional
    # here; the API's own startup enforces it's set before serving requests.
    api_bearer_token: str | None = None

    # Optional, per source. Collectors must degrade gracefully (log + [])
    # when their key is unset, never crash the run.
    virustotal_api_key: str | None = None
    hudsonrock_api_key: str | None = None
    searchapi_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    cache_path: str = "lantern_cache.db"

    @property
    def user_agent(self) -> str:
        return f"Lantern-OSINT/0.1 (+contact: {self.contact_email})"


class SettingsError(Exception):
    pass


@lru_cache
def get_settings(env_path: str | Path | None = None) -> Settings:
    load_dotenv(env_path)

    contact_email = os.getenv("CONTACT_EMAIL")
    if not contact_email:
        raise SettingsError("CONTACT_EMAIL must be set (see .env.example)")

    return Settings(
        contact_email=contact_email,
        api_bearer_token=os.getenv("API_BEARER_TOKEN") or None,
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        hudsonrock_api_key=os.getenv("HUDSONROCK_API_KEY") or None,
        searchapi_api_key=os.getenv("SEARCHAPI_API_KEY") or None,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        cache_path=os.getenv("CACHE_PATH", "lantern_cache.db"),
    )
