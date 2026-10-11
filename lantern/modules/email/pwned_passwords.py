from __future__ import annotations

import hashlib

import httpx

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 10.0


class PwnedPasswordsError(Exception):
    pass


async def check_password(password: str, http: httpx.AsyncClient, user_agent: str) -> int:
    """Return how many times this password appears in known breaches, via
    HIBP's k-anonymity range API. Not a Collector: it takes a password, not
    a classified entity, so it doesn't fit the dispatcher pipeline — it's
    invoked directly as its own CLI/API action instead. Only a 5-character
    SHA-1 prefix ever leaves this process; the password itself never does.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = await http.get(
            RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": user_agent},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise PwnedPasswordsError(f"request failed: {exc}") from exc

    for line in response.text.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix.strip().upper() == suffix:
            return int(count)
    return 0
