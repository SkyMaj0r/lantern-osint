from __future__ import annotations

import hashlib

import httpx
import pytest
import respx

from lantern.modules.email.pwned_passwords import PwnedPasswordsError, check_password

PASSWORD = "correct horse battery staple"
SHA1 = hashlib.sha1(PASSWORD.encode()).hexdigest().upper()
PREFIX, SUFFIX = SHA1[:5], SHA1[5:]


@respx.mock
async def test_only_prefix_is_sent_and_match_is_found() -> None:
    route = respx.get(f"https://api.pwnedpasswords.com/range/{PREFIX}").mock(
        return_value=httpx.Response(200, text=f"{SUFFIX}:3730471\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n")
    )

    async with httpx.AsyncClient() as client:
        count = await check_password(PASSWORD, client, "Lantern-OSINT/0.1 (+contact: test@example.com)")

    assert count == 3730471
    request = route.calls.last.request
    assert PASSWORD not in str(request.url)
    assert SUFFIX not in str(request.url)


@respx.mock
async def test_returns_zero_when_suffix_not_in_range() -> None:
    respx.get(f"https://api.pwnedpasswords.com/range/{PREFIX}").mock(
        return_value=httpx.Response(200, text="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n")
    )

    async with httpx.AsyncClient() as client:
        count = await check_password(PASSWORD, client, "Lantern-OSINT/0.1 (+contact: test@example.com)")

    assert count == 0


@respx.mock
async def test_raises_pwned_passwords_error_on_request_failure() -> None:
    respx.get(f"https://api.pwnedpasswords.com/range/{PREFIX}").mock(side_effect=httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as client:
        with pytest.raises(PwnedPasswordsError):
            await check_password(PASSWORD, client, "Lantern-OSINT/0.1 (+contact: test@example.com)")
