import ipaddress

import httpx
import pytest

from lantern.core.ssrf import SSRFError, SSRFGuardTransport, is_blocked_ip, resolve_safe


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:10.0.0.1",  # IPv4-mapped IPv6 must unwrap before checking
    ],
)
def test_blocked_addresses(ip: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_allowed_addresses(ip: str) -> None:
    assert not is_blocked_ip(ipaddress.ip_address(ip))


async def test_resolve_safe_rejects_ip_literal_in_blocked_range() -> None:
    with pytest.raises(SSRFError):
        await resolve_safe("127.0.0.1")


async def test_resolve_safe_allows_public_ip_literal() -> None:
    ip = await resolve_safe("8.8.8.8")
    assert str(ip) == "8.8.8.8"


async def test_transport_rejects_disallowed_scheme() -> None:
    transport = SSRFGuardTransport()
    request = httpx.Request("GET", "ftp://example.com/")
    with pytest.raises(SSRFError):
        await transport.handle_async_request(request)


async def test_transport_rejects_loopback_target() -> None:
    transport = SSRFGuardTransport()
    request = httpx.Request("GET", "http://127.0.0.1/admin")
    with pytest.raises(SSRFError):
        await transport.handle_async_request(request)
